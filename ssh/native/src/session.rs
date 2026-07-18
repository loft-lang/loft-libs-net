// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Async SSH sessions behind a synchronous, polling FFI.
//!
//! russh runs on one shared tokio runtime.  Connect + auth + shell-open are
//! short, so the FFI calls them with `block_on`.  Once the shell is open, a
//! per-session background task owns the channel and:
//!   - appends every received `Data`/`ExtendedData` chunk to an ordered
//!     `inbound` buffer that `recv` drains, and
//!   - writes bytes / window-changes it receives over an mpsc queue that
//!     `send` / `resize` push to.
//!
//! **Load-bearing invariant:** the bytes `recv` returns, concatenated across
//! calls, equal exactly the bytes the remote shell produced, in order, with
//! none lost or duplicated — across the task <-> FFI-thread boundary.  A single
//! producer (the task) appends under the `inbound` mutex and `recv` takes the
//! whole buffer under the same mutex, so order and completeness hold; the mpsc
//! FIFO gives the same guarantee for `send`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use russh::client;
use russh::{ChannelMsg, Disconnect};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// The one shared tokio runtime (built lazily on first connect).
fn rt() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build tokio runtime")
    })
}

/// Run a future to completion from a **non-runtime** thread.
///
/// loft's own `--native` runtime is async: calling `Runtime::block_on` directly
/// from one of its worker threads panics ("cannot start a runtime from within a
/// runtime"), which the native FFI wrapper swallows into a default return — so
/// `connect` silently looked like it *succeeded* under `--native` while working
/// under the interpreter.  Driving the future on a scoped helper thread keeps
/// `block_on` off loft's runtime thread, so connect / auth / shell-open behave
/// identically on both backends.  Used only for the short setup calls; the
/// running shell never blocks (it is pumped by a spawned task).
fn run_blocking<F>(fut: F) -> F::Output
where
    F: std::future::Future + Send,
    F::Output: Send,
{
    std::thread::scope(|s| s.spawn(|| rt().block_on(fut)).join().unwrap())
}

/// A command from the FFI thread to a session's shell I/O task.
enum Cmd {
    Data(Vec<u8>),
    Resize(u32, u32),
    Close,
}

/// State shared between a session's I/O task and the FFI thread.
struct Shell {
    /// Bytes received from the remote, in arrival order; drained by `recv`.
    inbound: Mutex<Vec<u8>>,
    /// False once the channel closes / EOFs.
    open: AtomicBool,
    /// To the I/O task: outbound bytes, resizes, close.
    tx: UnboundedSender<Cmd>,
}

/// A registered session: the russh handle keeps the SSH connection alive; the
/// shell state exists once `open_shell` has run.
struct Entry {
    handle: client::Handle<ClientHandler>,
    shell: Option<Arc<Shell>>,
}

fn registry() -> &'static Mutex<HashMap<i32, Entry>> {
    static REG: OnceLock<Mutex<HashMap<i32, Entry>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_id() -> i32 {
    static NEXT: AtomicI32 = AtomicI32::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Host-key handler.  Accepts any server key: this client authenticates by
/// password over the already-encrypted transport.  A stored known-hosts (TOFU)
/// check is a future hardening step — recorded here so accepting the key is a
/// conscious choice, not a silent hole.
struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Connect + transport handshake.  Handle >= 0 on success, -1 on failure.
pub fn connect(host: &str, port: u16) -> i32 {
    let config = Arc::new(client::Config::default());
    let host = host.to_string();
    let connected = run_blocking(async move {
        client::connect(config, (host.as_str(), port), ClientHandler).await
    });
    match connected {
        Ok(handle) => {
            let id = next_id();
            registry()
                .lock()
                .unwrap()
                .insert(id, Entry { handle, shell: None });
            id
        }
        Err(_) => -1,
    }
}

/// Password authentication.
pub fn login(id: i32, user: &str, password: &str) -> bool {
    let mut reg = registry().lock().unwrap();
    let Some(entry) = reg.get_mut(&id) else {
        return false;
    };
    let result = run_blocking(entry.handle.authenticate_password(user, password));
    matches!(result, Ok(client::AuthResult::Success))
}

/// Open a PTY-backed shell and spawn its I/O task.
pub fn open_shell(id: i32, term: &str, cols: u32, rows: u32) -> bool {
    let mut reg = registry().lock().unwrap();
    let Some(entry) = reg.get_mut(&id) else {
        return false;
    };
    let term = term.to_string();
    let opened = run_blocking(async {
        let channel = entry.handle.channel_open_session().await.ok()?;
        channel
            .request_pty(false, &term, cols, rows, 0, 0, &[])
            .await
            .ok()?;
        channel.request_shell(false).await.ok()?;
        Some(channel)
    });
    let Some(channel) = opened else {
        return false;
    };
    let (tx, rx) = unbounded_channel();
    let shell = Arc::new(Shell {
        inbound: Mutex::new(Vec::new()),
        open: AtomicBool::new(true),
        tx,
    });
    rt().spawn(io_task(channel, rx, shell.clone()));
    entry.shell = Some(shell);
    true
}

/// The per-session shell pump: remote data -> `inbound`; commands -> channel.
async fn io_task(
    mut channel: russh::Channel<client::Msg>,
    mut rx: UnboundedReceiver<Cmd>,
    shell: Arc<Shell>,
) {
    loop {
        tokio::select! {
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { data }) => {
                    shell.inbound.lock().unwrap().extend_from_slice(&data);
                }
                Some(ChannelMsg::ExtendedData { data, .. }) => {
                    shell.inbound.lock().unwrap().extend_from_slice(&data);
                }
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                    shell.open.store(false, Ordering::SeqCst);
                    break;
                }
                _ => {}
            },
            cmd = rx.recv() => match cmd {
                Some(Cmd::Data(bytes)) => { let _ = channel.data(&bytes[..]).await; }
                Some(Cmd::Resize(c, r)) => { let _ = channel.window_change(c, r, 0, 0).await; }
                Some(Cmd::Close) | None => {
                    let _ = channel.eof().await;
                    shell.open.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    }
}

fn shell_of(id: i32) -> Option<Arc<Shell>> {
    registry().lock().unwrap().get(&id).and_then(|e| e.shell.clone())
}

/// Enqueue bytes for the remote shell.
pub fn send(id: i32, data: &[u8]) {
    if let Some(shell) = shell_of(id) {
        let _ = shell.tx.send(Cmd::Data(data.to_vec()));
    }
}

/// Drain all bytes received since the last call.
pub fn recv(id: i32) -> Vec<u8> {
    match shell_of(id) {
        Some(shell) => std::mem::take(&mut *shell.inbound.lock().unwrap()),
        None => Vec::new(),
    }
}

/// Notify the remote of a terminal resize.
pub fn resize(id: i32, cols: u32, rows: u32) {
    if let Some(shell) = shell_of(id) {
        let _ = shell.tx.send(Cmd::Resize(cols, rows));
    }
}

/// True while the shell channel is open.
pub fn is_open(id: i32) -> bool {
    shell_of(id)
        .map(|s| s.open.load(Ordering::SeqCst))
        .unwrap_or(false)
}

/// Close the shell channel and disconnect the session.
pub fn close(id: i32) {
    let entry = registry().lock().unwrap().remove(&id);
    if let Some(entry) = entry {
        if let Some(shell) = &entry.shell {
            let _ = shell.tx.send(Cmd::Close);
        }
        let handle = entry.handle;
        rt().spawn(async move {
            let _ = handle
                .disconnect(Disconnect::ByApplication, "", "en")
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Falsification probe for the load-bearing invariant: bytes appended by a
    /// producer thread, drained by repeated `recv`-style takes, come back in
    /// order and complete.  Exercises the cross-thread `inbound` mutex directly
    /// (no network), the part most likely to lose or reorder bytes.
    #[test]
    fn inbound_is_ordered_and_lossless() {
        let (tx, _rx) = unbounded_channel();
        let shell = Arc::new(Shell {
            inbound: Mutex::new(Vec::new()),
            open: AtomicBool::new(true),
            tx,
        });
        const N: usize = 100_000;
        let producer = {
            let shell = shell.clone();
            std::thread::spawn(move || {
                for i in 0..N {
                    shell.inbound.lock().unwrap().push((i % 256) as u8);
                }
            })
        };
        let mut drained: Vec<u8> = Vec::new();
        while drained.len() < N {
            let chunk = std::mem::take(&mut *shell.inbound.lock().unwrap());
            drained.extend_from_slice(&chunk);
        }
        producer.join().unwrap();
        // any trailing bytes appended between the last take and join:
        drained.extend_from_slice(&std::mem::take(&mut *shell.inbound.lock().unwrap()));
        assert_eq!(drained.len(), N);
        for (i, b) in drained.iter().enumerate() {
            assert_eq!(*b, (i % 256) as u8, "byte {i} out of order");
        }
    }
}
