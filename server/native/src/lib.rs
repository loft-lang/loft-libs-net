// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Minimal blocking HTTP server + WebSocket — std::net only, no external deps.
//! Polling model: loft controls the loop, native does TCP I/O.

mod websocket;

use loft_ffi::{LoftRef, LoftStore, LoftStr};
use loft_ffi_macros::loft_native;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

// ── The accepted connection: plain TCP or TLS over TCP ─────────────────────
//
// Everything downstream (parse_request, respond, the websocket framing) is written over
// `Read + Write`, so it does not care which this is. The one place that DID care is the
// fast-idle poll, which used `TcpStream::peek` to check for a pending WS frame without
// consuming it. rustls cannot peek — you cannot look at plaintext without decrypting, which
// consumes the record — so the TLS arm keeps a small read-ahead buffer: `probe_header`
// reads up to two bytes into it non-blocking, and `Read` drains that buffer before the
// stream. From the caller's side a probe is still non-destructive; the bytes come back on
// the next read. This preserves the "12 Hz collapse" fast-idle fix for TLS too.
enum ServerStreamInner {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}

struct ServerStream {
    inner: ServerStreamInner,
    peekbuf: VecDeque<u8>,
}

/// The result of a non-destructive 2-byte probe of a WS connection.
enum Probe {
    Closed,     // orderly EOF
    Pending,    // fewer than 2 bytes available right now (idle, or a header still arriving)
    Ready,      // at least 2 bytes are available — a frame is waiting
}

impl ServerStream {
    fn plain(s: TcpStream) -> Self {
        ServerStream { inner: ServerStreamInner::Plain(s), peekbuf: VecDeque::new() }
    }
    fn tls(s: rustls::StreamOwned<rustls::ServerConnection, TcpStream>) -> Self {
        ServerStream { inner: ServerStreamInner::Tls(Box::new(s)), peekbuf: VecDeque::new() }
    }
    fn sock(&self) -> &TcpStream {
        match &self.inner {
            ServerStreamInner::Plain(s) => s,
            ServerStreamInner::Tls(t) => &t.sock,
        }
    }
    fn set_nonblocking(&self, on: bool) -> std::io::Result<()> {
        self.sock().set_nonblocking(on)
    }
    fn set_read_timeout(&self, d: Option<std::time::Duration>) -> std::io::Result<()> {
        self.sock().set_read_timeout(d)
    }

    /// Non-destructively check whether a 2-byte WS header is pending, without blocking.
    /// Plain uses `peek` (the kernel keeps the bytes); TLS reads-ahead into `peekbuf`, which
    /// the next `read` drains first — so either way the bytes are still delivered.
    fn probe_header(&mut self) -> Probe {
        match &mut self.inner {
            ServerStreamInner::Plain(s) => {
                let _ = s.set_nonblocking(true);
                let mut hdr = [0u8; 2];
                let r = s.peek(&mut hdr);
                let _ = s.set_nonblocking(false);
                match r {
                    Ok(0) => Probe::Closed,
                    Ok(n) if n < 2 => Probe::Pending,
                    Ok(_) => Probe::Ready,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        Probe::Pending
                    }
                    Err(_) => Probe::Closed,
                }
            }
            ServerStreamInner::Tls(t) => {
                if self.peekbuf.len() >= 2 {
                    return Probe::Ready;
                }
                let _ = t.sock.set_nonblocking(true);
                let mut buf = [0u8; 2];
                let r = t.read(&mut buf);
                let _ = t.sock.set_nonblocking(false);
                match r {
                    Ok(0) => {
                        // 0 from rustls after some plaintext is still buffered means "no
                        // plaintext this instant", not a close — only a real close if nothing
                        // is buffered anywhere.
                        if self.peekbuf.is_empty() { Probe::Closed } else { Probe::Ready }
                    }
                    Ok(n) => {
                        self.peekbuf.extend(&buf[..n]);
                        if self.peekbuf.len() >= 2 { Probe::Ready } else { Probe::Pending }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        if self.peekbuf.len() >= 2 { Probe::Ready } else { Probe::Pending }
                    }
                    Err(_) => {
                        if self.peekbuf.is_empty() { Probe::Closed } else { Probe::Ready }
                    }
                }
            }
        }
    }
}

impl Read for ServerStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Drain any bytes a prior probe read ahead, before touching the stream.
        if !self.peekbuf.is_empty() {
            let mut n = 0;
            while n < buf.len() {
                match self.peekbuf.pop_front() {
                    Some(b) => {
                        buf[n] = b;
                        n += 1;
                    }
                    None => break,
                }
            }
            return Ok(n);
        }
        match &mut self.inner {
            ServerStreamInner::Plain(s) => s.read(buf),
            ServerStreamInner::Tls(t) => t.read(buf),
        }
    }
}

impl Write for ServerStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut self.inner {
            ServerStreamInner::Plain(s) => s.write(buf),
            ServerStreamInner::Tls(t) => t.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match &mut self.inner {
            ServerStreamInner::Plain(s) => s.flush(),
            ServerStreamInner::Tls(t) => t.flush(),
        }
    }
}

/// A bound listener: the TCP socket plus, for a TLS listener, the shared server config used to
/// wrap each accepted connection.
struct Listener {
    tcp: TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
}

thread_local! {
    static LISTENERS: RefCell<Vec<Option<Listener>>> = const { RefCell::new(Vec::new()) };
    static CURRENT_CONN: RefCell<Option<ServerStream>> = const { RefCell::new(None) };
    static LAST_METHOD: RefCell<String> = const { RefCell::new(String::new()) };
    static LAST_PATH: RefCell<String> = const { RefCell::new(String::new()) };
    static LAST_BODY: RefCell<String> = const { RefCell::new(String::new()) };
    /// Raw header block from the most recent accept (line-separated
    /// `Key: Value` lines).  Stored separately from the body so the
    /// existing HTTP API keeps its `body`-only semantics while
    /// `n_ws_upgrade` can find `Sec-WebSocket-Key`.
    static LAST_HEADERS: RefCell<String> = const { RefCell::new(String::new()) };
    /// Buffer for the last `n_tcp_slice` result (binary-safe byte slice).
    static SLICE_BUF: RefCell<String> = const { RefCell::new(String::new()) };
}

fn parse_request<S: Read + Write>(stream: &mut S) -> Option<(String, String, String, String)> {
    // Read the header block BYTE-BY-BYTE.  We deliberately do NOT use
    // BufReader here: a custom client may send WebSocket frames
    // immediately after its `Upgrade: websocket` request without
    // waiting for the server's `101 Switching Protocols` response.
    // A BufReader's internal buffer would slurp those leading WS
    // frame bytes along with the header bytes; on drop they vanish,
    // so the first ws_recv after the upgrade misses the client's
    // first frame.  Reading byte-by-byte until "\r\n\r\n" leaves the
    // post-header bytes in the kernel buffer for ws_read_frame.
    // Mirrors the client-side fix in lib/web/native/src/ws_client.rs.
    let mut window: [u8; 4] = [0, 0, 0, 0];
    let mut header_text = String::new();
    loop {
        let mut byte = [0u8; 1];
        match stream.read(&mut byte) {
            Ok(0) => return None, // EOF before headers complete
            Ok(_) => {}
            Err(_) => return None,
        }
        header_text.push(byte[0] as char);
        window[0] = window[1];
        window[1] = window[2];
        window[2] = window[3];
        window[3] = byte[0];
        if window == *b"\r\n\r\n" {
            break;
        }
        // Cap to avoid slurping a hostile peer's giant header block forever.
        if header_text.len() > 16 * 1024 {
            return None;
        }
    }

    let mut lines = header_text.split("\r\n");
    let request_line = lines.next()?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();

    let mut headers = String::new();
    let mut content_length: usize = 0;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':')
            && key.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or(0);
        }
        headers.push_str(line);
        headers.push('\n');
    }

    let mut body = String::new();
    if content_length > 0 {
        let mut buf = vec![0u8; content_length];
        stream.read_exact(&mut buf).ok()?;
        body = String::from_utf8_lossy(&buf).to_string();
    }

    Some((method, path, headers, body))
}

// ── C-ABI exports ───────────────────────────────────────────────────────
//
// EVERY integer in these signatures is `i64`, because that is what the loft side
// declares.  `server.loft` types each of these natives with `integer`, and loft maps
// `integer` to `i64` (doc/claude/PACKAGES.md § native type mapping) — so loft emits
//   unsafe extern "C" { fn n_tcp_listen(port: i64) -> i64; }
// and calls it directly.  A narrower Rust signature here is NOT a harmless narrowing:
// on x86-64 SysV an `i32` return leaves the upper half of `rax` undefined, so loft
// reads whatever happened to be there.  That is exactly how `n_tcp_listen`'s -1
// arrived in loft as 4294967295 on `--native` while `--interpret` correctly saw -1,
// which silently defeated every `handle >= 0` check on the native backend.
//
// So: widen at the boundary, shadow straight back to the working width inside.  If a
// new export needs a narrow type, change the `#native` declaration in `server.loft`
// too — the two sides are one contract.

/// Bind a listener at `addr:port` with an optional TLS config. The single home every listen
/// variant routes through, so binding, the store, and the log line are written once.
fn bind_listener(addr: &str, port: u32, tls: Option<Arc<rustls::ServerConfig>>) -> i64 {
    let bind = format!("{addr}:{port}");
    match TcpListener::bind(&bind) {
        Ok(tcp) => {
            let scheme = if tls.is_some() { "https/wss" } else { "http/ws" };
            eprintln!("loft server listening on {bind} ({scheme})");
            LISTENERS.with(|l| {
                let mut l = l.borrow_mut();
                let idx = l.len();
                l.push(Some(Listener { tcp, tls }));
                idx as i64
            })
        }
        Err(e) => {
            eprintln!("loft_tcp_listen: cannot bind {bind}: {e}");
            -1
        }
    }
}

/// Build a rustls server config from a PEM cert chain + PEM private key. Returns None on any
/// parse failure (empty chain, unreadable key, no usable key) — the caller reports a bind
/// failure, never a plaintext fallback: a listener asked for TLS that silently served cleartext
/// would be the worst possible surprise.
fn server_config_from_pem(cert_pem: &str, key_pem: &str) -> Option<Arc<rustls::ServerConfig>> {
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
    if certs.is_empty() {
        eprintln!("loft_tcp_listen_tls: no certificate found in the PEM cert chain");
        return None;
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes()).ok()??;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .ok()?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| eprintln!("loft_tcp_listen_tls: bad certificate/key pair: {e}"))
    .ok()?;
    Some(Arc::new(config))
}

/// Bind a plaintext TCP listener on `0.0.0.0:port`. Returns handle (>= 0) or -1.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_tcp_listen(port: i64) -> i64 {
    bind_listener("0.0.0.0", port as u32, None)
}

/// Bind a plaintext TCP listener on a caller-chosen address (`addr:port`) — L3.2. `0.0.0.0`
/// accepts from the network; `127.0.0.1` restricts to loopback, which is the safe default the
/// reverse-proxy notes warned `n_tcp_listen` did NOT give. Returns handle (>= 0) or -1.
///
/// # Safety
/// `addr_ptr`/`addr_len` must describe a valid UTF-8 slice or be `(NULL, 0)`.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_tcp_listen_on(addr_ptr: *const u8, addr_len: usize, port: i64) -> i64 {
    let addr = unsafe { loft_ffi::text_opt(addr_ptr, addr_len) }
        .filter(|s| !s.is_empty())
        .unwrap_or("0.0.0.0")
        .to_string();
    bind_listener(&addr, port as u32, None)
}

/// Bind a TLS listener on `0.0.0.0:port` with a PEM cert chain + PEM private key — L3.1.
/// Returns handle (>= 0), or -1 if the certificate/key is unusable or the bind fails.
///
/// # Safety
/// The four `ptr`/`len` pairs must each describe a valid UTF-8 slice or be `(NULL, 0)`.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_tcp_listen_tls(
    port: i64,
    cert_ptr: *const u8,
    cert_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> i64 {
    unsafe { listen_tls_on("0.0.0.0", port, cert_ptr, cert_len, key_ptr, key_len) }
}

/// Bind a TLS listener on a caller-chosen address (`addr:port`) — L3.1 + L3.2 together.
///
/// # Safety
/// Every `ptr`/`len` pair must describe a valid UTF-8 slice or be `(NULL, 0)`.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_tcp_listen_tls_on(
    addr_ptr: *const u8,
    addr_len: usize,
    port: i64,
    cert_ptr: *const u8,
    cert_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> i64 {
    let addr = unsafe { loft_ffi::text_opt(addr_ptr, addr_len) }
        .filter(|s| !s.is_empty())
        .unwrap_or("0.0.0.0")
        .to_string();
    unsafe { listen_tls_on(&addr, port, cert_ptr, cert_len, key_ptr, key_len) }
}

/// # Safety
/// The `ptr`/`len` pairs must each describe a valid UTF-8 slice or be `(NULL, 0)`.
unsafe fn listen_tls_on(
    addr: &str,
    port: i64,
    cert_ptr: *const u8,
    cert_len: usize,
    key_ptr: *const u8,
    key_len: usize,
) -> i64 {
    let cert = unsafe { loft_ffi::text_opt(cert_ptr, cert_len) }.unwrap_or("");
    let key = unsafe { loft_ffi::text_opt(key_ptr, key_len) }.unwrap_or("");
    match server_config_from_pem(cert, key) {
        Some(cfg) => bind_listener(addr, port as u32, Some(cfg)),
        None => -1,
    }
}

/// Accept the next connection from a listener, completing the TLS handshake if it is a TLS
/// listener. Returns:
///   `Some(Ok(stream))`  — a connection was accepted (and, for TLS, handshaked)
///   `Some(Err(()))`     — an error (accept failed, or the TLS handshake failed)
///   `None`              — nothing pending (WouldBlock)
/// `nonblocking` sets the listener's mode for this accept. A TLS handshake failure is an
/// error for THIS connection only — never a downgrade to plaintext.
fn accept_stream(handle: i32, nonblocking: bool) -> Option<Result<ServerStream, ()>> {
    let accepted = LISTENERS.with(|l| {
        let l = l.borrow();
        let listener = l.get(handle as usize).and_then(|opt| opt.as_ref())?;
        let _ = listener.tcp.set_nonblocking(nonblocking);
        match listener.tcp.accept() {
            Ok((s, _)) => Some(Some((s, listener.tls.clone()))),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Some(None),
            Err(_) => Some(None),
        }
    })?;
    let (tcp, tls) = accepted?;
    match tls {
        None => Some(Ok(ServerStream::plain(tcp))),
        Some(cfg) => {
            // Complete the TLS handshake synchronously (blocking) so a failure surfaces HERE,
            // not later as a mid-stream error that looks like a broken client.
            let _ = tcp.set_nonblocking(false);
            let conn = match rustls::ServerConnection::new(cfg) {
                Ok(c) => c,
                Err(_) => return Some(Err(())),
            };
            let mut sock = tcp;
            let mut conn = conn;
            if conn.complete_io(&mut sock).is_err() {
                return Some(Err(()));
            }
            Some(Ok(ServerStream::tls(rustls::StreamOwned::new(conn, sock))))
        }
    }
}

/// Accept the next connection and parse the HTTP request, NON-BLOCKING.
/// Returns true if a connection was accepted + parsed; false if nothing was
/// pending OR an error occurred (callers cannot distinguish the two — by
/// design, they just poll again on a tick).
///
/// This is the polling variant used by servers that interleave HTTP serving
/// with multi-client WebSocket pumping (single-port HTTP + WS).  The legacy
/// blocking `n_tcp_accept` below remains for single-client servers that
/// only need to handle one request at a time.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_tcp_accept_nonblocking(handle: i64) -> bool {
    let handle = handle as i32;
    let mut stream = match accept_stream(handle, true) {
        Some(Ok(s)) => s,
        _ => return false, // nothing pending, accept error, or TLS handshake failure
    };
    // The accepted stream may inherit non-blocking from the listener on some
    // platforms; force blocking so parse_request reads the (small) HTTP head
    // synchronously without an EAGAIN dance.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(500)));
    match parse_request(&mut stream) {
        Some((method, path, headers, body)) => {
            LAST_METHOD.with(|m| *m.borrow_mut() = method);
            LAST_PATH.with(|p| *p.borrow_mut() = path);
            LAST_HEADERS.with(|h| *h.borrow_mut() = headers);
            LAST_BODY.with(|b| *b.borrow_mut() = body);
            CURRENT_CONN.with(|c| *c.borrow_mut() = Some(stream));
            true
        }
        None => false,
    }
}

/// Accept the next connection and parse the HTTP request.
/// Blocks until a connection arrives. Returns true on success, false on error.
/// After success, call loft_tcp_method/path/body to read the request fields.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_tcp_accept(handle: i64) -> bool {
    let handle = handle as i32;
    let mut stream = match accept_stream(handle, false) {
        Some(Ok(s)) => s,
        _ => return false,
    };
    match parse_request(&mut stream) {
        Some((method, path, headers, body)) => {
            LAST_METHOD.with(|m| *m.borrow_mut() = method);
            LAST_PATH.with(|p| *p.borrow_mut() = path);
            LAST_HEADERS.with(|h| *h.borrow_mut() = headers);
            LAST_BODY.with(|b| *b.borrow_mut() = body);
            CURRENT_CONN.with(|c| *c.borrow_mut() = Some(stream));
            true
        }
        None => false,
    }
}

/// Get the method of the last accepted request.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_tcp_method() -> LoftStr {
    LAST_METHOD.with(|m| loft_ffi::ret_ref(&m.borrow()))
}

/// Get the path of the last accepted request.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_tcp_path() -> LoftStr {
    LAST_PATH.with(|p| loft_ffi::ret_ref(&p.borrow()))
}

/// Get the body of the last accepted request.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_tcp_body() -> LoftStr {
    LAST_BODY.with(|b| loft_ffi::ret_ref(&b.borrow()))
}

/// Get the request headers of the last accepted request as newline-separated
/// `Key: Value` lines (already parsed by `parse_request`).  The loft side splits
/// them into a `vector<text>` and looks up individual headers (Range, If-Range,
/// Origin, …).
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_tcp_headers() -> LoftStr {
    LAST_HEADERS.with(|h| loft_ffi::ret_ref(&h.borrow()))
}

/// Send an HTTP response on the current connection and close it.
/// Defaults to `Content-Type: text/plain; charset=utf-8` for backward
/// compatibility with v1/v2 server programs.  Use
/// `n_tcp_respond_typed` when serving HTML / CSS / JSON / etc.
///
/// # Safety
///
/// `body_ptr` / `body_len` must describe a valid byte slice or be `(NULL, 0)`.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_tcp_respond(status: i64, body_ptr: *const u8, body_len: usize) {
    let status = status as u16;
    unsafe { write_response(status, "text/plain; charset=utf-8", body_ptr, body_len) }
}

/// Send an HTTP response with a caller-specified Content-Type and
/// close the connection.  TTT v3 needs this to serve the index HTML
/// and the loft client source from the same loft program that hosts
/// the WebSocket game protocol.
///
/// `content_type` should be the full media type (e.g.
/// `"text/html; charset=utf-8"` or `"application/wasm"`); pass an
/// empty / null pointer to fall back to `text/plain`.
///
/// # Safety
///
/// `body_ptr` / `body_len` must describe a valid byte slice or be
/// `(NULL, 0)`.  `ct_ptr` / `ct_len` must describe a valid UTF-8
/// slice or be `(NULL, 0)`.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_tcp_respond_typed(
    status: i64,
    body_ptr: *const u8,
    body_len: usize,
    ct_ptr: *const u8,
    ct_len: usize,
) {
    let status = status as u16;
    let ct = unsafe { loft_ffi::text_opt(ct_ptr, ct_len) }
        .filter(|s| !s.is_empty())
        .unwrap_or("text/plain; charset=utf-8");
    unsafe { write_response(status, ct, body_ptr, body_len) }
}

/// `#native "n_tcp_respond_bytes"` — respond with a RAW BYTE BODY.
///
/// ⚠⚠ WHY THIS EXISTS RATHER THAN REUSING `respond_typed`.  Every other respond takes
/// loft `text`, and `write_response` runs the body through `loft_ffi::text_opt`, which
/// validates UTF-8 and yields `""` on failure.  A PNG is not valid UTF-8, so serving one
/// through the text path produced **HTTP 200 with Content-Length: 0** — a successful
/// empty response, which is the worst possible failure: the browser shows a broken image
/// and nothing anywhere reports an error.  Measured 2026-08-21 against the loft repo's
/// own `doc/images/*.png`, every one of which the review viewer was serving that way.
///
/// `text_from_bytes` does not rescue it either — its documented behaviour for
/// non-UTF-8 input is the empty text.  The bytes have to stay bytes end to end, which is
/// what this does: read the `vector<u8>` straight out of the store and hand the slice to
/// `send_and_close` with no string in the path.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_tcp_respond_bytes(
    store: LoftStore,
    status: i64,
    body: LoftRef,
    ct_ptr: *const u8,
    ct_len: usize,
) {
    let status = status as u16;
    let ct = unsafe { loft_ffi::text_opt(ct_ptr, ct_len) }
        .filter(|s| !s.is_empty())
        .unwrap_or("application/octet-stream");
    let bytes = unsafe { read_byte_vector(&store, &body) };

    // Headers built as text, body appended as bytes — the two are concatenated at the
    // byte level so nothing re-validates the payload.
    let head = format!(
        "HTTP/1.1 {status} {}\r\n\
         Content-Length: {}\r\n\
         Content-Type: {ct}\r\n\
         Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n\
         Pragma: no-cache\r\n\
         Expires: 0\r\n\
         Connection: close\r\n\r\n",
        status_text(status),
        bytes.len()
    );
    let mut out = Vec::with_capacity(head.len() + bytes.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(&bytes);
    send_and_close(&out);
}

/// Read a loft `vector<u8>` out of the store as a byte slice.  An unset ref or a
/// zero-length vector answers empty rather than faulting.
unsafe fn read_byte_vector(store: &LoftStore, vec: &LoftRef) -> Vec<u8> {
    if vec.rec == 0 {
        return Vec::new();
    }
    let len = unsafe { store.vector_len(vec) } as usize;
    if len == 0 {
        return Vec::new();
    }
    let ptr = unsafe { store.vector_data_ptr(vec) };
    unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
}

fn status_text(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        304 => "Not Modified",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        416 => "Range Not Satisfiable",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

fn send_and_close(bytes: &[u8]) {
    CURRENT_CONN.with(|c| {
        if let Some(ref mut stream) = *c.borrow_mut() {
            let _ = stream.write_all(bytes);
            let _ = stream.flush();
        }
    });
    // Close the connection.
    CURRENT_CONN.with(|c| *c.borrow_mut() = None);
}

unsafe fn write_response(status: u16, content_type: &str, body_ptr: *const u8, body_len: usize) {
    let body = unsafe { loft_ffi::text_opt(body_ptr, body_len) }.unwrap_or("");
    let response = format!(
        "HTTP/1.1 {status} {}\r\n\
         Content-Length: {}\r\n\
         Content-Type: {content_type}\r\n\
         Cache-Control: no-store, no-cache, must-revalidate, max-age=0\r\n\
         Pragma: no-cache\r\n\
         Expires: 0\r\n\
         Connection: close\r\n\r\n\
         {body}",
        status_text(status),
        body.len()
    );
    send_and_close(response.as_bytes());
}

/// Send a response with caller-controlled headers (DESIGN-http-data-serving S2).
/// `headers` is newline-separated `Key: Value` lines; the caller owns caching,
/// Content-Type, Content-Range, and the CORS headers.  `Content-Length` is
/// auto-added from the body byte length UNLESS the caller supplied one (a HEAD
/// reply passes an explicit length with an empty body); `Connection: close` is
/// always appended.  The body is written verbatim, so binary payloads survive.
///
/// # Safety
///
/// `body_ptr`/`body_len` and `headers_ptr`/`headers_len` must each describe a
/// valid byte slice or be `(NULL, 0)`.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_tcp_respond_full(
    status: i64,
    body_ptr: *const u8,
    body_len: usize,
    headers_ptr: *const u8,
    headers_len: usize,
) {
    let status = status as u16;
    let body = unsafe { loft_ffi::text_opt(body_ptr, body_len) }.unwrap_or("");
    let headers = unsafe { loft_ffi::text_opt(headers_ptr, headers_len) }.unwrap_or("");
    let mut block = String::new();
    let mut has_len = false;
    for line in headers.split('\n') {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        if line.to_ascii_lowercase().starts_with("content-length:") {
            has_len = true;
        }
        block.push_str(line);
        block.push_str("\r\n");
    }
    if !has_len {
        block.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    let response = format!(
        "HTTP/1.1 {} {}\r\n{block}Connection: close\r\n\r\n{body}",
        status,
        status_text(status)
    );
    send_and_close(response.as_bytes());
}

/// Binary-safe byte slice of `body`: bytes `[off, off+len)`, clamped to the
/// body length.  Used by loft `serve_range` to cut a partial-content slice
/// without loft's char-indexing, which would re-encode bytes > 127 and corrupt
/// binary data.  The result lives in a thread-local until the next call.
///
/// # Safety
///
/// `body_ptr` / `body_len` must describe a valid byte slice or be `(NULL, 0)`.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_tcp_slice(
    body_ptr: *const u8,
    body_len: usize,
    off: i64,
    len: i64,
) -> LoftStr {
    let body: &[u8] = if body_ptr.is_null() || body_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(body_ptr, body_len) }
    };
    let start = (off.max(0) as usize).min(body.len());
    let end = start.saturating_add(len.max(0) as usize).min(body.len());
    SLICE_BUF.with(|b| {
        *b.borrow_mut() = unsafe { String::from_utf8_unchecked(body[start..end].to_vec()) };
        loft_ffi::ret_ref(&b.borrow())
    })
}

/// Close a listener.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_tcp_close(handle: i64) {
    let handle = handle as i32;
    LISTENERS.with(|l| {
        let mut l = l.borrow_mut();
        if let Some(slot) = l.get_mut(handle as usize) {
            *slot = None;
        }
    });
}

// ── WebSocket C-ABI exports (SRV.3) ─────────────────────────────────────

thread_local! {
    static WS_CONNS: RefCell<Vec<Option<ServerStream>>> = const { RefCell::new(Vec::new()) };
    static WS_LAST_MSG: RefCell<String> = const { RefCell::new(String::new()) };
    static WS_LAST_OPCODE: RefCell<u8> = const { RefCell::new(0) };
}

/// Upgrade the current HTTP connection to WebSocket. Returns handle (>= 0) or -1.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_upgrade() -> i64 {
    let hdrs = LAST_HEADERS.with(|h| h.borrow().clone());
    let stream = CURRENT_CONN.with(|c| c.borrow_mut().take());
    match stream {
        Some(mut s) => {
            if !websocket::ws_upgrade(&mut s, &hdrs) {
                return -1;
            }
            WS_CONNS.with(|conns| {
                let mut conns = conns.borrow_mut();
                let idx = conns.len();
                conns.push(Some(s));
                idx as i64
            })
        }
        None => -1,
    }
}

/// Read the next WebSocket message. Returns true on success, false on close/error.
/// After success, call loft_ws_message/loft_ws_opcode to get the data.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_recv(handle: i64) -> bool {
    let handle = handle as i32;
    WS_CONNS.with(|conns| {
        let mut conns = conns.borrow_mut();
        let stream = match conns.get_mut(handle as usize).and_then(|o| o.as_mut()) {
            Some(s) => s,
            None => return false,
        };
        match websocket::ws_read_frame(stream) {
            Some(frame) => {
                if frame.opcode == websocket::OP_CLOSE {
                    return false;
                }
                if frame.opcode == websocket::OP_PING {
                    let _ = websocket::ws_write_frame(stream, websocket::OP_PONG, &frame.payload);
                    // Recurse to get the next real message
                    return true; // signal caller to call recv again
                }
                WS_LAST_OPCODE.with(|o| *o.borrow_mut() = frame.opcode);
                WS_LAST_MSG.with(|m| {
                    *m.borrow_mut() = String::from_utf8_lossy(&frame.payload).to_string();
                });
                true
            }
            None => false,
        }
    })
}

/// Get the last received WebSocket message text.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_message() -> LoftStr {
    WS_LAST_MSG.with(|m| loft_ffi::ret_ref(&m.borrow()))
}

/// Get the last received WebSocket opcode (1=text, 2=binary, 8=close, 9=ping, 10=pong).
#[loft_native]
#[unsafe(no_mangle)]
// `i64` on the C boundary: the loft declaration types this `integer`, and loft emits
// the extern from the DECLARATION, so a narrower Rust return leaves the upper half of
// the register undefined and loft reads garbage — visibly, for negatives, on --native
// only.  Narrow inside the body instead.
pub extern "C" fn n_ws_opcode() -> i64 {
    WS_LAST_OPCODE.with(|o| i64::from(*o.borrow()))
}

/// Send a text WebSocket message.
///
/// # Safety
///
/// `msg_ptr` / `msg_len` must describe a valid byte slice.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_ws_send(handle: i64, msg_ptr: *const u8, msg_len: usize) -> bool {
    let handle = handle as i32;
    let msg = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
    WS_CONNS.with(|conns| {
        let mut conns = conns.borrow_mut();
        match conns.get_mut(handle as usize).and_then(|o| o.as_mut()) {
            Some(stream) => websocket::ws_write_frame(stream, websocket::OP_TEXT, msg),
            None => false,
        }
    })
}

/// Send a binary WebSocket message.  Same byte buffer as `n_ws_send`,
/// but the frame goes out with opcode `0x02` (binary) instead of
/// `0x01` (text).  TTT v5 + plan-36 use this for `world_snapshot` and
/// `world_delta` blobs.
///
/// # Safety
///
/// `msg_ptr` / `msg_len` must describe a valid byte slice.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_ws_send_binary(handle: i64, msg_ptr: *const u8, msg_len: usize) -> bool {
    let handle = handle as i32;
    let msg = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
    WS_CONNS.with(|conns| {
        let mut conns = conns.borrow_mut();
        match conns.get_mut(handle as usize).and_then(|o| o.as_mut()) {
            Some(stream) => websocket::ws_write_frame(stream, websocket::OP_BINARY, msg),
            None => false,
        }
    })
}

/// Close a WebSocket connection.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_close(handle: i64) {
    let handle = handle as i32;
    WS_CONNS.with(|conns| {
        let mut conns = conns.borrow_mut();
        if let Some(slot) = conns.get_mut(handle as usize) {
            if let Some(stream) = slot.as_mut() {
                let _ = websocket::ws_write_frame(stream, websocket::OP_CLOSE, &[]);
            }
            *slot = None;
        }
    });
}

// ── Multi-client server primitives (TIC_TAC_TOE v2 ground layer) ─────────
//
// The legacy flow is `n_tcp_accept` (blocking) → `n_ws_upgrade` (consumes
// CURRENT_CONN) → one client at a time.  The multi-client flow below
// combines accept + parse + upgrade into a single non-blocking call so
// the loft program can hold many concurrent WebSocket clients and poll
// each without head-of-line blocking on any one of them.
//
// The clean event-pump entry point (`n_ws_next_event`) is below.  Loft
// programs use it via `Server::run(on_connect, on_message)` and never
// see the slot table directly.  The split entry points
// (`n_ws_accept_nonblocking`, `n_ws_clients_len`,
// `n_ws_client_active`) are kept as a private fallback path.
//
// Per-client streams are set non-blocking with a short read timeout
// (20 ms) on accept so polling stays cheap.

/// Three-way result of accepting a pending connection on a
/// non-blocking listener.  Both NoneYet and Error look identical
/// to the event pump (nothing to deliver this poll), but the
/// legacy `n_ws_accept_nonblocking` entry point keeps its -1 / -2
/// distinction by reading this directly.
enum AcceptOutcome {
    Pending(i32),
    /// A non-WebSocket HTTP request was accepted: the stream is parked in
    /// CURRENT_CONN and LAST_METHOD/PATH/HEADERS/BODY are set, so the loft
    /// event handler can read the path and reply via `tcp_respond_*` (which
    /// writes to CURRENT_CONN and closes).  Lets a single-port server serve
    /// its page AND drive WebSockets through the one event pump.
    Http,
    NoneYet,
    Error,
}

fn try_accept_inner(listener_handle: i32) -> AcceptOutcome {
    // Accept + (for a TLS listener) complete the handshake in one place.
    let mut stream = match accept_stream(listener_handle, true) {
        None => return AcceptOutcome::NoneYet,
        Some(Ok(s)) => s,
        Some(Err(())) => return AcceptOutcome::Error, // accept or TLS handshake failed
    };
    // Force blocking for the HTTP read (small, finite); the post-upgrade WS read polling
    // switches to a short read timeout below.
    let _ = stream.set_nonblocking(false);
    let (method, path, headers, body) = match parse_request(&mut stream) {
        Some(t) => t,
        None => return AcceptOutcome::Error,
    };
    // A request without a Sec-WebSocket-Key is a plain HTTP request, not a WS
    // upgrade.  Park it for the loft handler to answer instead of dropping it
    // (so the same event pump serves the page + the WebSockets on one port).
    if !headers.to_ascii_lowercase().contains("sec-websocket-key") {
        LAST_METHOD.with(|m| *m.borrow_mut() = method);
        LAST_PATH.with(|p| *p.borrow_mut() = path);
        LAST_HEADERS.with(|h| *h.borrow_mut() = headers);
        LAST_BODY.with(|b| *b.borrow_mut() = body);
        CURRENT_CONN.with(|c| *c.borrow_mut() = Some(stream));
        return AcceptOutcome::Http;
    }
    if !websocket::ws_upgrade(&mut stream, &headers) {
        return AcceptOutcome::Error;
    }
    // Switch to short-timeout reads so polling stays non-blocking.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(20)));
    let id = WS_CONNS.with(|conns| {
        let mut conns = conns.borrow_mut();
        // Reuse a freed slot if any (id stability across reconnects
        // is not required at this layer; ids are reused after close).
        for (i, slot) in conns.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(stream);
                return i as i32;
            }
        }
        let idx = conns.len();
        conns.push(Some(stream));
        idx as i32
    });
    AcceptOutcome::Pending(id)
}

/// Try to accept a pending connection on a non-blocking listener.  If
/// one is pending, parse the HTTP request, perform the WebSocket
/// upgrade, register the stream as a client, and return its id (>= 0).
/// If no connection is pending, returns -1.  Returns -2 on a listener
/// or upgrade error so loft can distinguish "not yet" from "broken".
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_accept_nonblocking(listener_handle: i64) -> i64 {
    let listener_handle = listener_handle as i32;
    match try_accept_inner(listener_handle) {
        AcceptOutcome::Pending(id) => i64::from(id),
        // Legacy WS-only entry point: a plain HTTP request has no client id
        // here, so report it as an error (the stream parked in CURRENT_CONN
        // is dropped on the next accept).  Multi-client servers use the
        // event pump (`n_ws_next_event`), which surfaces HTTP properly.
        AcceptOutcome::Http => -2,
        AcceptOutcome::NoneYet => -1,
        AcceptOutcome::Error => -2,
    }
}

/// Total length of the WS_CONNS table (active + closed slots).
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_clients_len() -> i64 {
    WS_CONNS.with(|conns| conns.borrow().len() as i64)
}

/// True iff the WS_CONNS slot at `id` is currently occupied.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_client_active(id: i64) -> bool {
    let id = id as i32;
    WS_CONNS.with(|conns| {
        conns
            .borrow()
            .get(id as usize)
            .map(|o| o.is_some())
            .unwrap_or(false)
    })
}

// ── Event pump primitives (clean loft surface) ──────────────────────────
//
// The event pump is the single supported path for multi-client
// servers in loft.  Loft programs call `Server::run(on_connect,
// on_message)`, which internally drains events via
// `n_ws_next_event` until it returns false, then sleeps briefly
// and tries again.
//
// At-most-one-event-per-call keeps event order roughly real-time
// (the loft side cannot fall behind by more than one event).
//
// The Disconnected kind (2) is surfaced so the loft drain loop can
// keep advancing, but the loft `run()` body discards it without
// calling any application callback.  This was the user's explicit
// directive: the loft side does not know about disconnects.

thread_local! {
    static WS_EVENT_KIND:      Cell<i32>       = const { Cell::new(-1) };
    static WS_EVENT_CLIENT_ID: Cell<i32>       = const { Cell::new(-1) };
    static WS_EVENT_PAYLOAD:   RefCell<String> = const { RefCell::new(String::new()) };
}

enum PollOutcome {
    NoData,
    Frame(String),
    Disconnected,
}

fn poll_one_client(id: i32) -> PollOutcome {
    WS_CONNS.with(|conns| {
        let mut conns = conns.borrow_mut();
        let Some(stream) = conns.get_mut(id as usize).and_then(|o| o.as_mut()) else {
            return PollOutcome::NoData;
        };
        // PING is handled inline (write PONG, then keep probing).
        // Anything else returns immediately: NoData on timeout,
        // Frame on a real text frame, Disconnected on close / EOF.
        loop {
            // @PLN18 phase 00(b) — fast-idle poll.  The blocking 20 ms read
            // timeout made every IDLE client cost ~21 ms per scan, so one empty
            // drain sweep cost N x 21 ms (measured 252.5 ms at 12 clients) and
            // the server tick collapsed (the "12 Hz" finding).  Probe the 2-byte
            // WS header non-blocking first: nothing pending -> NoData in
            // microseconds; bytes pending -> fall through to the blocking frame
            // read.  `probe_header` is non-destructive on both transports (plain
            // via `peek`, TLS via a read-ahead buffer the frame read drains).
            match stream.probe_header() {
                Probe::Closed => return PollOutcome::Disconnected,
                Probe::Pending => return PollOutcome::NoData,
                Probe::Ready => {} // a frame is pending — read it
            }
            match websocket::ws_read_frame_detailed(stream) {
                websocket::ReadOutcome::NoData => return PollOutcome::NoData,
                websocket::ReadOutcome::Closed => return PollOutcome::Disconnected,
                websocket::ReadOutcome::Frame(frame) => {
                    if frame.opcode == websocket::OP_CLOSE {
                        return PollOutcome::Disconnected;
                    }
                    if frame.opcode == websocket::OP_PING {
                        let _ =
                            websocket::ws_write_frame(stream, websocket::OP_PONG, &frame.payload);
                        continue;
                    }
                    let payload = String::from_utf8_lossy(&frame.payload).to_string();
                    return PollOutcome::Frame(payload);
                }
            }
        }
    })
}

/// Drain at most one event from the listener+clients on this server.
/// Returns true if an event was found (call n_ws_event_kind /
/// n_ws_event_client_id / n_ws_event_payload to read it).  Returns
/// false when nothing is pending.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_next_event(listener_handle: i64) -> bool {
    let listener_handle = listener_handle as i32;
    match try_accept_inner(listener_handle) {
        AcceptOutcome::Pending(cid) => {
            WS_EVENT_KIND.with(|k| k.set(0));
            WS_EVENT_CLIENT_ID.with(|c| c.set(cid));
            WS_EVENT_PAYLOAD.with(|p| p.borrow_mut().clear());
            return true;
        }
        AcceptOutcome::Http => {
            // Kind 3 = HTTP request.  No client id (-1); the request path is
            // delivered as the payload, and the stream is parked in
            // CURRENT_CONN for the handler's `respond_*` call.
            let path = LAST_PATH.with(|p| p.borrow().clone());
            WS_EVENT_KIND.with(|k| k.set(3));
            WS_EVENT_CLIENT_ID.with(|c| c.set(-1));
            WS_EVENT_PAYLOAD.with(|p| *p.borrow_mut() = path);
            return true;
        }
        AcceptOutcome::NoneYet | AcceptOutcome::Error => {}
    }
    let len = WS_CONNS.with(|c| c.borrow().len()) as i32;
    for i in 0..len {
        let active = WS_CONNS.with(|c| c.borrow().get(i as usize).is_some_and(|o| o.is_some()));
        if !active {
            continue;
        }
        match poll_one_client(i) {
            PollOutcome::NoData => continue,
            PollOutcome::Frame(s) => {
                WS_EVENT_KIND.with(|k| k.set(1));
                WS_EVENT_CLIENT_ID.with(|c| c.set(i));
                WS_EVENT_PAYLOAD.with(|p| *p.borrow_mut() = s);
                return true;
            }
            PollOutcome::Disconnected => {
                WS_CONNS.with(|c| {
                    if let Some(slot) = c.borrow_mut().get_mut(i as usize) {
                        *slot = None;
                    }
                });
                WS_EVENT_KIND.with(|k| k.set(2));
                WS_EVENT_CLIENT_ID.with(|c| c.set(i));
                WS_EVENT_PAYLOAD.with(|p| p.borrow_mut().clear());
                return true;
            }
        }
    }
    false
}

/// Read the kind of the last event surfaced by n_ws_next_event.
/// 0 = Connected, 1 = Message, 2 = Disconnected.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_event_kind() -> i64 {
    WS_EVENT_KIND.with(|k| i64::from(k.get()))
}

/// Read the client id of the last event surfaced by n_ws_next_event.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_event_client_id() -> i64 {
    WS_EVENT_CLIENT_ID.with(|c| i64::from(c.get()))
}

/// Read the payload of the last event surfaced by n_ws_next_event.
/// Empty string for Connected and Disconnected events.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_event_payload() -> LoftStr {
    WS_EVENT_PAYLOAD.with(|p| loft_ffi::ret_ref(&p.borrow()))
}

/// Sleep for `ms` milliseconds.  The loft `run()` loop calls this
/// when a drain pass produced zero events to avoid CPU-spinning in
/// the no-clients-yet phase.  Doing the sleep in Rust keeps the
/// loft side oblivious to timing primitives — there is no general
/// `sleep` in the loft stdlib today.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_idle_sleep_ms(ms: i64) {
    let ms = ms as i32;
    if ms > 0 {
        std::thread::sleep(std::time::Duration::from_millis(ms as u64));
    }
}

/// Send a text frame to every active WebSocket client.  Returns the
/// number of successful sends.  No iteration in loft.  The handle
/// argument is accepted for API symmetry with send_to / disconnect
/// but is currently ignored — WS_CONNS is a single thread-local
/// table shared across all servers in this thread.
///
/// # Safety
///
/// `msg_ptr` / `msg_len` must describe a valid byte slice.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_ws_broadcast(_handle: i64, msg_ptr: *const u8, msg_len: usize) -> i64 {
    let _handle = _handle as i32;
    let msg = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
    WS_CONNS.with(|conns| {
        let mut conns = conns.borrow_mut();
        let mut count: i64 = 0;
        for slot in conns.iter_mut() {
            if let Some(stream) = slot.as_mut()
                && websocket::ws_write_frame(stream, websocket::OP_TEXT, msg)
            {
                count += 1;
            }
        }
        count
    })
}

// The `loft_ffi::loft_register!` + `loft_register_bridges!` invocations are
// GENERATED by `build.rs` (via `loft-ffi-build::generate_register_from_loft_with_bridges`)
// scanning this crate's loft sources for `#native` annotations.  Defining a
// native function (its `#[loft_native]` + co-located `#native` decl) IS
// registering it — no hand-maintained symbol list.
include!(concat!(env!("OUT_DIR"), "/loft_register_gen.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    /// P221: when a client sends WS frame bytes immediately after the
    /// upgrade request without waiting for `101 Switching Protocols`,
    /// `parse_request` must NOT swallow them.  The bytes after the
    /// `\r\n\r\n` header terminator must remain in the kernel buffer
    /// for the next reader (e.g. `ws_read_frame`).  The original
    /// `BufReader::new(stream)` implementation absorbed those bytes
    /// into its internal buffer and lost them when the BufReader
    /// dropped at end of `parse_request`.
    #[test]
    fn p221_parse_request_leaves_post_header_bytes_in_kernel_buffer() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();

        let trailing: &[u8] = b"WS-FRAME-BYTES-XYZ";
        let trailing_owned = trailing.to_vec();
        let client = thread::spawn(move || {
            let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            // Aggressive client: write the upgrade request AND the
            // first WS frame back-to-back, before reading the 101.
            let req = b"GET /ws HTTP/1.1\r\n\
                Host: 127.0.0.1\r\n\
                Upgrade: websocket\r\n\
                Connection: Upgrade\r\n\
                Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                Sec-WebSocket-Version: 13\r\n\
                \r\n";
            s.write_all(req).expect("write headers");
            s.write_all(&trailing_owned).expect("write trailing");
            // Hand the stream back via a small read so the test can
            // close once the server has consumed the trailing bytes.
            let mut sink = [0u8; 8];
            let _ = s.read(&mut sink);
        });

        let (mut server_stream, _peer) = listener.accept().expect("accept");
        let parsed = parse_request(&mut server_stream).expect("parse");
        assert_eq!(parsed.0, "GET");
        assert_eq!(parsed.1, "/ws");

        // The trailing bytes the client appended after the header
        // terminator must still be readable from the kernel buffer.
        server_stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut buf = vec![0u8; trailing.len()];
        server_stream.read_exact(&mut buf).expect("read trailing");
        assert_eq!(&buf[..], trailing, "post-header bytes were swallowed");

        drop(server_stream);
        let _ = client.join();
    }

    /// @PLAN36-1.9: a hostile client can send a 127-length WS frame header
    /// claiming a near-u64::MAX payload.  The reader must reject it as
    /// `Closed` after reading the length field — NOT trust it and attempt a
    /// multi-exabyte `vec![0u8; len]`, which aborts the whole process (and
    /// every other client's session with it).
    #[test]
    fn p_oversized_ws_frame_rejected_without_alloc() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();

        let client = thread::spawn(move || {
            let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            // FIN + binary opcode (0x82); masked + 127-length marker (0xFF);
            // then a u64::MAX payload length.  No mask/payload follow — the
            // reader must bail at the length check before reading them.
            let mut frame = vec![0x82u8, 0xFFu8];
            frame.extend_from_slice(&u64::MAX.to_be_bytes());
            let _ = s.write_all(&frame);
            let mut sink = [0u8; 4];
            let _ = s.read(&mut sink); // keep open until the server reads
        });

        let (mut server_stream, _peer) = listener.accept().expect("accept");
        server_stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        match websocket::ws_read_frame_detailed(&mut server_stream) {
            websocket::ReadOutcome::Closed => {}
            websocket::ReadOutcome::Frame(_) => panic!("oversized frame accepted as a Frame"),
            websocket::ReadOutcome::NoData => panic!("oversized frame returned NoData"),
        }

        drop(server_stream);
        let _ = client.join();
    }

    // ── L3 verification: the server terminates TLS for HTTP and WebSocket ───────────────────
    const CERT_PEM: &str = include_str!("../tests/fixtures/cert.pem");
    const KEY_PEM: &str = include_str!("../tests/fixtures/key.pem");

    // A rustls client that trusts anything — the fixture cert is self-signed, and this is the
    // client half of the loopback test, not production. Mirrors the web client's dev opt-out.
    #[derive(Debug)]
    struct NoVerify;
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &rustls_pki_types::CertificateDer<'_>,
            _: &[rustls_pki_types::CertificateDer<'_>],
            _: &rustls_pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls_pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls_pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    fn client_config() -> Arc<rustls::ClientConfig> {
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
        )
    }

    // Connect a TLS client to 127.0.0.1:port and return the handshaked stream.
    fn tls_client(port: u16) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
        let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let mut conn = rustls::ClientConnection::new(client_config(), name).unwrap();
        let mut sock = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        conn.complete_io(&mut sock).expect("client TLS handshake");
        rustls::StreamOwned::new(conn, sock)
    }

    #[test]
    fn server_config_from_pem_accepts_good_rejects_bad() {
        assert!(
            server_config_from_pem(CERT_PEM, KEY_PEM).is_some(),
            "a valid PEM cert+key builds a server config"
        );
        assert!(
            server_config_from_pem("not a certificate", "not a key").is_none(),
            "garbage PEM is rejected — a TLS listener never falls back to cleartext"
        );
        assert!(
            server_config_from_pem("", KEY_PEM).is_none(),
            "an empty cert chain is rejected"
        );
    }

    // L3.2: listen_on binds the requested address, not the 0.0.0.0 wildcard.
    #[test]
    fn bind_address_is_honored() {
        let h = bind_listener("127.0.0.1", 0, None);
        assert!(h >= 0, "loopback bind succeeds");
        let bound_ip = LISTENERS.with(|l| {
            l.borrow()[h as usize]
                .as_ref()
                .unwrap()
                .tcp
                .local_addr()
                .unwrap()
                .ip()
        });
        assert!(bound_ip.is_loopback(), "a 127.0.0.1 listener is bound to loopback, not the wildcard");
    }

    // L3.1 + L3.3: a TLS listener terminates HTTP AND a WebSocket upgrade + echo, over the same
    // op surface a plaintext server uses — the server side never mentions TLS.
    #[test]
    fn tls_http_then_ws_over_the_same_surface() {
        let cfg = server_config_from_pem(CERT_PEM, KEY_PEM).unwrap();
        let handle = bind_listener("127.0.0.1", 0, Some(cfg)) as i32;
        let port = LISTENERS.with(|l| {
            l.borrow()[handle as usize].as_ref().unwrap().tcp.local_addr().unwrap().port()
        });

        // (1) HTTP over TLS — L3.1. Client thread does GET /; server accepts + responds.
        let c1 = thread::spawn(move || {
            let mut tls = tls_client(port);
            tls.write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            let mut buf = [0u8; 256];
            let n = tls.read(&mut buf).unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        let mut s = match accept_stream(handle, false).unwrap() {
            Ok(s) => s,
            Err(()) => panic!("TLS accept/handshake failed"),
        };
        let (method, path, _h, _b) = parse_request(&mut s).expect("parse the request over TLS");
        assert_eq!(method, "GET");
        assert_eq!(path, "/hello");
        let body = b"tls-ok";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        s.write_all(resp.as_bytes()).unwrap();
        s.flush().unwrap();
        drop(s);
        let got = c1.join().unwrap();
        assert!(got.starts_with("HTTP/1.1 200 OK"), "client got a 200 over TLS: {got:?}");
        assert!(got.trim_end().ends_with("tls-ok"), "client got the body over TLS: {got:?}");

        // (2) WebSocket over TLS — L3.3. Client upgrades + sends a masked frame; server upgrades
        // + reads it back through the same websocket path a plaintext server uses.
        let c2 = thread::spawn(move || {
            let mut tls = tls_client(port);
            // a minimal, spec-correct upgrade request (the accept token is checked by the client
            // in a real browser; here we just need the server to 101 and then read our frame)
            let key = "dGhlIHNhbXBsZSBub25jZQ=="; // RFC 6455 example key
            let req = format!(
                "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            );
            tls.write_all(req.as_bytes()).unwrap();
            // read the 101 response head
            let mut buf = [0u8; 256];
            let _ = tls.read(&mut buf).unwrap();
            // send one masked text frame "over-tls"
            let payload = b"over-tls";
            let mask = [0x11u8, 0x22, 0x33, 0x44];
            let mut frame = vec![0x81u8, 0x80 | payload.len() as u8];
            frame.extend_from_slice(&mask);
            for (i, b) in payload.iter().enumerate() {
                frame.push(b ^ mask[i % 4]);
            }
            tls.write_all(&frame).unwrap();
            tls.flush().unwrap();
            thread::sleep(std::time::Duration::from_millis(200));
        });
        let mut ws = match accept_stream(handle, false).unwrap() {
            Ok(s) => s,
            Err(()) => panic!("TLS accept for WS failed"),
        };
        let (_m, _p, headers, _b) = parse_request(&mut ws).expect("parse the WS upgrade over TLS");
        assert!(websocket::ws_upgrade(&mut ws, &headers), "the server completes the WS upgrade over TLS");
        let frame = websocket::ws_read_frame(&mut ws).expect("a WS frame arrives over TLS");
        assert_eq!(frame.opcode, websocket::OP_TEXT);
        assert_eq!(String::from_utf8_lossy(&frame.payload), "over-tls");
        let _ = c2.join();
    }
}
