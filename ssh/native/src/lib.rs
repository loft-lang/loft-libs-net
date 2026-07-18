// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Native SSH client for loft.  A synchronous, polling FFI over an async russh
//! session (see `session`): `n_ssh_recv` drains an ordered byte buffer the
//! session's background task fills, and `n_ssh_send` enqueues bytes the task
//! writes — so a loft program drives an interactive remote shell without any
//! async in loft.  Binary-safe both ways (raw bytes via `from_utf8_unchecked` /
//! `byte_at`), matching the `web` library's convention.

// These `n_*` are called only by the loft runtime through the generated bridge;
// the pointer/len contract is loft's, so per-fn `# Safety` sections add nothing
// (the `web` library allows the same lint on its FFI surface).
#![allow(clippy::missing_safety_doc)]

use loft_ffi::LoftStr;
use loft_ffi_macros::loft_native;
use std::cell::RefCell;

mod session;

thread_local! {
    // Holds the bytes returned by the most recent `n_ssh_recv`, so the returned
    // `LoftStr` borrows a live buffer.  Built via `from_utf8_unchecked`: it is a
    // byte buffer, not necessarily valid UTF-8 — read it with `n_byte_at`.
    static LAST_RECV: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Connect + SSH transport handshake.  Returns a session handle (>= 0) or -1.
///
/// Returns `i64` (not `i32`): loft `integer` is i64, and under `--native` a
/// negative `i32` return is zero-extended to a large positive value (so `-1`
/// reads as `4294967295` and `ok()` wrongly passes) — any FFI that can return
/// a negative integer must be i64 to stay identical across interpret/native.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_ssh_connect(host_ptr: *const u8, host_len: usize, port: i64) -> i64 {
    let host = unsafe { loft_ffi::text(host_ptr, host_len) };
    session::connect(host, port as u16) as i64
}

/// Password authentication.  Returns true on success.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_ssh_login(
    handle: i32,
    user_ptr: *const u8,
    user_len: usize,
    pw_ptr: *const u8,
    pw_len: usize,
) -> bool {
    let user = unsafe { loft_ffi::text(user_ptr, user_len) };
    let password = unsafe { loft_ffi::text(pw_ptr, pw_len) };
    session::login(handle, user, password)
}

/// Request a PTY (`term`, `cols` x `rows`) and start the login shell.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_ssh_open_shell(
    handle: i32,
    term_ptr: *const u8,
    term_len: usize,
    cols: i64,
    rows: i64,
) -> bool {
    let term = unsafe { loft_ffi::text(term_ptr, term_len) };
    session::open_shell(handle, term, cols as u32, rows as u32)
}

/// Send raw bytes to the remote shell.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_ssh_send(handle: i32, data_ptr: *const u8, data_len: usize) {
    let data = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
    session::send(handle, data);
}

/// Drain and return the bytes received since the last call ("" when idle).
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ssh_recv(handle: i32) -> LoftStr {
    let bytes = session::recv(handle);
    LAST_RECV.with(|b| {
        // SAFETY: the buffer is only ever read back through `n_byte_at` /
        // `len`, which treat it as raw bytes — never as UTF-8.
        *b.borrow_mut() = unsafe { String::from_utf8_unchecked(bytes) };
        loft_ffi::ret_ref(&b.borrow())
    })
}

/// Notify the remote of a terminal resize.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ssh_resize(handle: i32, cols: i64, rows: i64) {
    session::resize(handle, cols as u32, rows as u32);
}

/// True while the shell channel is open.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ssh_is_open(handle: i32) -> bool {
    session::is_open(handle)
}

/// Close the shell channel and disconnect.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ssh_close(handle: i32) {
    session::close(handle);
}

/// Read the byte at `idx` of a byte buffer; -1 if out of range.  Pure compute,
/// byte-identical on every backend (the `web` `byte_at` convention).
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_byte_at(idx: i64, data_ptr: *const u8, data_len: usize) -> i64 {
    if idx < 0 || (idx as usize) >= data_len {
        return -1;
    }
    unsafe { *data_ptr.add(idx as usize) as i64 }
}

// build.rs generates the `loft_register!` list from the `#native` annotations
// in ../src/ssh.loft — the symbol list lives in exactly one place.
include!(concat!(env!("OUT_DIR"), "/loft_register_gen.rs"));
