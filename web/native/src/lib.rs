// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later

//! Native HTTP client + WebSocket client.  HTTP uses ureq; WebSocket uses
//! plain std::net (native build) or host imports (wasm build).
//! WebSocket sessions auto-reconnect on connection failure with exponential
//! backoff capped at 10 seconds — see `ws_client::ensure_connected`.

use loft_ffi::LoftStr;
use loft_ffi_macros::loft_native;

mod ws_client;

/// Perform an HTTP request and return `(status, body_bytes, response_headers)`.
/// The body is read as raw bytes (NOT `into_string`) so binary payloads with
/// embedded NUL bytes survive intact — the same convention as the `pack_*` /
/// `byte_at` builder.  `status == 0` signals a transport error (no response).
fn do_request(
    method: &str,
    url: &str,
    body: Option<&str>,
    headers: &[(&str, &str)],
) -> (i32, Vec<u8>, Vec<(String, String)>) {
    let agent = http_agent();
    let mut req = match method {
        "GET" => agent.get(url),
        "POST" => agent.post(url),
        "PUT" => agent.put(url),
        "DELETE" => agent.delete(url),
        "HEAD" => agent.head(url),
        _ => return (0, Vec::new(), Vec::new()),
    };
    for (k, v) in headers {
        req = req.set(k, v);
    }
    let response = if let Some(b) = body {
        req.send_string(b)
    } else {
        req.call()
    };
    // Both success and HTTP-error responses carry a body + headers worth
    // returning (a 206 range read, a 404 page, …); only transport failures don't.
    let resp = match response {
        Ok(resp) => resp,
        Err(ureq::Error::Status(_, resp)) => resp,
        Err(_) => return (0, Vec::new(), Vec::new()),
    };
    let status = resp.status() as i32;
    let resp_headers: Vec<(String, String)> = resp
        .headers_names()
        .into_iter()
        .filter_map(|name| resp.header(&name).map(|v| (name.clone(), v.to_string())))
        .collect();
    let mut body_bytes = Vec::new();
    let _ = resp.into_reader().read_to_end(&mut body_bytes);
    (status, body_bytes, resp_headers)
}

/// A ureq agent whose TLS root store is the bundled Mozilla roots (webpki-roots)
/// PLUS any CAs named by the `SSL_CERT_FILE` environment variable — the same
/// convention curl (`--cacert` / `SSL_CERT_FILE`) and openssl use. Certificate
/// verification stays ON; `SSL_CERT_FILE` only ADDS trust anchors, so a private
/// or test CA (e.g. an internal / Pebble ACME endpoint) can be reached without
/// weakening validation of public endpoints. Unset `SSL_CERT_FILE` → the default
/// public-roots behaviour, unchanged.
fn http_agent() -> ureq::Agent {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Ok(path) = std::env::var("SSL_CERT_FILE") {
        if let Ok(pem) = std::fs::read(&path) {
            let mut rd: &[u8] = &pem;
            for cert in rustls_pemfile::certs(&mut rd).flatten() {
                let _ = roots.add(cert);
            }
        }
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    ureq::AgentBuilder::new()
        .tls_config(std::sync::Arc::new(config))
        .build()
}

fn parse_headers(header_text: &str) -> Vec<(&str, &str)> {
    header_text
        .split('\n')
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            line.split_once(':').map(|(k, v)| (k.trim(), v.trim()))
        })
        .collect()
}

// ── C-ABI exports ───────────────────────────────────────────────────────

/// HTTP request. Returns status code; response body available via n_http_body.
/// This function stores the body in a thread-local for the interpreter to retrieve.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_http_do(
    method_ptr: *const u8,
    method_len: usize,
    url_ptr: *const u8,
    url_len: usize,
    body_ptr: *const u8,
    body_len: usize,
    headers_ptr: *const u8,
    headers_len: usize,
) -> i64 {
    let method = unsafe { loft_ffi::text(method_ptr, method_len) };
    let url = unsafe { loft_ffi::text(url_ptr, url_len) };
    let body = unsafe { loft_ffi::text_opt(body_ptr, body_len) };
    let headers_text = unsafe { loft_ffi::text_opt(headers_ptr, headers_len) }.unwrap_or("");
    let headers = parse_headers(headers_text);
    let (status, body_bytes, resp_headers) = do_request(method, url, body, &headers);
    // Store the raw body bytes for n_http_body (binary-safe: a String built via
    // from_utf8_unchecked carries NUL bytes verbatim, read back with byte_at).
    LAST_BODY.with(|b| *b.borrow_mut() = unsafe { String::from_utf8_unchecked(body_bytes) });
    // Store response headers as newline-separated "Key: Value" for n_http_headers.
    let headers_joined = resp_headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}"))
        .collect::<Vec<_>>()
        .join("\n");
    LAST_HEADERS.with(|h| *h.borrow_mut() = headers_joined);
    i64::from(status)
}

/// Return the body from the last HTTP request (raw bytes, NUL-preserving).
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_http_body() -> LoftStr {
    LAST_BODY.with(|b| loft_ffi::ret_ref(&b.borrow()))
}

/// Return the response headers from the last HTTP request as newline-separated
/// `Key: Value` lines (the loft side splits them into a `vector<text>`).
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_http_headers() -> LoftStr {
    LAST_HEADERS.with(|h| loft_ffi::ret_ref(&h.borrow()))
}

/// Resolve a URL's size via a `HEAD` request → `Content-Length`, without
/// downloading the body.  Returns the byte length, or `-1` if the request
/// failed or the server did not report a length.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_http_size(url_ptr: *const u8, url_len: usize) -> i64 {
    let url = unsafe { loft_ffi::text(url_ptr, url_len) };
    let (status, _body, headers) = do_request("HEAD", url, None, &[]);
    if !(200..400).contains(&status) {
        return -1;
    }
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<i64>().ok())
        .unwrap_or(-1)
}

use std::cell::RefCell;
use std::io::Read;

thread_local! {
    static LAST_BODY: RefCell<String> = const { RefCell::new(String::new()) };
    static LAST_HEADERS: RefCell<String> = const { RefCell::new(String::new()) };
}

// ── WebSocket client C-ABI exports ───────────────────────────────────────

/// Open (or queue for retry) a WebSocket connection.  Always returns a
/// non-negative handle unless the URL is malformed.  If the initial
/// handshake fails, the slot is created in disconnected state and the
/// next send/recv will trigger a reconnect attempt subject to backoff.
#[loft_native]
#[unsafe(no_mangle)]
// `i64` on the C boundary: the loft declaration types this `integer`, and loft emits
// the extern from the DECLARATION, so a narrower Rust return leaves the upper half of
// the register undefined and loft reads garbage — visibly, for negatives, on --native
// only.  Narrow inside the body instead.
pub unsafe extern "C" fn n_ws_connect(url_ptr: *const u8, url_len: usize) -> i64 {
    let url = unsafe { loft_ffi::text(url_ptr, url_len) };
    i64::from(ws_client::connect(url))
}

/// Send a text message on a WebSocket.  Returns true on success, false if
/// the connection is not currently live (caller may retry on the next
/// poll — reconnect is automatic with backoff).
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_ws_client_send(
    handle: i32,
    msg_ptr: *const u8,
    msg_len: usize,
) -> bool {
    let msg = unsafe { loft_ffi::text(msg_ptr, msg_len) };
    ws_client::send(handle, msg)
}

/// Send a binary message on a WebSocket.  Same byte buffer as
/// `n_ws_client_send`, but the frame goes out with opcode `0x02`
/// (binary) instead of `0x01` (text).  TTT v5 + plan-36 use this
/// for `world_snapshot` / `world_delta` blobs from the client side
/// (bulk world data; client never sends bulk in this design, but
/// the symmetry keeps the API uniform with lib/server).
///
/// # Safety
///
/// `msg_ptr` / `msg_len` must describe a valid byte slice.
#[loft_native]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn n_ws_client_send_binary(
    handle: i32,
    msg_ptr: *const u8,
    msg_len: usize,
) -> bool {
    let msg = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
    ws_client::send_binary(handle, msg)
}

/// Poll for the next received message.  Returns true if a message was
/// delivered (then call n_ws_client_message), false if the queue is
/// empty or the connection is currently down.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_client_recv(handle: i64) -> bool {
    let handle = handle as i32;
    ws_client::recv(handle)
}

/// Get the last message returned by `n_ws_client_recv`.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_client_message() -> LoftStr {
    LAST_WS_MSG.with(|m| {
        let new = ws_client::last_message();
        *m.borrow_mut() = new;
        loft_ffi::ret_ref(&m.borrow())
    })
}

/// Get the opcode of the last frame surfaced by `n_ws_client_recv`.
/// 1 = text, 2 = binary, 8 = close, 9 = ping, 10 = pong.  Loft
/// programs that handle binary frames check this after a successful
/// recv to decide whether the message bytes are utf-8 text or a
/// binary blob.
#[loft_native]
#[unsafe(no_mangle)]
// `i64` on the C boundary: the loft declaration types this `integer`, and loft emits
// the extern from the DECLARATION, so a narrower Rust return leaves the upper half of
// the register undefined and loft reads garbage — visibly, for negatives, on --native
// only.  Narrow inside the body instead.
pub extern "C" fn n_ws_client_opcode() -> i64 {
    i64::from(ws_client::last_opcode())
}

/// Close a WebSocket session permanently (no reconnect).
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_client_close(handle: i64) {
    let handle = handle as i32;
    ws_client::close(handle);
}

/// Block the calling thread for `ms` milliseconds.  Used by tests to
/// pace WebSocket client behaviour deterministically when wall-clock
/// races would otherwise dominate (P229a — macOS scheduler is fast
/// enough that two clients complete their move sequence with no
/// observable overlap).  Negative / zero values are no-ops.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_sleep_ms(ms: i64) {
    let ms = ms as i32;
    if ms <= 0 {
        return;
    }
    std::thread::sleep(std::time::Duration::from_millis(ms as u64));
}

// ── Binary buffer construction (TTT v5 / plan-36) ──────────────────────
//
// Loft `text` is a UTF-8 byte buffer; the lexer + interpreter both
// treat the codepoint 0 (NUL) as the `character` null sentinel, so a
// `text` built via `"{c}{c}…"` interpolation silently drops zero bytes.
// Binary protocols that include zero bytes (e.g. the v5 5-byte blob
// header `[type:u8] [session:u32-LE]` for any small session id) cannot
// be assembled that way.
//
// `n_pack_*` are a thread-local builder pattern: reset, push fields by
// type, then take the buffer as a `text` whose bytes carry the binary
// payload verbatim (NUL bytes preserved).  The receiver reads bytes
// out via `n_byte_at` so multi-byte UTF-8 misinterpretation cannot
// corrupt the stream.

thread_local! {
    static LAST_WS_MSG: RefCell<String> = const { RefCell::new(String::new()) };
    static PACK_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static LAST_PACKED: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Empty the per-thread pack buffer.  Call before each blob.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_pack_reset() {
    PACK_BUF.with(|b| b.borrow_mut().clear());
}

/// Append a single byte to the pack buffer.  `b` is masked to 8 bits.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_pack_u8(b: i64) {
    let b = b as i32;
    PACK_BUF.with(|buf| buf.borrow_mut().push((b & 0xff) as u8));
}

/// Append a 2-byte little-endian unsigned value to the pack buffer.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_pack_u16_le(v: i64) {
    let v = v as i32;
    PACK_BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        let v = (v & 0xffff) as u16;
        buf.extend_from_slice(&v.to_le_bytes());
    });
}

/// Append a 4-byte little-endian unsigned value to the pack buffer.
/// Loft `integer` is i32 — bit-cast to u32 to preserve the LE byte
/// pattern across the sign boundary.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_pack_u32_le(v: i64) {
    let v = v as i32;
    PACK_BUF.with(|buf| {
        let mut buf = buf.borrow_mut();
        let v = v as u32;
        buf.extend_from_slice(&v.to_le_bytes());
    });
}

/// Take the contents of the pack buffer and surface them as a `text`
/// whose UTF-8 bytes are exactly the buffer bytes.  Resets the buffer.
/// The resulting `text` lives in `LAST_PACKED` until the next
/// `n_pack_take` call — copy / send before reusing.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_pack_take() -> LoftStr {
    PACK_BUF.with(|buf| {
        let v = std::mem::take(&mut *buf.borrow_mut());
        LAST_PACKED.with(|p| {
            *p.borrow_mut() = unsafe { String::from_utf8_unchecked(v) };
            loft_ffi::ret_ref(&p.borrow())
        })
    })
}

/// Read the byte at `idx` of the text payload.  Out-of-range returns
/// -1.  Negative `idx` is also out-of-range.  Used to decode binary
/// frames received via `try_recv` / `pump`.
///
/// Argument order is `(idx, text_ptr, text_len)` so the auto-marshal
/// recognises the `(I32, Text) -> I32` signature in
/// `src/extensions.rs::auto_marshal_dispatcher`.  The natural
/// `(text, idx)` order would have demanded a `(Text, I32) -> I32`
/// branch we'd otherwise need to add.
///
/// # Safety
///
/// `text_ptr` / `text_len` must describe a valid byte slice.
#[loft_native]
#[unsafe(no_mangle)]
// `i64` on the C boundary: the loft declaration types this `integer`, and loft emits
// the extern from the DECLARATION, so a narrower Rust return leaves the upper half of
// the register undefined and loft reads garbage — visibly, for negatives, on --native
// only.  Narrow inside the body instead.
pub unsafe extern "C" fn n_byte_at(idx: i64, text_ptr: *const u8, text_len: usize) -> i64 {
    if idx < 0 || (idx as usize) >= text_len {
        return -1;
    }
    unsafe { i64::from(*text_ptr.add(idx as usize)) }
}

// ── WsGroup: multiplexed client-side receiver ───────────────────────────
//
// A thread-local list of WsHandler ids.  `poll` scans them round-robin
// and returns the first one with a message ready.  One timeout across
// all handles instead of one per handle — the key win for multi-client
// drain performance.

thread_local! {
    static WS_GROUP: std::cell::RefCell<Vec<i32>> = const { std::cell::RefCell::new(Vec::new()) };
    static WS_GROUP_OFFSET: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Clear the group handle list.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_group_clear() {
    WS_GROUP.with(|g| g.borrow_mut().clear());
    WS_GROUP_OFFSET.with(|o| o.set(0));
}

/// Add a handle to the group.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_group_add(handle: i64) {
    let handle = handle as i32;
    WS_GROUP.with(|g| g.borrow_mut().push(handle));
}

/// Poll the group round-robin.  Returns the handle that has a message
/// (read it with n_ws_client_message), or -1 if none are ready.
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_ws_group_poll() -> i64 {
    let (handles, offset) = WS_GROUP.with(|g| {
        let g = g.borrow();
        (g.clone(), WS_GROUP_OFFSET.with(|o| o.get()))
    });
    let result = ws_client::poll_group(&handles, offset);
    if result >= 0 {
        // Advance offset past the handle that fired so the next poll
        // starts from the one after it — round-robin fairness.
        if let Some(pos) = handles.iter().position(|&h| h == result) {
            WS_GROUP_OFFSET.with(|o| o.set((pos + 1) % handles.len()));
        }
    }
    i64::from(result)
}

// @PLAN12 phase 2 final step (2026-05-24): the `loft_ffi::loft_register!`
// invocation is generated by `build.rs` from
// `lib/web/loft.toml::[native.functions]`, so the symbol list lives in
// exactly one place.  Adding a new web symbol is now a single edit to
// `loft.toml` (plus the `pub unsafe extern "C" fn` body above).
include!(concat!(env!("OUT_DIR"), "/loft_register_gen.rs"));

/// Yield one frame to the host event loop (@PLN84 ZT-C).  Native no-op (no
/// event loop); the browser target lowers this to the loft_web.ws_yield
/// asyncify suspend (see wasm/src/lib.rs).
#[loft_native]
#[unsafe(no_mangle)]
pub extern "C" fn n_yield_frame() {}
