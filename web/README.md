<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# web — HTTP client + WebSocket client for loft

## Install

```sh
loft install web
```

## Surface

A guide: [docs/01-getting-started.loft](docs/01-getting-started.loft) — what each call answers
when the other end is not there, the packer, and `byte_at`.

### HTTP client

Requests return `HttpResponse { status: integer, body: text, headers: vector<text> }`.
The `body` carries **raw bytes** — binary-safe and NUL-preserving; read individual
bytes with `byte_at(i, response.body)` (index first). `headers` are the response's
`"Key: Value"` lines.  An unreachable server answers status 0, never an error.

- `http_get(url)` · `http_post(url, body)` · `http_put(url, body)` · `http_delete(url)`
  → `HttpResponse`
- `*_h(...)` variants take a `vector<text>` of `"Key: Value"` **request** headers
- `http_size(url) -> integer` — total byte size via `HEAD` (Content-Length), with a
  Content-Range fallback for CDNs that omit the length on `HEAD` (e.g. github-raw);
  `-1` if unavailable
- `http_get_range(url, offset, len)` · `_h(...)` → `HttpResponse` — a
  `Range: bytes=` read (**206 Partial Content**) returning just the requested slice,
  for partial reads of a large remote file
- `response.ok()` — true for a 2xx status

Natively it is the `loft_web` cdylib (ureq); in the browser the same calls go through
`fetch()`.

### WebSocket client

`ws_handler(url) -> WsHandler?` (null only for an address it cannot use; a server that is
down still gives a handle, which reconnects with backoff), then `send` / `send_binary`,
`try_recv` or `pump(on_message)`, `last_opcode`, and `close`.  `wss://` validates
certificates natively.  In the browser it is the platform WebSocket: call `frame_yield()`
once per pass of the receive loop so the event loop can deliver messages.

`ws_group()` + `add` + `poll` receive from several handlers in one scan (native only — in
the browser `poll` answers -1; use `try_recv` per handler).  `sleep_ms(ms)` paces a native
loop and returns at once in the browser.

### Binary packing

`pack_reset` / `pack_u8` / `pack_u16_le` / `pack_u32_le` / `pack_take` build a frame that
keeps its zero bytes (interpolation drops them); each `pack_*` keeps the low 8, 16 or 32
bits of its argument.  `byte_at(i, t)` reads a byte back, `-1` past the end.  The same on
every target.
