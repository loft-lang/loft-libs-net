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

### HTTP client

Requests return `HttpResponse { status: integer, body: text, headers: vector<text> }`.
The `body` carries **raw bytes** — binary-safe and NUL-preserving; read individual
bytes with `byte_at(response.body, i)`. `headers` are the response's `"Key: Value"`
lines.

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

Backed by the native cdylib `loft_web` (ureq). **Native / interpret today; a browser
`fetch()` backend is in progress (#517 Phase B) so a loft-in-wasm client can fetch
the same way.**

### WebSocket client — all targets

`ws_handler(url)` + `send` / `try_recv` / `pump` / `close`, browser-bridged via the
`[wasm.bridge]` routes (the sole browser transport until the HTTP fetch backend lands).

### Binary packing — all targets, pure loft

`pack_reset` / `pack_u8` / `pack_u16_le` / `pack_u32_le` / `pack_take` + `byte_at`.

## Provenance

Extracted from the loft monorepo's `lib/web/` 2026-05-24 as part
of [@PLAN12](https://github.com/jjstwerff/loft/blob/main/doc/claude/lib_plans/12-library-extraction/README.md)
Phase 6.
