<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# server: HTTP byte-range data serving (Range · headers · CORS · HEAD)

The mirror half of the `web` client's #517 data-access stack. The client can now
**request** byte ranges, read response headers, and query size; this lets the loft
`server` **answer** them, so a loft-in-the-browser client can fetch tile ranges
from a loft-hosted file. (If tiles are served from a static host / CDN, that host
already does this and none of the below is needed — this is only for serving from
the loft server itself.)

## Design invariant

**Native stays a thin transport; HTTP policy lives in testable loft.** Add exactly
two native primitives — *read the request headers* and *write a response with
arbitrary headers + more status codes* — then express Range, CORS, HEAD, and
conditional requests as **pure loft** on top. Rationale: HTTP semantics are where
the bugs and the edge cases live (off-by-one ranges, `*/total`, case-insensitive
headers); in loft they get a both-backend test matrix, and the native surface that
needs `--native` codegen review stays minimal.

Head start: `parse_request` **already captures** the request headers into
`LAST_HEADERS` — they are simply not exposed yet.

## Verifiable steps

Each step is independently landable and has an in-repo round-trip test (a loft
`server` on `127.0.0.1` + the `web` client, both native/interpret — **no browser
needed** except S4's cross-origin proof, which reuses the Node asyncify driver).

### S1 — Expose request headers  (foundational primitive #1)

- **Native:** `n_tcp_headers() -> LoftStr` returning the already-stored
  `LAST_HEADERS`.
- **loft:** `Request.headers: vector<text>` (split on `\n`) + `pub fn
  header(self: Request, name: text) -> text` — case-insensitive lookup, `""` if
  absent.
- **Verify:** start a server whose handler echoes `request.header("Range")` into
  the body; a client `http_get_h(url, ["Range: bytes=5-9"])` asserts the echoed
  value is `bytes=5-9`. Loft round-trip test in `server/tests/`.

### S2 — Arbitrary response headers + range status codes  (primitive #2)

- **Native:** `n_tcp_respond_full(status, body_ptr, body_len, headers_ptr,
  headers_len)` — a `write_response` variant that emits the caller's
  `"Key: Value\n"` lines alongside the auto `Content-Length`; add `206 Partial
  Content`, `416 Range Not Satisfiable`, `304 Not Modified` to the status-text
  map. Confirm the body is written `as_bytes()` with `Content-Length` = byte
  length (binary-safe — the tile data has NUL bytes).
- **loft:** `pub fn respond_with_headers(self: Request, status: integer, body:
  text, headers: vector<text>)`.
- **Verify:** handler responds `206` with `["Content-Range: bytes 0-9/100",
  "ETag: \"abc\""]`; client reads `response.status == 206` and finds both header
  lines in `response.headers`. Assert a raw-byte body with an embedded NUL
  survives (client `body.len()` matches).

### S3 — Range serving  (pure loft; composes S1 + S2) — the core

- **loft:** `pub fn serve_range(self: Request, body: text) -> boolean` —
  read `Range: bytes=off-last`; absent → return `false` (caller serves a normal
  `200`); present → respond `206` with the slice + `Content-Range: bytes
  off-last/total` + `Accept-Ranges: bytes`; malformed / past-end → `416` +
  `Content-Range: bytes */total`. Needs a byte slice of `text` — use `byte_at`
  in a loop, or add a tiny `n_slice_bytes(s, off, len)` native if the loop is a
  hot path.
- **Verify (the main matrix):** server serves a known 1000-byte body via
  `serve_range`; drive the client across cells — `(0,16)`, `(100,50)`,
  `(984,16)` (last), `(0,1000)` (whole), `(2000,10)` (past-end → 416),
  open-ended — and for each assert **status, `body.len()`, the exact bytes**
  (hand-computed, not just self-consistent), and the `Content-Range` line. Run
  the client on **both** interpret and native.

### S4 — CORS + preflight  (pure loft; composes S2)

- **loft:** `pub fn cors_headers(origin: text) -> vector<text>` →
  `Access-Control-Allow-Origin`, `Access-Control-Expose-Headers: Content-Range,
  Content-Length, ETag, Accept-Ranges`, `Access-Control-Allow-Headers: Range,
  If-Range, If-None-Match`, `Access-Control-Allow-Methods: GET, HEAD, OPTIONS`.
  `pub fn handle_preflight(self: Request) -> boolean` — `OPTIONS` → `204` + CORS,
  return `true`.
- **Verify:** the **end-to-end browser proof** — build a loft server that serves a
  range with `cors_headers`, and a `--html` wasm client that fetches it; run the
  client under the Node asyncify driver (real `fetch`, real CORS-exposed headers)
  and assert it reads `Content-Range`. Plus a preflight unit test (`OPTIONS` →
  `204` + `Access-Control-*` present).

### S5 — HEAD  (small; composes S2)

- **loft:** in the handler, `method == "HEAD"` → respond headers only
  (`Content-Length` = full resource size, `Accept-Ranges: bytes`, `ETag`) with an
  **empty** body. Requires `respond_with_headers` to honour a caller-supplied
  `Content-Length` rather than auto-deriving `0` from the empty body (design note
  for S2: if the caller passes `Content-Length`, do not override).
- **Verify:** client `http_size(url)` (HEAD) against the loft server returns the
  resource's true size with no body transferred.

### S6 — Conditional (ETag / If-Range / If-None-Match)  (pure loft; optional)

- **loft:** honour `If-None-Match` (`304` on ETag match) and `If-Range` (fall back
  to a full `200` when the range's `If-Range` ETag no longer matches).
- **Verify:** matching `If-None-Match` → `304` + empty body; mismatch → `200`/`206`
  with body.

## Sequencing

S1 and S2 are the two primitives and unblock everything. S3 (Range) is the core
value and the richest test matrix. S4 closes the browser loop. S5/S6 are small
follow-ons. Ship S1→S2→S3 first; that alone makes loft-served byte-range fetch
work for a same-origin or CORS-configured static-equivalent server.

## Non-goals

Streaming / chunked transfer (the whole slice fits in memory for tile reads);
multi-range (`Range: bytes=0-9,20-29`) — single-range only; HTTP/2.
