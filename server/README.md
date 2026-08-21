<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# server — HTTP + WebSocket server for loft

A small server library: accept TCP connections, answer HTTP requests, and
run WebSocket connections. The public API lives in `src/server.loft`; a thin
native layer (`cdylib loft_server`) wraps the OS sockets and the `tungstenite`
WebSocket handshake/framing.

## Install

```sh
loft install server   # also pulls `web` (shared binary-pack helpers)
```

Then `use server;` in your program. `--native` is required to run a real
server (the socket layer is native code; it is not available under
`--interpret`-only or `--html`/wasm).

## HTTP server

`listen` opens a port and returns a `Server`. Iterating the server yields one
`Request` per connection (`next` blocks until a client connects). Answer each
request with one of the `respond*` methods, which sends the reply and closes
the connection.

**If the port cannot be taken, `listen` halts** with a message naming the port. That is
deliberate: a server that did not get its port cannot do its job, and the previous
behaviour — hand back a `Server` that accepts nothing — was invisible from inside the
process (every call quietly did nothing; `run` spun forever on an empty event pump) and
from outside it (a readiness probe that connects to the port reaches whoever *did* win
the bind, and reports success).

When losing the port is an outcome you mean to handle — retrying elsewhere, scanning a
range — use `try_listen` and check `bound()`:

```loft
srv = server::try_listen(8080);
if !srv.bound() { srv = server::try_listen(8081); }
if !srv.bound() { panic("no free port"); }
```

```loft
use server;

fn main() {
  srv = server::listen(8080);
  for req in srv {                 // one Request per connection
    if req.path == "/" {
      req.respond_html("<h1>Hello from loft</h1>");
    } else {
      req.respond_404();
    }
  }
}
```

A `Request` has these fields: `method` (`"GET"` / `"POST"` / …), `path`,
`body` (the raw request body, empty for GET), and `headers` (the request
headers as `"Key: Value"` lines; use `req.header(name)` to look one up).

Responders (each sends the reply and closes the connection):

| method | what it sends |
|---|---|
| `req.respond(status, body)` | `body` as `text/plain` |
| `req.respond_typed(status, body, content_type)` | `body` with your own `Content-Type` |
| `req.respond_bytes(status, bytes, content_type)` | a **raw byte** body — images, fonts, wasm |
| `req.respond_html(body)` | `body` as `text/html` (status 200) |
| `req.respond_css(body)` | `body` as `text/css` (status 200) |
| `req.respond_js(body)` | `body` as `application/javascript` (status 200) |
| `req.respond_loft(body)` | loft source as `text/plain` (status 200) |
| `req.respond_404()` | `404 Not Found` |

`srv.next_nonblocking()` is the non-blocking form of the accept — it returns
`null` immediately when no connection is pending, so one loop can interleave
HTTP accepts with other work (e.g. the multi-client WebSocket pump below).
`srv.close()` shuts the listener down.

## HTTP data serving — byte ranges, headers, CORS

The `web` client's #517 data-access stack (`http_get_range`, `http_size`,
response headers) has a matching server side, so a loft server can serve binary
byte-range requests — including to a browser (wasm) client.

- `req.header(name) -> text` — read a request header case-insensitively
  (`"Range"`, `"Origin"`, `"If-None-Match"`); `""` if absent. (`Request` also
  carries the full `headers: vector<text>`.)
⚠⚠ **Anything binary must use `respond_bytes`, and the text responses fail SILENTLY on
it.** `respond` / `respond_typed` take loft `text`, and a `text` built from non-UTF-8 bytes
is the EMPTY text — `text_from_bytes` documents exactly that. So serving a PNG through them
answers **`200 OK` with `Content-Length: 0`**: a success the caller cannot tell from an
empty file, a broken image in the browser, and no error reported anywhere. Measured
2026-08-21, that is how loft's own review viewer had been serving every `doc/images/*.png`.
An empty `content_type` defaults to `application/octet-stream`.

- `req.respond_with_headers(status, body, headers)` — reply with your own header
  lines (`Content-Range`, `ETag`, CORS, …); `Content-Length` is added
  automatically and the body is written **verbatim (binary-safe)**. Status codes
  now include `206`, `304`, `416`.
- `req.serve_range(body, extra) -> boolean` — serve a `Range: bytes=off-last`
  request as `206 Partial Content` (or `416`), adding `extra` headers; returns
  `false` when there is no Range header so the caller can serve the full body.
- `cors_headers(origin) -> vector<text>` — the CORS headers a browser needs to
  read `Content-Range` / `ETag` cross-origin.

The one-call helper ties it together:

```loft
srv = server::listen(8080);
etag = "\"tiles-v1\"";
for req in srv {
  req.serve_data(read_tile_block(), etag, "*");   // range + CORS + HEAD + 304
}
```

`serve_data(body, etag, origin)` handles an `OPTIONS` preflight (`204` + CORS),
`If-None-Match` (`304`), `HEAD` (headers + `Content-Length`, no body), a `Range`
request (`206` slice), and otherwise the full `200`. Pass `etag` / `origin` as
`""` to skip the conditional / CORS parts. Single-range only.

## WebSocket — single client

After a connection is accepted, `ws_upgrade()` upgrades it to a `WebSocket`
(returns `null` if the request was not a WebSocket handshake). `next()` reads
the next message and returns `null` when the peer closes.

```loft
use server;

fn main() {
  srv = server::listen(8080);
  for req in srv {
    ws = server::ws_upgrade();
    if ws == null { req.respond_404(); continue; }
    while true {
      msg = ws.next();             // null when the client disconnects
      if msg == null { break; }
      _ = ws.send(msg);            // echo it back
    }
    ws.close();
  }
}
```

`WebSocket` methods: `next() -> text?`, `send(msg) -> boolean`,
`send_binary(msg) -> boolean` (opcode-2 binary frame — loft `text` is a byte
buffer), `last_opcode() -> integer` (1 = text, 2 = binary, 8 = close, after a
`next`), and `close()`.

## WebSocket — many clients

For a multiplayer server, register one event handler with `run`. Rust drives
the accept loop, per-client polling, frame parsing, and disconnect detection,
and calls your handler for each event. The handler closure captures your
server state, so mutations are visible across every call.

```loft
use server;

fn main() {
  srv = server::listen(8080);
  srv.run(fn(ev: server::WsEvent) {
    if ev.connected {
      _ = srv.send_to(ev.cid, "0:welcome");         // one client
    } else if ev.message {
      // the wire frame "<msg_id>:<payload>" is pre-split for you
      _ = srv.broadcast("{ev.msg_id}:{ev.payload}"); // every client
    } else if ev.http {
      srv.respond_html("<h1>game server</h1>");      // a plain page request
    }
  });
}
```

A `WsEvent` carries `connected` / `message` / `http` (mutually-exclusive
booleans), `cid` (the client id; `-1` for `http`), `msg_id` + `payload` (the
split message; empty for non-message events), and `path` (for `http` events).

- `srv.send_to(cid, msg) -> boolean` — send to one client.
- `srv.broadcast(msg) -> integer` — send to all; returns the count sent.
- `srv.disconnect(cid)` — force-close one client.
- `srv.respond_html/respond_typed/respond_404` — reply to the current `http` event.

Disconnects are absorbed silently — the handler is not called for them; clean
up per-client state lazily on next access. If you also need a periodic tick
(timers, snapshots), run your own loop calling `srv.poll_event()` (the
non-blocking single-event drain that `run` wraps) instead of `run`.

## Provenance

Extracted from the main loft repo's `lib/server/` on 2026-05-24. Depends on
`web` for the shared binary-pack helpers used by `send_binary`.
