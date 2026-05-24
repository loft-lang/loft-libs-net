<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# server — HTTP + WebSocket server for loft

## Install

```sh
loft install server   # pulls web 0.1+ as a transitive dep
```

## Surface

- TCP socket primitives: `tcp_listen`, `tcp_accept`, `tcp_recv`, `tcp_send`, `tcp_close`.
- WebSocket server: `ws_handshake`, frame parsing, group broadcast.
- HTTP request parsing + response building.

Native code (cdylib `loft_server`) wraps OS sockets + tungstenite
for the WebSocket layer.

## Provenance

Extracted from `lib/server/` 2026-05-24.  Depends on `web` for
shared binary-pack helpers.
