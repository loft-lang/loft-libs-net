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

Per-function target support matters here — the two halves differ:

- `http_get(url) -> text` — **interpret / native / native-wasm only** (no browser)
- `http_do(method, url, body) -> text` — `POST`/`PUT`/`DELETE` etc. — **same: no browser**
- `ws_connect(url, origin)` + `ws_client_send` / `ws_client_recv` / `try_recv` for
  WebSocket client — **all four targets** (the `[wasm.bridge]` routes these in `--html`)
- Binary-frame packing helpers: `pack_u8`/`pack_u16_le`/`pack_u32_le` + `pack_take` —
  pure loft, all targets.

**WebSocket is the only browser-bridged transport.**  The `http_*` calls have no
`--html` bridge — in the browser, let JS own the network (`fetch`) and hand loft
the bytes via the engine's `host_input()`.

Native code (cdylib `loft_web`) backs the HTTP + WebSocket calls
via the ureq + tungstenite crates.

## Provenance

Extracted from the loft monorepo's `lib/web/` 2026-05-24 as part
of [@PLAN12](https://github.com/jjstwerff/loft/blob/main/doc/claude/lib_plans/12-library-extraction/README.md)
Phase 6.
