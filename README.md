<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# loft-libs-net — networking libraries for loft

Multi-package chunk repo for HTTP / WebSocket / game-networking
primitives.

Per the chunked-repo design in
[loft's lib_plans/12-library-extraction/](https://github.com/jjstwerff/loft/blob/main/doc/claude/lib_plans/12-library-extraction/README.md)
§ Chunk grouping.

## Packages

| Subdir | Package | Status |
|---|---|---|
| [`web/`](web/) | `web` — HTTP client + WebSocket | v0.1.0 (extracted 2026-05-24) |
| [`server/`](server/) | `server` — HTTP server + WebSocket server (depends on `web`) | v0.1.0 (extracted 2026-05-24) |
| [`game_protocol/`](game_protocol/) | `game_protocol` — packet framing + game networking (depends on `web` + `server`) | v0.1.0 (extracted 2026-05-24) |

Internal chunk dependency graph:

```
web ← server ← game_protocol
       ↑__________________|
```

`web` has no internal deps (publish first); `server` consumes
`web`; `game_protocol` consumes both.

## Installing a package

```sh
loft install web        # HTTP client + WS
loft install server     # HTTP server (pulls in web as a transitive dep)
loft install game_protocol
```

## Versioning + tags

Per-package tag prefix per the multi-package convention:

| Package + version | Git tag |
|---|---|
| web 0.1.0 | `web-v0.1.0` |
| server 0.1.0 | `server-v0.1.0` |
| game_protocol 0.1.0 | `game_protocol-v0.1.0` |

## License

LGPL-3.0-or-later — see [LICENSE](LICENSE).
