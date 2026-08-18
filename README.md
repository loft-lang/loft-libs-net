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
| [`web/`](web/) | `web` — HTTP client + WebSocket client | v0.3.5 |
| [`server/`](server/) | `server` — HTTP server + WebSocket server (depends on `web`) | v0.5.1 |
| [`game_protocol/`](game_protocol/) | `game_protocol` — per-tick state-update + event framing (depends on `web` + `server`) | v0.1.3 |
| [`ssh/`](ssh/) | `ssh` — SSH client (interactive remote shell; password auth) | v0.1.1 |

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
loft install ssh        # SSH client (interactive remote shell)
```

## Versioning + tags

Per-package tag prefix per the multi-package convention:

| Package + version | Git tag |
|---|---|
| web 0.3.5 | `web-v0.3.5` |
| server 0.5.1 | `server-v0.5.1` |
| game_protocol 0.1.3 | `game_protocol-v0.1.3` |
| ssh 0.1.1 | `ssh-v0.1.1` |

## License

LGPL-3.0-or-later — see [LICENSE](LICENSE).
