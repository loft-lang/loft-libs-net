<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# game_protocol — the message types a game's client and server share

The vocabulary both ends of a multiplayer game agree on: `MsgType` (state sync and delta,
player input, ping and pong, chat, lobby and match events, error), `WsMessage` (a type and a
text payload) and `GameEnvelope` (sender, recipient, sequence, timestamp and the message),
with `msg_ping` / `msg_pong` / `msg_chat` / `msg_input` / `msg_state` / `msg_error` to build
the common ones.  Pure loft.

It does not move bytes.  The transport — `web`'s WebSocket, `server`'s loop, anything that
carries text — is the program's own; an envelope goes on the wire as JSON with `"{env:j}"`
and comes back with `GameEnvelope.parse(text)`.  The package declares `web` and `server`
because its `examples/` — a tic-tac-toe client and server, and the v5 session demos — run
over them; the message types themselves use neither.

## Install

```sh
loft install game_protocol
```

## What it is not

There is no packet framing, no ack or retransmit, and no ordering: only `msg_ping` /
`msg_pong` number their messages, and routing (`recipient`) is left for the program to set.
A game that needs reliable delivery builds it on its transport.

A guide: [docs/01-getting-started.loft](docs/01-getting-started.loft).
