<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# ssh — SSH client for loft

A blocking / polling SSH client for driving an **interactive remote shell** —
for example attaching `tmux` from a terminal app. Password authentication only;
the password is used for the handshake and never stored.

**Native-only.** SSH needs real TCP sockets, so this library ships the
interpreter and `--native` targets and deliberately does **not** ship the
browser (`--html`) target — a browser cannot open a raw socket. The native
crate wraps [`russh`](https://crates.io/crates/russh) on a tokio runtime behind
a synchronous, polling FFI, so no async leaks into loft.

## Example

```loft
use ssh;

fn main() {
  s = ssh::connect("laptop.local", 42022);
  if !s.ok() { println("connect failed"); return; }
  if !s.login("me", read_password()) { println("auth failed"); return; }
  s.open_shell("xterm-256color", 80, 24);
  s.send("tmux attach\n");

  while s.is_open() {
    out = s.recv();                       // non-blocking; "" when idle
    for i in 0..len(out) {
      feed_terminal(ssh::byte_at(i, out));  // raw byte stream
    }
    // ... render, read input, s.send(keys), s.resize(cols, rows) ...
  }
  s.close();
}
```

## API

| Function | Purpose |
|---|---|
| `connect(host, port) -> Session` | TCP connect + SSH transport handshake |
| `session.ok() -> boolean` | did the connect/handshake succeed |
| `session.login(user, password) -> boolean` | password authentication |
| `session.open_shell(term, cols, rows) -> boolean` | request a PTY + start the shell |
| `session.send(data)` | send bytes to the shell (binary-safe) |
| `session.recv() -> text` | drain received bytes (non-blocking; read with `byte_at`) |
| `session.resize(cols, rows)` | notify the remote of a terminal resize |
| `session.is_open() -> boolean` | is the shell channel still open |
| `session.close()` | close the channel + disconnect |
| `byte_at(idx, data) -> integer` | read one byte of a `recv` result (-1 if out of range) |

## Security

- **Password auth only** — no private key is read or stored.
- **The server host key is currently accepted unconditionally.** The transport
  is still encrypted, but a stored known-hosts (TOFU) check is a planned
  hardening step (`native/src/session.rs::check_server_key`). Until then, use it
  on networks you trust.

## Testing

- `tests/connect_fail.loft` — connecting to a closed port must fail; also proves
  the library loads on the interpreter and `--native`. Runs in the normal gate.
- `tests-network/login_reject.loft` — against a local `sshd`, a bad password must
  be rejected (needs `sshd` on `127.0.0.1:22`).
- `native/src/session.rs` — a Rust unit test (`inbound_is_ordered_and_lossless`)
  that falsifies the load-bearing invariant if the cross-thread byte queue ever
  loses or reorders bytes. Run with `cargo test` in `native/`.

The full success path (interactive shell over a real login) is a manual check —
run the example against a host you can log into.
