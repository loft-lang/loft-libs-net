<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# ssh — SSH client for loft

A blocking / polling SSH client for driving an **interactive remote shell** —
for example attaching `tmux` from a terminal app. Password authentication only;
the password is used for the handshake and never stored.

**Native-only.** SSH needs real TCP sockets, so this library ships the
interpreter and compiled targets and deliberately does **not** ship the
browser (`--html`) target — a browser cannot open a raw socket. The natives are
loft's own, its `net` component: an SSH client in C over loft's sockets and its
vendored BearSSL (curve25519 key exchange, Ed25519 / ECDSA / RSA host keys,
AES-GCM or AES-CTR with HMAC-SHA2), polled from loft, so no async leaks in and
the package builds no crate.

## Example

```loft
use ssh;

// `read_password` and `feed_terminal` stand for your app's own input and terminal emulator.
fn main() {
  s = ssh::connect("laptop.local", 42022);
  if !s.ok() { println("connect failed"); return; }
  if !s.login("me", read_password()) { println("auth failed"); return; }
  s.open_shell("xterm-256color", 80, 24);
  s.send("tmux attach\n");

  while s.is_open() {
    out = s.recv();                       // non-blocking; "" when idle
    for i in 0..out.size() {              // BYTES: `len` counts characters
      feed_terminal(ssh::byte_at(i, out));  // raw byte stream
    }
    // ... render, read input, s.send(keys), s.resize(cols, rows) ...
  }
  s.close();
}
```

A guide: [docs/01-getting-started.loft](docs/01-getting-started.loft).

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
- **The server's host key is not checked against a known-hosts store** — its
  signature over the key exchange is always verified, but any key the server
  holds is accepted.  The transport is encrypted, yet nothing tells you the host
  is the one you meant, so use it on networks you trust.

## Testing

- `tests/connect_fail.loft` — connecting to a closed port must fail; also proves
  the library loads on the interpreter and `--native`. Runs in the normal gate.
- `tests-network/login_reject.loft` — against a local `sshd`, a bad password must
  be rejected (needs `sshd` on `127.0.0.1:22`).
- loft's own `tests/ssh_natives.rs` holds the natives to their promises — login,
  pty and resize, bytes both ways through each side's flow control, the shell's
  exit — against a small test server, on every backend; the protocol is checked
  against OpenSSH (loft's C_BACKEND.md § The SSH client).
