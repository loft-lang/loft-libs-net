<!--
Copyright (c) 2026 Jurjen Stellingwerff
SPDX-License-Identifier: LGPL-3.0-or-later
-->

# ZT-E — signed-WASM plugin runtime (design)

Part of [@PLN84 § ZT-E](../../doc/claude/plans/84-zero-trust-libs.md). Built here
in `tools/zt-e-plugin-staging/` because the home library is TBD
(`loft-libs-net` or a new chunk). Each file below records where it ultimately
belongs.

---

## The ONE invariant (the security gate)

> **No byte of plugin code runs unless a *trusted* Ed25519 public key verifies
> the signature over the *exact* module bytes that will be instantiated — the
> verify is the single gate every load path passes through, *before*
> instantiation, and it fails *closed*.**

Everything in E2 (host) and E3 (browser) is one mechanism asserting this
invariant; E1 (the ABI) is what runs *after* the gate admits a module.

### Why "exact bytes" is load-bearing (the over-unification trap)

The elegant-but-wrong version of this gate verifies a *parsed / validated /
re-serialized* module and then instantiates *a different byte buffer*. A
tampered byte the parser happens to tolerate (or normalizes away) would verify
clean and still reach execution. So the invariant pins the **byte buffer
identity**: the signature is computed over, and verified against, the *same*
`&[u8]` that is handed to `wasmtime::Module::from_binary` / `WebAssembly.
instantiate`. No re-encode between verify and load.

### Fail-closed is load-bearing

A missing signature, a malformed signature, a malformed key, an empty
trusted-authors list — every one of these is a **reject**, never a "skip the
check and load anyway". The default with no trusted keys is: nothing loads.

---

## Re-assertion sites — driving `N × silence` down (protocol step 2)

The invariant must hold at **two** independent loaders: the host (`wasmtime`,
Rust) and the browser (`WebAssembly.instantiate`, JS). N = 2, and an omission
(load-before-verify) is *silent* (a plugin just runs). Two cures, both applied:

1. **One shared contract, not two ad-hoc checks.** Both loaders verify the
   *same* signature over the *same* canonical byte buffer against the *same*
   trusted-key-set format (a list of 32-byte raw Ed25519 public keys, hex). The
   signing tool (`loft-keygen sign`) is shared; neither loader invents its own
   signing rule. So a divergence between the two loaders is a *test failure*,
   not a silent hole.
2. **The same four-case matrix runs on both sides.** `signed→accept`,
   `tampered→reject`, `unsigned→reject`, `wrong-key→reject`. The matrix is the
   instrument that makes the class visible; a loader that forgets the gate fails
   ≥3 of its 4 cells loudly.

---

## Failure paths (enumerated before code — where the invariant surfaces)

| # | Path | Required behaviour | Cell |
|---|---|---|---|
| F1 | correctly-signed module, trusted key | **accept**, instantiate, run | `signed→accept` |
| F2 | one byte of the wasm flipped after signing | **reject** (sig no longer matches bytes) | `tampered→reject` |
| F3 | no signature supplied / empty / wrong length | **reject** (fail-closed) | `unsigned→reject` |
| F4 | validly signed, but by a key NOT in trusted list | **reject** (untrusted author) | `wrong-key→reject` |
| F5 | malformed wasm that *is* correctly signed | reject at instantiate, AFTER the gate passed — distinct from F1-F4; a signed-but-broken module is the author's bug, not a trust failure | (out of the 4 security cells) |
| F6 | trusted list empty | **reject everything** (no implicit trust) | covered by F4 with empty list |
| F7 | signature verifies but over a *re-serialized* buffer | impossible by construction — we never re-serialize between verify and load (the "exact bytes" invariant) | design-enforced |

F1–F4 are the four mandated security cases; F5–F7 are the boundary cases that
keep the gate honest.

---

## The signing scheme (shared by host + browser)

- **Message** = the raw wasm module bytes, verbatim.
- **Signature** = raw 64-byte Ed25519 (`loft-keygen sign --in <wasm> --key
  <32-byte raw private> --out <wasm>.sig`). Detached, lives next to the module.
- **Author identity** = a 32-byte raw Ed25519 public key (`loft-keygen
  generate` emits the keypair; the `.pub` is 64 hex chars).
- **Trusted-authors list** = a set of such public keys. The host takes them as
  hex strings (CLI / a `trusted_authors.txt`); the browser takes them as an
  array of hex strings. Reject iff **no** trusted key verifies the signature.

This is byte-identical to the registry trust root loft already ships
(`src/registry_keys.rs`, `loft-keygen`), so the plugin gate reuses a vetted,
already-tested signing path rather than inventing one — directly serving the
PLUGINS.md §9c.5 model ("plugins signed by authors' Ed25519 keys; a bundled
trusted-author list; a plugin loads ONLY if it bears a valid signature AND the
author key is trusted").

---

## E1 — the plugin ABI

The six-export op-log CRDT contract (PLUGINS.md §9c.2, the op-log deviation):

| Export | In | Out |
|---|---|---|
| `initial_state()` | — | empty CRDT state |
| `apply_op(state, op)` | state + one decrypted op | new state |
| `make_op(state, action)` | state + user input | a new op (or nothing) |
| `render(state)` | state | render commands for the host UI |
| `snapshot(state)` | state | serialised snapshot bytes |
| `load_snapshot(bytes)` | snapshot bytes | CRDT state |

**Boundary representation.** State, ops, actions, render output and snapshots
all cross the wasm boundary as **byte buffers in linear memory**. The wasm
exports therefore use a uniform `(ptr,len) -> (ptr,len)` calling convention over
a small `plugin_alloc`/`plugin_dealloc` pair the host uses to hand bytes in and
read bytes out. This matches the ABI table (snapshot/load_snapshot are
explicitly bytes; ops are decrypted bytes; render output is inspected by the
host) and keeps the plugin a *pure, deterministic* function of its inputs
(§9c.2 / §8.17).

**The canonical contract is `reference-plugin/src/plugin_abi.loft`** — the ABI
written as a loft `interface`. The reference plugin's *logic* lives in
`reference-plugin/src/counter_plugin.loft` (a CRDT counter: state is a running
sum of signed increments; each op is an i64 delta — commutative, so replays in
any order converge — the §8.17 invariant).

**Codegen gap (documented, NOT blocking ZT-E).** loft `--native-wasm` today
emits a WASI *command* module (`_start` → `n_main`) — a program, not a library
with named ABI exports (verified: a hello.loft wasm exports `_start`/`main`,
not arbitrary names). There is no loft-source annotation yet to export
`initial_state`/`apply_op`/… as named wasm exports. ZT-E's load-bearing
deliverable is the *gate* (E2/E3) plus the *ABI definition* (E1); it must not
block on a new codegen feature. So the reference plugin reaches wasm through a
thin Rust shim (`reference-plugin/wasm-shim/`) that exposes the six exports with
the `(ptr,len)` convention and implements the same counter logic the loft source
specifies. The shim is the stand-in for the missing
`loft --native-wasm --exports` path; **the gate does not care how the wasm was
produced** — it verifies bytes, so a future loft-source-only plugin loads
through exactly the same gate. The codegen feature routes to its canonical home
as a follow-up; see § "Follow-up".

---

## E2 — host loader (`wasmtime`, the loft server's role)

A Rust crate (`host-loader/`) whose `verify_then_load(wasm_bytes, sig_bytes,
trusted_keys)`:

1. Verifies the Ed25519 signature over `wasm_bytes` against each trusted key;
   if none verifies → `Err(Reject::*)` — **return before touching wasmtime**.
2. Only then `Module::from_binary(&engine, wasm_bytes)` (the *same* buffer).
3. Instantiate, look up the six exports, drive a counter scenario.

The verify step is physically before any `wasmtime` call, so "no byte runs
before verify" is structural, not a convention.

Tests (`host-loader/tests/security_gate.rs`) run the four cells F1–F4 plus the
fail-closed boundaries (empty trust list, short signature).

**Ultimately lives in:** the loft server binary's plugin subsystem (home TBD —
`loft-libs-net/server` plugin host, or a new `loft-libs-plugins` chunk). The
`verify_then_load` function is the reusable core; the `PluginInstance` wrapper
(the six-export driver) is the embedder.

---

## E3 — browser loader (JS, the same gate)

`browser-loader/plugin_loader.mjs`: `loadPlugin(wasmBytes, sigBytes,
trustedKeysHex)`:

1. Ed25519-verify via WebCrypto `crypto.subtle.verify` (Node 22 / modern
   browsers support Ed25519 natively) against each trusted key — this is the
   ZT-B "bridged crypto" surface (the browser's native Ed25519, the same one the
   `crypto` lib's wasm bridge routes to). If none verify → throw, **return
   before `WebAssembly.instantiate`**.
2. Only then `WebAssembly.instantiate(wasmBytes, imports)` (the *same* buffer).
3. Call the six exports; run the same counter scenario.

Tests (`browser-loader/security_gate.test.mjs`, run under Node 22) run the same
four cells, asserting byte-for-byte the same accept/reject decisions as the host
loader.

**Ultimately lives in:** the browser client's plugin host (the consumer's WASM
client). `plugin_loader.mjs` is the reusable core; in production the trusted-key
list comes from the bundled signed list + the user's `trusted_plugin_author`
records (§9c.5), not a literal array.

---

## Follow-up (routed, not done here)

- **loft codegen `#export "<name>"`** — emit a loft function as a named wasm
  library export (multi-entry `output_native_reachable`), so the reference
  plugin can be produced from loft source directly with no Rust shim. Canonical
  home: a `loft-lang/plans` issue under @PLN84's ABI line / PACKAGES.md wasm
  section. XS-to-S but needs codegen design (export table, the `(ptr,len)` ABI
  in generated Rust) → its own slot, not inlined into ZT-E.
