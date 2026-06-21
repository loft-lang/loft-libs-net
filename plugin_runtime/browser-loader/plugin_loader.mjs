// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// ZT-E E3 — browser plugin loader: the SAME security gate as the host (E2),
// in JS, over the browser's native Ed25519 (WebCrypto `crypto.subtle`).
//
// THE INVARIANT (DESIGN.md): no plugin code runs unless a TRUSTED Ed25519 key
// verifies the signature over the EXACT module bytes, BEFORE
// `WebAssembly.instantiate`, failing CLOSED.  This mirrors the Rust host's
// `verify_then_load` so a divergence between the two loaders is a test failure,
// not a silent hole.
//
// `crypto.subtle` Ed25519 is the ZT-B "bridged crypto" surface — the same
// browser-native Ed25519 the `crypto` lib's wasm bridge routes to.  Node 22
// and modern browsers expose it as a global `crypto.subtle`.
//
// Ultimately lives in: the browser client's plugin host.  In production the
// trusted-key list comes from the bundled signed list + the user's
// `trusted_plugin_author` records (§9c.5), not a literal array.

/// Why a plugin was rejected — mirrors the host loader's `Reject`.
export const Reject = Object.freeze({
  Untrusted: "no trusted key verifies the plugin signature",
  MalformedSignature: "plugin signature is not a 64-byte Ed25519 signature",
  NoTrustedKeys: "trusted-authors list is empty (nothing can load)",
});

export class PluginRejected extends Error {
  constructor(reason) {
    super(`REJECTED: ${reason}`);
    this.name = "PluginRejected";
    this.reason = reason;
  }
}

function hexToBytes(hex) {
  hex = hex.trim();
  if (hex.length !== 64) throw new Error(`expected 64 hex chars, got ${hex.length}`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// A raw 32-byte Ed25519 public key isn't directly importable by WebCrypto; it
// must be wrapped as SubjectPublicKeyInfo (SPKI) DER.  The Ed25519 SPKI prefix
// is a fixed 12-byte header followed by the 32-byte key (RFC 8410).
const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

function rawKeyToSpki(raw32) {
  const out = new Uint8Array(ED25519_SPKI_PREFIX.length + 32);
  out.set(ED25519_SPKI_PREFIX, 0);
  out.set(raw32, ED25519_SPKI_PREFIX.length);
  return out;
}

async function importEd25519PublicKey(raw32) {
  return crypto.subtle.importKey(
    "spki",
    rawKeyToSpki(raw32),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
}

/// THE GATE.  Verify `signature` (64 raw bytes) over `wasmBytes` against any of
/// `trustedKeysHex` (each 64 hex chars = a 32-byte raw Ed25519 public key).
/// Resolves `true` iff some trusted key verifies; never throws on a bad input
/// (returns false) so the caller treats "couldn't verify" as a reject.
export async function verifySignature(wasmBytes, signature, trustedKeysHex) {
  if (!trustedKeysHex || trustedKeysHex.length === 0) {
    return { ok: false, reason: Reject.NoTrustedKeys };
  }
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    return { ok: false, reason: Reject.MalformedSignature };
  }
  const msg = wasmBytes instanceof Uint8Array ? wasmBytes : new Uint8Array(wasmBytes);
  for (const hex of trustedKeysHex) {
    let key;
    try {
      key = await importEd25519PublicKey(hexToBytes(hex));
    } catch {
      continue; // skip a malformed trusted-key entry
    }
    let valid = false;
    try {
      valid = await crypto.subtle.verify({ name: "Ed25519" }, key, signature, msg);
    } catch {
      valid = false;
    }
    if (valid) return { ok: true };
  }
  return { ok: false, reason: Reject.Untrusted };
}

/// Verify-then-instantiate.  Rejects (throws `PluginRejected`) BEFORE
/// `WebAssembly.instantiate`, over the EXACT same `wasmBytes` it verified.
/// On success returns the instantiated plugin wrapped in a `BrowserPlugin`.
export async function loadPlugin(wasmBytes, signature, trustedKeysHex) {
  const gate = await verifySignature(wasmBytes, signature, trustedKeysHex);
  if (!gate.ok) {
    throw new PluginRejected(gate.reason); // <-- no instantiate on reject
  }
  // Only now instantiate — the SAME bytes we verified (no re-encode).
  const { instance } = await WebAssembly.instantiate(wasmBytes, {});
  return new BrowserPlugin(instance);
}

/// The six-export ABI driver over the (ptr,len)->(ptr,len) byte-buffer ABI
/// (mirror of the host's `PluginInstance`).
export class BrowserPlugin {
  constructor(instance) {
    const e = instance.exports;
    for (const name of [
      "memory", "plugin_alloc", "plugin_dealloc",
      "initial_state", "apply_op", "make_op", "render", "snapshot", "load_snapshot",
    ]) {
      if (!(name in e)) throw new Error(`plugin missing export: ${name}`);
    }
    this.e = e;
  }

  #hostToWasm(bytes) {
    const len = bytes.length;
    const ptr = this.e.plugin_alloc(len);
    new Uint8Array(this.e.memory.buffer, ptr, len).set(bytes);
    return [ptr, len];
  }

  #wasmToHost(packed) {
    // packed is a BigInt (u64): (ptr << 32) | len
    const ptr = Number(packed >> 32n);
    const len = Number(packed & 0xffffffffn);
    const out = new Uint8Array(len);
    if (len) out.set(new Uint8Array(this.e.memory.buffer, ptr, len));
    this.e.plugin_dealloc(ptr, len);
    return out;
  }

  initialState() {
    return this.#wasmToHost(this.e.initial_state());
  }
  applyOp(state, op) {
    const [sp, sl] = this.#hostToWasm(state);
    const [op_p, op_l] = this.#hostToWasm(op);
    const r = this.#wasmToHost(this.e.apply_op(sp, sl, op_p, op_l));
    this.e.plugin_dealloc(sp, sl);
    this.e.plugin_dealloc(op_p, op_l);
    return r;
  }
  makeOp(state, action) {
    const [sp, sl] = this.#hostToWasm(state);
    const [ap, al] = this.#hostToWasm(action);
    const r = this.#wasmToHost(this.e.make_op(sp, sl, ap, al));
    this.e.plugin_dealloc(sp, sl);
    this.e.plugin_dealloc(ap, al);
    return r;
  }
  render(state) {
    const [sp, sl] = this.#hostToWasm(state);
    const r = this.#wasmToHost(this.e.render(sp, sl));
    this.e.plugin_dealloc(sp, sl);
    return r;
  }
  snapshot(state) {
    const [sp, sl] = this.#hostToWasm(state);
    const r = this.#wasmToHost(this.e.snapshot(sp, sl));
    this.e.plugin_dealloc(sp, sl);
    return r;
  }
  loadSnapshot(bytes) {
    const [bp, bl] = this.#hostToWasm(bytes);
    const r = this.#wasmToHost(this.e.load_snapshot(bp, bl));
    this.e.plugin_dealloc(bp, bl);
    return r;
  }
}

/// Encode an i64 as 8 little-endian bytes (the counter ABI encoding).
export function i64le(v) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigInt64(0, BigInt(v), true);
  return out;
}
