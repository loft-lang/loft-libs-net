// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// ZT-E E3 — the browser security gate, as the SAME four-plus-boundary cases the
// host loader (E2) runs, asserting byte-for-byte the same accept/reject
// decisions.  Run under Node 22 (global `crypto.subtle` Ed25519):
//   node tools/zt-e-plugin-staging/browser-loader/security_gate.test.mjs
//
// Exit 0 = all cells pass; exit 1 = any cell failed (the security gate is red).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  loadPlugin, verifySignature, PluginRejected, Reject, i64le,
} from "./plugin_loader.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const STAGING = join(HERE, "..");
const wasm = () => new Uint8Array(readFileSync(join(STAGING, "build/counter_plugin.wasm")));
const sigA = () => new Uint8Array(readFileSync(join(STAGING, "build/counter_plugin.wasm.sig")));
const sigB = () => new Uint8Array(readFileSync(join(STAGING, "build/counter_plugin.wasm.sigB")));
const keyA = () => readFileSync(join(STAGING, "keys/authorA/public_key.hex"), "utf8").trim();
const keyB = () => readFileSync(join(STAGING, "keys/authorB/public_key.hex"), "utf8").trim();

let passed = 0, failed = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
    passed++;
  } catch (e) {
    console.log(`  FAIL ${name}\n         ${e.message}`);
    failed++;
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
async function expectReject(promise, reason, msg) {
  try {
    await promise;
  } catch (e) {
    assert(e instanceof PluginRejected, `${msg}: threw ${e?.name}, not PluginRejected`);
    if (reason) assert(e.reason === reason, `${msg}: reason "${e.reason}" != expected "${reason}"`);
    return;
  }
  throw new Error(`${msg}: expected a PluginRejected, but loadPlugin RESOLVED`);
}

console.log("ZT-E E3 — browser security gate (WebCrypto Ed25519)");

// ── F1: correctly-signed, trusted key -> ACCEPT, and the module RUNS ─────────
await test("F1 signed -> ACCEPT and runs (counter = 12)", async () => {
  const p = await loadPlugin(wasm(), sigA(), [keyA()]);
  let state = p.initialState();
  for (const action of [5n, 10n, -3n]) {
    const op = p.makeOp(state, i64le(action));
    state = p.applyOp(state, op);
  }
  const rendered = new TextDecoder().decode(p.render(state));
  assert(rendered === "12", `F1: counter must render 12, got "${rendered}"`);
  // snapshot round-trip too
  const restored = p.loadSnapshot(p.snapshot(state));
  assert(new TextDecoder().decode(p.render(restored)) === "12", "F1: snapshot round-trip must preserve 12");
});

// ── F2: one byte of the wasm flipped after signing -> REJECT ────────────────
await test("F2 tampered -> REJECT", async () => {
  const bytes = wasm();
  bytes[Math.floor(bytes.length / 2)] ^= 0xff;
  await expectReject(loadPlugin(bytes, sigA(), [keyA()]), Reject.Untrusted, "F2");
});

// ── F3: no signature / empty / wrong length -> REJECT (fail closed) ──────────
await test("F3 unsigned -> REJECT", async () => {
  await expectReject(loadPlugin(wasm(), new Uint8Array(0), [keyA()]), Reject.MalformedSignature, "F3a empty");
  await expectReject(loadPlugin(wasm(), new Uint8Array(10), [keyA()]), Reject.MalformedSignature, "F3b short");
  await expectReject(loadPlugin(wasm(), new Uint8Array(64), [keyA()]), Reject.Untrusted, "F3c bogus 64-byte");
});

// ── F4: validly signed, but by a key NOT in the trusted list -> REJECT ──────
await test("F4 wrong-key -> REJECT (and B verifies under B's own key)", async () => {
  await expectReject(loadPlugin(wasm(), sigB(), [keyA()]), Reject.Untrusted, "F4");
  // symmetric sanity: B's signature IS valid under B's key (proves it's about trust)
  const gate = await verifySignature(wasm(), sigB(), [keyB()]);
  assert(gate.ok, "B's signature must verify under B's own key");
});

// ── F6: empty trusted list -> REJECT everything ─────────────────────────────
await test("F6 empty trust list -> REJECT", async () => {
  await expectReject(loadPlugin(wasm(), sigA(), []), Reject.NoTrustedKeys, "F6");
});

// ── Multi-key: A trusted among several keys -> ACCEPT ───────────────────────
await test("multi-key: any trusted key accepts", async () => {
  const gate = await verifySignature(wasm(), sigA(), [keyB(), keyA()]);
  assert(gate.ok, "a signature by ANY trusted key must be accepted");
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
