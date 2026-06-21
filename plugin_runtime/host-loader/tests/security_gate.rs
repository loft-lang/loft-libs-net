// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// ZT-E E2 — the security gate, as four-plus-boundary negative tests.
//
// THE GATE'S INVARIANT: no plugin code runs unless a TRUSTED Ed25519 key
// verifies the signature over the EXACT module bytes, BEFORE instantiation,
// failing CLOSED.  The four mandated cells (DESIGN.md F1-F4):
//   F1 signed   -> ACCEPT (and the module runs)
//   F2 tampered -> REJECT
//   F3 unsigned -> REJECT
//   F4 wrong-key-> REJECT
// plus the fail-closed boundaries F6 (empty trust list) and the short-sig case.
//
// Fixtures are produced by ../../build/sign-and-build-fixtures.sh:
//   build/counter_plugin.wasm        the module
//   build/counter_plugin.wasm.sig    A's signature (trusted author)
//   build/counter_plugin.wasm.sigB   B's signature (untrusted author)
//   keys/authorA/registry-signing-key.pub   trusted public key (hex)
//   keys/authorB/registry-signing-key.pub   untrusted public key (hex)

use std::path::PathBuf;
use wasmtime::Engine;
use zt_e_host_loader::{hex_to_key, verify_then_load, LoadError, PluginInstance, Reject};

fn staging() -> PathBuf {
    // tests run with CWD = the host-loader crate dir; staging root is one up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn wasm_bytes() -> Vec<u8> {
    std::fs::read(staging().join("build/counter_plugin.wasm")).expect("build/counter_plugin.wasm — run build/sign-and-build-fixtures.sh first")
}
fn sig_a() -> Vec<u8> {
    std::fs::read(staging().join("build/counter_plugin.wasm.sig")).expect("A signature")
}
fn sig_b() -> Vec<u8> {
    std::fs::read(staging().join("build/counter_plugin.wasm.sigB")).expect("B signature")
}
fn key_a() -> [u8; 32] {
    let hex = std::fs::read_to_string(staging().join("keys/authorA/public_key.hex")).expect("A pub");
    hex_to_key(&hex).unwrap()
}
fn key_b() -> [u8; 32] {
    let hex = std::fs::read_to_string(staging().join("keys/authorB/public_key.hex")).expect("B pub");
    hex_to_key(&hex).unwrap()
}

// ── F1: correctly-signed, trusted key -> ACCEPT, and the module RUNS ─────────

#[test]
fn f1_signed_accepts_and_runs() {
    let engine = Engine::default();
    let module = verify_then_load(&engine, &wasm_bytes(), &sig_a(), &[key_a()])
        .expect("F1: a correctly-signed plugin must be accepted");

    // ...and it actually runs the counter to the expected value.
    let mut p = PluginInstance::new(&engine, &module).expect("instantiate");
    let mut state = p.initial_state().unwrap();
    for action in [5i64, 10, -3] {
        let op = p.make_op(&state, &action.to_le_bytes()).unwrap();
        state = p.apply_op(&state, &op).unwrap();
    }
    let rendered = String::from_utf8(p.render(&state).unwrap()).unwrap();
    assert_eq!(rendered, "12", "F1: counter must render 12 (CRDT sum +5+10-3)");
}

// ── F2: one byte of the wasm flipped after signing -> REJECT ────────────────

#[test]
fn f2_tampered_rejects() {
    let engine = Engine::default();
    let mut tampered = wasm_bytes();
    // flip a byte deep in the code section (not the magic header), so it is a
    // genuine content change the signature no longer covers.
    let i = tampered.len() / 2;
    tampered[i] ^= 0xFF;

    let r = verify_then_load(&engine, &tampered, &sig_a(), &[key_a()]);
    assert_eq!(
        r.err(),
        Some(LoadError::Reject(Reject::Untrusted)),
        "F2: a tampered module must be REJECTED before instantiation"
    );
}

// ── F3: no signature / empty / wrong length -> REJECT (fail closed) ──────────

#[test]
fn f3_unsigned_rejects() {
    let engine = Engine::default();
    // empty signature
    assert_eq!(
        verify_then_load(&engine, &wasm_bytes(), &[], &[key_a()]).err(),
        Some(LoadError::Reject(Reject::MalformedSignature)),
        "F3a: an empty signature must be REJECTED"
    );
    // wrong-length signature (not 64 bytes)
    assert_eq!(
        verify_then_load(&engine, &wasm_bytes(), &[0u8; 10], &[key_a()]).err(),
        Some(LoadError::Reject(Reject::MalformedSignature)),
        "F3b: a short signature must be REJECTED"
    );
    // a 64-byte all-zero signature is well-formed but verifies under no key
    assert_eq!(
        verify_then_load(&engine, &wasm_bytes(), &[0u8; 64], &[key_a()]).err(),
        Some(LoadError::Reject(Reject::Untrusted)),
        "F3c: a bogus 64-byte signature must be REJECTED"
    );
}

// ── F4: validly signed, but by a key NOT in the trusted list -> REJECT ──────

#[test]
fn f4_wrong_key_rejects() {
    let engine = Engine::default();
    // B's signature is cryptographically VALID — but we trust only A.
    let r = verify_then_load(&engine, &wasm_bytes(), &sig_b(), &[key_a()]);
    assert_eq!(
        r.err(),
        Some(LoadError::Reject(Reject::Untrusted)),
        "F4: a plugin signed by an untrusted author must be REJECTED"
    );

    // Symmetric sanity: trusting B instead, B's signature is accepted (proves
    // the rejection is about TRUST, not a broken signature).
    assert!(
        verify_then_load(&engine, &wasm_bytes(), &sig_b(), &[key_b()]).is_ok(),
        "B's signature must verify under B's own key"
    );
}

// ── F6: empty trusted list -> REJECT everything (no implicit trust) ─────────

#[test]
fn f6_empty_trust_list_rejects() {
    let engine = Engine::default();
    let r = verify_then_load(&engine, &wasm_bytes(), &sig_a(), &[]);
    assert_eq!(
        r.err(),
        Some(LoadError::Reject(Reject::NoTrustedKeys)),
        "F6: with no trusted keys, even a correctly-signed plugin must be REJECTED"
    );
}

// ── Multi-key: A trusted among several keys -> ACCEPT (any trusted verifies) ─

#[test]
fn multi_key_any_trusted_accepts() {
    let engine = Engine::default();
    // trust both B and A; A's signature must still verify (A is in the set).
    assert!(
        verify_then_load(&engine, &wasm_bytes(), &sig_a(), &[key_b(), key_a()]).is_ok(),
        "a signature by ANY trusted key must be accepted"
    );
}
