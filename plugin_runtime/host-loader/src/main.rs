// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// ZT-E E2 — CLI front-end for the host plugin loader.
//
//   load-plugin <plugin.wasm> <plugin.wasm.sig> <trusted_pub_hex>...
//
// Verifies the plugin's Ed25519 signature against the trusted-author public
// keys, and only on success instantiates + runs the counter scenario.  Exit 0
// = accepted and ran; exit 2 = REJECTED by the gate; exit 1 = usage / other.

use std::process::exit;
use wasmtime::Engine;
use zt_e_host_loader::{verify_then_load, hex_to_key, LoadError, PluginInstance};

fn die(msg: &str) -> ! {
    eprintln!("load-plugin: {msg}");
    exit(1);
}

fn le8(v: i64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        die("usage: load-plugin <plugin.wasm> <plugin.wasm.sig> <trusted_pub_hex>...");
    }
    let wasm = std::fs::read(&args[1]).unwrap_or_else(|e| die(&format!("read {}: {e}", args[1])));
    let sig = std::fs::read(&args[2]).unwrap_or_else(|e| die(&format!("read {}: {e}", args[2])));
    let trusted: Vec<[u8; 32]> = args[3..]
        .iter()
        .map(|h| hex_to_key(h).unwrap_or_else(|e| die(&format!("trusted key {h}: {e}"))))
        .collect();

    let engine = Engine::default();
    let module = match verify_then_load(&engine, &wasm, &sig, &trusted) {
        Ok(m) => {
            println!("GATE: ACCEPTED — signature verified against a trusted author");
            m
        }
        Err(LoadError::Reject(r)) => {
            println!("GATE: REJECTED — {r}");
            exit(2);
        }
        Err(LoadError::Wasm(e)) => die(&format!("trusted module failed to load: {e}")),
    };

    // Drive the counter scenario, proving the six exports run.
    let mut p = PluginInstance::new(&engine, &module).unwrap_or_else(|e| die(&e));
    let mut state = p.initial_state().unwrap_or_else(|e| die(&e));
    println!("initial render = {}", show(&mut p, &state));

    // make_op turns "add 5" into an op, apply it; then +10, -3 -> 12
    for action in [5i64, 10, -3] {
        let op = p.make_op(&state, &le8(action)).unwrap_or_else(|e| die(&e));
        state = p.apply_op(&state, &op).unwrap_or_else(|e| die(&e));
    }
    println!("after +5 +10 -3 render = {}", show(&mut p, &state));

    // snapshot / load_snapshot round-trip
    let snap = p.snapshot(&state).unwrap_or_else(|e| die(&e));
    let restored = p.load_snapshot(&snap).unwrap_or_else(|e| die(&e));
    println!("after snapshot->load render = {}", show(&mut p, &restored));

    let rendered = String::from_utf8_lossy(&p.render(&restored).unwrap_or_else(|e| die(&e))).into_owned();
    if rendered == "12" {
        println!("PLUGIN RAN OK (counter = 12)");
    } else {
        die(&format!("unexpected counter render: {rendered}"));
    }
}

fn show(p: &mut PluginInstance, state: &[u8]) -> String {
    match p.render(state) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) => format!("<render error: {e}>"),
    }
}
