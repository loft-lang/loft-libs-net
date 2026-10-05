// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// web-reference — the pure-Rust twin of bench/bench.loft, one file, std only.  The rows
// time the per-byte binary-frame helpers, whose loft calls cross into the native crate
// once per byte; here the crate functions' BODIES (native/src/lib.rs: `n_pack_reset`,
// `n_pack_u8`, `n_pack_take`, `n_byte_at`) are called as plain Rust functions, with no
// crossing at all.  Same workload, same bytes, same hash: the ratio between the lanes is
// the cost of the crossing.
//
//     mkdir -p bench/.build && rustc -O --edition=2021 bench/bench.rs -o bench/.build/stats_rs
//     bench/.build/stats_rs --n 20
use std::cell::RefCell;
use std::hint::black_box;
use std::time::Instant;

const FNV_OFFSET: i64 = 2166136261;
const FNV_PRIME: i64 = 16777619;

fn fnv(h0: i64, v: &[i64]) -> i64 {
    let mut h = h0;
    for &x in v {
        let w = x & 0xFFFF_FFFF;
        for sh in [24, 16, 8, 0] {
            h = ((h ^ ((w >> sh) & 255)) * FNV_PRIME) & 0xFFFF_FFFF;
        }
    }
    h
}

fn fnv_bytes(h0: i64, t: &[u8]) -> i64 {
    let mut h = h0;
    for &b in t {
        h = ((h ^ b as i64) * FNV_PRIME) & 0xFFFF_FFFF;
    }
    h
}

struct Row {
    name: &'static str,
    iters: i64,
    us: i64,
    px: i64,
    hash: i64,
    sink: i64,
}

fn print_row(r: &Row) {
    let ns_op = r.us * 1000 / r.iters;
    let ns_px = if r.px > 0 { (r.us * 1000) as f64 / (r.iters * r.px) as f64 } else { 0.0 };
    println!("{}\t{}\t{}\t{}\t{}\t{:.3}\t{:x}", r.name, r.iters, r.us, ns_op, r.px, ns_px, r.hash);
    if black_box(r.sink) == i64::MIN {
        println!("(unreachable — keeps the sink alive)");
    }
}

// ── The crate bodies (native/src/lib.rs), minus the C boundary ──────

thread_local! {
    static PACK_BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static LAST_PACKED: RefCell<String> = const { RefCell::new(String::new()) };
}

fn pack_reset() {
    PACK_BUF.with(|b| b.borrow_mut().clear());
}

fn pack_u8(b: i64) {
    let b = b as i32;
    PACK_BUF.with(|buf| buf.borrow_mut().push((b & 0xff) as u8));
}

/// `n_pack_take` hands loft a reference to `LAST_PACKED`, which loft copies into a text of
/// its own; the clone is that copy.
fn pack_take() -> String {
    PACK_BUF.with(|buf| {
        let v = std::mem::take(&mut *buf.borrow_mut());
        LAST_PACKED.with(|p| {
            *p.borrow_mut() = unsafe { String::from_utf8_unchecked(v) };
            p.borrow().clone()
        })
    })
}

unsafe fn byte_at(idx: i64, text_ptr: *const u8, text_len: usize) -> i64 {
    if idx < 0 || (idx as usize) >= text_len {
        return -1;
    }
    unsafe { i64::from(*text_ptr.add(idx as usize)) }
}

// ── Send side ───────────────────────────────────────────────────────

const PK_FRAMES: i64 = 1024;
const PK_BYTES: i64 = 1024;

fn pack_frames(salt: i64, frames: &mut Vec<String>, keep: bool) -> i64 {
    let mut total = 0i64;
    for f in 0..PK_FRAMES {
        pack_reset();
        for k in 0..PK_BYTES {
            pack_u8(k * 131 + f * 7 + salt * 13);
        }
        let fr = pack_take();
        total += fr.len() as i64;
        if keep {
            frames.push(fr);
        }
    }
    total
}

fn bench_pack_u8(n: i64) -> Row {
    let mut none: Vec<String> = Vec::new();
    let t0 = Instant::now();
    let mut sink = 0i64;
    for r in 0..n {
        sink += pack_frames(black_box(r), &mut none, false);
    }
    let us = t0.elapsed().as_micros() as i64;
    let mut frames: Vec<String> = Vec::new();
    pack_frames(0, &mut frames, true);
    let mut h = FNV_OFFSET;
    for fr in &frames {
        h = fnv_bytes(h, fr.as_bytes());
    }
    Row { name: "pack_u8", iters: n, us, px: PK_FRAMES * PK_BYTES, hash: h, sink: black_box(sink) }
}

// ── Receive side ────────────────────────────────────────────────────

const BA_SIZE: i64 = 65536;
const BA_PASSES: i64 = 16;

fn byte_frame() -> Vec<u8> {
    (0..BA_SIZE).map(|k| ((k * 131 + (k >> 8) * 7) & 255) as u8).collect()
}

fn read_frame(fr: &[u8], salt: i64) -> i64 {
    let mut acc = 0i64;
    for p in 0..BA_PASSES {
        let off = salt * 17 + p * 4099;
        for i in 0..BA_SIZE {
            let b = unsafe { byte_at((i + off) & 65535, fr.as_ptr(), fr.len()) };
            acc = (acc * 31 + b) & 0xFFFF_FFFF;
        }
    }
    acc
}

fn bench_byte_at(n: i64) -> Row {
    let fr = byte_frame();
    let t0 = Instant::now();
    let mut sink = 0i64;
    for r in 0..n {
        sink += read_frame(black_box(&fr), black_box(r));
    }
    let us = t0.elapsed().as_micros() as i64;
    let one = [read_frame(&fr, 0), fr.len() as i64, fnv_bytes(FNV_OFFSET, &fr)];
    Row { name: "byte_at", iters: n, us, px: BA_PASSES * BA_SIZE, hash: fnv(FNV_OFFSET, &one),
          sink: black_box(sink) }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut n: i64 = 20;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--n" && i + 1 < args.len() {
            n = args[i + 1].parse().unwrap_or(20);
            i += 1;
        }
        i += 1;
    }
    if n < 1 {
        n = 1;
    }
    println!("routine\titers\tus\tns_op\tpx\tns_px\thash");
    print_row(&bench_pack_u8(n));
    print_row(&bench_byte_at(n));
}
