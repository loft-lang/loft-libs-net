// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// game_protocol-reference — the pure-Rust twin of the `game_protocol` package's performance
// pass (bench/bench.loft), one file built with `rustc -O`.  It computes the SAME workload and
// prints the same rows, hash included: a row whose hash matches the loft build's is a
// like-for-like comparison, and only then is a routine's loft time judged against it
// (@FR-Perf-Weight).  No dependencies and no cleverness — plain idiomatic Rust, the speed an
// industry implementation reaches without effort, which is exactly what the bar should be.
//
//     rustc -O --edition=2021 bench/bench.rs -o bench/.build/stats_rs && bench/.build/stats_rs --n 2
//
// `msg_ping` is a port of src/game_protocol.loft's: the same two structs, built and returned
// by value, the timestamp read from the wall clock in milliseconds exactly as loft's `now()`
// reads it (`SystemTime::now()` since the epoch).  `black_box` guards each op's INPUT (the
// repetition number) and the sink — never anything inside a kernel.
use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const FNV_OFFSET: i64 = 2166136261;
const FNV_PRIME: i64 = 16777619;

const CALLS: i64 = 100000;

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
}

// ── game_protocol.loft ──────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum MsgType {
    StateFullSync,
    StateDelta,
    PlayerInput,
    Ping,
    Pong,
    ChatMessage,
    LobbyJoin,
    LobbyLeave,
    LobbyList,
    MatchStart,
    MatchEnd,
    Error,
}

struct WsMessage {
    msg_type: MsgType,
    payload: String,
}

struct GameEnvelope {
    sender: String,
    recipient: String,
    sequence: i64,
    timestamp: i64,
    message: WsMessage,
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(i64::MIN, |d| d.as_millis() as i64)
}

fn msg_ping(seq: i64) -> GameEnvelope {
    GameEnvelope {
        sender: String::new(),
        recipient: String::new(),
        sequence: seq,
        timestamp: now(),
        message: WsMessage { msg_type: MsgType::Ping, payload: String::new() },
    }
}

// ── msg_ping ────────────────────────────────────────────────────────

fn ping_op(r: i64) -> [i64; 4] {
    let (mut seq, mut pings, mut bytes, mut stamp) = (0i64, 0i64, 0i64, 0i64);
    for i in 0..CALLS {
        let env = msg_ping((r & 1) + i);
        seq += env.sequence;
        if env.message.msg_type == MsgType::Ping {
            pings += 1;
        }
        bytes += (env.sender.len() + env.recipient.len() + env.message.payload.len()) as i64;
        stamp += env.timestamp & 1023;
    }
    [seq, pings, bytes, stamp]
}

fn bench_ping(n: i64) -> Row {
    let t0 = Instant::now();
    let mut sink = 0i64;
    for r in 0..n {
        let one = ping_op(black_box(r));
        sink = sink.wrapping_add(one[0] + one[3]);
    }
    let us = t0.elapsed().as_micros() as i64;
    let c = ping_op(0);
    Row { name: "msg_ping", iters: n, us, px: CALLS, hash: fnv(FNV_OFFSET, &c[..3]),
          sink: black_box(sink) }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut n = 20i64;
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--n" && i + 1 < args.len() {
            n = args[i + 1].parse().unwrap_or(1);
            i += 1;
        }
        i += 1;
    }
    if n < 1 {
        n = 1;
    }
    let t0 = Instant::now();
    println!("routine\titers\tus\tns_op\tpx\tns_px\thash");
    let rows = [bench_ping(n)];
    let mut sink = 0i64;
    for row in &rows {
        print_row(row);
        sink = sink.wrapping_add(row.sink);
    }
    println!("time: {}ms sink={}", t0.elapsed().as_millis(), sink);
}
