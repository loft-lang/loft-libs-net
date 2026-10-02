// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// server-reference — the pure-Rust twin of the `server` package's performance pass
// (bench/bench.loft), one file built with `rustc -O`.  It computes the SAME workload and
// prints the same rows, hash included: a row whose hash matches the loft build's is a
// like-for-like comparison, and only then is a routine's loft time judged against it
// (@FR-Perf-Weight).  No dependencies and no cleverness — plain idiomatic Rust, the speed an
// industry implementation reaches without effort, which is exactly what the bar should be.
//
//     rustc -O --edition=2021 bench/bench.rs -o bench/.build/stats_rs && bench/.build/stats_rs --n 2
//
// `header` is the idiomatic form of src/server.loft's `Request.header`: split each line at
// its first ':' and compare the name with `eq_ignore_ascii_case`, the value being the rest
// of the line, trimmed.  That answers exactly what the loft routine answers (lowercase the
// line, test the `name:` prefix, rejoin the pieces after the first ':') for every header
// whose name carries no ':' — the hash checks it — without allocating per line.
// `black_box` guards each op's INPUT (the repetition number) and the sink — never anything
// inside a kernel.
use std::hint::black_box;
use std::time::Instant;

const FNV_OFFSET: i64 = 2166136261;
const FNV_PRIME: i64 = 16777619;

const LOOKUPS: usize = 10000;

fn fnv_text(h0: i64, t: &str) -> i64 {
    let mut h = h0;
    for &b in t.as_bytes() {
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
}

fn timed<F: FnMut(i64) -> i64>(n: i64, mut f: F) -> (i64, i64) {
    let t0 = Instant::now();
    let mut sink = 0i64;
    for r in 0..n {
        sink = sink.wrapping_add(f(black_box(r)));
    }
    (t0.elapsed().as_micros() as i64, black_box(sink))
}

// ── header ──────────────────────────────────────────────────────────

#[allow(dead_code)]
struct Request {
    method: String,
    path: String,
    body: String,
    headers: Vec<String>,
}

impl Request {
    fn header(&self, name: &str) -> &str {
        for h in &self.headers {
            if let Some((key, value)) = h.split_once(':') {
                if key.eq_ignore_ascii_case(name) {
                    return value.trim();
                }
            }
        }
        ""
    }
}

fn make_request(r: i64) -> Request {
    let port = 8080 + (r & 1);
    Request {
        method: "GET".to_string(),
        path: "/assets/tiles/0012.bin".to_string(),
        body: String::new(),
        headers: vec![
            "Host: tiles.example.test".to_string(),
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
                .to_string(),
            "Accept: application/octet-stream, */*;q=0.8".to_string(),
            "Accept-Language: en-US,en;q=0.5".to_string(),
            "Accept-Encoding: gzip, deflate, br, zstd".to_string(),
            "Referer: https://game.example.test/play".to_string(),
            format!("Origin: https://game.example.test:{port}"),
            "Connection: keep-alive".to_string(),
            "Cookie: session=4f2a9c01d3; theme=dark".to_string(),
            "sec-fetch-dest: empty".to_string(),
            "sec-fetch-mode: cors".to_string(),
            "If-Modified-Since: Tue, 22 Sep 2026 10:15:00 GMT".to_string(),
            "if-none-match: \"v3-abc-0012\"".to_string(),
            "Range: bytes=4096-8191".to_string(),
        ],
    }
}

const NAMES: [&str; 8] = [
    "Host", "Origin", "range", "If-None-Match", "ACCEPT-ENCODING", "X-Forwarded-For",
    "If-Modified-Since", "cookie",
];

fn header_op(r: i64) -> i64 {
    let req = make_request(r);
    let mut sum = 0i64;
    for i in 0..LOOKUPS {
        sum += req.header(NAMES[i & 7]).len() as i64;
    }
    sum
}

fn header_hash() -> i64 {
    let req = make_request(0);
    let mut h = FNV_OFFSET;
    for i in 0..LOOKUPS {
        h = fnv_text(h, req.header(NAMES[i & 7]));
    }
    h
}

fn bench_header(n: i64) -> Row {
    let (us, sink) = timed(n, header_op);
    Row { name: "header", iters: n, us, px: LOOKUPS as i64, hash: header_hash(), sink }
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
    let rows = [bench_header(n)];
    let mut sink = 0i64;
    for row in &rows {
        print_row(row);
        sink = sink.wrapping_add(row.sink);
    }
    println!("time: {}ms sink={}", t0.elapsed().as_millis(), sink);
}
