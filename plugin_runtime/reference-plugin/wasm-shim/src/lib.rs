// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// ZT-E E1 — reference plugin wasm exports (the six-function ABI).
//
// Mirrors ../src/counter_plugin.loft: a CRDT counter whose ops are commutative
// i64 deltas.  This is the hand-written stand-in for a future
// `loft --native-wasm --exports` codegen path (see ../../DESIGN.md § Follow-up);
// the signature gate (E2/E3) verifies the module bytes and does not care how the
// wasm was produced, so a loft-source-only plugin will load through exactly the
// same gate.
//
// ABI across the wasm boundary — every value is a byte buffer in linear memory:
//   * the host calls `plugin_alloc(len)` to get a ptr, writes `len` bytes there,
//     then passes (ptr, len) into an export;
//   * each export returns a packed u64 = (out_ptr << 32) | out_len; the host
//     reads `out_len` bytes at `out_ptr`, then calls `plugin_dealloc(out_ptr,
//     out_len)`.
// State/op/action/snapshot are 8 little-endian bytes of an i64; render output is
// the ASCII-decimal total.  Uses the default std allocator on
// wasm32-unknown-unknown (panic=abort + opt-level=z keep the module small).

use std::mem;

// --- the (ptr,len) memory ABI the host drives ---

/// Reserve `len` bytes the host can write an argument into.  Returns a pointer
/// into wasm linear memory.  The host fills it, hands it to an export, and the
/// export takes ownership (frees it).
#[no_mangle]
pub extern "C" fn plugin_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    mem::forget(buf);
    ptr
}

/// Free a buffer the host is done reading (an export's return buffer).
///
/// # Safety
/// `ptr`/`len` must come from a prior `plugin_alloc(len)` or a returned export
/// buffer of exactly `len` bytes, freed at most once.
#[no_mangle]
pub unsafe extern "C" fn plugin_dealloc(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len != 0 {
        drop(Vec::from_raw_parts(ptr, len, len));
    }
}

/// Pack an owned byte buffer into the u64 (ptr<<32 | len) the host unpacks.
fn ret(bytes: Vec<u8>) -> u64 {
    // shrink so cap == len, so the host's dealloc(len) matches the allocation.
    let mut b = bytes;
    b.shrink_to_fit();
    let len = b.len();
    let ptr = b.as_mut_ptr() as u32;
    mem::forget(b);
    ((ptr as u64) << 32) | (len as u64)
}

/// Borrow the host-provided argument bytes (read-only) for the call's duration.
///
/// # Safety
/// `ptr`/`len` must describe a valid host-written buffer.
unsafe fn arg<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(ptr, len)
    }
}

// --- the counter CRDT (mirror of counter_plugin.loft) ---

fn le_to_i64(b: &[u8]) -> i64 {
    if b.len() < 8 {
        return 0;
    }
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    i64::from_le_bytes(a)
}

fn i64_to_le(v: i64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

// --- the six ABI exports ---

/// `initial_state() -> state` : the empty document (total 0).
#[no_mangle]
pub extern "C" fn initial_state() -> u64 {
    ret(i64_to_le(0))
}

/// `apply_op(state, op) -> state` : fold one delta into the total.
///
/// # Safety
/// Both (ptr,len) pairs must describe valid host buffers.
#[no_mangle]
pub unsafe extern "C" fn apply_op(
    state_ptr: *const u8,
    state_len: usize,
    op_ptr: *const u8,
    op_len: usize,
) -> u64 {
    let total = le_to_i64(arg(state_ptr, state_len));
    let delta = le_to_i64(arg(op_ptr, op_len));
    ret(i64_to_le(total.wrapping_add(delta)))
}

/// `make_op(state, action) -> op` : an "add N" action becomes the op for N;
/// an action of 0 produces no op (an empty buffer).
///
/// # Safety
/// Both (ptr,len) pairs must describe valid host buffers.
#[no_mangle]
pub unsafe extern "C" fn make_op(
    _state_ptr: *const u8,
    _state_len: usize,
    action_ptr: *const u8,
    action_len: usize,
) -> u64 {
    let n = le_to_i64(arg(action_ptr, action_len));
    if n == 0 {
        return ret(Vec::new());
    }
    ret(i64_to_le(n))
}

/// `render(state) -> bytes` : the decimal total as ASCII (the host UI string).
///
/// # Safety
/// (ptr,len) must describe a valid host buffer.
#[no_mangle]
pub unsafe extern "C" fn render(state_ptr: *const u8, state_len: usize) -> u64 {
    let total = le_to_i64(arg(state_ptr, state_len));
    let mut out = Vec::new();
    // build the decimal digits manually (keeps the module dependency-free).
    let neg = total < 0;
    let mut n = if neg { (total as i128).unsigned_abs() } else { total as u128 };
    if n == 0 {
        out.push(b'0');
    } else {
        let mut digits = [0u8; 40];
        let mut i = 0;
        while n > 0 {
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
            i += 1;
        }
        if neg {
            out.push(b'-');
        }
        while i > 0 {
            i -= 1;
            out.push(digits[i]);
        }
    }
    ret(out)
}

/// `snapshot(state) -> bytes` : a counter's snapshot is its state verbatim.
///
/// # Safety
/// (ptr,len) must describe a valid host buffer.
#[no_mangle]
pub unsafe extern "C" fn snapshot(state_ptr: *const u8, state_len: usize) -> u64 {
    ret(arg(state_ptr, state_len).to_vec())
}

/// `load_snapshot(bytes) -> state` : adopt the snapshot bytes as state.
///
/// # Safety
/// (ptr,len) must describe a valid host buffer.
#[no_mangle]
pub unsafe extern "C" fn load_snapshot(bytes_ptr: *const u8, bytes_len: usize) -> u64 {
    ret(arg(bytes_ptr, bytes_len).to_vec())
}
