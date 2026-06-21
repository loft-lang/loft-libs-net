// Copyright (c) 2026 Jurjen Stellingwerff
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// ZT-E E2 — host plugin loader: the security gate + the six-export ABI driver.
//
// THE INVARIANT (DESIGN.md): no byte of plugin code runs unless a *trusted*
// Ed25519 public key verifies the signature over the *exact* module bytes that
// will be instantiated — the verify is the single gate every load path passes
// through, BEFORE instantiation, and it fails CLOSED.
//
// `verify_then_load` enforces it structurally: the verify returns `Err` before
// any `wasmtime` call, and the *same* `&[u8]` it verified is the buffer handed
// to `Module::from_binary`.  There is no path that instantiates an unverified
// or re-serialized module.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use wasmtime::{Engine, Instance, Memory, Module, Store, TypedFunc};

/// Why a plugin was rejected.  Every variant is a *refusal to run code* — the
/// gate never falls open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reject {
    /// No trusted key verifies the signature (tampered bytes, or a valid
    /// signature by an author not on the trusted list).
    Untrusted,
    /// The signature blob is not a well-formed 64-byte Ed25519 signature
    /// (missing / truncated / wrong length) — fail closed.
    MalformedSignature,
    /// The trusted-authors list is empty — with no trusted key, nothing loads.
    NoTrustedKeys,
    /// All trusted-key entries were malformed (not 32 raw bytes) — fail closed.
    NoUsableKeys,
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Reject::Untrusted => "no trusted key verifies the plugin signature",
            Reject::MalformedSignature => "plugin signature is not a 64-byte Ed25519 signature",
            Reject::NoTrustedKeys => "trusted-authors list is empty (nothing can load)",
            Reject::NoUsableKeys => "no trusted-authors entry is a valid 32-byte Ed25519 key",
        };
        f.write_str(s)
    }
}
impl std::error::Error for Reject {}

/// THE GATE.  Verify `signature` over `wasm_bytes` against `trusted_keys`
/// (each a 32-byte raw Ed25519 public key); only if some trusted key verifies
/// do we compile the module — from the *same* `wasm_bytes`.
///
/// Returns `Err(Reject)` *before touching wasmtime* on any failure, so no
/// plugin code can run unverified.  A signed-but-broken module (valid
/// signature, malformed wasm) surfaces as `Err(LoadError::Wasm)` from
/// `Module::from_binary` — distinct from a *trust* rejection.
pub fn verify_then_load(
    engine: &Engine,
    wasm_bytes: &[u8],
    signature: &[u8],
    trusted_keys: &[[u8; 32]],
) -> Result<Module, LoadError> {
    // 1. THE GATE — fail closed on every bad-input path, before any wasmtime
    //    call.  Order matters only for diagnostics; any failure is a reject.
    if trusted_keys.is_empty() {
        return Err(Reject::NoTrustedKeys.into());
    }
    let sig_arr: [u8; 64] = signature
        .try_into()
        .map_err(|_| LoadError::Reject(Reject::MalformedSignature))?;
    let sig = Signature::from_bytes(&sig_arr);

    let mut any_usable_key = false;
    let mut verified = false;
    for raw in trusted_keys {
        let Ok(vk) = VerifyingKey::from_bytes(raw) else {
            continue; // skip a malformed trusted-key entry, try the next
        };
        any_usable_key = true;
        if vk.verify(wasm_bytes, &sig).is_ok() {
            verified = true;
            break;
        }
    }
    if !any_usable_key {
        return Err(Reject::NoUsableKeys.into());
    }
    if !verified {
        return Err(Reject::Untrusted.into());
    }

    // 2. ONLY NOW compile the module — from the SAME bytes we verified.  No
    //    re-encode between verify and load (the "exact bytes" invariant).
    Module::from_binary(engine, wasm_bytes).map_err(|e| LoadError::Wasm(e.to_string()))
}

/// A load failure: either the trust gate rejected it, or the (trusted) module
/// itself failed to compile/instantiate.  Keeping these distinct matters — a
/// `Reject` is a *security* outcome; a `Wasm` error is an author bug in an
/// already-trusted module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    Reject(Reject),
    Wasm(String),
}
impl From<Reject> for LoadError {
    fn from(r: Reject) -> Self {
        LoadError::Reject(r)
    }
}
impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Reject(r) => write!(f, "REJECTED: {r}"),
            LoadError::Wasm(e) => write!(f, "wasm load error: {e}"),
        }
    }
}
impl std::error::Error for LoadError {}

/// A loaded, instantiated plugin: the embedder that drives the six exports
/// over the (ptr,len)->(ptr,len) byte-buffer ABI (DESIGN.md § E1).
pub struct PluginInstance {
    store: Store<()>,
    memory: Memory,
    alloc: TypedFunc<u32, u32>,
    dealloc: TypedFunc<(u32, u32), ()>,
    initial_state: TypedFunc<(), u64>,
    apply_op: TypedFunc<(u32, u32, u32, u32), u64>,
    make_op: TypedFunc<(u32, u32, u32, u32), u64>,
    render: TypedFunc<(u32, u32), u64>,
    snapshot: TypedFunc<(u32, u32), u64>,
    load_snapshot: TypedFunc<(u32, u32), u64>,
}

impl PluginInstance {
    /// Instantiate a verified module and bind its six ABI exports + the
    /// alloc/dealloc/memory the host drives.  Errors if any export is missing
    /// or has the wrong signature — a module that passed the gate but doesn't
    /// implement the ABI is an author bug, not a trust failure.
    pub fn new(engine: &Engine, module: &Module) -> Result<Self, String> {
        let mut store = Store::new(engine, ());
        let instance =
            Instance::new(&mut store, module, &[]).map_err(|e| format!("instantiate: {e}"))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or("plugin exports no `memory`")?;
        macro_rules! func {
            ($name:literal, $params:ty, $ret:ty) => {
                instance
                    .get_typed_func::<$params, $ret>(&mut store, $name)
                    .map_err(|e| format!("export `{}`: {e}", $name))?
            };
        }
        Ok(Self {
            alloc: func!("plugin_alloc", u32, u32),
            dealloc: func!("plugin_dealloc", (u32, u32), ()),
            initial_state: func!("initial_state", (), u64),
            apply_op: func!("apply_op", (u32, u32, u32, u32), u64),
            make_op: func!("make_op", (u32, u32, u32, u32), u64),
            render: func!("render", (u32, u32), u64),
            snapshot: func!("snapshot", (u32, u32), u64),
            load_snapshot: func!("load_snapshot", (u32, u32), u64),
            memory,
            store,
        })
    }

    /// Copy `bytes` into a fresh wasm buffer; returns its (ptr,len).
    fn host_to_wasm(&mut self, bytes: &[u8]) -> Result<(u32, u32), String> {
        let len = bytes.len() as u32;
        let ptr = self
            .alloc
            .call(&mut self.store, len)
            .map_err(|e| format!("plugin_alloc: {e}"))?;
        self.memory
            .write(&mut self.store, ptr as usize, bytes)
            .map_err(|e| format!("memory write: {e}"))?;
        Ok((ptr, len))
    }

    /// Unpack an export's `(ptr<<32)|len` return, copy the bytes out, and free
    /// the wasm-side buffer.
    fn wasm_to_host(&mut self, packed: u64) -> Result<Vec<u8>, String> {
        let ptr = (packed >> 32) as u32;
        let len = (packed & 0xFFFF_FFFF) as u32;
        let mut out = vec![0u8; len as usize];
        if len != 0 {
            self.memory
                .read(&self.store, ptr as usize, &mut out)
                .map_err(|e| format!("memory read: {e}"))?;
        }
        self.dealloc
            .call(&mut self.store, (ptr, len))
            .map_err(|e| format!("plugin_dealloc: {e}"))?;
        Ok(out)
    }

    // --- the six ABI calls ---

    pub fn initial_state(&mut self) -> Result<Vec<u8>, String> {
        let packed = self
            .initial_state
            .call(&mut self.store, ())
            .map_err(|e| format!("initial_state: {e}"))?;
        self.wasm_to_host(packed)
    }

    pub fn apply_op(&mut self, state: &[u8], op: &[u8]) -> Result<Vec<u8>, String> {
        let (sp, sl) = self.host_to_wasm(state)?;
        let (op_p, op_l) = self.host_to_wasm(op)?;
        let packed = self
            .apply_op
            .call(&mut self.store, (sp, sl, op_p, op_l))
            .map_err(|e| format!("apply_op: {e}"))?;
        // free the two input buffers we handed in
        self.dealloc.call(&mut self.store, (sp, sl)).ok();
        self.dealloc.call(&mut self.store, (op_p, op_l)).ok();
        self.wasm_to_host(packed)
    }

    pub fn make_op(&mut self, state: &[u8], action: &[u8]) -> Result<Vec<u8>, String> {
        let (sp, sl) = self.host_to_wasm(state)?;
        let (ap, al) = self.host_to_wasm(action)?;
        let packed = self
            .make_op
            .call(&mut self.store, (sp, sl, ap, al))
            .map_err(|e| format!("make_op: {e}"))?;
        self.dealloc.call(&mut self.store, (sp, sl)).ok();
        self.dealloc.call(&mut self.store, (ap, al)).ok();
        self.wasm_to_host(packed)
    }

    pub fn render(&mut self, state: &[u8]) -> Result<Vec<u8>, String> {
        let (sp, sl) = self.host_to_wasm(state)?;
        let packed = self
            .render
            .call(&mut self.store, (sp, sl))
            .map_err(|e| format!("render: {e}"))?;
        self.dealloc.call(&mut self.store, (sp, sl)).ok();
        self.wasm_to_host(packed)
    }

    pub fn snapshot(&mut self, state: &[u8]) -> Result<Vec<u8>, String> {
        let (sp, sl) = self.host_to_wasm(state)?;
        let packed = self
            .snapshot
            .call(&mut self.store, (sp, sl))
            .map_err(|e| format!("snapshot: {e}"))?;
        self.dealloc.call(&mut self.store, (sp, sl)).ok();
        self.wasm_to_host(packed)
    }

    pub fn load_snapshot(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let (bp, bl) = self.host_to_wasm(bytes)?;
        let packed = self
            .load_snapshot
            .call(&mut self.store, (bp, bl))
            .map_err(|e| format!("load_snapshot: {e}"))?;
        self.dealloc.call(&mut self.store, (bp, bl)).ok();
        self.wasm_to_host(packed)
    }
}

/// Parse a hex string (64 chars) into a 32-byte raw Ed25519 public key.
pub fn hex_to_key(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", hex.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("bad hex at {i}: {e}"))?;
    }
    Ok(out)
}
