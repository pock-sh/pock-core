# pock-core

Zero-knowledge crypto core for Pock. One Rust crate, compiled native (for the
CLI / Tauri) and to WebAssembly (for the web app / browser extension). The
server only ever sees ciphertext, public keys, and wrapped key blobs.

Design + decisions: `../docs/superpowers/specs/2026-06-30-pock-crypto-core-design.md`.

## Crypto stack (Phase 0)

| Concern | Choice |
| --- | --- |
| KDF | Argon2id (Native / Constrained profiles) + HKDF-SHA256 |
| Master key | random 256-bit AUK, multi-wrapped (2SKD passphrase + raw KEKs) |
| AEAD | XChaCha20-Poly1305 (24-byte random nonce) |
| KEM | X-Wing (X25519 + ML-KEM-768), isolated behind `kem.rs` |
| Multi-recipient | HPKE base-mode wrap (KEM encap -> HKDF -> AEAD) |
| Signatures / identity | Ed25519 |

Every versioned artifact carries `v: 1` and rejects unknown versions on parse.
Secret intermediates are zeroized on drop.

## Modules

`error` · `aead` · `kdf` · `sign` · `kem` · `identity` · `envelope` · `item`
(per-item DEK, per-recipient wraps, `grant`) · `auk` (multi-wrap unlock) ·
`wasm` (feature-gated bindings).

## Build & test

```sh
# Native
cargo test                  # full suite
cargo clippy --all-targets  # lints

# WebAssembly
cargo build --target wasm32-unknown-unknown --features wasm
wasm-pack build --target web --features wasm   # emits ./pkg

# WASM tests: the repo-root package.json is "type": "module", which makes
# wasm-pack's CommonJS test glue fail under Node when written inside the repo
# tree. Point TMPDIR outside the tree:
TMPDIR=/tmp/wasmtmp wasm-pack test --node --features wasm
```

## getrandom on wasm32

Two getrandom majors are in the tree and both need a wasm backend:
- `getrandom 0.2` (this crate + `rand_core 0.6`) -> the `js` feature, enabled by
  this crate's `wasm` feature (`getrandom/js`).
- `getrandom 0.4` (via `x-wing` -> `rand_core 0.10`) -> the `wasm_js` feature
  (the `getrandom_v04` alias dep, wasm32-only) plus the
  `--cfg getrandom_backend="wasm_js"` rustflag in `.cargo/config.toml`.

## Status

Phase 0 (this crate) is complete and reviewed. Not yet wired into the CLI or web
app; that is Phase 1. `x-wing` is a pre-release dependency pinned via
`Cargo.lock` — track it for API churn before any GA.
