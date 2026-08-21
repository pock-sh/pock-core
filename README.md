# pock-core

The cryptography behind [Pock](https://pock.sh), in one Rust crate. It holds the
key derivation, the authenticated encryption, the hybrid key exchange, and the
serialised formats that Pock's clients read and write. Everything is offline and
side-effect free: no network, no storage, no key management policy. The same
crate compiles native for the CLI and desktop app, to WebAssembly for the web
app and browser extension, and to an XCFramework for iOS. A Pock server only
ever sees the outputs — ciphertext, public keys, and wrapped key blobs.

## Primitives

| Concern | Choice | Source |
| --- | --- | --- |
| Key exchange | X-Wing hybrid KEM (X25519 + ML-KEM-768) | `src/kem.rs` |
| Authenticated encryption | XChaCha20-Poly1305, 24-byte random nonce | `src/aead.rs` |
| Signatures | Ed25519 | `src/sign.rs` |
| Password hashing | Argon2id (Native and Constrained profiles) | `src/kdf.rs` |
| Key derivation | HKDF-SHA256 with domain-separated info strings | `src/kdf.rs` |

Every versioned artifact carries `v: 1` and rejects unknown versions on parse.
Secret intermediates are zeroized on drop. Binary output is base64
URL-safe without padding.

## Formats

- **Envelope** (`src/envelope.rs`) — a KEM ciphertext plus an AEAD blob, sealed
  to one recipient public key.
- **Encrypted item** (`src/item.rs`) — one ciphertext under a per-item DEK, with
  the DEK wrapped in an envelope once per recipient.
- **Share bundle** (`src/share.rs`) — a self-contained `PKEV` binary file
  carrying a set of named files, either symmetric (`xchacha`) or KEM-sealed
  (`xwing`).
- **Wrapped AUK** (`src/auk.rs`) — the account unlock key under one of several
  wraps: a two-secret passphrase derivation, or a raw KEK.

`src/flows.rs` composes those formats into the operations a client actually
calls (create and unlock a vault, rotate a key, encrypt an item, export a
backup). Every binding is a thin adapter over `flows`, so all three surfaces
produce byte-identical output.

## Bindings

**Rust**

```toml
[dependencies]
pock-core = { git = "https://github.com/pock-sh/pock-core", tag = "v0.3.0" }
```

A crates.io release will follow; until then pin the git tag.

**WebAssembly** — `scripts/pack-wasm.sh` builds the `wasm` feature with
`wasm-pack` and packs `@pock-sh/pock-core`. Each release attaches the tarball
(`pock-sh-pock-core-0.3.0.tgz`).

**Swift** — the `uniffi` feature generates a Swift wrapper over an XCFramework,
published as the `PockCore` package.

```swift
.package(url: "https://github.com/pock-sh/pock-core", from: "0.3.0")
```

```swift
.product(name: "PockCore", package: "pock-core")
```

Resolve a tagged version, not `main`. The generated Swift sources and the
pinned `binaryTarget` URL and checksum exist only on release tags; on `main`
they are build outputs and are gitignored, so `main` resolves to an empty
`PockCore` target.

The `wasm` and `uniffi` features are orthogonal and must never be enabled
together, so this crate has no working `--all-features` build.

## Building

```sh
cargo test                     # native suite
cargo test --features uniffi   # UniFFI surface

# WebAssembly: builds ./pkg and packs the npm tarball at the repo root
./scripts/pack-wasm.sh

# Swift: builds PockCoreFFI.xcframework and the wrapper in swift/Sources/PockCore
./scripts/build-xcframework.sh   # macOS with Xcode
```

WASM tests need `TMPDIR` outside the repo tree, because `wasm-pack`'s CommonJS
test glue fails under a `"type": "module"` package:

```sh
TMPDIR=/tmp/wasmtmp wasm-pack test --node --features wasm
```

### getrandom on wasm32

Two getrandom majors are in the tree and both need a wasm backend:

- `getrandom 0.2` (this crate and `rand_core 0.6`) takes the `js` feature,
  enabled by this crate's `wasm` feature.
- `getrandom 0.4` (via `x-wing` and `rand_core 0.10`) takes the `wasm_js`
  feature, enabled through the wasm32-only `getrandom_v04` alias dependency,
  plus the `--cfg getrandom_backend="wasm_js"` rustflag in `.cargo/config.toml`.

## Threat model

What Pock defends against, what it does not, and how the key and release
transparency logs work: <https://pock.sh/security>.

## Release transparency

Pock publishes a signed manifest of every shipped release into an append-only
Merkle log, so a tampered or targeted build leaves permanent public evidence.
The log and the endpoints for auditing it are described at
<https://pock.sh/security#tamper-evidence>.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md).

## Status

`x-wing` is a pre-release dependency pinned through `Cargo.lock`. Track it for
API churn before treating this crate as stable.

## License

MIT. See [LICENSE](LICENSE).
