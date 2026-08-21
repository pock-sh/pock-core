# Changelog

## 0.2.0

First standalone release, extracted from the Pock monorepo.

- Added `flows`, a binding-independent module holding the composed crypto
  operations. The WebAssembly and UniFFI surfaces are now thin adapters over it,
  so every binding produces byte-identical output.
- Added the `uniffi` feature and a Swift package, `PockCore`, distributed as a
  `PockCoreFFI.xcframework` binary target pinned by checksum on each release
  tag.
- Added `scripts/pack-wasm.sh`, which packs the WebAssembly build as the npm
  package `@pock-sh/pock-core`.
- Added CI and a tag-driven release workflow that builds and attaches the
  XCFramework zip, its SHA-256, and the npm tarball.
- Added README, SECURITY policy, and MIT license for the public repository.

## 0.1.0

Initial in-monorepo version. Argon2id and HKDF-SHA256 key derivation,
XChaCha20-Poly1305 AEAD, X-Wing (X25519 + ML-KEM-768) hybrid KEM, Ed25519
signatures, and the envelope, item, share bundle, and wrapped AUK formats.
