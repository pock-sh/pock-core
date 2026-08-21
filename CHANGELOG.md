# Changelog

## 0.3.0

Adds the pure flows that previously existed only in the monorepo's TypeScript,
so every surface — browser, CLI, desktop, Swift — computes them identically.

- Added `nscrypto`, the `pns1.` namespace-protection layer: PBKDF2-HMAC-SHA256
  (600,000 iterations) wrapping a random namespace key, AES-GCM-256 per value,
  and **standard** base64 throughout. Wire-identical to
  `app/lib/namespace-crypto.ts`, pinned by a vector that implementation
  produced.
- Added `keylog`, the key-transparency canonical byte encodings — `Rot` /
  `canonical_rot`, `leaf_bytes`, `sth_message`, `cert_bytes`, the RFC-6962
  `hash_leaf` / `hash_children`, and k-of-n `verify_cert`. Byte-identical to
  `app/lib/key-log.ts`, `chat-app/worker/keycert.ts` and
  `chat-app/src/lib/keytrust.ts`. `verify_cert` accepts both base64 dialects and
  verifies **non-strictly**, matching the `@noble/curves` verifier that produced
  every certificate already in the log.
- Added `flows::message_digest` — `SHA-256(aad ‖ ct)`, the bytes a chat message
  signature covers.
- Added `flows::create_vault_profile`, so a native surface can mint with the
  heavier Argon2 profile. `create_vault` is now `create_vault_profile(p,
  "constrained")` and is unchanged in behaviour.
- Added `flows::ns_*`, `cert_bytes_json`, `leaf_bytes_json`, `sth_message_json`
  and `verify_cert_json`, mirrored on both the wasm and UniFFI surfaces. The
  namespace key crosses a binding boundary only as standard base64, never as
  raw bytes.
- `WRONG_CREDENTIAL_MESSAGES` moved from the UniFFI adapter to `error` and is
  now public, so downstream crates classify against one table instead of a
  drifting copy. It gains `"wrong namespace passphrase"`.

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
