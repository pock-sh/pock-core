//! pock-core: zero-knowledge crypto primitives shared by every Pock surface.
pub mod error;
pub mod aead;
pub mod kdf;
pub mod sign;
pub mod kem;
pub mod identity;
pub mod envelope;
pub mod item;
pub mod auk;
pub mod backup;
pub mod share;
/// `pns1.` namespace protection (PBKDF2 + AES-GCM, standard base64).
pub mod nscrypto;
/// Key-transparency canonical byte encodings and k-of-n cert verification.
pub mod keylog;
pub mod flows;

#[cfg(feature = "wasm")]
pub mod wasm;

// `uniffi` and `wasm` are orthogonal: never enable both in one build.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
pub mod uniffi_api;
