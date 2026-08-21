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
pub mod flows;

#[cfg(feature = "wasm")]
pub mod wasm;

// `uniffi` and `wasm` are orthogonal: never enable both in one build.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
pub mod uniffi_api;
