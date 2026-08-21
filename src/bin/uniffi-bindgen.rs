//! Bindings generator entry point.
//!
//! Built only with `--features uniffi-cli`; it is never part of the shipped
//! library. Usage:
//!
//! ```text
//! cargo run --features uniffi-cli --bin uniffi-bindgen -- \
//!     generate --library target/release/libpock_core.dylib \
//!     --language swift --out-dir target/swift-bindings
//! ```
fn main() {
    uniffi::uniffi_bindgen_main()
}
