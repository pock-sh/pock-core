//! wasm-bindgen adapters. Every function here is a one-line delegation to
//! `crate::flows`; all logic lives there so the wasm, UniFFI and native
//! surfaces stay byte-for-byte identical.

use wasm_bindgen::prelude::*;

// Re-exported so `pock_core::wasm::GeneratedIdentity` keeps working.
pub use crate::flows::GeneratedIdentity;

// On wasm32 we depend on getrandom 0.4 (via x-wing -> rand_core 0.10) with its
// `wasm_js` backend. The renamed `getrandom_v04` dependency in Cargo.toml turns
// on that feature; reference it here so the dependency is never pruned.
#[cfg(target_arch = "wasm32")]
#[allow(unused_imports)]
use getrandom_v04 as _;

fn js(e: crate::error::CoreError) -> JsError {
    JsError::new(&e.to_string())
}

#[wasm_bindgen]
pub fn wasm_generate_identity() -> String {
    crate::flows::generate_identity()
}

#[wasm_bindgen]
pub fn wasm_encrypt_item(value: &str, recipient_pub_blobs_json: &str) -> Result<String, JsError> {
    crate::flows::encrypt_item(value, recipient_pub_blobs_json).map_err(js)
}

#[wasm_bindgen]
pub fn wasm_decrypt_item(item_json: &str, identity_secret_b64: &str) -> Result<String, JsError> {
    crate::flows::decrypt_item(item_json, identity_secret_b64).map_err(js)
}

#[wasm_bindgen]
pub fn wasm_encrypt_share(bundle_json: &str, cipher_id: &str) -> Result<String, JsError> {
    crate::flows::encrypt_share(bundle_json, cipher_id).map_err(js)
}

#[wasm_bindgen]
pub fn wasm_decrypt_share(envelope_b64: &str, key_blob: &str) -> Result<String, JsError> {
    crate::flows::decrypt_share(envelope_b64, key_blob).map_err(js)
}

#[wasm_bindgen]
pub fn wasm_create_vault(passphrase: &str) -> Result<String, JsError> {
    crate::flows::create_vault(passphrase).map_err(js)
}

#[wasm_bindgen]
pub fn wasm_unlock_vault(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    wrapped_identity_b64: &str,
) -> Result<String, JsError> {
    crate::flows::unlock_vault(passphrase, secret_key_b64, wrapped_auk_json, wrapped_identity_b64).map_err(js)
}

/// Unlock using ONLY the recovery code (a single high-entropy factor). No passphrase or
/// Secret Key needed — this is the "I forgot my passphrase" path.
#[wasm_bindgen]
pub fn wasm_unlock_recovery(
    recovery_code: &str,
    wrapped_recovery_json: &str,
    wrapped_identity_b64: &str,
) -> Result<String, JsError> {
    crate::flows::unlock_recovery(recovery_code, wrapped_recovery_json, wrapped_identity_b64).map_err(js)
}

/// After a recovery unlock, re-wrap the AUK under a NEW passphrase (+ the Secret Key), so
/// the user can set a passphrase they'll remember. Returns the new wrappedAukPassphrase to
/// register server-side. The identity keypair itself is unchanged.
#[wasm_bindgen]
pub fn wasm_reset_passphrase(
    recovery_code: &str,
    wrapped_recovery_json: &str,
    secret_key_b64: &str,
    new_passphrase: &str,
) -> Result<String, JsError> {
    crate::flows::reset_passphrase(recovery_code, wrapped_recovery_json, secret_key_b64, new_passphrase)
        .map_err(js)
}

/// Random 32-byte XChaCha20-Poly1305 key, base64. Used as a chat channel key
/// or a per-attachment blob key.
#[wasm_bindgen]
pub fn wasm_generate_symmetric_key() -> String {
    crate::flows::generate_symmetric_key()
}

/// Symmetric AEAD seal: returns nonce||ciphertext. `aad` binds context (e.g.
/// `channel_id|key_version|sender_id`) into the tag without being stored.
#[wasm_bindgen]
pub fn wasm_seal_symmetric(key_b64: &str, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    crate::flows::seal_symmetric(key_b64, plaintext, aad).map_err(js)
}

#[wasm_bindgen]
pub fn wasm_open_symmetric(key_b64: &str, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    crate::flows::open_symmetric(key_b64, blob, aad).map_err(js)
}

/// Ed25519 signature over `msg` with the identity's signing key, base64.
#[wasm_bindgen]
pub fn wasm_sign_message(identity_secret_b64: &str, msg: &[u8]) -> Result<String, JsError> {
    crate::flows::sign_message(identity_secret_b64, msg).map_err(js)
}

#[wasm_bindgen]
pub fn wasm_verify_message(sign_pubkey_b64: &str, msg: &[u8], sig_b64: &str) -> Result<bool, JsError> {
    crate::flows::verify_message(sign_pubkey_b64, msg, sig_b64).map_err(js)
}

/// Change the passphrase while unlocked (old passphrase known). The AUK,
/// identity, recovery code, and passkeys are all unchanged — this only
/// re-wraps the AUK under the new passphrase + same Secret Key.
#[wasm_bindgen]
pub fn wasm_change_passphrase(
    old_passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    new_passphrase: &str,
) -> Result<String, JsError> {
    crate::flows::change_passphrase(old_passphrase, secret_key_b64, wrapped_auk_json, new_passphrase)
        .map_err(js)
}

/// Rotate the Secret Key (the "have" factor). Mints a fresh 16-byte key and
/// re-wraps the AUK under passphrase + new key. Recovery and passkey wraps
/// are KEK-based and unaffected.
#[wasm_bindgen]
pub fn wasm_rotate_secret_key(
    passphrase: &str,
    old_secret_key_b64: &str,
    wrapped_auk_json: &str,
) -> Result<String, JsError> {
    crate::flows::rotate_secret_key(passphrase, old_secret_key_b64, wrapped_auk_json).map_err(js)
}

/// Regenerate the recovery code. Mints a fresh high-entropy code and wraps
/// the AUK under its derived KEK; the old code stops working once the server
/// replaces the stored recovery wrap.
#[wasm_bindgen]
pub fn wasm_rotate_recovery_code(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
) -> Result<String, JsError> {
    crate::flows::rotate_recovery_code(passphrase, secret_key_b64, wrapped_auk_json).map_err(js)
}

/// Deep rotation: mint a brand-new identity keypair wrapped under the same
/// AUK. The caller must re-encrypt every item to the new public identity and
/// re-register pubkeys server-side; until then old blobs still need the old
/// secret (also returned).
#[wasm_bindgen]
pub fn wasm_rotate_identity(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    old_wrapped_identity_b64: &str,
) -> Result<String, JsError> {
    crate::flows::rotate_identity(passphrase, secret_key_b64, wrapped_auk_json, old_wrapped_identity_b64)
        .map_err(js)
}

/// Encrypted binary vault backup (.pockvault). Standalone: only the backup
/// passphrase is needed to restore.
#[wasm_bindgen]
pub fn wasm_export_backup(json: &str, passphrase: &str) -> Result<Vec<u8>, JsError> {
    crate::flows::export_backup(json, passphrase).map_err(js)
}

#[wasm_bindgen]
pub fn wasm_import_backup(data: &[u8], passphrase: &str) -> Result<String, JsError> {
    crate::flows::import_backup(data, passphrase).map_err(js)
}

#[wasm_bindgen]
pub fn wasm_enroll_prf(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    prf_secret_b64: &str,
) -> Result<String, JsError> {
    crate::flows::enroll_prf(passphrase, secret_key_b64, wrapped_auk_json, prf_secret_b64).map_err(js)
}

#[wasm_bindgen]
pub fn wasm_unlock_prf(
    prf_secret_b64: &str,
    wrapped_auk_prf_json: &str,
    wrapped_identity_b64: &str,
) -> Result<String, JsError> {
    crate::flows::unlock_prf(prf_secret_b64, wrapped_auk_prf_json, wrapped_identity_b64).map_err(js)
}

// ---- Account Master Key (AMK) -------------------------------------------------
//
// See `crate::flows` for how the AMK is sealed under the AUK and why the AUK
// never crosses the binding boundary.

/// Create-or-load the Account Master Key (Ed25519) sealed under the AUK
/// (passphrase path). Returns JSON `{ "amkPub": b64, "wrappedAmk": b64 }`.
#[wasm_bindgen]
pub fn wasm_amk_ensure(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    existing_wrapped_amk: &str,
) -> Result<String, JsError> {
    crate::flows::amk_ensure(passphrase, secret_key_b64, wrapped_auk_json, existing_wrapped_amk).map_err(js)
}

/// Sign `msg` with the AMK (unsealed under the AUK, passphrase path). Returns
/// base64 Ed25519 signature.
#[wasm_bindgen]
pub fn wasm_amk_sign(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    wrapped_amk: &str,
    msg: &[u8],
) -> Result<String, JsError> {
    crate::flows::amk_sign(passphrase, secret_key_b64, wrapped_auk_json, wrapped_amk, msg).map_err(js)
}

/// Create-or-load the AMK sealed under the AUK (PRF / passkey path).
#[wasm_bindgen]
pub fn wasm_amk_ensure_prf(
    prf_secret_b64: &str,
    wrapped_auk_prf_json: &str,
    existing_wrapped_amk: &str,
) -> Result<String, JsError> {
    crate::flows::amk_ensure_prf(prf_secret_b64, wrapped_auk_prf_json, existing_wrapped_amk).map_err(js)
}

/// Sign `msg` with the AMK (unsealed under the AUK, PRF / passkey path).
#[wasm_bindgen]
pub fn wasm_amk_sign_prf(
    prf_secret_b64: &str,
    wrapped_auk_prf_json: &str,
    wrapped_amk: &str,
    msg: &[u8],
) -> Result<String, JsError> {
    crate::flows::amk_sign_prf(prf_secret_b64, wrapped_auk_prf_json, wrapped_amk, msg).map_err(js)
}
