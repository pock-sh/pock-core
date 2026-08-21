//! UniFFI (Swift / Kotlin) surface for `crate::flows`.
//!
//! This module is a pure adapter: every function here forwards straight to the
//! identically-named function in [`crate::flows`] and converts the error type.
//! There is deliberately no logic, no I/O and no state — behaviour must stay
//! byte-for-byte identical to the wasm surface, which wraps the same flows.
//!
//! UniFFI passes owned values across the FFI boundary, so each wrapper takes
//! `String` / `Vec<u8>` and re-borrows them for the `&str` / `&[u8]` flow.
//! Swift sees camelCase names: `createVault(passphrase:)`, `sealSymmetric(...)`.

use crate::error::CoreError;
use crate::flows;

/// The error Swift sees. Variants are coarse *categories* so a caller can
/// branch on "the user typed the wrong secret" versus "the caller passed
/// garbage" without string-matching. `message` is always the unchanged
/// `Display` text of the underlying [`CoreError`], so existing user-facing
/// strings survive verbatim.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PockCoreError {
    /// Wrong passphrase, wrong recovery code, wrong Secret Key, or an unlock
    /// that failed because the supplied credential could not open the wrapper.
    #[error("{message}")]
    WrongCredential { message: String },
    /// The caller supplied a structurally invalid argument.
    #[error("{message}")]
    InvalidInput { message: String },
    /// A JSON payload could not be parsed or serialised.
    #[error("{message}")]
    Json { message: String },
    /// A base64 (or other encoding) payload could not be decoded.
    #[error("{message}")]
    Encoding { message: String },
    /// Anything else — cryptographic primitive failures that are not a wrong
    /// credential (KDF, KEM, signature verification).
    #[error("{message}")]
    Other { message: String },
}

/// True when a flow-level message means "the credential the user supplied was
/// wrong", as opposed to "the input was malformed".
fn reads_as_wrong_credential(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("wrong ") || lower.contains("unlock failed")
}

impl From<CoreError> for PockCoreError {
    fn from(e: CoreError) -> Self {
        let message = e.to_string();
        // Every variant is listed explicitly: adding a variant to `CoreError`
        // must be a compile error here, not a silent fall-through to `Other`.
        match e {
            // AEAD only ever fails on the open side, and only when the key is
            // wrong or the ciphertext was tampered with.
            CoreError::Aead => PockCoreError::WrongCredential { message },
            CoreError::WrongKey => PockCoreError::WrongCredential { message },
            CoreError::Decode(_) => PockCoreError::Encoding { message },
            CoreError::Encoding(_) => PockCoreError::Encoding { message },
            CoreError::Json(_) => PockCoreError::Json { message },
            CoreError::InvalidInput(_) => PockCoreError::InvalidInput { message },
            CoreError::Kdf(_) => PockCoreError::Other { message },
            CoreError::Kem => PockCoreError::Other { message },
            CoreError::Signature => PockCoreError::Other { message },
            CoreError::Flow(ref s) => {
                if reads_as_wrong_credential(s) {
                    PockCoreError::WrongCredential { message }
                } else {
                    PockCoreError::InvalidInput { message }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Identity + item/share encryption
// ---------------------------------------------------------------------------

#[uniffi::export]
pub fn generate_identity() -> String {
    flows::generate_identity()
}

#[uniffi::export]
pub fn encrypt_item(
    value: String,
    recipient_pub_blobs_json: String,
) -> Result<String, PockCoreError> {
    flows::encrypt_item(&value, &recipient_pub_blobs_json).map_err(Into::into)
}

#[uniffi::export]
pub fn decrypt_item(
    item_json: String,
    identity_secret_b64: String,
) -> Result<String, PockCoreError> {
    flows::decrypt_item(&item_json, &identity_secret_b64).map_err(Into::into)
}

#[uniffi::export]
pub fn encrypt_share(bundle_json: String, cipher_id: String) -> Result<String, PockCoreError> {
    flows::encrypt_share(&bundle_json, &cipher_id).map_err(Into::into)
}

#[uniffi::export]
pub fn decrypt_share(envelope_b64: String, key_blob: String) -> Result<String, PockCoreError> {
    flows::decrypt_share(&envelope_b64, &key_blob).map_err(Into::into)
}

// ---------------------------------------------------------------------------
// Vault lifecycle
// ---------------------------------------------------------------------------

#[uniffi::export]
pub fn create_vault(passphrase: String) -> Result<String, PockCoreError> {
    flows::create_vault(&passphrase).map_err(Into::into)
}

#[uniffi::export]
pub fn unlock_vault(
    passphrase: String,
    secret_key_b64: String,
    wrapped_auk_json: String,
    wrapped_identity_b64: String,
) -> Result<String, PockCoreError> {
    flows::unlock_vault(
        &passphrase,
        &secret_key_b64,
        &wrapped_auk_json,
        &wrapped_identity_b64,
    )
    .map_err(Into::into)
}

#[uniffi::export]
pub fn unlock_recovery(
    recovery_code: String,
    wrapped_recovery_json: String,
    wrapped_identity_b64: String,
) -> Result<String, PockCoreError> {
    flows::unlock_recovery(
        &recovery_code,
        &wrapped_recovery_json,
        &wrapped_identity_b64,
    )
    .map_err(Into::into)
}

#[uniffi::export]
pub fn reset_passphrase(
    recovery_code: String,
    wrapped_recovery_json: String,
    secret_key_b64: String,
    new_passphrase: String,
) -> Result<String, PockCoreError> {
    flows::reset_passphrase(
        &recovery_code,
        &wrapped_recovery_json,
        &secret_key_b64,
        &new_passphrase,
    )
    .map_err(Into::into)
}

#[uniffi::export]
pub fn change_passphrase(
    old_passphrase: String,
    secret_key_b64: String,
    wrapped_auk_json: String,
    new_passphrase: String,
) -> Result<String, PockCoreError> {
    flows::change_passphrase(
        &old_passphrase,
        &secret_key_b64,
        &wrapped_auk_json,
        &new_passphrase,
    )
    .map_err(Into::into)
}

#[uniffi::export]
pub fn rotate_secret_key(
    passphrase: String,
    old_secret_key_b64: String,
    wrapped_auk_json: String,
) -> Result<String, PockCoreError> {
    flows::rotate_secret_key(&passphrase, &old_secret_key_b64, &wrapped_auk_json)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn rotate_recovery_code(
    passphrase: String,
    secret_key_b64: String,
    wrapped_auk_json: String,
) -> Result<String, PockCoreError> {
    flows::rotate_recovery_code(&passphrase, &secret_key_b64, &wrapped_auk_json)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn rotate_identity(
    passphrase: String,
    secret_key_b64: String,
    wrapped_auk_json: String,
    old_wrapped_identity_b64: String,
) -> Result<String, PockCoreError> {
    flows::rotate_identity(
        &passphrase,
        &secret_key_b64,
        &wrapped_auk_json,
        &old_wrapped_identity_b64,
    )
    .map_err(Into::into)
}

// ---------------------------------------------------------------------------
// Symmetric AEAD + signatures
// ---------------------------------------------------------------------------

#[uniffi::export]
pub fn generate_symmetric_key() -> String {
    flows::generate_symmetric_key()
}

#[uniffi::export]
pub fn seal_symmetric(
    key_b64: String,
    plaintext: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>, PockCoreError> {
    flows::seal_symmetric(&key_b64, &plaintext, &aad).map_err(Into::into)
}

#[uniffi::export]
pub fn open_symmetric(
    key_b64: String,
    blob: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>, PockCoreError> {
    flows::open_symmetric(&key_b64, &blob, &aad).map_err(Into::into)
}

#[uniffi::export]
pub fn sign_message(identity_secret_b64: String, msg: Vec<u8>) -> Result<String, PockCoreError> {
    flows::sign_message(&identity_secret_b64, &msg).map_err(Into::into)
}

#[uniffi::export]
pub fn verify_message(
    sign_pubkey_b64: String,
    msg: Vec<u8>,
    sig_b64: String,
) -> Result<bool, PockCoreError> {
    flows::verify_message(&sign_pubkey_b64, &msg, &sig_b64).map_err(Into::into)
}

// ---------------------------------------------------------------------------
// Backup
// ---------------------------------------------------------------------------

#[uniffi::export]
pub fn export_backup(json: String, passphrase: String) -> Result<Vec<u8>, PockCoreError> {
    flows::export_backup(&json, &passphrase).map_err(Into::into)
}

#[uniffi::export]
pub fn import_backup(data: Vec<u8>, passphrase: String) -> Result<String, PockCoreError> {
    flows::import_backup(&data, &passphrase).map_err(Into::into)
}

// ---------------------------------------------------------------------------
// Platform authenticator (PRF / Touch ID)
// ---------------------------------------------------------------------------

#[uniffi::export]
pub fn enroll_prf(
    passphrase: String,
    secret_key_b64: String,
    wrapped_auk_json: String,
    prf_secret_b64: String,
) -> Result<String, PockCoreError> {
    flows::enroll_prf(
        &passphrase,
        &secret_key_b64,
        &wrapped_auk_json,
        &prf_secret_b64,
    )
    .map_err(Into::into)
}

#[uniffi::export]
pub fn unlock_prf(
    prf_secret_b64: String,
    wrapped_auk_prf_json: String,
    wrapped_identity_b64: String,
) -> Result<String, PockCoreError> {
    flows::unlock_prf(
        &prf_secret_b64,
        &wrapped_auk_prf_json,
        &wrapped_identity_b64,
    )
    .map_err(Into::into)
}

// ---------------------------------------------------------------------------
// Account master key (AMK)
// ---------------------------------------------------------------------------

#[uniffi::export]
pub fn amk_ensure(
    passphrase: String,
    secret_key_b64: String,
    wrapped_auk_json: String,
    existing_wrapped_amk: String,
) -> Result<String, PockCoreError> {
    flows::amk_ensure(
        &passphrase,
        &secret_key_b64,
        &wrapped_auk_json,
        &existing_wrapped_amk,
    )
    .map_err(Into::into)
}

#[uniffi::export]
pub fn amk_sign(
    passphrase: String,
    secret_key_b64: String,
    wrapped_auk_json: String,
    wrapped_amk: String,
    msg: Vec<u8>,
) -> Result<String, PockCoreError> {
    flows::amk_sign(
        &passphrase,
        &secret_key_b64,
        &wrapped_auk_json,
        &wrapped_amk,
        &msg,
    )
    .map_err(Into::into)
}

#[uniffi::export]
pub fn amk_ensure_prf(
    prf_secret_b64: String,
    wrapped_auk_prf_json: String,
    existing_wrapped_amk: String,
) -> Result<String, PockCoreError> {
    flows::amk_ensure_prf(
        &prf_secret_b64,
        &wrapped_auk_prf_json,
        &existing_wrapped_amk,
    )
    .map_err(Into::into)
}

#[uniffi::export]
pub fn amk_sign_prf(
    prf_secret_b64: String,
    wrapped_auk_prf_json: String,
    wrapped_amk: String,
    msg: Vec<u8>,
) -> Result<String, PockCoreError> {
    flows::amk_sign_prf(
        &prf_secret_b64,
        &wrapped_auk_prf_json,
        &wrapped_amk,
        &msg,
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_passphrase_maps_to_wrong_credential() {
        let created = flows::create_vault("right passphrase").unwrap();
        let v: serde_json::Value = serde_json::from_str(&created).unwrap();
        let secret_key = v["secretKey"].as_str().unwrap().to_string();
        let wrapped_auk = v["wrappedAukPassphrase"].to_string();
        let wrapped_identity = v["wrappedIdentity"].as_str().unwrap().to_string();

        let err = unlock_vault(
            "wrong passphrase".into(),
            secret_key,
            wrapped_auk,
            wrapped_identity,
        )
        .unwrap_err();

        match err {
            PockCoreError::WrongCredential { ref message } => {
                assert_eq!(message, "wrong passphrase or secret key");
            }
            other => panic!("expected WrongCredential, got {other:?}"),
        }
    }

    #[test]
    fn bad_base64_maps_to_encoding() {
        let err = seal_symmetric("!!! not base64 !!!".into(), vec![1, 2, 3], vec![])
            .unwrap_err();
        assert!(
            matches!(err, PockCoreError::Encoding { .. }),
            "expected Encoding, got {err:?}"
        );
    }

    #[test]
    fn malformed_json_maps_to_json() {
        let err = encrypt_item("secret".into(), "{ not json".into()).unwrap_err();
        assert!(
            matches!(err, PockCoreError::Json { .. }),
            "expected Json, got {err:?}"
        );
    }

    #[test]
    fn message_is_the_underlying_display_text_unchanged() {
        let source = CoreError::InvalidInput("nope".into());
        let expected = source.to_string();
        let mapped: PockCoreError = source.into();
        match mapped {
            PockCoreError::InvalidInput { message } => assert_eq!(message, expected),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn every_core_error_variant_maps_to_a_category() {
        let cases: Vec<(CoreError, &str)> = vec![
            (CoreError::Aead, "WrongCredential"),
            (CoreError::Kdf("x".into()), "Other"),
            (CoreError::Kem, "Other"),
            (CoreError::Signature, "Other"),
            (CoreError::Decode("x".into()), "Encoding"),
            (CoreError::WrongKey, "WrongCredential"),
            (CoreError::InvalidInput("x".into()), "InvalidInput"),
            (CoreError::Json("x".into()), "Json"),
            (CoreError::Encoding("x".into()), "Encoding"),
            (
                CoreError::Flow("wrong recovery code".into()),
                "WrongCredential",
            ),
            (
                CoreError::Flow("touch id unlock failed".into()),
                "WrongCredential",
            ),
            (CoreError::Flow("unknown cipher id".into()), "InvalidInput"),
        ];
        for (source, want) in cases {
            let rendered = source.to_string();
            let got = match PockCoreError::from(source) {
                PockCoreError::WrongCredential { .. } => "WrongCredential",
                PockCoreError::InvalidInput { .. } => "InvalidInput",
                PockCoreError::Json { .. } => "Json",
                PockCoreError::Encoding { .. } => "Encoding",
                PockCoreError::Other { .. } => "Other",
            };
            assert_eq!(got, want, "mapping for {rendered:?}");
        }
    }
}
