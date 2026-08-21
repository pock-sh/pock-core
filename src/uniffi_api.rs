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
//!
//! **Zeroization.** The owned argument UniFFI hands us is a fresh copy of the
//! caller's secret, living in this crate's heap. Every parameter that carries
//! secret material — passphrases, Secret Keys, recovery codes, identity secrets,
//! symmetric keys, PRF outputs, and plaintext — is shadowed with
//! [`Zeroizing`] so that copy is wiped when the wrapper returns. Wrapped/sealed
//! blobs (`wrapped_auk_json`, `wrapped_identity_b64`, `wrapped_amk`, ciphertext,
//! public keys, signatures) are already encrypted or public and are left alone.

use crate::error::CoreError;
use crate::flows;
use zeroize::Zeroizing;

/// The exact [`CoreError::Flow`] messages that mean "the credential the user
/// supplied was wrong" (as opposed to "the caller passed something malformed").
///
/// These are literal strings constructed in `crate::flows`; matching them
/// exactly — rather than sniffing for substrings — keeps the classification
/// deterministic and means a reworded flow message shows up as a test failure
/// instead of silently changing category. Every other `Flow` message, including
/// the two `FromUtf8Error` pass-throughs in `flows`, is `InvalidInput`.
pub(crate) const WRONG_CREDENTIAL_MESSAGES: &[&str] = &[
    "wrong passphrase or secret key",
    "wrong recovery code",
    "wrong passphrase or corrupted backup",
    "decrypt failed (wrong key or tampered)",
    "touch id unlock failed",
];

/// The error Swift sees. Variants are coarse *categories* so a caller can
/// branch on "the user typed the wrong secret" versus "the caller passed
/// garbage" without string-matching. `message` is always the unchanged
/// `Display` text of the underlying [`CoreError`], so existing user-facing
/// strings survive verbatim.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PockCoreError {
    /// The supplied credential did not open the data.
    ///
    /// Covers a wrong passphrase, a wrong recovery code, a wrong Secret Key, a
    /// failed platform-authenticator (Touch ID / PRF) unlock — **and AEAD
    /// failures generally, which mean "wrong key *or* tampered ciphertext"**.
    /// AEAD carries no way to tell those two apart, so do not present this to a
    /// user as "wrong passphrase" unconditionally; on a decrypt path it may
    /// equally mean the stored blob was corrupted or modified. Inspect
    /// `message` for the specific wording when the distinction matters.
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
                if WRONG_CREDENTIAL_MESSAGES.contains(&s.as_str()) {
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
    let value = Zeroizing::new(value);
    flows::encrypt_item(&value, &recipient_pub_blobs_json).map_err(Into::into)
}

#[uniffi::export]
pub fn decrypt_item(
    item_json: String,
    identity_secret_b64: String,
) -> Result<String, PockCoreError> {
    let identity_secret_b64 = Zeroizing::new(identity_secret_b64);
    flows::decrypt_item(&item_json, &identity_secret_b64).map_err(Into::into)
}

#[uniffi::export]
pub fn encrypt_share(bundle_json: String, cipher_id: String) -> Result<String, PockCoreError> {
    let bundle_json = Zeroizing::new(bundle_json);
    flows::encrypt_share(&bundle_json, &cipher_id).map_err(Into::into)
}

#[uniffi::export]
pub fn decrypt_share(envelope_b64: String, key_blob: String) -> Result<String, PockCoreError> {
    let key_blob = Zeroizing::new(key_blob);
    flows::decrypt_share(&envelope_b64, &key_blob).map_err(Into::into)
}

// ---------------------------------------------------------------------------
// Vault lifecycle
// ---------------------------------------------------------------------------

#[uniffi::export]
pub fn create_vault(passphrase: String) -> Result<String, PockCoreError> {
    let passphrase = Zeroizing::new(passphrase);
    flows::create_vault(&passphrase).map_err(Into::into)
}

#[uniffi::export]
pub fn unlock_vault(
    passphrase: String,
    secret_key_b64: String,
    wrapped_auk_json: String,
    wrapped_identity_b64: String,
) -> Result<String, PockCoreError> {
    let passphrase = Zeroizing::new(passphrase);
    let secret_key_b64 = Zeroizing::new(secret_key_b64);
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
    let recovery_code = Zeroizing::new(recovery_code);
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
    let recovery_code = Zeroizing::new(recovery_code);
    let secret_key_b64 = Zeroizing::new(secret_key_b64);
    let new_passphrase = Zeroizing::new(new_passphrase);
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
    let old_passphrase = Zeroizing::new(old_passphrase);
    let secret_key_b64 = Zeroizing::new(secret_key_b64);
    let new_passphrase = Zeroizing::new(new_passphrase);
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
    let passphrase = Zeroizing::new(passphrase);
    let old_secret_key_b64 = Zeroizing::new(old_secret_key_b64);
    flows::rotate_secret_key(&passphrase, &old_secret_key_b64, &wrapped_auk_json)
        .map_err(Into::into)
}

#[uniffi::export]
pub fn rotate_recovery_code(
    passphrase: String,
    secret_key_b64: String,
    wrapped_auk_json: String,
) -> Result<String, PockCoreError> {
    let passphrase = Zeroizing::new(passphrase);
    let secret_key_b64 = Zeroizing::new(secret_key_b64);
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
    let passphrase = Zeroizing::new(passphrase);
    let secret_key_b64 = Zeroizing::new(secret_key_b64);
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
    let key_b64 = Zeroizing::new(key_b64);
    let plaintext = Zeroizing::new(plaintext);
    flows::seal_symmetric(&key_b64, &plaintext, &aad).map_err(Into::into)
}

#[uniffi::export]
pub fn open_symmetric(
    key_b64: String,
    blob: Vec<u8>,
    aad: Vec<u8>,
) -> Result<Vec<u8>, PockCoreError> {
    let key_b64 = Zeroizing::new(key_b64);
    flows::open_symmetric(&key_b64, &blob, &aad).map_err(Into::into)
}

#[uniffi::export]
pub fn sign_message(identity_secret_b64: String, msg: Vec<u8>) -> Result<String, PockCoreError> {
    let identity_secret_b64 = Zeroizing::new(identity_secret_b64);
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
    let json = Zeroizing::new(json);
    let passphrase = Zeroizing::new(passphrase);
    flows::export_backup(&json, &passphrase).map_err(Into::into)
}

#[uniffi::export]
pub fn import_backup(data: Vec<u8>, passphrase: String) -> Result<String, PockCoreError> {
    let passphrase = Zeroizing::new(passphrase);
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
    let passphrase = Zeroizing::new(passphrase);
    let secret_key_b64 = Zeroizing::new(secret_key_b64);
    let prf_secret_b64 = Zeroizing::new(prf_secret_b64);
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
    let prf_secret_b64 = Zeroizing::new(prf_secret_b64);
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
    let passphrase = Zeroizing::new(passphrase);
    let secret_key_b64 = Zeroizing::new(secret_key_b64);
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
    let passphrase = Zeroizing::new(passphrase);
    let secret_key_b64 = Zeroizing::new(secret_key_b64);
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
    let prf_secret_b64 = Zeroizing::new(prf_secret_b64);
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
    let prf_secret_b64 = Zeroizing::new(prf_secret_b64);
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

    /// Name of the `PockCoreError` category a `CoreError` maps to.
    fn category(e: CoreError) -> &'static str {
        match PockCoreError::from(e) {
            PockCoreError::WrongCredential { .. } => "WrongCredential",
            PockCoreError::InvalidInput { .. } => "InvalidInput",
            PockCoreError::Json { .. } => "Json",
            PockCoreError::Encoding { .. } => "Encoding",
            PockCoreError::Other { .. } => "Other",
        }
    }

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
        let err = seal_symmetric("!!! not base64 !!!".into(), vec![1, 2, 3], vec![]).unwrap_err();
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

    /// The `WRONG_CREDENTIAL_MESSAGES` table must be matched exactly — no
    /// substring sniffing. Every literal in it maps to `WrongCredential`.
    #[test]
    fn every_wrong_credential_message_maps_to_wrong_credential() {
        for msg in WRONG_CREDENTIAL_MESSAGES {
            assert_eq!(
                category(CoreError::Flow((*msg).to_string())),
                "WrongCredential",
                "flow message {msg:?}"
            );
        }
    }

    /// The literal `Flow` messages in `crate::flows` that are *not* credential
    /// failures, plus a message that would have been caught by the old
    /// `contains("wrong ")` heuristic but is not a real flow message.
    #[test]
    fn other_flow_messages_map_to_invalid_input() {
        for msg in [
            "unknown cipher id",
            "bad symmetric key length",
            "bad sign pubkey length",
            "bad signature length",
            "bad secret key",
            "bad amk length",
            // Not a real flow message; the old substring heuristic would have
            // mis-filed it as WrongCredential.
            "the wrong sort of input entirely",
        ] {
            assert_eq!(
                category(CoreError::Flow(msg.to_string())),
                "InvalidInput",
                "flow message {msg:?}"
            );
        }
    }

    /// `flows::decrypt_share` and `flows::import_backup` pass a
    /// `FromUtf8Error::to_string()` through `CoreError::Flow`. That is a
    /// malformed-payload condition, not a wrong credential.
    #[test]
    fn utf8_flow_passthrough_maps_to_invalid_input() {
        let utf8_err = String::from_utf8(vec![0xff, 0xfe, 0xfd]).unwrap_err();
        let rendered = utf8_err.to_string();
        let mapped = PockCoreError::from(CoreError::Flow(rendered.clone()));
        match mapped {
            PockCoreError::InvalidInput { message } => assert_eq!(message, rendered),
            other => panic!("expected InvalidInput for {rendered:?}, got {other:?}"),
        }
    }

    #[test]
    fn core_error_variant_table_maps_as_expected() {
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
                CoreError::Flow("wrong passphrase or secret key".into()),
                "WrongCredential",
            ),
            (
                CoreError::Flow("wrong recovery code".into()),
                "WrongCredential",
            ),
            (
                CoreError::Flow("wrong passphrase or corrupted backup".into()),
                "WrongCredential",
            ),
            (
                CoreError::Flow("decrypt failed (wrong key or tampered)".into()),
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
            assert_eq!(category(source), want, "mapping for {rendered:?}");
        }
    }
}
