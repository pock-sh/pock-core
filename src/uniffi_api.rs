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

/// The credential-failure classification table. It lives in [`crate::error`] so
/// `pock-client` and any other consumer classify against the same list instead
/// of keeping a copy that drifts; it is re-exported here because this module's
/// mapping is its primary user.
pub use crate::error::WRONG_CREDENTIAL_MESSAGES;

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

// ---------------------------------------------------------------------------
// Chat message digest
// ---------------------------------------------------------------------------

/// `SHA-256(aad ‖ ct)` — the bytes a chat message signature covers.
#[uniffi::export]
pub fn message_digest(aad: Vec<u8>, ct: Vec<u8>) -> Vec<u8> {
    flows::message_digest(&aad, &ct)
}

/// Create a vault with an explicit Argon2 profile ("native" | "constrained").
#[uniffi::export]
pub fn create_vault_profile(passphrase: String, profile_id: String) -> Result<String, PockCoreError> {
    let passphrase = Zeroizing::new(passphrase);
    flows::create_vault_profile(&passphrase, &profile_id).map_err(Into::into)
}

// ---------------------------------------------------------------------------
// `pns1.` namespace protection
// ---------------------------------------------------------------------------
//
// The namespace key crosses this boundary as STANDARD base64 rather than as a
// `Vec<u8>`, so no raw key bytes land in a Swift/Kotlin buffer the host might
// retain or log. The base64 string is still secret material and is `Zeroizing`
// here, as are the passphrase and the plaintext value.

/// A fresh namespace key, standard base64.
#[uniffi::export]
pub fn ns_random_nk() -> String {
    flows::ns_random_nk()
}

/// A fresh 16-byte PBKDF2 salt, standard base64.
#[uniffi::export]
pub fn ns_random_salt() -> String {
    flows::ns_random_salt()
}

/// A fresh namespace recovery code (`"a1b2-c3d4-…"`).
#[uniffi::export]
pub fn ns_random_recovery_code() -> String {
    flows::ns_random_recovery_code()
}

/// Wrap the namespace key under a namespace passphrase.
#[uniffi::export]
pub fn ns_wrap_nk(nk_b64: String, passphrase: String, salt_b64: String) -> Result<String, PockCoreError> {
    let nk_b64 = Zeroizing::new(nk_b64);
    let passphrase = Zeroizing::new(passphrase);
    flows::ns_wrap_nk(&nk_b64, &passphrase, &salt_b64).map_err(Into::into)
}

/// Unwrap the namespace key, returned as standard base64.
#[uniffi::export]
pub fn ns_unwrap_nk(wrapped: String, passphrase: String, salt_b64: String) -> Result<String, PockCoreError> {
    let passphrase = Zeroizing::new(passphrase);
    flows::ns_unwrap_nk(&wrapped, &passphrase, &salt_b64).map_err(Into::into)
}

/// Encrypt one value under the namespace key; result carries the `pns1.` prefix.
#[uniffi::export]
pub fn ns_protect_value(nk_b64: String, value: String) -> Result<String, PockCoreError> {
    let nk_b64 = Zeroizing::new(nk_b64);
    let value = Zeroizing::new(value);
    flows::ns_protect_value(&nk_b64, &value).map_err(Into::into)
}

/// Decrypt a `pns1.` value under the namespace key.
#[uniffi::export]
pub fn ns_unprotect_value(nk_b64: String, blob: String) -> Result<String, PockCoreError> {
    let nk_b64 = Zeroizing::new(nk_b64);
    flows::ns_unprotect_value(&nk_b64, &blob).map_err(Into::into)
}

/// Standard base64 of `SHA-256(nk)`, for the audit log.
#[uniffi::export]
pub fn ns_nk_hash(nk_b64: String) -> Result<String, PockCoreError> {
    let nk_b64 = Zeroizing::new(nk_b64);
    flows::ns_nk_hash(&nk_b64).map_err(Into::into)
}

/// Whether a stored value carries the `pns1.` prefix.
#[uniffi::export]
pub fn ns_is_protected(blob: String) -> bool {
    flows::ns_is_protected(&blob)
}

// ---------------------------------------------------------------------------
// Key-transparency canonical bytes
// ---------------------------------------------------------------------------

/// Canonical bytes of `{userId,kemPubkey,signPubkey,rot,principalSeq,ts}`.
#[uniffi::export]
pub fn cert_bytes(cert_json: String) -> Result<Vec<u8>, PockCoreError> {
    flows::cert_bytes_json(&cert_json).map_err(Into::into)
}

/// Canonical bytes of `{userId,kemPubkey,signPubkey,ts}`.
#[uniffi::export]
pub fn leaf_bytes(leaf_json: String) -> Result<Vec<u8>, PockCoreError> {
    flows::leaf_bytes_json(&leaf_json).map_err(Into::into)
}

/// Canonical bytes of `{logId,size,root,ts}`.
#[uniffi::export]
pub fn sth_message(sth_json: String) -> Result<Vec<u8>, PockCoreError> {
    flows::sth_message_json(&sth_json).map_err(Into::into)
}

/// k-of-n verification of a succession certificate.
#[uniffi::export]
pub fn verify_cert(
    cert_json: String,
    sigs_json: String,
    custodians_json: String,
    threshold: u32,
) -> Result<bool, PockCoreError> {
    flows::verify_cert_json(&cert_json, &sigs_json, &custodians_json, threshold).map_err(Into::into)
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

    /// A fresh vault, parsed. Every credential-failure test below starts from a
    /// real `create_vault` so the wrapped blobs it feeds back in are the ones
    /// the crate actually produces.
    fn new_vault(passphrase: &str) -> serde_json::Value {
        serde_json::from_str(&create_vault(passphrase.into()).unwrap()).unwrap()
    }

    /// Asserts the error a real flow returned is the `WrongCredential`
    /// category carrying exactly `expected`, and that `expected` is genuinely
    /// one of the `WRONG_CREDENTIAL_MESSAGES` entries — so the assertion is
    /// tied to the table rather than to a literal repeated in the test.
    fn assert_wrong_credential(err: PockCoreError, expected: &str) {
        assert!(
            WRONG_CREDENTIAL_MESSAGES.contains(&expected),
            "{expected:?} is not in WRONG_CREDENTIAL_MESSAGES"
        );
        match err {
            PockCoreError::WrongCredential { ref message } => assert_eq!(message, expected),
            other => panic!("expected WrongCredential({expected:?}), got {other:?}"),
        }
    }

    #[test]
    fn wrong_passphrase_maps_to_wrong_credential() {
        let v = new_vault("right passphrase");

        let err = unlock_vault(
            "wrong passphrase".into(),
            v["secretKey"].as_str().unwrap().to_string(),
            v["wrappedAukPassphrase"].to_string(),
            v["wrappedIdentity"].as_str().unwrap().to_string(),
        )
        .unwrap_err();

        assert_wrong_credential(err, "wrong passphrase or secret key");
    }

    /// Drives the 0.3.0 addition to the table through the real namespace flow,
    /// so the entry is proved by a failure the crate actually produces.
    #[test]
    fn wrong_namespace_passphrase_maps_to_wrong_credential() {
        let nk = ns_random_nk();
        let salt = ns_random_salt();
        let wrapped = ns_wrap_nk(nk, "right passphrase".into(), salt.clone()).unwrap();

        let err = ns_unwrap_nk(wrapped, "wrong passphrase".into(), salt).unwrap_err();

        assert_wrong_credential(err, "wrong namespace passphrase");
    }

    /// The namespace surface round-trips across the FFI wrappers, not just in
    /// `flows` — the base64 hand-off is where a boundary bug would show up.
    #[test]
    fn the_namespace_ffi_wrappers_roundtrip() {
        let nk = ns_random_nk();
        let salt = ns_random_salt();
        let wrapped = ns_wrap_nk(nk.clone(), "pw".into(), salt.clone()).unwrap();
        assert_eq!(ns_unwrap_nk(wrapped, "pw".into(), salt).unwrap(), nk);

        let blob = ns_protect_value(nk.clone(), "s3cret".into()).unwrap();
        assert!(ns_is_protected(blob.clone()));
        assert_eq!(ns_unprotect_value(nk.clone(), blob).unwrap(), "s3cret");
        assert!(!ns_nk_hash(nk).unwrap().is_empty());
        assert_eq!(ns_random_recovery_code().len(), 24);
    }

    /// `message_digest` and the key-log encoders are pure and infallible-ish;
    /// pin their FFI shape so a rename shows up here.
    #[test]
    fn the_keylog_ffi_wrappers_produce_canonical_bytes() {
        assert_eq!(message_digest(b"aad".to_vec(), b"ct".to_vec()).len(), 32);
        let cert = r#"{"userId":"u","kemPubkey":"K","signPubkey":"S","rot":{"custodians":["A"],"threshold":1},"principalSeq":0,"ts":1}"#;
        assert_eq!(
            String::from_utf8(cert_bytes(cert.into()).unwrap()).unwrap(),
            "pock-keycert-v1\nu\nK\nS\nA|1\n0\n1"
        );
        assert_eq!(
            String::from_utf8(leaf_bytes(r#"{"userId":"u","kemPubkey":"K","signPubkey":"S","ts":7}"#.into()).unwrap()).unwrap(),
            "pock-keylog-v1\nu\nK\nS\n7"
        );
        assert_eq!(
            String::from_utf8(sth_message(r#"{"logId":"L","size":3,"root":"ab","ts":7}"#.into()).unwrap()).unwrap(),
            "pock-sth-v1\nL\n3\nab\n7"
        );
        assert!(!verify_cert(cert.into(), "[]".into(), r#"["A"]"#.into(), 1).unwrap());
    }

    /// A vault minted with the native profile must unlock through the same FFI.
    #[test]
    fn create_vault_profile_native_unlocks_over_the_ffi() {
        let v: serde_json::Value =
            serde_json::from_str(&create_vault_profile("pw".into(), "native".into()).unwrap()).unwrap();
        unlock_vault(
            "pw".into(),
            v["secretKey"].as_str().unwrap().to_string(),
            v["wrappedAukPassphrase"].to_string(),
            v["wrappedIdentity"].as_str().unwrap().to_string(),
        )
        .expect("native vault must unlock");
        match create_vault_profile("pw".into(), "nope".into()).unwrap_err() {
            PockCoreError::InvalidInput { .. } => {}
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn wrong_recovery_code_maps_to_wrong_credential() {
        let v = new_vault("right passphrase");
        let real_code = v["recoveryCode"].as_str().unwrap().to_string();
        let wrong_code = format!("{real_code}-nope");

        let err = unlock_recovery(
            wrong_code,
            v["wrappedAukRecovery"].to_string(),
            v["wrappedIdentity"].as_str().unwrap().to_string(),
        )
        .unwrap_err();

        assert_wrong_credential(err, "wrong recovery code");
    }

    #[test]
    fn wrong_backup_passphrase_maps_to_wrong_credential() {
        let blob = export_backup(r#"{"items":[]}"#.into(), "right passphrase".into()).unwrap();

        let err = import_backup(blob, "wrong passphrase".into()).unwrap_err();

        assert_wrong_credential(err, "wrong passphrase or corrupted backup");
    }

    #[test]
    fn failed_prf_unlock_maps_to_wrong_credential() {
        let v = new_vault("right passphrase");
        let wrapped_prf = enroll_prf(
            "right passphrase".into(),
            v["secretKey"].as_str().unwrap().to_string(),
            v["wrappedAukPassphrase"].to_string(),
            generate_symmetric_key(),
        )
        .unwrap();

        // A different authenticator (or a PRF evaluation against the wrong
        // credential) yields a different secret, so the KEK does not unwrap.
        let err = unlock_prf(
            generate_symmetric_key(),
            wrapped_prf,
            v["wrappedIdentity"].as_str().unwrap().to_string(),
        )
        .unwrap_err();

        assert_wrong_credential(err, "touch id unlock failed");
    }

    #[test]
    fn wrong_symmetric_key_maps_to_wrong_credential() {
        let blob =
            seal_symmetric(generate_symmetric_key(), b"hello".to_vec(), b"aad".to_vec()).unwrap();

        let err = open_symmetric(generate_symmetric_key(), blob, b"aad".to_vec()).unwrap_err();

        assert_wrong_credential(err, "decrypt failed (wrong key or tampered)");
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

    /// The table must not grow an entry that no flow drives. Each literal here
    /// is proved against a real flow's output by the test named beside it, so
    /// the classification is checked end to end and not against itself. Adding
    /// a message to `WRONG_CREDENTIAL_MESSAGES` without a flow test that emits
    /// it fails here; so does a stale entry no flow produces any more.
    #[test]
    fn every_wrong_credential_message_is_driven_by_a_flow_test() {
        let covered = [
            // wrong_passphrase_maps_to_wrong_credential (unlock_vault)
            "wrong passphrase or secret key",
            // wrong_recovery_code_maps_to_wrong_credential (unlock_recovery)
            "wrong recovery code",
            // wrong_backup_passphrase_maps_to_wrong_credential (import_backup)
            "wrong passphrase or corrupted backup",
            // wrong_symmetric_key_maps_to_wrong_credential (open_symmetric)
            "decrypt failed (wrong key or tampered)",
            // failed_prf_unlock_maps_to_wrong_credential (unlock_prf)
            "touch id unlock failed",
            // wrong_namespace_passphrase_maps_to_wrong_credential (ns_unwrap_nk)
            "wrong namespace passphrase",
        ];
        for msg in WRONG_CREDENTIAL_MESSAGES {
            assert!(
                covered.contains(msg),
                "{msg:?} is in the table but no flow test drives it"
            );
            // Belt and braces: the table entry itself still has to classify.
            assert_eq!(
                category(CoreError::Flow((*msg).to_string())),
                "WrongCredential",
                "flow message {msg:?}"
            );
        }
        for msg in covered {
            assert!(
                WRONG_CREDENTIAL_MESSAGES.contains(&msg),
                "{msg:?} is claimed as covered but is not in the table"
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
            (
                CoreError::Flow("wrong namespace passphrase".into()),
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
