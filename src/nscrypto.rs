//! `pns1.` namespace protection — the Rust twin of `app/lib/namespace-crypto.ts`.
//!
//! A protected folder holds a random 32-byte **namespace key** (NK). The NK
//! encrypts each protected value; the NK itself is wrapped by a PBKDF2 key
//! derived from the namespace passphrase (or from a recovery code, which is
//! just another passphrase as far as this module is concerned).
//!
//! Wire format, byte-for-byte identical to the TypeScript original:
//!
//! * KDF — PBKDF2-HMAC-SHA256, [`PBKDF2_ITERS`] iterations, 256-bit output.
//! * AEAD — AES-GCM-256 with a random 12-byte IV and no additional data.
//! * Blob — `"<b64(iv)>.<b64(ct||tag)>"`, **standard** base64 (`+` / `/`, with
//!   `=` padding). This is deliberately *not* the `URL_SAFE_NO_PAD` alphabet the
//!   rest of pock-core uses: the TS side is built on `btoa`, and existing stored
//!   namespaces are encoded that way.
//! * Protected value — the blob with [`PROTECTED_PREFIX`] prepended.
//!
//! Everything here is pure: no I/O, no storage, no clock.

use crate::error::CoreError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Marks a value as namespace-protected. Present on `protect_value` output and
/// tolerated-but-optional on the `unprotect_value` input.
pub const PROTECTED_PREFIX: &str = "pns1.";

/// PBKDF2 work factor. Must match `PBKDF2_ITERS` in `app/lib/namespace-crypto.ts`
/// exactly — a different count derives a different key and every stored
/// namespace stops opening.
pub const PBKDF2_ITERS: u32 = 600_000;

/// Standard base64 (padded), the alphabet `btoa` produces.
fn b64std(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Decodes standard base64. Padding is optional so a value that lost its `=`
/// in transit still opens; the URL-safe alphabet is **not** accepted here,
/// because nothing has ever written a namespace blob in it.
fn unb64std(s: &str) -> Result<Vec<u8>, CoreError> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s))
        .map_err(|e| CoreError::Encoding(e.to_string()))
}

/// PBKDF2-HMAC-SHA256 over the passphrase and the (base64) salt.
fn derive_key(passphrase: &str, salt_b64: &str) -> Result<[u8; 32], CoreError> {
    let salt = unb64std(salt_b64)?;
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, PBKDF2_ITERS, &mut key);
    Ok(key)
}

/// AES-GCM-256 seal with a fresh random IV, rendered as `"b64(iv).b64(ct)"`.
fn aes_encrypt(key: &[u8; 32], data: &[u8]) -> Result<String, CoreError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CoreError::Aead)?;
    let mut iv = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: data, aad: &[] })
        .map_err(|_| CoreError::Aead)?;
    Ok(format!("{}.{}", b64std(&iv), b64std(&ct)))
}

/// The inverse of [`aes_encrypt`]. A missing dot is a malformed blob; a failed
/// tag check is reported as the classified credential message, because the only
/// way a caller reaches it in practice is a wrong namespace passphrase.
fn aes_decrypt(key: &[u8; 32], blob: &str) -> Result<Vec<u8>, CoreError> {
    let (iv_b64, ct_b64) = blob
        .split_once('.')
        .ok_or_else(|| CoreError::InvalidInput("malformed pns1 blob".into()))?;
    let iv = unb64std(iv_b64)?;
    if iv.len() != 12 {
        return Err(CoreError::InvalidInput("malformed pns1 blob".into()));
    }
    let ct = unb64std(ct_b64)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CoreError::Aead)?;
    cipher
        .decrypt(Nonce::from_slice(&iv), Payload { msg: &ct, aad: &[] })
        .map_err(|_| CoreError::Flow("wrong namespace passphrase".into()))
}

/// A fresh namespace key.
pub fn random_nk() -> [u8; 32] {
    let mut nk = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nk);
    nk
}

/// A fresh 16-byte PBKDF2 salt, standard base64.
pub fn random_salt_b64() -> String {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    b64std(&salt)
}

/// A fresh namespace recovery code: 10 random bytes as lowercase hex, grouped
/// in fours (`"a1b2-c3d4-e5f6-0718-293a"`).
pub fn random_ns_recovery_code() -> String {
    let mut b = [0u8; 10];
    rand::rngs::OsRng.fill_bytes(&mut b);
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).expect("hex is ascii").to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// Wraps the namespace key under a passphrase-derived PBKDF2 key.
pub fn wrap_nk(nk: &[u8], passphrase: &str, salt_b64: &str) -> Result<String, CoreError> {
    let mut key = derive_key(passphrase, salt_b64)?;
    let out = aes_encrypt(&key, nk);
    key.zeroize();
    out
}

/// Unwraps a namespace key. A wrong passphrase surfaces as the classified
/// `"wrong namespace passphrase"` flow message.
pub fn unwrap_nk(wrapped: &str, passphrase: &str, salt_b64: &str) -> Result<Vec<u8>, CoreError> {
    let mut key = derive_key(passphrase, salt_b64)?;
    let out = aes_decrypt(&key, wrapped);
    key.zeroize();
    out
}

/// Encrypts a single value under the namespace key, prefixed `pns1.`.
pub fn protect_value(nk: &[u8], value: &str) -> Result<String, CoreError> {
    let key = nk_key(nk)?;
    Ok(format!("{}{}", PROTECTED_PREFIX, aes_encrypt(&key, value.as_bytes())?))
}

/// Decrypts a protected value. The prefix is stripped when present and its
/// absence is tolerated, matching `unprotectValue` in the TS original.
pub fn unprotect_value(nk: &[u8], blob: &str) -> Result<String, CoreError> {
    let key = nk_key(nk)?;
    let body = blob.strip_prefix(PROTECTED_PREFIX).unwrap_or(blob);
    let pt = aes_decrypt(&key, body)?;
    String::from_utf8(pt).map_err(|e| CoreError::Flow(e.to_string()))
}

/// Whether a stored value is namespace-protected.
pub fn is_protected_blob(blob: &str) -> bool {
    blob.starts_with(PROTECTED_PREFIX)
}

/// A stable, non-reversing identifier for a namespace key, for the audit log.
/// Standard base64 of `SHA-256(nk)`, matching `nkHash` in the TS original.
pub fn nk_hash(nk: &[u8]) -> String {
    b64std(&Sha256::digest(nk))
}

fn nk_key(nk: &[u8]) -> Result<[u8; 32], CoreError> {
    let key: [u8; 32] = nk
        .try_into()
        .map_err(|_| CoreError::InvalidInput("namespace key must be 32 bytes".into()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vector produced by app/lib/namespace-crypto.ts (Web Crypto) via
    // scripts/fixtures/seed-namespace-vector.mts in the monorepo. These prove
    // the Rust side is wire-compatible with every namespace already stored by
    // the browser, not merely self-consistent.
    const TS_SALT: &str = "AAAAAAAAAAAAAAAAAAAAAA==";
    const TS_WRAPPED: &str =
        "U9FZTfIDWBdLPBSB.rNjHLoGoborbEucrhf5F7H+j8fFPmC/p6ZQ8ZAxl+gVVP3U/j/s/uJf4IEeH3Blz";
    const TS_PROTECTED: &str = "pns1.3dPQK9tz4wEysh/3.Pm66ipYUxn++AKieo88QTuFaap4w4A==";
    const TS_NK_HASH: &str = "S7Bvjk46dxXSAdVz0KpCN2LlXavWGiwCJ4+lbMbSlOA=";

    #[test]
    fn unwraps_a_blob_produced_by_the_typescript_implementation() {
        let nk = unwrap_nk(TS_WRAPPED, "hunter2", TS_SALT).expect("TS wrap must unwrap in Rust");
        assert_eq!(nk, vec![7u8; 32], "the TS side wrapped an all-sevens key");
        assert_eq!(nk_hash(&nk), TS_NK_HASH);
        assert_eq!(unprotect_value(&nk, TS_PROTECTED).unwrap(), "s3cret");
    }

    #[test]
    fn a_wrong_namespace_passphrase_reports_the_classified_message() {
        let e = unwrap_nk(TS_WRAPPED, "nope", TS_SALT).unwrap_err();
        assert_eq!(e.to_string(), "wrong namespace passphrase");
    }

    #[test]
    fn roundtrips_protect_value_with_the_pns1_prefix_and_standard_base64() {
        let nk = random_nk();
        let blob = protect_value(&nk, "s3cret").unwrap();
        assert!(blob.starts_with(PROTECTED_PREFIX));
        assert!(is_protected_blob(&blob));
        assert_eq!(unprotect_value(&nk, &blob).unwrap(), "s3cret");
        let body = &blob[PROTECTED_PREFIX.len()..];
        assert_eq!(body.split('.').count(), 2, "iv and ct are dot-separated");
        assert!(!body.contains('-') && !body.contains('_'), "standard base64, not url-safe");
    }

    #[test]
    fn a_namespace_recovery_code_is_hex_in_four_char_groups() {
        let c = random_ns_recovery_code();
        assert_eq!(c.len(), 24, "10 bytes -> 20 hex chars + 4 dashes");
        assert!(c.split('-').all(|g| g.len() == 4 && g.chars().all(|ch| ch.is_ascii_hexdigit())));
    }

    #[test]
    fn unprotect_value_tolerates_a_missing_prefix() {
        let nk = random_nk();
        let blob = protect_value(&nk, "s3cret").unwrap();
        let bare = blob.strip_prefix(PROTECTED_PREFIX).unwrap();
        assert!(!is_protected_blob(bare));
        assert_eq!(unprotect_value(&nk, bare).unwrap(), "s3cret");
    }

    #[test]
    fn a_blob_without_a_dot_is_malformed_not_a_wrong_passphrase() {
        let nk = random_nk();
        let e = unprotect_value(&nk, "pns1.no-separator-here").unwrap_err();
        assert_eq!(e.to_string(), "invalid input: malformed pns1 blob");
    }

    #[test]
    fn a_tampered_ciphertext_does_not_open() {
        let nk = random_nk();
        let blob = protect_value(&nk, "s3cret").unwrap();
        let mut bytes = blob.into_bytes();
        let last = bytes.len() - 3;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(unprotect_value(&nk, &tampered).is_err());
    }

    #[test]
    fn a_wrong_namespace_key_does_not_open_a_protected_value() {
        let blob = protect_value(&random_nk(), "s3cret").unwrap();
        assert!(unprotect_value(&random_nk(), &blob).is_err());
    }

    #[test]
    fn a_short_namespace_key_is_rejected_as_invalid_input() {
        let e = protect_value(&[0u8; 16], "s3cret").unwrap_err();
        assert_eq!(e.to_string(), "invalid input: namespace key must be 32 bytes");
    }

    #[test]
    fn wrap_nk_roundtrips_through_a_freshly_generated_salt() {
        let nk = random_nk();
        let salt = random_salt_b64();
        assert_eq!(unb64std(&salt).unwrap().len(), 16);
        let wrapped = wrap_nk(&nk, "correct horse", &salt).unwrap();
        assert_eq!(unwrap_nk(&wrapped, "correct horse", &salt).unwrap(), nk.to_vec());
    }

    #[test]
    fn a_recovery_code_wraps_the_same_key_as_the_passphrase_does() {
        let nk = random_nk();
        let salt = random_salt_b64();
        let code = random_ns_recovery_code();
        let by_pass = wrap_nk(&nk, "pw", &salt).unwrap();
        let by_code = wrap_nk(&nk, &code, &salt).unwrap();
        assert_ne!(by_pass, by_code, "different wrapping credentials, different blobs");
        assert_eq!(unwrap_nk(&by_code, &code, &salt).unwrap(), nk.to_vec());
        assert!(unwrap_nk(&by_code, "pw", &salt).is_err());
    }

    #[test]
    fn a_different_salt_derives_a_different_wrapping_key() {
        let nk = random_nk();
        let wrapped = wrap_nk(&nk, "pw", TS_SALT).unwrap();
        assert!(unwrap_nk(&wrapped, "pw", "BBBBBBBBBBBBBBBBBBBBBB==").is_err());
    }

    #[test]
    fn each_seal_draws_a_fresh_iv() {
        let nk = random_nk();
        let a = protect_value(&nk, "s3cret").unwrap();
        let b = protect_value(&nk, "s3cret").unwrap();
        assert_ne!(a, b, "a reused IV would be catastrophic for AES-GCM");
    }
}
