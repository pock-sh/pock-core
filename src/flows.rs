//! Binding-independent crypto flows.
//!
//! Every function here is pure Rust: no wasm, no UniFFI, no HTTP, no storage.
//! The wasm bindings in `crate::wasm` (and any future UniFFI bindings) are thin
//! adapters over this module, so all surfaces produce byte-identical output.

use crate::aead::{open_aad, seal_aad, AeadKey};
use crate::auk::{
    unwrap_identity, unwrap_secret, unwrap_with_kek, unwrap_with_passphrase, wrap_identity,
    wrap_secret, wrap_with_kek, wrap_with_passphrase, Auk, SecretKey, WrappedAuk,
};
use crate::error::CoreError;
use crate::identity::{Identity, PublicIdentity, PublicIdentityBlob};
use crate::item::{decrypt_item as item_decrypt, encrypt_item as item_encrypt, EncryptedItem};
use crate::kdf::{hkdf_sha256, KdfProfile};
use crate::share::{decrypt_share as share_decrypt, encrypt_share as share_encrypt, Bundle, ShareCipher};
use crate::sign::{SignPublic, SignSecret};

use base64::Engine;
use serde::{Deserialize, Serialize};

pub(crate) fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
pub(crate) fn unb64(s: &str) -> Result<Vec<u8>, CoreError> {
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?)
}

#[derive(Serialize, Deserialize)]
pub struct GeneratedIdentity {
    pub secret_b64: String,
    pub public: PublicIdentityBlob,
}

pub fn generate_identity() -> String {
    let id = Identity::generate();
    let out = GeneratedIdentity { secret_b64: b64(&id.to_secret_bytes()), public: id.public().to_blob() };
    serde_json::to_string(&out).expect("serialize identity")
}

pub fn encrypt_item(value: &str, recipient_pub_blobs_json: &str) -> Result<String, CoreError> {
    let blobs: Vec<PublicIdentityBlob> = serde_json::from_str(recipient_pub_blobs_json)?;
    let mut recipients = Vec::new();
    for b in &blobs {
        recipients.push(PublicIdentity::from_blob(b)?.kem);
    }
    let item = item_encrypt(value.as_bytes(), &recipients)?;
    Ok(serde_json::to_string(&item)?)
}

pub fn decrypt_item(item_json: &str, identity_secret_b64: &str) -> Result<String, CoreError> {
    let item: EncryptedItem = serde_json::from_str(item_json)?;
    let id = Identity::from_secret_bytes(&unb64(identity_secret_b64)?)?;
    let pub_kem = id.public().kem;
    let plaintext = item_decrypt(&item, &id.kem, &pub_kem)?;
    String::from_utf8(plaintext).map_err(|e| CoreError::Flow(e.to_string()))
}

pub fn encrypt_share(bundle_json: &str, cipher_id: &str) -> Result<String, CoreError> {
    let bundle: Bundle = serde_json::from_str(bundle_json)?;
    let cipher = ShareCipher::from_id(cipher_id).ok_or_else(|| CoreError::Flow("unknown cipher id".into()))?;
    let (envelope, key_blob) = share_encrypt(&bundle, cipher)?;
    let out = serde_json::json!({ "envelope_b64": b64(&envelope), "key_blob": key_blob });
    Ok(out.to_string())
}

pub fn decrypt_share(envelope_b64: &str, key_blob: &str) -> Result<String, CoreError> {
    let envelope = unb64(envelope_b64)?;
    let bundle = share_decrypt(&envelope, key_blob)?;
    Ok(serde_json::to_string(&bundle)?)
}

pub fn create_vault(passphrase: &str) -> Result<String, CoreError> {
    use rand::RngCore;
    let identity = Identity::generate();
    let auk = Auk::generate();
    let secret_key = SecretKey::random();
    let mut rb = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut rb);
    let recovery_code = b64(&rb);

    let wrapped_pp = wrap_with_passphrase(&auk, passphrase.as_bytes(), &secret_key, KdfProfile::Constrained);
    let recovery_kek = hkdf_sha256(recovery_code.as_bytes(), b"", b"pock/recovery/v1");
    let wrapped_rec = wrap_with_kek(&auk, &recovery_kek, "recovery");
    let wrapped_identity = wrap_identity(&auk, &identity);
    let pubid = identity.public();

    let out = serde_json::json!({
        "signPubkey": b64(pubid.sign.as_bytes()),
        "kemPubkey": b64(&pubid.kem.as_bytes()),
        "wrappedIdentity": wrapped_identity,
        "secretKey": b64(secret_key.as_bytes()),
        "recoveryCode": recovery_code,
        "wrappedAukPassphrase": serde_json::to_value(&wrapped_pp)?,
        "wrappedAukRecovery": serde_json::to_value(&wrapped_rec)?,
        "identitySecretB64": b64(&identity.to_secret_bytes()),
    });
    Ok(out.to_string())
}

pub fn unlock_vault(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    wrapped_identity_b64: &str,
) -> Result<String, CoreError> {
    let sk_bytes = unb64(secret_key_b64)?;
    let sk_arr: [u8; 16] = sk_bytes.as_slice().try_into().map_err(|_| CoreError::Flow("bad secret key".into()))?;
    let secret_key = SecretKey::from_bytes(sk_arr);
    let wrapped_auk: WrappedAuk = serde_json::from_str(wrapped_auk_json)?;
    let auk = unwrap_with_passphrase(&wrapped_auk, passphrase.as_bytes(), &secret_key)
        .map_err(|_| CoreError::Flow("wrong passphrase or secret key".into()))?;
    let identity = unwrap_identity(&auk, wrapped_identity_b64)?;
    Ok(serde_json::json!({ "identitySecretB64": b64(&identity.to_secret_bytes()) }).to_string())
}

/// Unlock using ONLY the recovery code (a single high-entropy factor). No passphrase or
/// Secret Key needed — this is the "I forgot my passphrase" path.
pub fn unlock_recovery(
    recovery_code: &str,
    wrapped_recovery_json: &str,
    wrapped_identity_b64: &str,
) -> Result<String, CoreError> {
    let wrapped_rec: WrappedAuk = serde_json::from_str(wrapped_recovery_json)?;
    let recovery_kek = hkdf_sha256(recovery_code.trim().as_bytes(), b"", b"pock/recovery/v1");
    let auk = unwrap_with_kek(&wrapped_rec, &recovery_kek)
        .map_err(|_| CoreError::Flow("wrong recovery code".into()))?;
    let identity = unwrap_identity(&auk, wrapped_identity_b64)?;
    Ok(serde_json::json!({ "identitySecretB64": b64(&identity.to_secret_bytes()) }).to_string())
}

/// After a recovery unlock, re-wrap the AUK under a NEW passphrase (+ the Secret Key), so
/// the user can set a passphrase they'll remember. Returns the new wrappedAukPassphrase to
/// register server-side. The identity keypair itself is unchanged.
pub fn reset_passphrase(
    recovery_code: &str,
    wrapped_recovery_json: &str,
    secret_key_b64: &str,
    new_passphrase: &str,
) -> Result<String, CoreError> {
    let wrapped_rec: WrappedAuk = serde_json::from_str(wrapped_recovery_json)?;
    let recovery_kek = hkdf_sha256(recovery_code.trim().as_bytes(), b"", b"pock/recovery/v1");
    let auk = unwrap_with_kek(&wrapped_rec, &recovery_kek)
        .map_err(|_| CoreError::Flow("wrong recovery code".into()))?;
    let sk_bytes = unb64(secret_key_b64)?;
    let sk_arr: [u8; 16] = sk_bytes.as_slice().try_into().map_err(|_| CoreError::Flow("bad secret key".into()))?;
    let secret_key = SecretKey::from_bytes(sk_arr);
    let wrapped_pp = wrap_with_passphrase(&auk, new_passphrase.as_bytes(), &secret_key, KdfProfile::Constrained);
    Ok(serde_json::json!({
        "wrappedAukPassphrase": serde_json::to_value(&wrapped_pp)?,
    })
    .to_string())
}

fn aead_key(key_b64: &str) -> Result<AeadKey, CoreError> {
    let kb = unb64(key_b64)?;
    let arr: [u8; 32] = kb
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Flow("bad symmetric key length".into()))?;
    Ok(AeadKey::from_bytes(arr))
}

/// Random 32-byte XChaCha20-Poly1305 key, base64. Used as a chat channel key
/// or a per-attachment blob key.
pub fn generate_symmetric_key() -> String {
    b64(AeadKey::random().as_bytes())
}

/// Symmetric AEAD seal: returns nonce||ciphertext. `aad` binds context (e.g.
/// `channel_id|key_version|sender_id`) into the tag without being stored.
pub fn seal_symmetric(key_b64: &str, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
    Ok(seal_aad(&aead_key(key_b64)?, plaintext, aad))
}

pub fn open_symmetric(key_b64: &str, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
    open_aad(&aead_key(key_b64)?, blob, aad)
        .map_err(|_| CoreError::Flow("decrypt failed (wrong key or tampered)".into()))
}

/// Ed25519 signature over `msg` with the identity's signing key, base64.
pub fn sign_message(identity_secret_b64: &str, msg: &[u8]) -> Result<String, CoreError> {
    let id = Identity::from_secret_bytes(&unb64(identity_secret_b64)?)?;
    Ok(b64(&id.sign.sign(msg)))
}

pub fn verify_message(sign_pubkey_b64: &str, msg: &[u8], sig_b64: &str) -> Result<bool, CoreError> {
    let pk_bytes = unb64(sign_pubkey_b64)?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Flow("bad sign pubkey length".into()))?;
    let sig_bytes = unb64(sig_b64)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Flow("bad signature length".into()))?;
    Ok(SignPublic::from_bytes(pk_arr).verify(msg, &sig_arr).is_ok())
}

fn parse_sk(secret_key_b64: &str) -> Result<SecretKey, CoreError> {
    let sk_bytes = unb64(secret_key_b64)?;
    let sk_arr: [u8; 16] = sk_bytes.as_slice().try_into().map_err(|_| CoreError::Flow("bad secret key".into()))?;
    Ok(SecretKey::from_bytes(sk_arr))
}

fn unlock_auk(passphrase: &str, secret_key_b64: &str, wrapped_auk_json: &str) -> Result<Auk, CoreError> {
    let wrapped: WrappedAuk = serde_json::from_str(wrapped_auk_json)?;
    unwrap_with_passphrase(&wrapped, passphrase.as_bytes(), &parse_sk(secret_key_b64)?)
        .map_err(|_| CoreError::Flow("wrong passphrase or secret key".into()))
}

/// Change the passphrase while unlocked (old passphrase known). The AUK,
/// identity, recovery code, and passkeys are all unchanged — this only
/// re-wraps the AUK under the new passphrase + same Secret Key.
pub fn change_passphrase(
    old_passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    new_passphrase: &str,
) -> Result<String, CoreError> {
    let auk = unlock_auk(old_passphrase, secret_key_b64, wrapped_auk_json)?;
    let wrapped = wrap_with_passphrase(&auk, new_passphrase.as_bytes(), &parse_sk(secret_key_b64)?, KdfProfile::Constrained);
    Ok(serde_json::json!({
        "wrappedAukPassphrase": serde_json::to_value(&wrapped)?,
    })
    .to_string())
}

/// Rotate the Secret Key (the "have" factor). Mints a fresh 16-byte key and
/// re-wraps the AUK under passphrase + new key. Recovery and passkey wraps
/// are KEK-based and unaffected.
pub fn rotate_secret_key(
    passphrase: &str,
    old_secret_key_b64: &str,
    wrapped_auk_json: &str,
) -> Result<String, CoreError> {
    let auk = unlock_auk(passphrase, old_secret_key_b64, wrapped_auk_json)?;
    let new_sk = SecretKey::random();
    let wrapped = wrap_with_passphrase(&auk, passphrase.as_bytes(), &new_sk, KdfProfile::Constrained);
    Ok(serde_json::json!({
        "secretKey": b64(new_sk.as_bytes()),
        "wrappedAukPassphrase": serde_json::to_value(&wrapped)?,
    })
    .to_string())
}

/// Regenerate the recovery code. Mints a fresh high-entropy code and wraps
/// the AUK under its derived KEK; the old code stops working once the server
/// replaces the stored recovery wrap.
pub fn rotate_recovery_code(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
) -> Result<String, CoreError> {
    use rand::RngCore;
    let auk = unlock_auk(passphrase, secret_key_b64, wrapped_auk_json)?;
    let mut rb = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut rb);
    let recovery_code = b64(&rb);
    let recovery_kek = hkdf_sha256(recovery_code.as_bytes(), b"", b"pock/recovery/v1");
    let wrapped = wrap_with_kek(&auk, &recovery_kek, "recovery");
    Ok(serde_json::json!({
        "recoveryCode": recovery_code,
        "wrappedAukRecovery": serde_json::to_value(&wrapped)?,
    })
    .to_string())
}

/// Deep rotation: mint a brand-new identity keypair wrapped under the same
/// AUK. The caller must re-encrypt every item to the new public identity and
/// re-register pubkeys server-side; until then old blobs still need the old
/// secret (also returned).
pub fn rotate_identity(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    old_wrapped_identity_b64: &str,
) -> Result<String, CoreError> {
    let auk = unlock_auk(passphrase, secret_key_b64, wrapped_auk_json)?;
    let old = unwrap_identity(&auk, old_wrapped_identity_b64)?;
    let fresh = Identity::generate();
    let pubid = fresh.public();
    Ok(serde_json::json!({
        "signPubkey": b64(pubid.sign.as_bytes()),
        "kemPubkey": b64(&pubid.kem.as_bytes()),
        "wrappedIdentity": wrap_identity(&auk, &fresh),
        "identitySecretB64": b64(&fresh.to_secret_bytes()),
        "oldIdentitySecretB64": b64(&old.to_secret_bytes()),
        "publicBlob": serde_json::to_value(pubid.to_blob())?,
    })
    .to_string())
}

/// Encrypted binary vault backup (.pockvault). Standalone: only the backup
/// passphrase is needed to restore.
pub fn export_backup(json: &str, passphrase: &str) -> Result<Vec<u8>, CoreError> {
    crate::backup::export_backup(json.as_bytes(), passphrase.as_bytes())
}

pub fn import_backup(data: &[u8], passphrase: &str) -> Result<String, CoreError> {
    let pt = crate::backup::import_backup(data, passphrase.as_bytes())
        .map_err(|_| CoreError::Flow("wrong passphrase or corrupted backup".into()))?;
    String::from_utf8(pt).map_err(|e| CoreError::Flow(e.to_string()))
}

const PRF_INFO: &[u8] = b"pock/webauthn-prf/v1";

fn prf_kek(prf_secret_b64: &str) -> Result<[u8; 32], CoreError> {
    let secret = unb64(prf_secret_b64)?;
    Ok(hkdf_sha256(&secret, b"", PRF_INFO))
}

pub fn enroll_prf(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    prf_secret_b64: &str,
) -> Result<String, CoreError> {
    let sk_bytes = unb64(secret_key_b64)?;
    let sk_arr: [u8; 16] = sk_bytes.as_slice().try_into().map_err(|_| CoreError::Flow("bad secret key".into()))?;
    let secret_key = SecretKey::from_bytes(sk_arr);
    let wrapped_auk: WrappedAuk = serde_json::from_str(wrapped_auk_json)?;
    let auk = unwrap_with_passphrase(&wrapped_auk, passphrase.as_bytes(), &secret_key)
        .map_err(|_| CoreError::Flow("wrong passphrase or secret key".into()))?;
    let kek = prf_kek(prf_secret_b64)?;
    let wrapped_prf = wrap_with_kek(&auk, &kek, "webauthn-prf");
    Ok(serde_json::to_string(&wrapped_prf)?)
}

pub fn unlock_prf(
    prf_secret_b64: &str,
    wrapped_auk_prf_json: &str,
    wrapped_identity_b64: &str,
) -> Result<String, CoreError> {
    let wrapped_prf: WrappedAuk = serde_json::from_str(wrapped_auk_prf_json)?;
    let kek = prf_kek(prf_secret_b64)?;
    let auk = unwrap_with_kek(&wrapped_prf, &kek)
        .map_err(|_| CoreError::Flow("touch id unlock failed".into()))?;
    let identity = unwrap_identity(&auk, wrapped_identity_b64)?;
    Ok(serde_json::json!({ "identitySecretB64": b64(&identity.to_secret_bytes()) }).to_string())
}

// ---- Account Master Key (AMK) -------------------------------------------------
//
// The AMK is a random Ed25519 key sealed under the AUK — the passphrase/passkey-
// gated root of trust. The AUK is derived inside the core and never crosses the
// binding boundary; AMK functions take unlock inputs and return only the AMK
// public key + the AUK-sealed `wrappedAmk` blob, or a signature.

/// Given an unsealed AUK, create-or-load the AMK. `existing_wrapped_amk` empty →
/// mint a fresh Ed25519 key and seal it; non-empty → load it (idempotent).
/// Returns `(SignSecret, wrappedAmk)`.
fn amk_ensure_from_auk(auk: &Auk, existing_wrapped_amk: &str) -> Result<(SignSecret, String), CoreError> {
    if existing_wrapped_amk.is_empty() {
        let s = SignSecret::random();
        let wrapped = wrap_secret(auk, &s.to_bytes());
        Ok((s, wrapped))
    } else {
        let bytes = unwrap_secret(auk, existing_wrapped_amk)?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| CoreError::Flow("bad amk length".into()))?;
        Ok((SignSecret::from_bytes(&arr)?, existing_wrapped_amk.to_string()))
    }
}

/// Unseal the AMK from the AUK and Ed25519-sign `msg`. Returns base64 signature.
fn amk_sign_from_auk(auk: &Auk, wrapped_amk: &str, msg: &[u8]) -> Result<String, CoreError> {
    let bytes = unwrap_secret(auk, wrapped_amk)?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| CoreError::Flow("bad amk length".into()))?;
    let s = SignSecret::from_bytes(&arr)?;
    Ok(b64(&s.sign(msg)))
}

/// Create-or-load the Account Master Key (Ed25519) sealed under the AUK
/// (passphrase path). Returns JSON `{ "amkPub": b64, "wrappedAmk": b64 }`.
pub fn amk_ensure(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    existing_wrapped_amk: &str,
) -> Result<String, CoreError> {
    let auk = unlock_auk(passphrase, secret_key_b64, wrapped_auk_json)?;
    let (amk_secret, wrapped_amk) = amk_ensure_from_auk(&auk, existing_wrapped_amk)?;
    Ok(serde_json::json!({
        "amkPub": b64(amk_secret.public().as_bytes()),
        "wrappedAmk": wrapped_amk,
    })
    .to_string())
}

/// Sign `msg` with the AMK (unsealed under the AUK, passphrase path). Returns
/// base64 Ed25519 signature.
pub fn amk_sign(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    wrapped_amk: &str,
    msg: &[u8],
) -> Result<String, CoreError> {
    let auk = unlock_auk(passphrase, secret_key_b64, wrapped_auk_json)?;
    amk_sign_from_auk(&auk, wrapped_amk, msg)
}

fn auk_from_prf(prf_secret_b64: &str, wrapped_auk_prf_json: &str) -> Result<Auk, CoreError> {
    let wrapped_prf: WrappedAuk = serde_json::from_str(wrapped_auk_prf_json)?;
    let kek = prf_kek(prf_secret_b64)?;
    unwrap_with_kek(&wrapped_prf, &kek).map_err(|_| CoreError::Flow("touch id unlock failed".into()))
}

/// Create-or-load the AMK sealed under the AUK (PRF / passkey path).
pub fn amk_ensure_prf(
    prf_secret_b64: &str,
    wrapped_auk_prf_json: &str,
    existing_wrapped_amk: &str,
) -> Result<String, CoreError> {
    let auk = auk_from_prf(prf_secret_b64, wrapped_auk_prf_json)?;
    let (amk_secret, wrapped_amk) = amk_ensure_from_auk(&auk, existing_wrapped_amk)?;
    Ok(serde_json::json!({
        "amkPub": b64(amk_secret.public().as_bytes()),
        "wrappedAmk": wrapped_amk,
    })
    .to_string())
}

/// Sign `msg` with the AMK (unsealed under the AUK, PRF / passkey path).
pub fn amk_sign_prf(
    prf_secret_b64: &str,
    wrapped_auk_prf_json: &str,
    wrapped_amk: &str,
    msg: &[u8],
) -> Result<String, CoreError> {
    let auk = auk_from_prf(prf_secret_b64, wrapped_auk_prf_json)?;
    amk_sign_from_auk(&auk, wrapped_amk, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_unlock_vault_roundtrip() {
        let created = create_vault("correct horse battery staple").unwrap();
        let v: serde_json::Value = serde_json::from_str(&created).unwrap();
        assert!(v.get("secretKey").is_some(), "create_vault JSON must expose secretKey: {created}");

        let secret_key = v["secretKey"].as_str().unwrap();
        let wrapped_auk = serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap();
        let wrapped_identity = v["wrappedIdentity"].as_str().unwrap();

        let unlocked =
            unlock_vault("correct horse battery staple", secret_key, &wrapped_auk, wrapped_identity).unwrap();
        let u: serde_json::Value = serde_json::from_str(&unlocked).unwrap();
        assert_eq!(u["identitySecretB64"].as_str().unwrap(), v["identitySecretB64"].as_str().unwrap());
    }

    #[test]
    fn enroll_and_unlock_prf() {
        let created = create_vault("pw").unwrap();
        let v: serde_json::Value = serde_json::from_str(&created).unwrap();
        let sk = v["secretKey"].as_str().unwrap();
        let wpp = serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap();
        let wid = v["wrappedIdentity"].as_str().unwrap();

        // 43 base64url 'A's decode to 32 zero bytes - a fixed stand-in for the
        // authenticator's PRF output.
        let prf_secret = "A".repeat(43);
        let wrapped_prf = enroll_prf("pw", sk, &wpp, &prf_secret).unwrap();
        let unlocked = unlock_prf(&prf_secret, &wrapped_prf, wid).unwrap();
        let u: serde_json::Value = serde_json::from_str(&unlocked).unwrap();
        assert_eq!(u["identitySecretB64"].as_str().unwrap(), v["identitySecretB64"].as_str().unwrap());
    }

    #[test]
    fn amk_ensure_is_idempotent_and_sign_verifies() {
        let created = create_vault("correct horse").unwrap();
        let v: serde_json::Value = serde_json::from_str(&created).unwrap();
        let sk = v["secretKey"].as_str().unwrap();
        let wpp = serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap();

        // First ensure mints the AMK.
        let out1: serde_json::Value =
            serde_json::from_str(&amk_ensure("correct horse", sk, &wpp, "").unwrap()).unwrap();
        let amk_pub = out1["amkPub"].as_str().unwrap().to_string();
        let wrapped_amk = out1["wrappedAmk"].as_str().unwrap().to_string();

        // Second ensure with the existing blob returns the SAME public key.
        let out2: serde_json::Value =
            serde_json::from_str(&amk_ensure("correct horse", sk, &wpp, &wrapped_amk).unwrap()).unwrap();
        assert_eq!(out2["amkPub"].as_str().unwrap(), amk_pub);

        let msg = b"succession-cert-bytes";
        let sig = amk_sign("correct horse", sk, &wpp, &wrapped_amk, msg).unwrap();
        assert!(verify_message(&amk_pub, msg, &sig).unwrap());

        // Wrong passphrase must not sign.
        assert!(amk_sign("wrong", sk, &wpp, &wrapped_amk, b"x").is_err());
    }

    #[test]
    fn amk_prf_path_signs_and_verifies() {
        let created = create_vault("pw").unwrap();
        let v: serde_json::Value = serde_json::from_str(&created).unwrap();
        let sk = v["secretKey"].as_str().unwrap();
        let wpp = serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap();
        let prf_secret = "A".repeat(43);
        let wrapped_prf = enroll_prf("pw", sk, &wpp, &prf_secret).unwrap();

        let out: serde_json::Value =
            serde_json::from_str(&amk_ensure_prf(&prf_secret, &wrapped_prf, "").unwrap()).unwrap();
        let amk_pub = out["amkPub"].as_str().unwrap().to_string();
        let wrapped_amk = out["wrappedAmk"].as_str().unwrap().to_string();

        let sig = amk_sign_prf(&prf_secret, &wrapped_prf, &wrapped_amk, b"cert").unwrap();
        assert!(verify_message(&amk_pub, b"cert", &sig).unwrap());
    }
}
