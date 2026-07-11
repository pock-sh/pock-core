#![cfg(feature = "wasm")]
use crate::aead::{open_aad, seal_aad, AeadKey};
use crate::auk::{
    unwrap_identity, unwrap_secret, unwrap_with_kek, unwrap_with_passphrase, wrap_identity,
    wrap_secret, wrap_with_kek, wrap_with_passphrase, Auk, SecretKey, WrappedAuk,
};
use crate::sign::{SignPublic, SignSecret};
use crate::identity::{Identity, PublicIdentity, PublicIdentityBlob};
use crate::item::{decrypt_item, encrypt_item, EncryptedItem};
use crate::kdf::{hkdf_sha256, KdfProfile};
use crate::share::{decrypt_share, encrypt_share, Bundle, ShareCipher};

use base64::Engine;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// On wasm32 we depend on getrandom 0.4 (via x-wing -> rand_core 0.10) with its
// `wasm_js` backend. The renamed `getrandom_v04` dependency in Cargo.toml turns
// on that feature; reference it here so the dependency is never pruned.
#[cfg(target_arch = "wasm32")]
#[allow(unused_imports)]
use getrandom_v04 as _;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
fn unb64(s: &str) -> Result<Vec<u8>, JsError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| JsError::new(&e.to_string()))
}

#[derive(Serialize, Deserialize)]
pub struct GeneratedIdentity {
    pub secret_b64: String,
    pub public: PublicIdentityBlob,
}

#[wasm_bindgen]
pub fn wasm_generate_identity() -> String {
    let id = Identity::generate();
    let out = GeneratedIdentity { secret_b64: b64(&id.to_secret_bytes()), public: id.public().to_blob() };
    serde_json::to_string(&out).expect("serialize identity")
}

#[wasm_bindgen]
pub fn wasm_encrypt_item(value: &str, recipient_pub_blobs_json: &str) -> Result<String, JsError> {
    let blobs: Vec<PublicIdentityBlob> = serde_json::from_str(recipient_pub_blobs_json)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let mut recipients = Vec::new();
    for b in &blobs {
        recipients.push(PublicIdentity::from_blob(b).map_err(|e| JsError::new(&e.to_string()))?.kem);
    }
    let item = encrypt_item(value.as_bytes(), &recipients).map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&item).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_decrypt_item(item_json: &str, identity_secret_b64: &str) -> Result<String, JsError> {
    let item: EncryptedItem = serde_json::from_str(item_json).map_err(|e| JsError::new(&e.to_string()))?;
    let id = Identity::from_secret_bytes(&unb64(identity_secret_b64)?)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let pub_kem = id.public().kem;
    let plaintext = decrypt_item(&item, &id.kem, &pub_kem).map_err(|e| JsError::new(&e.to_string()))?;
    String::from_utf8(plaintext).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_encrypt_share(bundle_json: &str, cipher_id: &str) -> Result<String, JsError> {
    let bundle: Bundle = serde_json::from_str(bundle_json).map_err(|e| JsError::new(&e.to_string()))?;
    let cipher = ShareCipher::from_id(cipher_id).ok_or_else(|| JsError::new("unknown cipher id"))?;
    let (envelope, key_blob) = encrypt_share(&bundle, cipher).map_err(|e| JsError::new(&e.to_string()))?;
    let out = serde_json::json!({ "envelope_b64": b64(&envelope), "key_blob": key_blob });
    Ok(out.to_string())
}

#[wasm_bindgen]
pub fn wasm_decrypt_share(envelope_b64: &str, key_blob: &str) -> Result<String, JsError> {
    let envelope = unb64(envelope_b64)?;
    let bundle = decrypt_share(&envelope, key_blob).map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_string(&bundle).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_create_vault(passphrase: &str) -> Result<String, JsError> {
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
        "wrappedAukPassphrase": serde_json::to_value(&wrapped_pp).map_err(|e| JsError::new(&e.to_string()))?,
        "wrappedAukRecovery": serde_json::to_value(&wrapped_rec).map_err(|e| JsError::new(&e.to_string()))?,
        "identitySecretB64": b64(&identity.to_secret_bytes()),
    });
    Ok(out.to_string())
}

#[wasm_bindgen]
pub fn wasm_unlock_vault(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    wrapped_identity_b64: &str,
) -> Result<String, JsError> {
    let sk_bytes = unb64(secret_key_b64)?;
    let sk_arr: [u8; 16] = sk_bytes.as_slice().try_into().map_err(|_| JsError::new("bad secret key"))?;
    let secret_key = SecretKey::from_bytes(sk_arr);
    let wrapped_auk: WrappedAuk = serde_json::from_str(wrapped_auk_json).map_err(|e| JsError::new(&e.to_string()))?;
    let auk = unwrap_with_passphrase(&wrapped_auk, passphrase.as_bytes(), &secret_key)
        .map_err(|_| JsError::new("wrong passphrase or secret key"))?;
    let identity = unwrap_identity(&auk, wrapped_identity_b64).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::json!({ "identitySecretB64": b64(&identity.to_secret_bytes()) }).to_string())
}

/// Unlock using ONLY the recovery code (a single high-entropy factor). No passphrase or
/// Secret Key needed — this is the "I forgot my passphrase" path.
#[wasm_bindgen]
pub fn wasm_unlock_recovery(
    recovery_code: &str,
    wrapped_recovery_json: &str,
    wrapped_identity_b64: &str,
) -> Result<String, JsError> {
    let wrapped_rec: WrappedAuk =
        serde_json::from_str(wrapped_recovery_json).map_err(|e| JsError::new(&e.to_string()))?;
    let recovery_kek = hkdf_sha256(recovery_code.trim().as_bytes(), b"", b"pock/recovery/v1");
    let auk = unwrap_with_kek(&wrapped_rec, &recovery_kek).map_err(|_| JsError::new("wrong recovery code"))?;
    let identity = unwrap_identity(&auk, wrapped_identity_b64).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::json!({ "identitySecretB64": b64(&identity.to_secret_bytes()) }).to_string())
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
    let wrapped_rec: WrappedAuk =
        serde_json::from_str(wrapped_recovery_json).map_err(|e| JsError::new(&e.to_string()))?;
    let recovery_kek = hkdf_sha256(recovery_code.trim().as_bytes(), b"", b"pock/recovery/v1");
    let auk = unwrap_with_kek(&wrapped_rec, &recovery_kek).map_err(|_| JsError::new("wrong recovery code"))?;
    let sk_bytes = unb64(secret_key_b64)?;
    let sk_arr: [u8; 16] = sk_bytes.as_slice().try_into().map_err(|_| JsError::new("bad secret key"))?;
    let secret_key = SecretKey::from_bytes(sk_arr);
    let wrapped_pp = wrap_with_passphrase(&auk, new_passphrase.as_bytes(), &secret_key, KdfProfile::Constrained);
    Ok(serde_json::json!({
        "wrappedAukPassphrase": serde_json::to_value(&wrapped_pp).map_err(|e| JsError::new(&e.to_string()))?,
    })
    .to_string())
}

fn aead_key(key_b64: &str) -> Result<AeadKey, JsError> {
    let kb = unb64(key_b64)?;
    let arr: [u8; 32] = kb.as_slice().try_into().map_err(|_| JsError::new("bad symmetric key length"))?;
    Ok(AeadKey::from_bytes(arr))
}

/// Random 32-byte XChaCha20-Poly1305 key, base64. Used as a chat channel key
/// or a per-attachment blob key.
#[wasm_bindgen]
pub fn wasm_generate_symmetric_key() -> String {
    b64(AeadKey::random().as_bytes())
}

/// Symmetric AEAD seal: returns nonce||ciphertext. `aad` binds context (e.g.
/// `channel_id|key_version|sender_id`) into the tag without being stored.
#[wasm_bindgen]
pub fn wasm_seal_symmetric(key_b64: &str, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    Ok(seal_aad(&aead_key(key_b64)?, plaintext, aad))
}

#[wasm_bindgen]
pub fn wasm_open_symmetric(key_b64: &str, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    open_aad(&aead_key(key_b64)?, blob, aad).map_err(|_| JsError::new("decrypt failed (wrong key or tampered)"))
}

/// Ed25519 signature over `msg` with the identity's signing key, base64.
#[wasm_bindgen]
pub fn wasm_sign_message(identity_secret_b64: &str, msg: &[u8]) -> Result<String, JsError> {
    let id = Identity::from_secret_bytes(&unb64(identity_secret_b64)?)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(b64(&id.sign.sign(msg)))
}

#[wasm_bindgen]
pub fn wasm_verify_message(sign_pubkey_b64: &str, msg: &[u8], sig_b64: &str) -> Result<bool, JsError> {
    let pk_bytes = unb64(sign_pubkey_b64)?;
    let pk_arr: [u8; 32] = pk_bytes.as_slice().try_into().map_err(|_| JsError::new("bad sign pubkey length"))?;
    let sig_bytes = unb64(sig_b64)?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| JsError::new("bad signature length"))?;
    Ok(SignPublic::from_bytes(pk_arr).verify(msg, &sig_arr).is_ok())
}

fn parse_sk(secret_key_b64: &str) -> Result<SecretKey, JsError> {
    let sk_bytes = unb64(secret_key_b64)?;
    let sk_arr: [u8; 16] = sk_bytes.as_slice().try_into().map_err(|_| JsError::new("bad secret key"))?;
    Ok(SecretKey::from_bytes(sk_arr))
}

fn unlock_auk(passphrase: &str, secret_key_b64: &str, wrapped_auk_json: &str) -> Result<Auk, JsError> {
    let wrapped: WrappedAuk = serde_json::from_str(wrapped_auk_json).map_err(|e| JsError::new(&e.to_string()))?;
    unwrap_with_passphrase(&wrapped, passphrase.as_bytes(), &parse_sk(secret_key_b64)?)
        .map_err(|_| JsError::new("wrong passphrase or secret key"))
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
    let auk = unlock_auk(old_passphrase, secret_key_b64, wrapped_auk_json)?;
    let wrapped = wrap_with_passphrase(&auk, new_passphrase.as_bytes(), &parse_sk(secret_key_b64)?, KdfProfile::Constrained);
    Ok(serde_json::json!({
        "wrappedAukPassphrase": serde_json::to_value(&wrapped).map_err(|e| JsError::new(&e.to_string()))?,
    })
    .to_string())
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
    let auk = unlock_auk(passphrase, old_secret_key_b64, wrapped_auk_json)?;
    let new_sk = SecretKey::random();
    let wrapped = wrap_with_passphrase(&auk, passphrase.as_bytes(), &new_sk, KdfProfile::Constrained);
    Ok(serde_json::json!({
        "secretKey": b64(new_sk.as_bytes()),
        "wrappedAukPassphrase": serde_json::to_value(&wrapped).map_err(|e| JsError::new(&e.to_string()))?,
    })
    .to_string())
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
    use rand::RngCore;
    let auk = unlock_auk(passphrase, secret_key_b64, wrapped_auk_json)?;
    let mut rb = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut rb);
    let recovery_code = b64(&rb);
    let recovery_kek = hkdf_sha256(recovery_code.as_bytes(), b"", b"pock/recovery/v1");
    let wrapped = wrap_with_kek(&auk, &recovery_kek, "recovery");
    Ok(serde_json::json!({
        "recoveryCode": recovery_code,
        "wrappedAukRecovery": serde_json::to_value(&wrapped).map_err(|e| JsError::new(&e.to_string()))?,
    })
    .to_string())
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
    let auk = unlock_auk(passphrase, secret_key_b64, wrapped_auk_json)?;
    let old = unwrap_identity(&auk, old_wrapped_identity_b64).map_err(|e| JsError::new(&e.to_string()))?;
    let fresh = Identity::generate();
    let pubid = fresh.public();
    Ok(serde_json::json!({
        "signPubkey": b64(pubid.sign.as_bytes()),
        "kemPubkey": b64(&pubid.kem.as_bytes()),
        "wrappedIdentity": wrap_identity(&auk, &fresh),
        "identitySecretB64": b64(&fresh.to_secret_bytes()),
        "oldIdentitySecretB64": b64(&old.to_secret_bytes()),
        "publicBlob": serde_json::to_value(pubid.to_blob()).map_err(|e| JsError::new(&e.to_string()))?,
    })
    .to_string())
}

/// Encrypted binary vault backup (.pockvault). Standalone: only the backup
/// passphrase is needed to restore.
#[wasm_bindgen]
pub fn wasm_export_backup(json: &str, passphrase: &str) -> Result<Vec<u8>, JsError> {
    crate::backup::export_backup(json.as_bytes(), passphrase.as_bytes())
        .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_import_backup(data: &[u8], passphrase: &str) -> Result<String, JsError> {
    let pt = crate::backup::import_backup(data, passphrase.as_bytes())
        .map_err(|_| JsError::new("wrong passphrase or corrupted backup"))?;
    String::from_utf8(pt).map_err(|e| JsError::new(&e.to_string()))
}

const PRF_INFO: &[u8] = b"pock/webauthn-prf/v1";

fn prf_kek(prf_secret_b64: &str) -> Result<[u8; 32], JsError> {
    let secret = unb64(prf_secret_b64)?;
    Ok(hkdf_sha256(&secret, b"", PRF_INFO))
}

#[wasm_bindgen]
pub fn wasm_enroll_prf(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    prf_secret_b64: &str,
) -> Result<String, JsError> {
    let sk_bytes = unb64(secret_key_b64)?;
    let sk_arr: [u8; 16] = sk_bytes.as_slice().try_into().map_err(|_| JsError::new("bad secret key"))?;
    let secret_key = SecretKey::from_bytes(sk_arr);
    let wrapped_auk: WrappedAuk = serde_json::from_str(wrapped_auk_json).map_err(|e| JsError::new(&e.to_string()))?;
    let auk = unwrap_with_passphrase(&wrapped_auk, passphrase.as_bytes(), &secret_key)
        .map_err(|_| JsError::new("wrong passphrase or secret key"))?;
    let kek = prf_kek(prf_secret_b64)?;
    let wrapped_prf = wrap_with_kek(&auk, &kek, "webauthn-prf");
    serde_json::to_string(&wrapped_prf).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_unlock_prf(
    prf_secret_b64: &str,
    wrapped_auk_prf_json: &str,
    wrapped_identity_b64: &str,
) -> Result<String, JsError> {
    let wrapped_prf: WrappedAuk = serde_json::from_str(wrapped_auk_prf_json).map_err(|e| JsError::new(&e.to_string()))?;
    let kek = prf_kek(prf_secret_b64)?;
    let auk = unwrap_with_kek(&wrapped_prf, &kek).map_err(|_| JsError::new("touch id unlock failed"))?;
    let identity = unwrap_identity(&auk, wrapped_identity_b64).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(serde_json::json!({ "identitySecretB64": b64(&identity.to_secret_bytes()) }).to_string())
}

// ---- Account Master Key (AMK) -------------------------------------------------
//
// The AMK is a random Ed25519 key sealed under the AUK — the passphrase/passkey-
// gated root of trust. The AUK is derived inside WASM and never crosses the
// boundary; AMK functions take unlock inputs and return only the AMK public key +
// the AUK-sealed `wrappedAmk` blob, or a signature.

/// Given an unsealed AUK, create-or-load the AMK. `existing_wrapped_amk` empty →
/// mint a fresh Ed25519 key and seal it; non-empty → load it (idempotent).
/// Returns `(SignSecret, wrappedAmk)`.
fn amk_ensure_from_auk(auk: &Auk, existing_wrapped_amk: &str) -> Result<(SignSecret, String), JsError> {
    if existing_wrapped_amk.is_empty() {
        let s = SignSecret::random();
        let wrapped = wrap_secret(auk, &s.to_bytes());
        Ok((s, wrapped))
    } else {
        let bytes = unwrap_secret(auk, existing_wrapped_amk).map_err(|e| JsError::new(&e.to_string()))?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| JsError::new("bad amk length"))?;
        Ok((SignSecret::from_bytes(&arr).map_err(|e| JsError::new(&e.to_string()))?, existing_wrapped_amk.to_string()))
    }
}

/// Unseal the AMK from the AUK and Ed25519-sign `msg`. Returns base64 signature.
fn amk_sign_from_auk(auk: &Auk, wrapped_amk: &str, msg: &[u8]) -> Result<String, JsError> {
    let bytes = unwrap_secret(auk, wrapped_amk).map_err(|e| JsError::new(&e.to_string()))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| JsError::new("bad amk length"))?;
    let s = SignSecret::from_bytes(&arr).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(b64(&s.sign(msg)))
}

/// Create-or-load the Account Master Key (Ed25519) sealed under the AUK
/// (passphrase path). Returns JSON `{ "amkPub": b64, "wrappedAmk": b64 }`.
#[wasm_bindgen]
pub fn wasm_amk_ensure(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    existing_wrapped_amk: &str,
) -> Result<String, JsError> {
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
#[wasm_bindgen]
pub fn wasm_amk_sign(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    wrapped_amk: &str,
    msg: &[u8],
) -> Result<String, JsError> {
    let auk = unlock_auk(passphrase, secret_key_b64, wrapped_auk_json)?;
    amk_sign_from_auk(&auk, wrapped_amk, msg)
}

fn auk_from_prf(prf_secret_b64: &str, wrapped_auk_prf_json: &str) -> Result<Auk, JsError> {
    let wrapped_prf: WrappedAuk =
        serde_json::from_str(wrapped_auk_prf_json).map_err(|e| JsError::new(&e.to_string()))?;
    let kek = prf_kek(prf_secret_b64)?;
    unwrap_with_kek(&wrapped_prf, &kek).map_err(|_| JsError::new("touch id unlock failed"))
}

/// Create-or-load the AMK sealed under the AUK (PRF / passkey path).
#[wasm_bindgen]
pub fn wasm_amk_ensure_prf(
    prf_secret_b64: &str,
    wrapped_auk_prf_json: &str,
    existing_wrapped_amk: &str,
) -> Result<String, JsError> {
    let auk = auk_from_prf(prf_secret_b64, wrapped_auk_prf_json)?;
    let (amk_secret, wrapped_amk) = amk_ensure_from_auk(&auk, existing_wrapped_amk)?;
    Ok(serde_json::json!({
        "amkPub": b64(amk_secret.public().as_bytes()),
        "wrappedAmk": wrapped_amk,
    })
    .to_string())
}

/// Sign `msg` with the AMK (unsealed under the AUK, PRF / passkey path).
#[wasm_bindgen]
pub fn wasm_amk_sign_prf(
    prf_secret_b64: &str,
    wrapped_auk_prf_json: &str,
    wrapped_amk: &str,
    msg: &[u8],
) -> Result<String, JsError> {
    let auk = auk_from_prf(prf_secret_b64, wrapped_auk_prf_json)?;
    amk_sign_from_auk(&auk, wrapped_amk, msg)
}
