#![cfg(feature = "wasm")]
use crate::auk::{
    unwrap_identity, unwrap_with_passphrase, wrap_identity, wrap_with_kek,
    wrap_with_passphrase, Auk, SecretKey, WrappedAuk,
};
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
