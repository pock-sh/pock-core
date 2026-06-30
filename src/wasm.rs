#![cfg(feature = "wasm")]
use crate::identity::{Identity, PublicIdentity, PublicIdentityBlob};
use crate::item::{decrypt_item, encrypt_item, EncryptedItem};
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
