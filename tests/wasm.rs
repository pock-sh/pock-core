#![cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;
use pock_core::wasm::{wasm_create_vault, wasm_decrypt_item, wasm_decrypt_share, wasm_encrypt_item, wasm_encrypt_share, wasm_generate_identity, wasm_unlock_vault};

#[wasm_bindgen_test]
fn share_roundtrip_both_ciphers() {
    let bundle = r#"{"v":1,"files":[{"name":".env","content":"K=V\n"}]}"#;
    for cipher in ["xchacha", "xwing"] {
        let enc = wasm_encrypt_share(bundle, cipher).unwrap();
        let v: serde_json::Value = serde_json::from_str(&enc).unwrap();
        let env_b64 = v["envelope_b64"].as_str().unwrap();
        let blob = v["key_blob"].as_str().unwrap();
        let back = wasm_decrypt_share(env_b64, blob).unwrap();
        assert!(back.contains("K=V"));
    }
}

#[wasm_bindgen_test]
fn end_to_end_identity_item_roundtrip() {
    let gen_json = wasm_generate_identity();
    let gen: serde_json::Value = serde_json::from_str(&gen_json).unwrap();
    let secret_b64 = gen["secret_b64"].as_str().unwrap().to_string();
    let public_blob = serde_json::to_string(&gen["public"]).unwrap();

    let recipients_json = format!("[{}]", public_blob);
    let item_json = wasm_encrypt_item("MY_SECRET=42", &recipients_json).unwrap();

    let recovered = wasm_decrypt_item(&item_json, &secret_b64).unwrap();
    assert_eq!(recovered, "MY_SECRET=42");
}

#[wasm_bindgen_test]
fn create_then_unlock_vault() {
    let created = wasm_create_vault("correct horse battery").unwrap();
    let v: serde_json::Value = serde_json::from_str(&created).unwrap();
    let secret_key = v["secretKey"].as_str().unwrap();
    let wrapped_auk = serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap();
    let wrapped_identity = v["wrappedIdentity"].as_str().unwrap();

    let unlocked = wasm_unlock_vault("correct horse battery", secret_key, &wrapped_auk, wrapped_identity).unwrap();
    let u: serde_json::Value = serde_json::from_str(&unlocked).unwrap();
    // Unlocked identity secret reproduces the same public identity used at create.
    assert_eq!(u["identitySecretB64"].as_str().unwrap(), v["identitySecretB64"].as_str().unwrap());
}

#[wasm_bindgen_test]
fn unlock_wrong_passphrase_fails() {
    let created = wasm_create_vault("right").unwrap();
    let v: serde_json::Value = serde_json::from_str(&created).unwrap();
    let res = wasm_unlock_vault(
        "wrong",
        v["secretKey"].as_str().unwrap(),
        &serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap(),
        v["wrappedIdentity"].as_str().unwrap(),
    );
    assert!(res.is_err());
}
