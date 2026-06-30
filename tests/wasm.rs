#![cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;
use pock_core::wasm::{wasm_decrypt_item, wasm_encrypt_item, wasm_generate_identity};

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
