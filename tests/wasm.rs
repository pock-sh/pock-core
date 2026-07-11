#![cfg(all(target_arch = "wasm32", feature = "wasm"))]
use wasm_bindgen_test::*;
use pock_core::wasm::{wasm_amk_ensure, wasm_amk_ensure_prf, wasm_amk_sign, wasm_amk_sign_prf, wasm_create_vault, wasm_decrypt_item, wasm_decrypt_share, wasm_encrypt_item, wasm_encrypt_share, wasm_enroll_prf, wasm_generate_identity, wasm_unlock_prf, wasm_unlock_vault, wasm_verify_message};

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

#[wasm_bindgen_test]
fn enroll_then_unlock_prf() {
    let created = wasm_create_vault("pw").unwrap();
    let v: serde_json::Value = serde_json::from_str(&created).unwrap();
    let sk = v["secretKey"].as_str().unwrap();
    let wpp = serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap();
    let wid = v["wrappedIdentity"].as_str().unwrap();

    // 43 base64url 'A's decode to 32 zero bytes - a fixed stand-in for the
    // authenticator's PRF output.
    let prf_secret = "A".repeat(43);
    let wrapped_prf = wasm_enroll_prf("pw", sk, &wpp, &prf_secret).unwrap();
    let unlocked = wasm_unlock_prf(&prf_secret, &wrapped_prf, wid).unwrap();
    let u: serde_json::Value = serde_json::from_str(&unlocked).unwrap();
    assert_eq!(u["identitySecretB64"].as_str().unwrap(), v["identitySecretB64"].as_str().unwrap());
}

#[wasm_bindgen_test]
fn amk_ensure_is_idempotent_and_sign_verifies() {
    // Build a real vault: AUK wrapped under a passphrase + secret key.
    let created = wasm_create_vault("correct horse").unwrap();
    let v: serde_json::Value = serde_json::from_str(&created).unwrap();
    let sk = v["secretKey"].as_str().unwrap();
    let wpp = serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap();

    // First ensure mints the AMK.
    let out1: serde_json::Value =
        serde_json::from_str(&wasm_amk_ensure("correct horse", sk, &wpp, "").unwrap()).unwrap();
    let amk_pub = out1["amkPub"].as_str().unwrap().to_string();
    let wrapped_amk = out1["wrappedAmk"].as_str().unwrap().to_string();

    // Second ensure with the existing blob returns the SAME public key (idempotent).
    let out2: serde_json::Value =
        serde_json::from_str(&wasm_amk_ensure("correct horse", sk, &wpp, &wrapped_amk).unwrap()).unwrap();
    assert_eq!(out2["amkPub"].as_str().unwrap(), amk_pub);

    // Sign with the AMK and verify against amkPub via the existing verify fn.
    let msg = b"succession-cert-bytes";
    let sig = wasm_amk_sign("correct horse", sk, &wpp, &wrapped_amk, msg).unwrap();
    assert!(wasm_verify_message(&amk_pub, msg, &sig).unwrap());
}

#[wasm_bindgen_test]
fn amk_sign_rejects_wrong_passphrase() {
    let created = wasm_create_vault("right").unwrap();
    let v: serde_json::Value = serde_json::from_str(&created).unwrap();
    let sk = v["secretKey"].as_str().unwrap();
    let wpp = serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap();
    let out: serde_json::Value =
        serde_json::from_str(&wasm_amk_ensure("right", sk, &wpp, "").unwrap()).unwrap();
    let wrapped_amk = out["wrappedAmk"].as_str().unwrap().to_string();
    assert!(wasm_amk_sign("wrong", sk, &wpp, &wrapped_amk, b"x").is_err());
}

#[wasm_bindgen_test]
fn amk_prf_path_signs_and_verifies() {
    // Build a vault, enroll a PRF passkey wrap, then drive the AMK PRF path.
    let created = wasm_create_vault("pw").unwrap();
    let v: serde_json::Value = serde_json::from_str(&created).unwrap();
    let sk = v["secretKey"].as_str().unwrap();
    let wpp = serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap();
    let prf_secret = "A".repeat(43); // 32 zero bytes, stand-in for authenticator PRF output
    let wrapped_prf = wasm_enroll_prf("pw", sk, &wpp, &prf_secret).unwrap();

    let out: serde_json::Value =
        serde_json::from_str(&wasm_amk_ensure_prf(&prf_secret, &wrapped_prf, "").unwrap()).unwrap();
    let amk_pub = out["amkPub"].as_str().unwrap().to_string();
    let wrapped_amk = out["wrappedAmk"].as_str().unwrap().to_string();

    let sig = wasm_amk_sign_prf(&prf_secret, &wrapped_prf, &wrapped_amk, b"cert").unwrap();
    assert!(wasm_verify_message(&amk_pub, b"cert", &sig).unwrap());
}
