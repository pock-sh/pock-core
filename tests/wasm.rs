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

// ---------------------------------------------------------------------------
// 0.3.0 additions: `pns1.` namespace protection + key-log canonical bytes.
// These run under wasm because the browser is the surface that has to agree
// with the TS implementation they replace.
// ---------------------------------------------------------------------------

/// The vector `app/lib/namespace-crypto.ts` produced (all-sevens NK, "hunter2",
/// an all-zero salt). If wasm ever diverges from native here, every namespace
/// already stored by the browser stops opening.
#[wasm_bindgen_test]
fn wasm_unwraps_the_typescript_namespace_vector() {
    use pock_core::wasm::{wasm_ns_nk_hash, wasm_ns_unprotect_value, wasm_ns_unwrap_nk};
    const SALT: &str = "AAAAAAAAAAAAAAAAAAAAAA==";
    const WRAPPED: &str =
        "U9FZTfIDWBdLPBSB.rNjHLoGoborbEucrhf5F7H+j8fFPmC/p6ZQ8ZAxl+gVVP3U/j/s/uJf4IEeH3Blz";
    const PROTECTED: &str = "pns1.3dPQK9tz4wEysh/3.Pm66ipYUxn++AKieo88QTuFaap4w4A==";

    let nk = wasm_ns_unwrap_nk(WRAPPED, "hunter2", SALT).unwrap();
    assert_eq!(nk, "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=");
    assert_eq!(wasm_ns_nk_hash(&nk).unwrap(), "S7Bvjk46dxXSAdVz0KpCN2LlXavWGiwCJ4+lbMbSlOA=");
    assert_eq!(wasm_ns_unprotect_value(&nk, PROTECTED).unwrap(), "s3cret");
    assert!(wasm_ns_unwrap_nk(WRAPPED, "nope", SALT).is_err());
}

#[wasm_bindgen_test]
fn wasm_namespace_roundtrip() {
    use pock_core::wasm::{
        wasm_ns_is_protected, wasm_ns_protect_value, wasm_ns_random_nk, wasm_ns_random_salt,
        wasm_ns_unprotect_value, wasm_ns_unwrap_nk, wasm_ns_wrap_nk,
    };
    let nk = wasm_ns_random_nk();
    let salt = wasm_ns_random_salt();
    let wrapped = wasm_ns_wrap_nk(&nk, "pw", &salt).unwrap();
    assert_eq!(wasm_ns_unwrap_nk(&wrapped, "pw", &salt).unwrap(), nk);

    let blob = wasm_ns_protect_value(&nk, "s3cret").unwrap();
    assert!(wasm_ns_is_protected(&blob));
    assert_eq!(wasm_ns_unprotect_value(&nk, &blob).unwrap(), "s3cret");
}

#[wasm_bindgen_test]
fn wasm_keylog_bytes_and_message_digest() {
    use pock_core::wasm::{wasm_cert_bytes, wasm_leaf_bytes, wasm_message_digest, wasm_sth_message};
    let cert = r#"{"userId":"u","kemPubkey":"K","signPubkey":"S","rot":{"custodians":["A","B"],"threshold":2},"principalSeq":4,"ts":9}"#;
    assert_eq!(
        String::from_utf8(wasm_cert_bytes(cert).unwrap()).unwrap(),
        "pock-keycert-v1\nu\nK\nS\nA,B|2\n4\n9"
    );
    assert_eq!(
        String::from_utf8(wasm_leaf_bytes(r#"{"userId":"u","kemPubkey":"K","signPubkey":"S","ts":7}"#).unwrap()).unwrap(),
        "pock-keylog-v1\nu\nK\nS\n7"
    );
    assert_eq!(
        String::from_utf8(wasm_sth_message(r#"{"logId":"L","size":3,"root":"ab","ts":7}"#).unwrap()).unwrap(),
        "pock-sth-v1\nL\n3\nab\n7"
    );
    assert_eq!(wasm_message_digest(b"aad", b"ct").len(), 32);
}

/// The @noble/curves-produced cert must verify through the wasm surface too —
/// this is the pairing that `chat-app` relies on when it stops using its own
/// TS verifier.
#[wasm_bindgen_test]
fn wasm_verify_cert_accepts_the_typescript_vector() {
    use pock_core::wasm::wasm_verify_cert;
    let cert = r#"{"userId":"user_2abc","kemPubkey":"KEMPUB","signPubkey":"SIGNPUB","rot":{"custodians":["_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg"],"threshold":1},"principalSeq":3,"ts":1710000000000}"#;
    let sigs = r#"["6KV+EujQRswHAS0RV4+lKqtaOOcWqAVmLBTElnglBYyTP0bM+dZTYkR66h0jI6Zg54G9ImJIb99YNGFhBMxlBA=="]"#;
    let custodians = r#"["_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg"]"#;
    assert!(wasm_verify_cert(cert, sigs, custodians, 1).unwrap());
    assert!(!wasm_verify_cert(cert, "[]", custodians, 1).unwrap());
}

#[wasm_bindgen_test]
fn wasm_create_vault_profile_rejects_an_unknown_profile() {
    use pock_core::wasm::wasm_create_vault_profile;
    assert!(wasm_create_vault_profile("pw", "paranoid").is_err());
}
