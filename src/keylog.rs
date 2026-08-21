//! Key-transparency canonical byte encodings — the Rust twin of
//! `app/lib/key-log.ts`, `chat-app/worker/keycert.ts` and
//! `chat-app/src/lib/keytrust.ts`.
//!
//! Every function here reproduces bytes that are already hashed into a
//! published Merkle tree or already covered by a stored signature, so the
//! encodings are frozen: domain tag, then fields separated by **literal
//! newlines**, numbers in plain decimal, no padding and no trailing newline.
//! A change here silently invalidates every existing log entry.
//!
//! Pure: no I/O, no clock, no network.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// The transparency log this crate's encodings belong to.
pub const LOG_ID: &str = "pock.sh/keylog/v1";

/// A Root of Trust: the custodian public keys that may co-sign an account's
/// key certificate, and how many of them a valid cert needs.
///
/// The serde derives are load-bearing: `pock_client::chat::keytrust::Proof`
/// deserialises a `Rot` straight out of the log's proof response and POSTs the
/// same shape back in a cert submission, so the field names must stay
/// `custodians` / `threshold` exactly as the Worker writes them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rot {
    pub custodians: Vec<String>,
    pub threshold: u32,
}

/// `"custodian1,custodian2|threshold"` — the single-line rendering of a Root of
/// Trust that [`cert_bytes`] embeds. Matches `canonicalRot` in the TS originals.
pub fn canonical_rot(rot: &Rot) -> String {
    format!("{}|{}", rot.custodians.join(","), rot.threshold)
}

/// The bytes hashed into a Merkle leaf. Public keys are base64 and can never
/// contain a newline, so newline delimiting is unambiguous.
pub fn leaf_bytes(user_id: &str, kem_pubkey: &str, sign_pubkey: &str, ts: i64) -> Vec<u8> {
    format!("pock-keylog-v1\n{user_id}\n{kem_pubkey}\n{sign_pubkey}\n{ts}").into_bytes()
}

/// The bytes the log operator signs to produce a Signed Tree Head.
pub fn sth_message(log_id: &str, size: u64, root_hex: &str, ts: i64) -> Vec<u8> {
    format!("pock-sth-v1\n{log_id}\n{size}\n{root_hex}\n{ts}").into_bytes()
}

/// The bytes the custodians sign to produce a succession certificate.
pub fn cert_bytes(
    user_id: &str,
    kem_pubkey: &str,
    sign_pubkey: &str,
    rot: &Rot,
    principal_seq: u64,
    ts: i64,
) -> Vec<u8> {
    format!(
        "pock-keycert-v1\n{user_id}\n{kem_pubkey}\n{sign_pubkey}\n{}\n{principal_seq}\n{ts}",
        canonical_rot(rot)
    )
    .into_bytes()
}

/// RFC-6962 leaf hash: `SHA-256(0x00 ‖ data)`.
pub fn hash_leaf(d: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(d);
    h.finalize().into()
}

/// RFC-6962 interior hash: `SHA-256(0x01 ‖ left ‖ right)`.
pub fn hash_children(l: &[u8], r: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// Decodes **both** base64 dialects, padded or not.
///
/// pock-core emits `URL_SAFE_NO_PAD` for public keys and signatures, while
/// older records and anything that went through `btoa` are standard base64.
/// The TS `b64ToBytes` in all three originals normalises `-`/`_` to `+`/`/`
/// and re-pads, so a strict single-alphabet decoder here would reject keys the
/// TS side accepts and would report them as invalid signatures.
fn b64_any(s: &str) -> Option<Vec<u8>> {
    let std: String = s.chars().map(|c| match c {
        '-' => '+',
        '_' => '/',
        other => other,
    }).collect();
    let trimmed = std.trim_end_matches('=');
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed).ok()
}

/// k-of-n verification of a succession certificate.
///
/// Counts **distinct** custodian public keys that have at least one valid
/// signature over `cert_bytes`; deduplicating by custodian (not by signature)
/// is what stops one custodian signing twice from satisfying a 2-of-2. A
/// `threshold` below 1 is always `false`, so an empty or malformed Root of
/// Trust can never be trivially satisfied.
///
/// Verification is **deliberately non-strict**: [`Verifier::verify`], never
/// `verify_strict`. Every cert in the log today was produced and accepted by
/// `@noble/curves`, whose default `verify` applies the permissive ZIP-215-style
/// rules rather than strict RFC-8032. Tightening this would reject certs the TS
/// Worker already stored and turn genuine members into a key mismatch. The
/// `verification_is_non_strict_*` tests below pin that against TS-captured
/// vectors.
pub fn verify_cert(
    cert_bytes: &[u8],
    sigs_b64: &[String],
    custodian_pubs_b64: &[String],
    threshold: u32,
) -> bool {
    if threshold < 1 {
        return false;
    }
    let mut seen: HashSet<&str> = HashSet::new();
    let mut count: u32 = 0;
    for pub_b64 in custodian_pubs_b64 {
        if !seen.insert(pub_b64.as_str()) {
            continue;
        }
        let Some(pk_bytes) = b64_any(pub_b64) else { continue };
        let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else { continue };
        let Ok(pk) = VerifyingKey::from_bytes(&pk_arr) else { continue };
        let ok = sigs_b64.iter().any(|s| {
            let Some(sig_bytes) = b64_any(s) else { return false };
            let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else { return false };
            pk.verify(cert_bytes, &Signature::from_bytes(&sig_arr)).is_ok()
        });
        if ok {
            count += 1;
        }
    }
    count >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // ---- vectors captured from the TypeScript originals via the monorepo's
    // scripts/fixtures/seed-keylog-vector.mts (@noble/curves + key-log.ts) ----
    const TS_CERT: &str = "pock-keycert-v1\nuser_2abc\nKEMPUB\nSIGNPUB\n_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg|1\n3\n1710000000000";
    const TS_CUSTODIAN: &str = "_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg";
    const TS_CUSTODIAN_STD: &str = "/RckOFqgx1tk+3jNYC+h2ZH96/drE8WO1wLqyDXp9hg=";
    const TS_SIG: &str = "6KV+EujQRswHAS0RV4+lKqtaOOcWqAVmLBTElnglBYyTP0bM+dZTYkR66h0jI6Zg54G9ImJIb99YNGFhBMxlBA==";
    const TS_SIG_URL: &str = "6KV-EujQRswHAS0RV4-lKqtaOOcWqAVmLBTElnglBYyTP0bM-dZTYkR66h0jI6Zg54G9ImJIb99YNGFhBMxlBA";
    // A = the identity point (a small-order key). @noble/curves' default verify
    // accepts this signature over ANY message; a strict RFC-8032 verifier
    // rejects the weak key outright. Captured with the same script.
    const TS_WEAK_PUB: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const TS_WEAK_SIG: &str = "7ch21oMf0hBdC0OJyi4oMWZGkokUbizgb67+mLIlSN8FAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

    fn test_signer() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let pk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.verifying_key().as_bytes());
        (sk, pk)
    }
    fn sign_b64(sk: &SigningKey, msg: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.sign(msg).to_bytes())
    }

    #[test]
    fn cert_bytes_match_the_typescript_encoding() {
        let rot = Rot { custodians: vec!["AMK1".into(), "AMK2".into()], threshold: 2 };
        assert_eq!(canonical_rot(&rot), "AMK1,AMK2|2");
        assert_eq!(
            String::from_utf8(cert_bytes("user_1", "KEM", "SIGN", &rot, 0, 1710000000000)).unwrap(),
            "pock-keycert-v1\nuser_1\nKEM\nSIGN\nAMK1,AMK2|2\n0\n1710000000000"
        );
    }

    #[test]
    fn cert_bytes_reproduce_the_typescript_captured_vector() {
        let rot = Rot { custodians: vec![TS_CUSTODIAN.into()], threshold: 1 };
        assert_eq!(
            String::from_utf8(cert_bytes("user_2abc", "KEMPUB", "SIGNPUB", &rot, 3, 1710000000000)).unwrap(),
            TS_CERT
        );
    }

    #[test]
    fn leaf_and_sth_encodings_are_exact() {
        assert_eq!(
            String::from_utf8(leaf_bytes("u", "K", "S", 7)).unwrap(),
            "pock-keylog-v1\nu\nK\nS\n7"
        );
        assert_eq!(
            String::from_utf8(sth_message("pock.sh/keylog/v1", 3, "ab12", 7)).unwrap(),
            "pock-sth-v1\npock.sh/keylog/v1\n3\nab12\n7"
        );
        assert_eq!(LOG_ID, "pock.sh/keylog/v1");
    }

    #[test]
    fn an_empty_custodian_set_still_renders_the_separator() {
        // The TS `custodians.join(",")` yields "" — the bar must survive so an
        // empty RoT does not collide with a single-custodian one.
        assert_eq!(canonical_rot(&Rot { custodians: vec![], threshold: 0 }), "|0");
    }

    #[test]
    fn rot_serialises_with_the_field_names_the_worker_sends() {
        let j = serde_json::to_string(&Rot { custodians: vec!["A".into()], threshold: 1 }).unwrap();
        assert_eq!(j, r#"{"custodians":["A"],"threshold":1}"#);
        assert_eq!(serde_json::from_str::<Rot>(&j).unwrap().threshold, 1);
    }

    #[test]
    fn merkle_hashes_are_domain_separated_rfc6962() {
        // Known-answer: SHA-256 of a single 0x00 byte is the hash of an empty leaf.
        let leaf = hash_leaf(b"");
        assert_eq!(
            hex(&leaf),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
        assert_ne!(hash_leaf(b"x").to_vec(), hash_children(b"", b"x").to_vec());
        let l = hash_leaf(b"l");
        let r = hash_leaf(b"r");
        assert_ne!(hash_children(&l, &r), hash_children(&r, &l), "order matters");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn verify_cert_counts_distinct_custodians_and_rejects_threshold_zero() {
        let (sk, pk) = test_signer();
        let msg = cert_bytes("u", "K", "S", &Rot { custodians: vec![pk.clone()], threshold: 1 }, 0, 1);
        let sig = sign_b64(&sk, &msg);
        assert!(verify_cert(&msg, std::slice::from_ref(&sig), std::slice::from_ref(&pk), 1));
        // Two signatures from ONE custodian cannot satisfy a 2-of-2 threshold.
        assert!(!verify_cert(&msg, &[sig.clone(), sig.clone()], &[pk.clone(), pk.clone()], 2));
        assert!(!verify_cert(&msg, &[sig], &[pk], 0), "threshold < 1 is always false");
    }

    #[test]
    fn verify_cert_rejects_a_signature_over_different_bytes() {
        let (sk, pk) = test_signer();
        let msg = cert_bytes("u", "K", "S", &Rot { custodians: vec![pk.clone()], threshold: 1 }, 0, 1);
        let other = cert_bytes("u", "K", "S", &Rot { custodians: vec![pk.clone()], threshold: 1 }, 1, 1);
        let sig = sign_b64(&sk, &msg);
        assert!(!verify_cert(&other, &[sig], &[pk], 1), "principalSeq is covered");
    }

    #[test]
    fn verify_cert_ignores_undecodable_and_wrong_length_inputs() {
        let (sk, pk) = test_signer();
        let msg = cert_bytes("u", "K", "S", &Rot { custodians: vec![pk.clone()], threshold: 1 }, 0, 1);
        let sig = sign_b64(&sk, &msg);
        // Garbage custodians and garbage sigs are skipped, never panic.
        assert!(verify_cert(&msg, &["!!!".into(), sig.clone()], &["***".into(), pk.clone()], 1));
        assert!(!verify_cert(&msg, &[sig], &["QUJD".into()], 1), "3-byte pubkey is not a key");
    }

    #[test]
    fn verify_cert_reaches_the_threshold_only_with_two_real_custodians() {
        let a = SigningKey::from_bytes(&[1u8; 32]);
        let b = SigningKey::from_bytes(&[2u8; 32]);
        let enc = |k: &SigningKey| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(k.verifying_key().as_bytes())
        };
        let (pa, pb) = (enc(&a), enc(&b));
        let rot = Rot { custodians: vec![pa.clone(), pb.clone()], threshold: 2 };
        let msg = cert_bytes("u", "K", "S", &rot, 0, 1);
        let sa = sign_b64(&a, &msg);
        let sb = sign_b64(&b, &msg);
        assert!(!verify_cert(&msg, std::slice::from_ref(&sa), &rot.custodians, 2), "1-of-2 is not enough");
        assert!(verify_cert(&msg, &[sa, sb], &rot.custodians, 2));
    }

    #[test]
    fn verify_cert_accepts_both_base64_dialects_like_the_typescript_decoder() {
        // pock-core emits URL_SAFE_NO_PAD; older records are standard base64.
        // The TS b64ToBytes accepts both, so this must too.
        for pub_b64 in [TS_CUSTODIAN, TS_CUSTODIAN_STD] {
            for sig_b64 in [TS_SIG, TS_SIG_URL] {
                assert!(
                    verify_cert(TS_CERT.as_bytes(), &[sig_b64.into()], &[pub_b64.into()], 1),
                    "pub={pub_b64} sig={sig_b64}"
                );
            }
        }
    }

    #[test]
    fn verification_is_non_strict_so_noble_produced_certs_still_pass() {
        // Vector captured from app/lib/key-log.ts + @noble/curves. If this ever
        // needs `verify_strict`, existing log entries would start failing.
        assert!(verify_cert(TS_CERT.as_bytes(), &[TS_SIG.into()], &[TS_CUSTODIAN.into()], 1));
    }

    #[test]
    fn verification_is_non_strict_for_a_small_order_custodian_key() {
        // @noble/curves' default verify accepts this pair, and `verify_strict`
        // would not. The assertion pins the choice made in `verify_cert`'s
        // docs: matching the TS verifier is what keeps already-stored certs
        // verifiable. (Nothing is weakened for real custodians — a small-order
        // custodian key can only be introduced by whoever writes the RoT, and
        // the TS side has always accepted it too.)
        assert!(verify_cert(
            TS_CERT.as_bytes(),
            &[TS_WEAK_SIG.into()],
            &[TS_WEAK_PUB.into()],
            1
        ));
        assert!(
            VerifyingKey::from_bytes(&<[u8; 32]>::try_from(b64_any(TS_WEAK_PUB).unwrap().as_slice()).unwrap())
                .unwrap()
                .verify_strict(
                    TS_CERT.as_bytes(),
                    &Signature::from_bytes(
                        &<[u8; 64]>::try_from(b64_any(TS_WEAK_SIG).unwrap().as_slice()).unwrap()
                    )
                )
                .is_err(),
            "the vector is only interesting because verify_strict rejects it"
        );
    }
}
