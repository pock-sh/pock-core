use crate::aead::{open as aead_open, seal as aead_seal, AeadKey};
use crate::error::{CoreError, Result};
use crate::kdf::hkdf_sha256;
use crate::kem::{KemCiphertext, KemPublic, KemSecret};
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const INFO: &[u8] = b"pock/envelope/v1";

#[derive(Serialize, Deserialize, Clone)]
pub struct Envelope {
    pub v: u8,
    pub kem_ct: String,
    pub aead: String,
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
fn unb64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| CoreError::Decode(e.to_string()))
}

pub fn seal_to(recipient: &KemPublic, plaintext: &[u8]) -> Envelope {
    let (kem_ct, shared) = recipient.encapsulate();
    let shared = Zeroizing::new(shared);
    let ct_bytes = kem_ct.as_bytes();
    let key = AeadKey::from_bytes(hkdf_sha256(&shared[..], &ct_bytes, INFO));
    let aead = aead_seal(&key, plaintext);
    Envelope { v: 1, kem_ct: b64(&ct_bytes), aead: b64(&aead) }
}

pub fn open_with(secret: &KemSecret, env: &Envelope) -> Result<Vec<u8>> {
    if env.v != 1 {
        return Err(CoreError::Decode(format!("unsupported envelope version: {}", env.v)));
    }
    let kem_ct = KemCiphertext::from_bytes(&unb64(&env.kem_ct)?)?;
    let shared = Zeroizing::new(secret.decapsulate(&kem_ct));
    let ct_bytes = kem_ct.as_bytes();
    let key = AeadKey::from_bytes(hkdf_sha256(&shared[..], &ct_bytes, INFO));
    aead_open(&key, &unb64(&env.aead)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::kem_generate;

    #[test]
    fn seal_open_roundtrip() {
        let (sk, pk) = kem_generate();
        let env = seal_to(&pk, b"a 32-byte data key goes in here!");
        assert_eq!(open_with(&sk, &env).unwrap(), b"a 32-byte data key goes in here!");
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let (_sk, pk) = kem_generate();
        let (sk_other, _pk_other) = kem_generate();
        let env = seal_to(&pk, b"secret");
        assert!(open_with(&sk_other, &env).is_err());
    }

    #[test]
    fn rejects_unknown_version() {
        let (sk, pk) = kem_generate();
        let mut env = seal_to(&pk, b"x");
        env.v = 2;
        assert!(open_with(&sk, &env).is_err());
    }

    #[test]
    fn two_recipients_each_open_their_own() {
        let (sk1, pk1) = kem_generate();
        let (sk2, pk2) = kem_generate();
        let dek = b"shared data key payload (32 byte)";
        let e1 = seal_to(&pk1, dek);
        let e2 = seal_to(&pk2, dek);
        assert_eq!(open_with(&sk1, &e1).unwrap(), dek);
        assert_eq!(open_with(&sk2, &e2).unwrap(), dek);
    }
}
