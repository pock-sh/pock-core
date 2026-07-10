use crate::error::{CoreError, Result};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce, Key};
use zeroize::{Zeroize, ZeroizeOnDrop};

const NONCE_LEN: usize = 24;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey([u8; 32]);

impl AeadKey {
    pub fn random() -> Self {
        let mut k = [0u8; 32];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut k);
        AeadKey(k)
    }
    pub fn from_bytes(b: [u8; 32]) -> Self { AeadKey(b) }
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

pub fn seal(key: &AeadKey, plaintext: &[u8]) -> Vec<u8> {
    seal_aad(key, plaintext, b"")
}

pub fn open(key: &AeadKey, blob: &[u8]) -> Result<Vec<u8>> {
    open_aad(key, blob, b"")
}

/// Like [`seal`] but binds associated data into the authentication tag, so a
/// ciphertext cannot be replayed under a different context (e.g. another
/// channel or sender).
pub fn seal_aad(key: &AeadKey, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    use chacha20poly1305::aead::Payload;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("XChaCha encrypt never fails");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    out
}

pub fn open_aad(key: &AeadKey, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::Payload;
    if blob.len() < NONCE_LEN { return Err(CoreError::Decode("aead blob too short".into())); }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key.0));
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, Payload { msg: ct, aad }).map_err(|_| CoreError::WrongKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = AeadKey::random();
        let msg = b"top secret env value";
        let blob = seal(&key, msg);
        assert_eq!(open(&key, &blob).unwrap(), msg);
    }

    #[test]
    fn nonce_is_unique_per_seal() {
        let key = AeadKey::random();
        let a = seal(&key, b"x");
        let b = seal(&key, b"x");
        assert_ne!(a[..24], b[..24], "nonces must differ");
    }

    #[test]
    fn wrong_key_fails() {
        let blob = seal(&AeadKey::random(), b"x");
        assert!(matches!(open(&AeadKey::random(), &blob), Err(CoreError::WrongKey)));
    }

    #[test]
    fn aad_mismatch_rejected() {
        let key = AeadKey::random();
        let blob = seal_aad(&key, b"msg", b"channel-a|v1");
        assert_eq!(open_aad(&key, &blob, b"channel-a|v1").unwrap(), b"msg");
        assert!(matches!(open_aad(&key, &blob, b"channel-b|v1"), Err(CoreError::WrongKey)));
        assert!(matches!(open_aad(&key, &blob, b""), Err(CoreError::WrongKey)));
    }

    #[test]
    fn empty_aad_is_plain_seal() {
        let key = AeadKey::random();
        let blob = seal(&key, b"msg");
        assert_eq!(open_aad(&key, &blob, b"").unwrap(), b"msg");
    }

    #[test]
    fn tamper_detected() {
        let key = AeadKey::random();
        let mut blob = seal(&key, b"hello");
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(open(&key, &blob).is_err());
    }
}
