use crate::aead::{open as aead_open, seal as aead_seal, AeadKey};
use crate::error::{CoreError, Result};
use crate::identity::Identity;
use crate::kdf::{argon2id, hkdf_sha256, KdfProfile};
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};

const SKD_INFO: &[u8] = b"pock/2skd/v1";

pub struct Auk(AeadKey);

pub struct SecretKey([u8; 16]);

#[derive(Serialize, Deserialize, Clone)]
pub struct WrappedAuk {
    pub v: u8,
    pub method: String,
    pub salt: String,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub blob: String,
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
fn unb64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| CoreError::Decode(e.to_string()))
}

impl Auk {
    pub fn generate() -> Self { Auk(AeadKey::random()) }
    fn key(&self) -> &AeadKey { &self.0 }
    fn from_key(k: AeadKey) -> Self { Auk(k) }
}

impl SecretKey {
    pub fn random() -> Self {
        let mut b = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut b);
        SecretKey(b)
    }
    pub fn as_bytes(&self) -> &[u8; 16] { &self.0 }
    pub fn from_bytes(b: [u8; 16]) -> Self { SecretKey(b) }
}

fn derive_passphrase_kek(passphrase: &[u8], salt: &[u8], secret_key: &SecretKey, profile: KdfProfile) -> Result<[u8; 32]> {
    let stretched = argon2id(passphrase, salt, profile)?;
    Ok(hkdf_sha256(&stretched, secret_key.as_bytes(), SKD_INFO))
}

pub fn wrap_with_passphrase(auk: &Auk, passphrase: &[u8], secret_key: &SecretKey, profile: KdfProfile) -> WrappedAuk {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let (m, t, p) = profile.params();
    let kek = derive_passphrase_kek(passphrase, &salt, secret_key, profile).expect("argon2 params valid");
    let blob = aead_seal(&AeadKey::from_bytes(kek), auk.key().as_bytes());
    WrappedAuk { v: 1, method: "passphrase".into(), salt: b64(&salt), m_kib: m, t, p, blob: b64(&blob) }
}

pub fn unwrap_with_passphrase(w: &WrappedAuk, passphrase: &[u8], secret_key: &SecretKey) -> Result<Auk> {
    if w.v != 1 {
        return Err(CoreError::Decode(format!("unsupported wrapped-auk version: {}", w.v)));
    }
    let salt = unb64(&w.salt)?;
    // Reconstruct the profile from stored params (only Native/Constrained are emitted, but honor stored values).
    let profile = if (w.m_kib, w.t, w.p) == KdfProfile::Native.params() { KdfProfile::Native } else { KdfProfile::Constrained };
    let kek = derive_passphrase_kek(passphrase, &salt, secret_key, profile)?;
    let auk_bytes = aead_open(&AeadKey::from_bytes(kek), &unb64(&w.blob)?)?;
    let arr: [u8; 32] = auk_bytes.as_slice().try_into().map_err(|_| CoreError::Decode("auk len".into()))?;
    Ok(Auk::from_key(AeadKey::from_bytes(arr)))
}

pub fn wrap_with_kek(auk: &Auk, kek: &[u8; 32], method: &str) -> WrappedAuk {
    let blob = aead_seal(&AeadKey::from_bytes(*kek), auk.key().as_bytes());
    WrappedAuk { v: 1, method: method.into(), salt: String::new(), m_kib: 0, t: 0, p: 0, blob: b64(&blob) }
}

pub fn unwrap_with_kek(w: &WrappedAuk, kek: &[u8; 32]) -> Result<Auk> {
    if w.v != 1 {
        return Err(CoreError::Decode(format!("unsupported wrapped-auk version: {}", w.v)));
    }
    let auk_bytes = aead_open(&AeadKey::from_bytes(*kek), &unb64(&w.blob)?)?;
    let arr: [u8; 32] = auk_bytes.as_slice().try_into().map_err(|_| CoreError::Decode("auk len".into()))?;
    Ok(Auk::from_key(AeadKey::from_bytes(arr)))
}

pub fn wrap_identity(auk: &Auk, id: &Identity) -> String {
    b64(&aead_seal(auk.key(), &id.to_secret_bytes()))
}

pub fn unwrap_identity(auk: &Auk, wrapped: &str) -> Result<Identity> {
    let secret = aead_open(auk.key(), &unb64(wrapped)?)?;
    Identity::from_secret_bytes(&secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_wrap_unwrap_roundtrip() {
        let auk = Auk::generate();
        let sk = SecretKey::random();
        let w = wrap_with_passphrase(&auk, b"correct horse battery", &sk, KdfProfile::Constrained);
        let restored = unwrap_with_passphrase(&w, b"correct horse battery", &sk).unwrap();
        assert_eq!(restored.key().as_bytes(), auk.key().as_bytes());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let auk = Auk::generate();
        let sk = SecretKey::random();
        let w = wrap_with_passphrase(&auk, b"right", &sk, KdfProfile::Constrained);
        assert!(unwrap_with_passphrase(&w, b"wrong", &sk).is_err());
    }

    #[test]
    fn wrong_secret_key_fails() {
        let auk = Auk::generate();
        let w = wrap_with_passphrase(&auk, b"pw", &SecretKey::random(), KdfProfile::Constrained);
        assert!(unwrap_with_passphrase(&w, b"pw", &SecretKey::random()).is_err());
    }

    #[test]
    fn multi_wrap_same_auk_from_two_methods() {
        let auk = Auk::generate();
        let sk = SecretKey::random();
        let pw = wrap_with_passphrase(&auk, b"pw", &sk, KdfProfile::Constrained);
        let prf_kek = [9u8; 32]; // stand-in for a WebAuthn-PRF-derived KEK
        let prf = wrap_with_kek(&auk, &prf_kek, "webauthn-prf");
        let a = unwrap_with_passphrase(&pw, b"pw", &sk).unwrap();
        let b = unwrap_with_kek(&prf, &prf_kek).unwrap();
        assert_eq!(a.key().as_bytes(), b.key().as_bytes());
    }

    #[test]
    fn auk_wraps_and_unwraps_identity() {
        let auk = Auk::generate();
        let id = Identity::generate();
        let wrapped = wrap_identity(&auk, &id);
        let restored = unwrap_identity(&auk, &wrapped).unwrap();
        assert_eq!(restored.public().kem.as_bytes(), id.public().kem.as_bytes());
    }

    #[test]
    fn rejects_unknown_wrapped_auk_version() {
        let auk = Auk::generate();
        let sk = SecretKey::random();
        let mut w = wrap_with_passphrase(&auk, b"pw", &sk, KdfProfile::Constrained);
        w.v = 2;
        assert!(unwrap_with_passphrase(&w, b"pw", &sk).is_err());
    }
}
