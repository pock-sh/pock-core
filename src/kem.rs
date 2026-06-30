//! KEM module: X-Wing (X25519 + ML-KEM-768) post-quantum key encapsulation.
//!
//! X-Wing combines X25519 and ML-KEM-768 into a hybrid KEM that is secure
//! against both classical and quantum adversaries.
//!
//! # Key sizes (x-wing 0.1.0-rc.0)
//! - Encapsulation (public) key: 1216 bytes
//! - Decapsulation (secret) key: 32 bytes (seed; full key derived internally)
//! - Ciphertext: 1120 bytes
//! - Shared secret: 32 bytes

use crate::error::{CoreError, Result};
use zeroize::Zeroizing;
use x_wing::{
    Ciphertext, Decapsulate, Decapsulator, DecapsulationKey, Encapsulate, EncapsulationKey, Kem,
    KeyExport, XWingKem, CIPHERTEXT_SIZE, DECAPSULATION_KEY_SIZE,
};

/// X-Wing KEM decapsulation (secret) key.
///
/// Holds a 32-byte seed; the full ML-KEM-768 + X25519 key pair is derived
/// from this seed on construction.
pub struct KemSecret(DecapsulationKey);

/// X-Wing KEM encapsulation (public) key.
///
/// 1216 bytes: ML-KEM-768 public key (1184 bytes) || X25519 public key (32 bytes).
#[derive(Clone)]
pub struct KemPublic(EncapsulationKey);

/// X-Wing KEM ciphertext (1120 bytes).
///
/// Produced by [`KemPublic::encapsulate`] and consumed by [`KemSecret::decapsulate`].
pub struct KemCiphertext(Ciphertext);

/// Generate a fresh X-Wing KEM keypair using the OS CSPRNG.
///
/// Returns `(KemSecret, KemPublic)`.
pub fn kem_generate() -> (KemSecret, KemPublic) {
    let (dk, ek) = XWingKem::generate_keypair();
    (KemSecret(dk), KemPublic(ek))
}

impl KemPublic {
    /// Encapsulate a fresh shared secret using the OS CSPRNG.
    ///
    /// Returns `(ciphertext, shared_secret_bytes)`.  The ciphertext must be
    /// sent to the holder of the matching [`KemSecret`]; the 32-byte shared
    /// secret is used locally as key material.
    pub fn encapsulate(&self) -> (KemCiphertext, [u8; 32]) {
        let (ct, ss) = self.0.encapsulate();
        let mut ss_bytes = Zeroizing::new([0u8; 32]);
        ss_bytes.copy_from_slice(&ss[..]);
        (KemCiphertext(ct), *ss_bytes)
    }

    /// Serialize the public key to bytes (1216 bytes).
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Deserialize a public key from bytes.
    ///
    /// # Errors
    /// Returns [`CoreError::Decode`] if the byte slice is not exactly 1216 bytes
    /// or the embedded ML-KEM-768 key fails validation.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        EncapsulationKey::try_from(b)
            .map(KemPublic)
            .map_err(|_| CoreError::Decode("kem public key".into()))
    }
}

impl KemSecret {
    /// Decapsulate a shared secret from a ciphertext.
    ///
    /// Returns a 32-byte shared secret.  X-Wing uses implicit rejection: if the
    /// ciphertext is invalid or was encrypted to a different key, a
    /// pseudorandom (but distinct) value is returned rather than an error.
    pub fn decapsulate(&self, ct: &KemCiphertext) -> [u8; 32] {
        let ss = self.0.decapsulate(&ct.0);
        let mut ss_bytes = Zeroizing::new([0u8; 32]);
        ss_bytes.copy_from_slice(&ss[..]);
        *ss_bytes
    }

    /// Derive the encapsulation (public) key from this decapsulation (secret) key.
    ///
    /// Uses `x_wing::Decapsulator::encapsulation_key()` which retrieves the
    /// `EncapsulationKey` stored inside the `DecapsulationKey` at construction time.
    pub fn encapsulation_key(&self) -> KemPublic {
        KemPublic(self.0.encapsulation_key().clone())
    }

    /// Serialize the secret key seed to bytes (32 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }

    /// Deserialize a secret key from its 32-byte seed.
    ///
    /// # Errors
    /// Returns [`CoreError::Decode`] if the byte slice is not exactly 32 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let arr: [u8; DECAPSULATION_KEY_SIZE] = b
            .try_into()
            .map_err(|_| CoreError::Decode("kem secret key len".into()))?;
        Ok(KemSecret(DecapsulationKey::from(arr)))
    }
}

impl KemCiphertext {
    /// Serialize the ciphertext to bytes (1120 bytes).
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Deserialize a ciphertext from bytes.
    ///
    /// # Errors
    /// Returns [`CoreError::Decode`] if the byte slice is not exactly 1120 bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != CIPHERTEXT_SIZE {
            return Err(CoreError::Decode("kem ciphertext len".into()));
        }
        let mut ct = Ciphertext::default();
        ct[0..CIPHERTEXT_SIZE].copy_from_slice(b);
        Ok(KemCiphertext(ct))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encap_decap_agree() {
        let (sk, pk) = kem_generate();
        let (ct, ss_sender) = pk.encapsulate();
        let ss_receiver = sk.decapsulate(&ct);
        assert_eq!(ss_sender, ss_receiver);
    }

    #[test]
    fn wrong_secret_yields_different_secret() {
        let (_sk_a, pk_a) = kem_generate();
        let (sk_b, _pk_b) = kem_generate();
        let (ct, ss_sender) = pk_a.encapsulate();
        // X-Wing implicit rejection: wrong key gives a different pseudorandom secret.
        assert_ne!(sk_b.decapsulate(&ct), ss_sender);
    }

    #[test]
    fn public_and_ciphertext_roundtrip_bytes() {
        let (sk, pk) = kem_generate();
        let pk2 = KemPublic::from_bytes(&pk.as_bytes()).unwrap();
        let (ct, ss) = pk2.encapsulate();
        let ct2 = KemCiphertext::from_bytes(&ct.as_bytes()).unwrap();
        assert_eq!(sk.decapsulate(&ct2), ss);
    }
}
