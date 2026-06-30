use crate::error::{CoreError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

pub struct SignSecret(SigningKey);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SignPublic([u8; 32]);

impl SignSecret {
    pub fn random() -> Self { SignSecret(SigningKey::generate(&mut OsRng)) }
    pub fn to_bytes(&self) -> [u8; 32] { self.0.to_bytes() }
    pub fn from_bytes(b: &[u8; 32]) -> Result<Self> { Ok(SignSecret(SigningKey::from_bytes(b))) }
    pub fn public(&self) -> SignPublic { SignPublic(self.0.verifying_key().to_bytes()) }
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] { self.0.sign(msg).to_bytes() }
}

impl SignPublic {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
    pub fn from_bytes(b: [u8; 32]) -> Self { SignPublic(b) }
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.0).map_err(|_| CoreError::Signature)?;
        let signature = Signature::from_bytes(sig);
        vk.verify(msg, &signature).map_err(|_| CoreError::Signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let sk = SignSecret::random();
        let pk = sk.public();
        let sig = sk.sign(b"enroll device");
        assert!(pk.verify(b"enroll device", &sig).is_ok());
    }

    #[test]
    fn tampered_message_rejected() {
        let sk = SignSecret::random();
        let sig = sk.sign(b"grant alice");
        assert!(sk.public().verify(b"grant bob", &sig).is_err());
    }

    #[test]
    fn secret_roundtrips_through_bytes() {
        let sk = SignSecret::random();
        let restored = SignSecret::from_bytes(&sk.to_bytes()).unwrap();
        assert_eq!(sk.public(), restored.public());
    }
}
