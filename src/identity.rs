//! Identity module: bundles an Ed25519 signing keypair with an X-Wing KEM keypair.
//!
//! An [`Identity`] is a secret bundle (sign seed || kem seed) held only by the
//! owner. Its [`PublicIdentity`] is the pair of public keys, serialized as a
//! versioned JSON blob with base64url-encoded keys (version = 1).

use crate::error::{CoreError, Result};
use crate::kem::{KemPublic, KemSecret, kem_generate};
use crate::sign::{SignPublic, SignSecret};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// A secret identity: Ed25519 signing key + X-Wing KEM decapsulation key.
pub struct Identity {
    pub sign: SignSecret,
    pub kem: KemSecret,
}

/// The public half of an [`Identity`]: Ed25519 verify key + X-Wing encapsulation key.
pub struct PublicIdentity {
    pub sign: SignPublic,
    pub kem: KemPublic,
}

/// Wire format for [`PublicIdentity`]: versioned JSON with base64url keys.
#[derive(Serialize, Deserialize)]
pub struct PublicIdentityBlob {
    pub v: u8,
    pub sign: String,
    pub kem: String,
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| CoreError::Decode(e.to_string()))
}

impl Identity {
    /// Generate a fresh random identity (Ed25519 + X-Wing keypair).
    pub fn generate() -> Self {
        let (kem, _kem_pub) = kem_generate();
        Identity { sign: SignSecret::random(), kem }
    }

    /// Derive the public identity from this secret identity.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity { sign: self.sign.public(), kem: self.kem.encapsulation_key() }
    }

    /// Serialize to raw bytes: `sign_seed (32 bytes) || kem_seed (32 bytes)`.
    pub fn to_secret_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.sign.to_bytes());
        out.extend_from_slice(&self.kem.to_bytes());
        out
    }

    /// Deserialize from raw bytes produced by [`to_secret_bytes`].
    ///
    /// # Errors
    /// Returns [`CoreError::Decode`] if the slice is too short or either key
    /// seed is invalid.
    pub fn from_secret_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 32 {
            return Err(CoreError::Decode("identity secret too short".into()));
        }
        let (sign_b, kem_b) = b.split_at(32);
        let sign_arr: [u8; 32] = sign_b
            .try_into()
            .map_err(|_| CoreError::Decode("sign len".into()))?;
        Ok(Identity {
            sign: SignSecret::from_bytes(&sign_arr)?,
            kem: KemSecret::from_bytes(kem_b)?,
        })
    }
}

impl PublicIdentity {
    /// Serialize to a versioned JSON blob with base64url-encoded keys.
    pub fn to_blob(&self) -> String {
        let blob = PublicIdentityBlob {
            v: 1,
            sign: b64(self.sign.as_bytes()),
            kem: b64(&self.kem.as_bytes()),
        };
        serde_json::to_string(&blob).expect("PublicIdentityBlob always serializes")
    }

    /// Deserialize from a blob produced by [`to_blob`].
    ///
    /// # Errors
    /// Returns [`CoreError::Decode`] if the JSON is invalid, the version is
    /// unrecognized, or either key fails validation.
    pub fn from_blob(blob: &str) -> Result<Self> {
        let b: PublicIdentityBlob = serde_json::from_str(blob)
            .map_err(|e| CoreError::Decode(e.to_string()))?;
        if b.v != 1 {
            return Err(CoreError::Decode(format!("unknown identity blob version {}", b.v)));
        }
        let sign_bytes = unb64(&b.sign)?;
        let sign_arr: [u8; 32] = sign_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::Decode("sign public key len".into()))?;
        let sign = SignPublic::from_bytes(sign_arr);
        let kem_bytes = unb64(&b.kem)?;
        let kem = KemPublic::from_bytes(&kem_bytes)?;
        Ok(PublicIdentity { sign, kem })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_blob_roundtrip() {
        let id = Identity::generate();
        let blob = id.public().to_blob();
        let restored = PublicIdentity::from_blob(&blob).unwrap();
        assert_eq!(restored.sign.as_bytes(), id.public().sign.as_bytes());
        assert_eq!(restored.kem.as_bytes(), id.public().kem.as_bytes());
    }

    #[test]
    fn secret_bytes_roundtrip() {
        let id = Identity::generate();
        let restored = Identity::from_secret_bytes(&id.to_secret_bytes()).unwrap();
        assert_eq!(restored.public().sign.as_bytes(), id.public().sign.as_bytes());
        assert_eq!(restored.public().kem.as_bytes(), id.public().kem.as_bytes());
    }
}
