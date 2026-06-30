use crate::error::{CoreError, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfProfile { Native, Constrained }

impl KdfProfile {
    /// (memory in KiB, iterations, parallelism)
    pub fn params(&self) -> (u32, u32, u32) {
        match self {
            KdfProfile::Native => (65536, 3, 4),      // 64 MiB
            KdfProfile::Constrained => (47104, 1, 1), // 46 MiB
        }
    }
}

pub fn argon2id(password: &[u8], salt: &[u8], profile: KdfProfile) -> Result<[u8; 32]> {
    let (m, t, p) = profile.params();
    let params = Params::new(m, t, p, Some(32)).map_err(|e| CoreError::Kdf(e.to_string()))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    a2.hash_password_into(password, salt, &mut out)
        .map_err(|e| CoreError::Kdf(e.to_string()))?;
    Ok(out)
}

pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("32 is a valid HKDF length");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_deterministic() {
        let salt = b"sixteen-byte-sal";
        let a = argon2id(b"correct horse", salt, KdfProfile::Constrained).unwrap();
        let b = argon2id(b"correct horse", salt, KdfProfile::Constrained).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn argon2id_password_sensitive() {
        let salt = b"sixteen-byte-sal";
        let a = argon2id(b"password-a", salt, KdfProfile::Constrained).unwrap();
        let b = argon2id(b"password-b", salt, KdfProfile::Constrained).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn profiles_have_expected_params() {
        assert_eq!(KdfProfile::Native.params(), (65536, 3, 4));
        assert_eq!(KdfProfile::Constrained.params(), (47104, 1, 1));
    }

    #[test]
    fn hkdf_deterministic_and_info_separated() {
        let ikm = [7u8; 32];
        let a = hkdf_sha256(&ikm, b"salt", b"pock/a/v1");
        let b = hkdf_sha256(&ikm, b"salt", b"pock/a/v1");
        let c = hkdf_sha256(&ikm, b"salt", b"pock/b/v1");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
