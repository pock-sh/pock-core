//! Encrypted binary vault backups (`.pockvault` files).
//!
//! Standalone portable format: everything needed to decrypt (except the
//! passphrase) is in the file header, so a backup survives loss of the
//! account, Secret Key, and pock itself. Deliberately NOT bound to the 2SKD
//! Secret Key — a backup is an escape hatch, and its passphrase must carry
//! the full security burden. Use a strong one.
//!
//! Layout: MAGIC(8) || salt(16) || m_kib(u32le) || t(u32le) || p(u32le)
//!         || aead_seal(kek, plaintext)   (nonce-prefixed XChaCha20-Poly1305)

use crate::aead::{open as aead_open, seal as aead_seal, AeadKey};
use crate::error::{CoreError, Result};
use crate::kdf::{argon2id, hkdf_sha256, KdfProfile};
use rand::RngCore;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"POCKVLT\x01";
const INFO: &[u8] = b"pock/backup/v1";
const HEADER_LEN: usize = 8 + 16 + 12;

fn derive_kek(passphrase: &[u8], salt: &[u8], profile: KdfProfile) -> Result<[u8; 32]> {
    let stretched = Zeroizing::new(argon2id(passphrase, salt, profile)?);
    Ok(hkdf_sha256(&stretched[..], b"", INFO))
}

pub fn export_backup(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let profile = KdfProfile::Constrained;
    let (m, t, p) = profile.params();
    let kek = Zeroizing::new(derive_kek(passphrase, &salt, profile)?);
    let sealed = aead_seal(&AeadKey::from_bytes(*kek), plaintext);

    let mut out = Vec::with_capacity(HEADER_LEN + sealed.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&m.to_le_bytes());
    out.extend_from_slice(&t.to_le_bytes());
    out.extend_from_slice(&p.to_le_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

pub fn import_backup(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    if data.len() < HEADER_LEN + 24 + 16 || &data[..8] != MAGIC {
        return Err(CoreError::Decode("not a pock vault backup".into()));
    }
    let salt = &data[8..24];
    let m = u32::from_le_bytes(data[24..28].try_into().unwrap());
    let t = u32::from_le_bytes(data[28..32].try_into().unwrap());
    let p = u32::from_le_bytes(data[32..36].try_into().unwrap());
    let profile = if (m, t, p) == KdfProfile::Native.params() {
        KdfProfile::Native
    } else if (m, t, p) == KdfProfile::Constrained.params() {
        KdfProfile::Constrained
    } else {
        return Err(CoreError::Decode("unknown backup KDF parameters".into()));
    };
    let kek = Zeroizing::new(derive_kek(passphrase, salt, profile)?);
    aead_open(&AeadKey::from_bytes(*kek), &data[HEADER_LEN..])
        .map_err(|_| CoreError::WrongKey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data = br#"{"items":[{"project":"prod","name":"DB_URL","value":"postgres://x"}]}"#;
        let file = export_backup(data, b"strong backup passphrase").unwrap();
        assert_eq!(&file[..8], MAGIC);
        let back = import_backup(&file, b"strong backup passphrase").unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let file = export_backup(b"secret", b"right").unwrap();
        assert!(matches!(import_backup(&file, b"wrong"), Err(CoreError::WrongKey)));
    }

    #[test]
    fn not_a_backup_rejected() {
        assert!(import_backup(b"definitely not a backup file", b"pw").is_err());
    }

    #[test]
    fn tampered_body_rejected() {
        let mut file = export_backup(b"secret", b"pw").unwrap();
        let last = file.len() - 1;
        file[last] ^= 1;
        assert!(import_backup(&file, b"pw").is_err());
    }

    #[test]
    fn salt_differs_per_export() {
        let a = export_backup(b"x", b"pw").unwrap();
        let b = export_backup(b"x", b"pw").unwrap();
        assert_ne!(a[8..24], b[8..24]);
    }
}
