use crate::aead::{open as aead_open, seal as aead_seal, AeadKey};
use crate::envelope::{open_with, seal_to, Envelope};
use crate::error::{CoreError, Result};
use crate::kem::{kem_generate, KemPublic, KemSecret};
use base64::Engine;
use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 4] = b"PKEV";
const VERSION: u8 = 2;
const TAG_XCHACHA: u8 = 1;
const TAG_XWING: u8 = 2;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EnvFile {
    pub name: String,
    pub content: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Bundle {
    pub v: u8,
    pub files: Vec<EnvFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShareCipher {
    Xchacha,
    Xwing,
}

impl ShareCipher {
    pub fn id(&self) -> &'static str {
        match self {
            ShareCipher::Xchacha => "xchacha",
            ShareCipher::Xwing => "xwing",
        }
    }
    pub fn from_id(s: &str) -> Option<ShareCipher> {
        match s {
            "xchacha" => Some(ShareCipher::Xchacha),
            "xwing" => Some(ShareCipher::Xwing),
            _ => None,
        }
    }
    fn tag(&self) -> u8 {
        match self {
            ShareCipher::Xchacha => TAG_XCHACHA,
            ShareCipher::Xwing => TAG_XWING,
        }
    }
    fn from_tag(t: u8) -> Result<ShareCipher> {
        match t {
            TAG_XCHACHA => Ok(ShareCipher::Xchacha),
            TAG_XWING => Ok(ShareCipher::Xwing),
            _ => Err(CoreError::Decode(format!("unknown share algoTag: {t}"))),
        }
    }
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
fn unb64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.trim())
        .map_err(|e| CoreError::Decode(e.to_string()))
}

fn frame(cipher: ShareCipher, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.push(cipher.tag());
    out.extend_from_slice(payload);
    out
}

/// Returns (cipher, payload-slice-start-index) after validating MAGIC + version.
fn unframe(envelope: &[u8]) -> Result<(ShareCipher, usize)> {
    if envelope.len() < 6 || &envelope[0..4] != MAGIC {
        return Err(CoreError::Decode("bad share envelope magic".into()));
    }
    if envelope[4] != VERSION {
        return Err(CoreError::Decode(format!("unsupported share version: {}", envelope[4])));
    }
    Ok((ShareCipher::from_tag(envelope[5])?, 6))
}

fn u16_be(n: usize) -> [u8; 2] {
    [((n >> 8) & 0xff) as u8, (n & 0xff) as u8]
}
fn read_u16_be(b: &[u8], off: usize) -> Result<usize> {
    if off + 2 > b.len() {
        return Err(CoreError::Decode("short xwing payload".into()));
    }
    Ok(((b[off] as usize) << 8) | (b[off + 1] as usize))
}

pub fn parse_key_blob(raw: &str) -> Result<(ShareCipher, Vec<u8>)> {
    // pock-key:v2:<cipher>:<b64url>
    let parts: Vec<&str> = raw.trim().splitn(4, ':').collect();
    if parts.len() != 4 || parts[0] != "pock-key" || parts[1] != "v2" {
        return Err(CoreError::Decode("invalid key blob (expected pock-key:v2:...)".into()));
    }
    let cipher = ShareCipher::from_id(parts[2])
        .ok_or_else(|| CoreError::Decode(format!("unknown cipher in key blob: {}", parts[2])))?;
    Ok((cipher, unb64(parts[3])?))
}

fn key_blob(cipher: ShareCipher, key_bytes: &[u8]) -> String {
    format!("pock-key:v2:{}:{}", cipher.id(), b64(key_bytes))
}

pub fn encrypt_share(bundle: &Bundle, cipher: ShareCipher) -> Result<(Vec<u8>, String)> {
    let data = serde_json::to_vec(bundle).map_err(|e| CoreError::Decode(e.to_string()))?;
    match cipher {
        ShareCipher::Xchacha => {
            let key = AeadKey::random();
            let payload = aead_seal(&key, &data);
            Ok((frame(cipher, &payload), key_blob(cipher, key.as_bytes())))
        }
        ShareCipher::Xwing => {
            let (sk, pk): (KemSecret, KemPublic) = kem_generate();
            let env: Envelope = seal_to(&pk, &data);
            let kem_ct = unb64(&env.kem_ct)?;
            let aead_blob = unb64(&env.aead)?;
            let mut payload = Vec::with_capacity(2 + kem_ct.len() + aead_blob.len());
            payload.extend_from_slice(&u16_be(kem_ct.len()));
            payload.extend_from_slice(&kem_ct);
            payload.extend_from_slice(&aead_blob);
            Ok((frame(cipher, &payload), key_blob(cipher, &sk.to_bytes())))
        }
    }
}

pub fn decrypt_share(envelope: &[u8], key_blob_str: &str) -> Result<Bundle> {
    let (env_cipher, off) = unframe(envelope)?;
    let (blob_cipher, key_bytes) = parse_key_blob(key_blob_str)?;
    if env_cipher != blob_cipher {
        return Err(CoreError::Decode("key blob cipher does not match envelope".into()));
    }
    let payload = &envelope[off..];
    let data = match env_cipher {
        ShareCipher::Xchacha => {
            let arr: [u8; 32] = key_bytes.as_slice().try_into()
                .map_err(|_| CoreError::Decode("xchacha key must be 32 bytes".into()))?;
            aead_open(&AeadKey::from_bytes(arr), payload)?
        }
        ShareCipher::Xwing => {
            let kem_len = read_u16_be(payload, 0)?;
            let kem_end = 2 + kem_len;
            if kem_end > payload.len() {
                return Err(CoreError::Decode("xwing kem_ct length out of range".into()));
            }
            let kem_ct = &payload[2..kem_end];
            let aead_blob = &payload[kem_end..];
            let env = Envelope { v: 1, kem_ct: b64(kem_ct), aead: b64(aead_blob) };
            let sk = KemSecret::from_bytes(&key_bytes)?;
            open_with(&sk, &env)?
        }
    };
    serde_json::from_slice(&data).map_err(|e| CoreError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Bundle {
        Bundle {
            v: 1,
            files: vec![EnvFile { name: ".env".into(), content: "API_KEY=secret123\n".into() }],
            note: Some("hi".into()),
        }
    }

    #[test]
    fn xchacha_roundtrip() {
        let (env, blob) = encrypt_share(&sample(), ShareCipher::Xchacha).unwrap();
        assert_eq!(decrypt_share(&env, &blob).unwrap(), sample());
        assert!(blob.starts_with("pock-key:v2:xchacha:"));
        assert_eq!(&env[0..4], b"PKEV");
        assert_eq!(env[4], 2);
        assert_eq!(env[5], 1);
    }

    #[test]
    fn xchacha_wrong_key_fails() {
        let (env, _blob) = encrypt_share(&sample(), ShareCipher::Xchacha).unwrap();
        let (_e2, blob2) = encrypt_share(&sample(), ShareCipher::Xchacha).unwrap();
        assert!(decrypt_share(&env, &blob2).is_err());
    }

    #[test]
    fn rejects_bad_magic_and_version() {
        let (mut env, blob) = encrypt_share(&sample(), ShareCipher::Xchacha).unwrap();
        let mut bad = env.clone();
        bad[0] = b'X';
        assert!(decrypt_share(&bad, &blob).is_err());
        env[4] = 9;
        assert!(decrypt_share(&env, &blob).is_err());
    }

    #[test]
    fn parse_key_blob_rejects_v1_and_junk() {
        assert!(parse_key_blob("pock-key:v1:xchacha20poly1305:AAAA").is_err());
        assert!(parse_key_blob("nope").is_err());
        let (c, k) = parse_key_blob("pock-key:v2:xchacha:AAAA").unwrap();
        assert_eq!(c, ShareCipher::Xchacha);
        assert_eq!(k, vec![0, 0, 0]);
    }

    #[test]
    fn xwing_roundtrip_multi_file() {
        let b = Bundle {
            v: 1,
            files: vec![
                EnvFile { name: ".env".into(), content: "A=1\n".into() },
                EnvFile { name: ".env.prod".into(), content: "B=2\n".into() },
            ],
            note: None,
        };
        let (env, blob) = encrypt_share(&b, ShareCipher::Xwing).unwrap();
        assert!(blob.starts_with("pock-key:v2:xwing:"));
        assert_eq!(env[5], 2);
        assert_eq!(decrypt_share(&env, &blob).unwrap(), b);
    }

    #[test]
    fn cipher_algotag_mismatch_fails() {
        let (env, _) = encrypt_share(&sample(), ShareCipher::Xwing).unwrap();
        let (_, xchacha_blob) = encrypt_share(&sample(), ShareCipher::Xchacha).unwrap();
        // xwing envelope + xchacha key blob must be rejected before any crypto.
        assert!(decrypt_share(&env, &xchacha_blob).is_err());
    }

    #[test]
    fn xwing_wrong_key_fails() {
        let (env, _) = encrypt_share(&sample(), ShareCipher::Xwing).unwrap();
        let (_, blob2) = encrypt_share(&sample(), ShareCipher::Xwing).unwrap();
        assert!(decrypt_share(&env, &blob2).is_err());
    }
}
