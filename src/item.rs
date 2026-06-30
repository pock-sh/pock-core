use crate::aead::{open as aead_open, seal as aead_seal, AeadKey};
use crate::envelope::{open_with, seal_to, Envelope};
use crate::error::{CoreError, Result};
use crate::kem::{KemPublic, KemSecret};
use base64::Engine;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct WrappedDek {
    pub recipient: String,
    pub env: Envelope,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedItem {
    pub v: u8,
    pub ciphertext: String,
    pub wrapped_deks: Vec<WrappedDek>,
}

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
fn unb64(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| CoreError::Decode(e.to_string()))
}
fn recipient_id(pk: &KemPublic) -> String {
    b64(&pk.as_bytes())
}

pub fn encrypt_item(value: &[u8], recipients: &[KemPublic]) -> EncryptedItem {
    let dek = AeadKey::random();
    let ciphertext = aead_seal(&dek, value);
    let wrapped_deks = recipients
        .iter()
        .map(|pk| WrappedDek {
            recipient: recipient_id(pk),
            env: seal_to(pk, dek.as_bytes()),
        })
        .collect();
    EncryptedItem {
        v: 1,
        ciphertext: b64(&ciphertext),
        wrapped_deks,
    }
}

fn recover_dek(item: &EncryptedItem, secret: &KemSecret, public: &KemPublic) -> Result<AeadKey> {
    let id = recipient_id(public);
    let wrapped = item
        .wrapped_deks
        .iter()
        .find(|w| w.recipient == id)
        .ok_or(CoreError::WrongKey)?;
    let dek_bytes = open_with(secret, &wrapped.env)?;
    let arr: [u8; 32] = dek_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Decode("dek len".into()))?;
    Ok(AeadKey::from_bytes(arr))
}

pub fn decrypt_item(
    item: &EncryptedItem,
    secret: &KemSecret,
    public: &KemPublic,
) -> Result<Vec<u8>> {
    if item.v != 1 {
        return Err(CoreError::Decode(format!(
            "unsupported item version: {}",
            item.v
        )));
    }
    let dek = recover_dek(item, secret, public)?;
    aead_open(&dek, &unb64(&item.ciphertext)?)
}

pub fn grant(
    item: &mut EncryptedItem,
    opener_secret: &KemSecret,
    opener_public: &KemPublic,
    new_recipient: &KemPublic,
) -> Result<()> {
    let dek = recover_dek(item, opener_secret, opener_public)?;
    item.wrapped_deks.push(WrappedDek {
        recipient: recipient_id(new_recipient),
        env: seal_to(new_recipient, dek.as_bytes()),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::kem_generate;

    #[test]
    fn owner_can_decrypt() {
        let (sk, pk) = kem_generate();
        let item = encrypt_item(b"DATABASE_URL=postgres://...", &[pk.clone()]);
        assert_eq!(
            decrypt_item(&item, &sk, &pk).unwrap(),
            b"DATABASE_URL=postgres://..."
        );
    }

    #[test]
    fn non_recipient_cannot_decrypt() {
        let (_sk, pk) = kem_generate();
        let (sk_other, pk_other) = kem_generate();
        let item = encrypt_item(b"secret", &[pk]);
        assert!(decrypt_item(&item, &sk_other, &pk_other).is_err());
    }

    #[test]
    fn grant_lets_new_recipient_decrypt() {
        let (sk1, pk1) = kem_generate();
        let (sk2, pk2) = kem_generate();
        let mut item = encrypt_item(b"API_KEY=xyz", &[pk1.clone()]);
        // pk2 cannot read yet.
        assert!(decrypt_item(&item, &sk2, &pk2).is_err());
        // owner grants to pk2 without seeing plaintext path changing the ciphertext.
        grant(&mut item, &sk1, &pk1, &pk2).unwrap();
        assert_eq!(decrypt_item(&item, &sk2, &pk2).unwrap(), b"API_KEY=xyz");
        // original ciphertext blob count: one ciphertext, two wraps.
        assert_eq!(item.wrapped_deks.len(), 2);
    }

    #[test]
    fn rejects_unknown_item_version() {
        let (sk, pk) = kem_generate();
        let mut item = encrypt_item(b"secret", &[pk.clone()]);
        item.v = 2;
        assert!(decrypt_item(&item, &sk, &pk).is_err());
    }
}
