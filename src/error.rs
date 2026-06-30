use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("AEAD encryption/decryption failed")]
    Aead,
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("KEM operation failed")]
    Kem,
    #[error("signature verification failed")]
    Signature,
    #[error("decode failed: {0}")]
    Decode(String),
    #[error("wrong key or corrupted ciphertext")]
    WrongKey,
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_render() {
        assert_eq!(CoreError::Aead.to_string(), "AEAD encryption/decryption failed");
        assert_eq!(CoreError::WrongKey.to_string(), "wrong key or corrupted ciphertext");
    }
}
