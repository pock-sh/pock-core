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
    #[error("json: {0}")]
    Json(String),
    #[error("encoding: {0}")]
    Encoding(String),
    /// A flow-level failure whose message is already user-facing and is rendered
    /// verbatim. Used by `crate::flows` to preserve the exact strings the wasm
    /// layer has always surfaced (e.g. "wrong passphrase or secret key").
    #[error("{0}")]
    Flow(String),
}

impl From<serde_json::Error> for CoreError {
    fn from(e: serde_json::Error) -> Self {
        CoreError::Json(e.to_string())
    }
}

impl From<base64::DecodeError> for CoreError {
    fn from(e: base64::DecodeError) -> Self {
        CoreError::Encoding(e.to_string())
    }
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
