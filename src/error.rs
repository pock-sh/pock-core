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

/// The exact [`CoreError::Flow`] messages that mean "the credential the user
/// supplied was wrong" (as opposed to "the caller passed something malformed").
///
/// These are literal strings constructed in [`crate::flows`] and
/// [`crate::nscrypto`]; matching them exactly — rather than sniffing for
/// substrings — keeps the classification deterministic and means a reworded
/// flow message shows up as a test failure instead of silently changing
/// category. Every other `Flow` message, including the `FromUtf8Error`
/// pass-throughs in `flows`, is a malformed-input condition.
///
/// This list lives here rather than in a binding adapter so every consumer —
/// the UniFFI surface, `pock-client`, anything downstream — classifies against
/// one table instead of keeping a copy that drifts.
pub const WRONG_CREDENTIAL_MESSAGES: &[&str] = &[
    "wrong passphrase or secret key",
    "wrong recovery code",
    "wrong passphrase or corrupted backup",
    "decrypt failed (wrong key or tampered)",
    "touch id unlock failed",
    "wrong namespace passphrase",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_messages_render() {
        assert_eq!(CoreError::Aead.to_string(), "AEAD encryption/decryption failed");
        assert_eq!(CoreError::WrongKey.to_string(), "wrong key or corrupted ciphertext");
    }

    /// A duplicate entry would let a reworded message keep classifying by
    /// accident, and the empty string would match a `Flow("")`.
    #[test]
    fn the_wrong_credential_table_is_distinct_and_non_empty() {
        let mut seen = std::collections::HashSet::new();
        for m in WRONG_CREDENTIAL_MESSAGES {
            assert!(!m.is_empty());
            assert!(seen.insert(*m), "duplicate entry {m:?}");
        }
        assert!(WRONG_CREDENTIAL_MESSAGES.contains(&"wrong namespace passphrase"));
    }
}
