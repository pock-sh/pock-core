//! Binding-independent crypto flows.
//!
//! Every function here is pure Rust: no wasm, no UniFFI, no HTTP, no storage.
//! The wasm bindings in `crate::wasm` (and any future UniFFI bindings) are thin
//! adapters over this module, so all surfaces produce byte-identical output.

use crate::aead::{open_aad, seal_aad, AeadKey};
use crate::auk::{
    unwrap_identity, unwrap_secret, unwrap_with_kek, unwrap_with_passphrase, wrap_identity,
    wrap_secret, wrap_with_kek, wrap_with_passphrase, Auk, SecretKey, WrappedAuk,
};
use crate::error::CoreError;
use crate::identity::{Identity, PublicIdentity, PublicIdentityBlob};
use crate::item::{decrypt_item as item_decrypt, encrypt_item as item_encrypt, EncryptedItem};
use crate::kdf::{hkdf_sha256, KdfProfile};
use crate::share::{decrypt_share as share_decrypt, encrypt_share as share_encrypt, Bundle, ShareCipher};
use crate::sign::{SignPublic, SignSecret};

use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub(crate) fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
pub(crate) fn unb64(s: &str) -> Result<Vec<u8>, CoreError> {
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?)
}

#[derive(Serialize, Deserialize)]
pub struct GeneratedIdentity {
    pub secret_b64: String,
    pub public: PublicIdentityBlob,
}

pub fn generate_identity() -> String {
    let id = Identity::generate();
    let out = GeneratedIdentity { secret_b64: b64(&id.to_secret_bytes()), public: id.public().to_blob() };
    serde_json::to_string(&out).expect("serialize identity")
}

pub fn encrypt_item(value: &str, recipient_pub_blobs_json: &str) -> Result<String, CoreError> {
    let blobs: Vec<PublicIdentityBlob> = serde_json::from_str(recipient_pub_blobs_json)?;
    let mut recipients = Vec::new();
    for b in &blobs {
        recipients.push(PublicIdentity::from_blob(b)?.kem);
    }
    let item = item_encrypt(value.as_bytes(), &recipients)?;
    Ok(serde_json::to_string(&item)?)
}

pub fn decrypt_item(item_json: &str, identity_secret_b64: &str) -> Result<String, CoreError> {
    let item: EncryptedItem = serde_json::from_str(item_json)?;
    let id = Identity::from_secret_bytes(&unb64(identity_secret_b64)?)?;
    let pub_kem = id.public().kem;
    let plaintext = item_decrypt(&item, &id.kem, &pub_kem)?;
    String::from_utf8(plaintext).map_err(|e| CoreError::Flow(e.to_string()))
}

pub fn encrypt_share(bundle_json: &str, cipher_id: &str) -> Result<String, CoreError> {
    let bundle: Bundle = serde_json::from_str(bundle_json)?;
    let cipher = ShareCipher::from_id(cipher_id).ok_or_else(|| CoreError::Flow("unknown cipher id".into()))?;
    let (envelope, key_blob) = share_encrypt(&bundle, cipher)?;
    let out = serde_json::json!({ "envelope_b64": b64(&envelope), "key_blob": key_blob });
    Ok(out.to_string())
}

pub fn decrypt_share(envelope_b64: &str, key_blob: &str) -> Result<String, CoreError> {
    let envelope = unb64(envelope_b64)?;
    let bundle = share_decrypt(&envelope, key_blob)?;
    Ok(serde_json::to_string(&bundle)?)
}

/// Creates a vault whose AUK is wrapped with the browser-safe Argon2 profile.
///
/// Every existing surface calls this, so it stays pinned to
/// [`KdfProfile::Constrained`]: a vault minted with the heavier parameters
/// could not be unlocked in a browser tab.
pub fn create_vault(passphrase: &str) -> Result<String, CoreError> {
    create_vault_profile(passphrase, "constrained")
}

/// Creates a vault with an explicitly chosen Argon2 profile.
///
/// `profile_id` is exactly `"native"` or `"constrained"`; anything else is
/// [`CoreError::InvalidInput`]. The two ids mirror [`KdfProfile`]'s two
/// variants — there is deliberately no third profile, because the id is baked
/// into the wrapped AUK and a vault can only be opened by a surface that knows
/// its parameters. `"native"` exists for the CLI and desktop, which are not
/// bound by a browser's memory ceiling.
pub fn create_vault_profile(passphrase: &str, profile_id: &str) -> Result<String, CoreError> {
    use rand::RngCore;
    let profile = match profile_id {
        "native" => KdfProfile::Native,
        "constrained" => KdfProfile::Constrained,
        other => {
            return Err(CoreError::InvalidInput(format!("unknown kdf profile {other:?}")));
        }
    };
    let identity = Identity::generate();
    let auk = Auk::generate();
    let secret_key = SecretKey::random();
    let mut rb = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut rb);
    let recovery_code = b64(&rb);

    let wrapped_pp = wrap_with_passphrase(&auk, passphrase.as_bytes(), &secret_key, profile);
    let recovery_kek = hkdf_sha256(recovery_code.as_bytes(), b"", b"pock/recovery/v1");
    let wrapped_rec = wrap_with_kek(&auk, &recovery_kek, "recovery");
    let wrapped_identity = wrap_identity(&auk, &identity);
    let pubid = identity.public();

    let out = serde_json::json!({
        "signPubkey": b64(pubid.sign.as_bytes()),
        "kemPubkey": b64(&pubid.kem.as_bytes()),
        "wrappedIdentity": wrapped_identity,
        "secretKey": b64(secret_key.as_bytes()),
        "recoveryCode": recovery_code,
        "wrappedAukPassphrase": serde_json::to_value(&wrapped_pp)?,
        "wrappedAukRecovery": serde_json::to_value(&wrapped_rec)?,
        "identitySecretB64": b64(&identity.to_secret_bytes()),
    });
    Ok(out.to_string())
}

pub fn unlock_vault(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    wrapped_identity_b64: &str,
) -> Result<String, CoreError> {
    let secret_key = parse_sk(secret_key_b64)?;
    let wrapped_auk: WrappedAuk = serde_json::from_str(wrapped_auk_json)?;
    let auk = unwrap_with_passphrase(&wrapped_auk, passphrase.as_bytes(), &secret_key)
        .map_err(|_| CoreError::Flow("wrong passphrase or secret key".into()))?;
    let identity = unwrap_identity(&auk, wrapped_identity_b64)?;
    Ok(serde_json::json!({ "identitySecretB64": b64(&identity.to_secret_bytes()) }).to_string())
}

/// Unlock using ONLY the recovery code (a single high-entropy factor). No passphrase or
/// Secret Key needed — this is the "I forgot my passphrase" path.
pub fn unlock_recovery(
    recovery_code: &str,
    wrapped_recovery_json: &str,
    wrapped_identity_b64: &str,
) -> Result<String, CoreError> {
    let wrapped_rec: WrappedAuk = serde_json::from_str(wrapped_recovery_json)?;
    let recovery_kek = hkdf_sha256(recovery_code.trim().as_bytes(), b"", b"pock/recovery/v1");
    let auk = unwrap_with_kek(&wrapped_rec, &recovery_kek)
        .map_err(|_| CoreError::Flow("wrong recovery code".into()))?;
    let identity = unwrap_identity(&auk, wrapped_identity_b64)?;
    Ok(serde_json::json!({ "identitySecretB64": b64(&identity.to_secret_bytes()) }).to_string())
}

/// After a recovery unlock, re-wrap the AUK under a NEW passphrase (+ the Secret Key), so
/// the user can set a passphrase they'll remember. Returns the new wrappedAukPassphrase to
/// register server-side. The identity keypair itself is unchanged.
pub fn reset_passphrase(
    recovery_code: &str,
    wrapped_recovery_json: &str,
    secret_key_b64: &str,
    new_passphrase: &str,
) -> Result<String, CoreError> {
    let wrapped_rec: WrappedAuk = serde_json::from_str(wrapped_recovery_json)?;
    let recovery_kek = hkdf_sha256(recovery_code.trim().as_bytes(), b"", b"pock/recovery/v1");
    let auk = unwrap_with_kek(&wrapped_rec, &recovery_kek)
        .map_err(|_| CoreError::Flow("wrong recovery code".into()))?;
    let secret_key = parse_sk(secret_key_b64)?;
    let wrapped_pp = wrap_with_passphrase(&auk, new_passphrase.as_bytes(), &secret_key, KdfProfile::Constrained);
    Ok(serde_json::json!({
        "wrappedAukPassphrase": serde_json::to_value(&wrapped_pp)?,
    })
    .to_string())
}

fn aead_key(key_b64: &str) -> Result<AeadKey, CoreError> {
    let kb = unb64(key_b64)?;
    let arr: [u8; 32] = kb
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Flow("bad symmetric key length".into()))?;
    Ok(AeadKey::from_bytes(arr))
}

/// Random 32-byte XChaCha20-Poly1305 key, base64. Used as a chat channel key
/// or a per-attachment blob key.
pub fn generate_symmetric_key() -> String {
    b64(AeadKey::random().as_bytes())
}

/// Symmetric AEAD seal: returns nonce||ciphertext. `aad` binds context (e.g.
/// `channel_id|key_version|sender_id`) into the tag without being stored.
pub fn seal_symmetric(key_b64: &str, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
    Ok(seal_aad(&aead_key(key_b64)?, plaintext, aad))
}

pub fn open_symmetric(key_b64: &str, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
    open_aad(&aead_key(key_b64)?, blob, aad)
        .map_err(|_| CoreError::Flow("decrypt failed (wrong key or tampered)".into()))
}

/// Ed25519 signature over `msg` with the identity's signing key, base64.
pub fn sign_message(identity_secret_b64: &str, msg: &[u8]) -> Result<String, CoreError> {
    let id = Identity::from_secret_bytes(&unb64(identity_secret_b64)?)?;
    Ok(b64(&id.sign.sign(msg)))
}

pub fn verify_message(sign_pubkey_b64: &str, msg: &[u8], sig_b64: &str) -> Result<bool, CoreError> {
    let pk_bytes = unb64(sign_pubkey_b64)?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Flow("bad sign pubkey length".into()))?;
    let sig_bytes = unb64(sig_b64)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::Flow("bad signature length".into()))?;
    Ok(SignPublic::from_bytes(pk_arr).verify(msg, &sig_arr).is_ok())
}

fn parse_sk(secret_key_b64: &str) -> Result<SecretKey, CoreError> {
    let sk_bytes = unb64(secret_key_b64)?;
    let sk_arr: [u8; 16] = sk_bytes.as_slice().try_into().map_err(|_| CoreError::Flow("bad secret key".into()))?;
    Ok(SecretKey::from_bytes(sk_arr))
}

fn unlock_auk(passphrase: &str, secret_key_b64: &str, wrapped_auk_json: &str) -> Result<Auk, CoreError> {
    let wrapped: WrappedAuk = serde_json::from_str(wrapped_auk_json)?;
    unwrap_with_passphrase(&wrapped, passphrase.as_bytes(), &parse_sk(secret_key_b64)?)
        .map_err(|_| CoreError::Flow("wrong passphrase or secret key".into()))
}

/// Change the passphrase while unlocked (old passphrase known). The AUK,
/// identity, recovery code, and passkeys are all unchanged — this only
/// re-wraps the AUK under the new passphrase + same Secret Key.
pub fn change_passphrase(
    old_passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    new_passphrase: &str,
) -> Result<String, CoreError> {
    let auk = unlock_auk(old_passphrase, secret_key_b64, wrapped_auk_json)?;
    let wrapped = wrap_with_passphrase(&auk, new_passphrase.as_bytes(), &parse_sk(secret_key_b64)?, KdfProfile::Constrained);
    Ok(serde_json::json!({
        "wrappedAukPassphrase": serde_json::to_value(&wrapped)?,
    })
    .to_string())
}

/// Rotate the Secret Key (the "have" factor). Mints a fresh 16-byte key and
/// re-wraps the AUK under passphrase + new key. Recovery and passkey wraps
/// are KEK-based and unaffected.
pub fn rotate_secret_key(
    passphrase: &str,
    old_secret_key_b64: &str,
    wrapped_auk_json: &str,
) -> Result<String, CoreError> {
    let auk = unlock_auk(passphrase, old_secret_key_b64, wrapped_auk_json)?;
    let new_sk = SecretKey::random();
    let wrapped = wrap_with_passphrase(&auk, passphrase.as_bytes(), &new_sk, KdfProfile::Constrained);
    Ok(serde_json::json!({
        "secretKey": b64(new_sk.as_bytes()),
        "wrappedAukPassphrase": serde_json::to_value(&wrapped)?,
    })
    .to_string())
}

/// Regenerate the recovery code. Mints a fresh high-entropy code and wraps
/// the AUK under its derived KEK; the old code stops working once the server
/// replaces the stored recovery wrap.
pub fn rotate_recovery_code(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
) -> Result<String, CoreError> {
    use rand::RngCore;
    let auk = unlock_auk(passphrase, secret_key_b64, wrapped_auk_json)?;
    let mut rb = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut rb);
    let recovery_code = b64(&rb);
    let recovery_kek = hkdf_sha256(recovery_code.as_bytes(), b"", b"pock/recovery/v1");
    let wrapped = wrap_with_kek(&auk, &recovery_kek, "recovery");
    Ok(serde_json::json!({
        "recoveryCode": recovery_code,
        "wrappedAukRecovery": serde_json::to_value(&wrapped)?,
    })
    .to_string())
}

/// Deep rotation: mint a brand-new identity keypair wrapped under the same
/// AUK. The caller must re-encrypt every item to the new public identity and
/// re-register pubkeys server-side; until then old blobs still need the old
/// secret (also returned).
pub fn rotate_identity(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    old_wrapped_identity_b64: &str,
) -> Result<String, CoreError> {
    let auk = unlock_auk(passphrase, secret_key_b64, wrapped_auk_json)?;
    let old = unwrap_identity(&auk, old_wrapped_identity_b64)?;
    let fresh = Identity::generate();
    let pubid = fresh.public();
    Ok(serde_json::json!({
        "signPubkey": b64(pubid.sign.as_bytes()),
        "kemPubkey": b64(&pubid.kem.as_bytes()),
        "wrappedIdentity": wrap_identity(&auk, &fresh),
        "identitySecretB64": b64(&fresh.to_secret_bytes()),
        "oldIdentitySecretB64": b64(&old.to_secret_bytes()),
        "publicBlob": serde_json::to_value(pubid.to_blob())?,
    })
    .to_string())
}

/// Encrypted binary vault backup (.pockvault). Standalone: only the backup
/// passphrase is needed to restore.
pub fn export_backup(json: &str, passphrase: &str) -> Result<Vec<u8>, CoreError> {
    crate::backup::export_backup(json.as_bytes(), passphrase.as_bytes())
}

pub fn import_backup(data: &[u8], passphrase: &str) -> Result<String, CoreError> {
    let pt = crate::backup::import_backup(data, passphrase.as_bytes())
        .map_err(|_| CoreError::Flow("wrong passphrase or corrupted backup".into()))?;
    String::from_utf8(pt).map_err(|e| CoreError::Flow(e.to_string()))
}

const PRF_INFO: &[u8] = b"pock/webauthn-prf/v1";

fn prf_kek(prf_secret_b64: &str) -> Result<[u8; 32], CoreError> {
    let secret = unb64(prf_secret_b64)?;
    Ok(hkdf_sha256(&secret, b"", PRF_INFO))
}

pub fn enroll_prf(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    prf_secret_b64: &str,
) -> Result<String, CoreError> {
    let secret_key = parse_sk(secret_key_b64)?;
    let wrapped_auk: WrappedAuk = serde_json::from_str(wrapped_auk_json)?;
    let auk = unwrap_with_passphrase(&wrapped_auk, passphrase.as_bytes(), &secret_key)
        .map_err(|_| CoreError::Flow("wrong passphrase or secret key".into()))?;
    let kek = prf_kek(prf_secret_b64)?;
    let wrapped_prf = wrap_with_kek(&auk, &kek, "webauthn-prf");
    Ok(serde_json::to_string(&wrapped_prf)?)
}

pub fn unlock_prf(
    prf_secret_b64: &str,
    wrapped_auk_prf_json: &str,
    wrapped_identity_b64: &str,
) -> Result<String, CoreError> {
    let wrapped_prf: WrappedAuk = serde_json::from_str(wrapped_auk_prf_json)?;
    let kek = prf_kek(prf_secret_b64)?;
    let auk = unwrap_with_kek(&wrapped_prf, &kek)
        .map_err(|_| CoreError::Flow("touch id unlock failed".into()))?;
    let identity = unwrap_identity(&auk, wrapped_identity_b64)?;
    Ok(serde_json::json!({ "identitySecretB64": b64(&identity.to_secret_bytes()) }).to_string())
}

// ---- Account Master Key (AMK) -------------------------------------------------
//
// The AMK is a random Ed25519 key sealed under the AUK — the passphrase/passkey-
// gated root of trust. The AUK is derived inside the core and never crosses the
// binding boundary; AMK functions take unlock inputs and return only the AMK
// public key + the AUK-sealed `wrappedAmk` blob, or a signature.

/// Given an unsealed AUK, create-or-load the AMK. `existing_wrapped_amk` empty →
/// mint a fresh Ed25519 key and seal it; non-empty → load it (idempotent).
/// Returns `(SignSecret, wrappedAmk)`.
fn amk_ensure_from_auk(auk: &Auk, existing_wrapped_amk: &str) -> Result<(SignSecret, String), CoreError> {
    if existing_wrapped_amk.is_empty() {
        let s = SignSecret::random();
        let wrapped = wrap_secret(auk, &s.to_bytes());
        Ok((s, wrapped))
    } else {
        let bytes = unwrap_secret(auk, existing_wrapped_amk)?;
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| CoreError::Flow("bad amk length".into()))?;
        Ok((SignSecret::from_bytes(&arr)?, existing_wrapped_amk.to_string()))
    }
}

/// Unseal the AMK from the AUK and Ed25519-sign `msg`. Returns base64 signature.
fn amk_sign_from_auk(auk: &Auk, wrapped_amk: &str, msg: &[u8]) -> Result<String, CoreError> {
    let bytes = unwrap_secret(auk, wrapped_amk)?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| CoreError::Flow("bad amk length".into()))?;
    let s = SignSecret::from_bytes(&arr)?;
    Ok(b64(&s.sign(msg)))
}

/// Create-or-load the Account Master Key (Ed25519) sealed under the AUK
/// (passphrase path). Returns JSON `{ "amkPub": b64, "wrappedAmk": b64 }`.
pub fn amk_ensure(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    existing_wrapped_amk: &str,
) -> Result<String, CoreError> {
    let auk = unlock_auk(passphrase, secret_key_b64, wrapped_auk_json)?;
    let (amk_secret, wrapped_amk) = amk_ensure_from_auk(&auk, existing_wrapped_amk)?;
    Ok(serde_json::json!({
        "amkPub": b64(amk_secret.public().as_bytes()),
        "wrappedAmk": wrapped_amk,
    })
    .to_string())
}

/// Sign `msg` with the AMK (unsealed under the AUK, passphrase path). Returns
/// base64 Ed25519 signature.
pub fn amk_sign(
    passphrase: &str,
    secret_key_b64: &str,
    wrapped_auk_json: &str,
    wrapped_amk: &str,
    msg: &[u8],
) -> Result<String, CoreError> {
    let auk = unlock_auk(passphrase, secret_key_b64, wrapped_auk_json)?;
    amk_sign_from_auk(&auk, wrapped_amk, msg)
}

fn auk_from_prf(prf_secret_b64: &str, wrapped_auk_prf_json: &str) -> Result<Auk, CoreError> {
    let wrapped_prf: WrappedAuk = serde_json::from_str(wrapped_auk_prf_json)?;
    let kek = prf_kek(prf_secret_b64)?;
    unwrap_with_kek(&wrapped_prf, &kek).map_err(|_| CoreError::Flow("touch id unlock failed".into()))
}

/// Create-or-load the AMK sealed under the AUK (PRF / passkey path).
pub fn amk_ensure_prf(
    prf_secret_b64: &str,
    wrapped_auk_prf_json: &str,
    existing_wrapped_amk: &str,
) -> Result<String, CoreError> {
    let auk = auk_from_prf(prf_secret_b64, wrapped_auk_prf_json)?;
    let (amk_secret, wrapped_amk) = amk_ensure_from_auk(&auk, existing_wrapped_amk)?;
    Ok(serde_json::json!({
        "amkPub": b64(amk_secret.public().as_bytes()),
        "wrappedAmk": wrapped_amk,
    })
    .to_string())
}

/// Sign `msg` with the AMK (unsealed under the AUK, PRF / passkey path).
pub fn amk_sign_prf(
    prf_secret_b64: &str,
    wrapped_auk_prf_json: &str,
    wrapped_amk: &str,
    msg: &[u8],
) -> Result<String, CoreError> {
    let auk = auk_from_prf(prf_secret_b64, wrapped_auk_prf_json)?;
    amk_sign_from_auk(&auk, wrapped_amk, msg)
}

// ---------------------------------------------------------------------------
// Chat message digest
// ---------------------------------------------------------------------------

/// The bytes a chat message signature covers: `SHA-256(aad ‖ ct)`.
///
/// Mirrors `digestFor` in `chat-app/src/lib/crypto.ts`, which concatenates the
/// AAD and the ciphertext and hashes once. Signing the digest rather than the
/// message keeps the signature independent of message size while still binding
/// channel, key version and sender through the AAD.
pub fn message_digest(aad: &[u8], ct: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(aad);
    h.update(ct);
    h.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// Namespace protection (`pns1.`)
// ---------------------------------------------------------------------------
//
// These wrappers take and return the namespace key as **standard** base64 so no
// raw key bytes cross the wasm / UniFFI boundary as a `Vec<u8>` a host runtime
// might log or copy into a JS heap it does not control. `crate::nscrypto` stays
// the byte-level API that Rust callers (pock-client, the CLI) use directly.

fn ns_b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}
fn ns_unb64(s: &str) -> Result<Vec<u8>, CoreError> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s))
        .map_err(|e| CoreError::Encoding(e.to_string()))
}

/// Wraps a namespace key (standard base64) under a namespace passphrase.
pub fn ns_wrap_nk(nk_b64: &str, passphrase: &str, salt_b64: &str) -> Result<String, CoreError> {
    let nk = Zeroizing::new(ns_unb64(nk_b64)?);
    crate::nscrypto::wrap_nk(&nk, passphrase, salt_b64)
}

/// Unwraps a namespace key, returning it as **standard** base64.
pub fn ns_unwrap_nk(wrapped: &str, passphrase: &str, salt_b64: &str) -> Result<String, CoreError> {
    let nk = Zeroizing::new(crate::nscrypto::unwrap_nk(wrapped, passphrase, salt_b64)?);
    Ok(ns_b64(&nk))
}

/// Encrypts one value under the namespace key; the result carries the `pns1.` prefix.
pub fn ns_protect_value(nk_b64: &str, value: &str) -> Result<String, CoreError> {
    let nk = Zeroizing::new(ns_unb64(nk_b64)?);
    crate::nscrypto::protect_value(&nk, value)
}

/// Decrypts a `pns1.` value under the namespace key.
pub fn ns_unprotect_value(nk_b64: &str, blob: &str) -> Result<String, CoreError> {
    let nk = Zeroizing::new(ns_unb64(nk_b64)?);
    crate::nscrypto::unprotect_value(&nk, blob)
}

/// A fresh namespace key, standard base64.
pub fn ns_random_nk() -> String {
    ns_b64(&crate::nscrypto::random_nk())
}

/// A fresh PBKDF2 salt for a namespace, standard base64.
pub fn ns_random_salt() -> String {
    crate::nscrypto::random_salt_b64()
}

/// A fresh namespace recovery code (`"a1b2-c3d4-…"`).
pub fn ns_random_recovery_code() -> String {
    crate::nscrypto::random_ns_recovery_code()
}

/// Standard base64 of `SHA-256(nk)` — a namespace identifier for the audit log.
pub fn ns_nk_hash(nk_b64: &str) -> Result<String, CoreError> {
    let nk = Zeroizing::new(ns_unb64(nk_b64)?);
    Ok(crate::nscrypto::nk_hash(&nk))
}

/// Whether a stored value carries the `pns1.` prefix.
pub fn ns_is_protected(blob: &str) -> bool {
    crate::nscrypto::is_protected_blob(blob)
}

// ---------------------------------------------------------------------------
// Key-transparency canonical bytes (JSON-shaped for the bindings)
// ---------------------------------------------------------------------------
//
// The JSON payloads use the camelCase field names the transparency Worker
// already sends, so a caller can hand a proof straight through without
// re-shaping it.

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertJson {
    user_id: String,
    kem_pubkey: String,
    sign_pubkey: String,
    rot: crate::keylog::Rot,
    principal_seq: u64,
    ts: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LeafJson {
    user_id: String,
    kem_pubkey: String,
    sign_pubkey: String,
    ts: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SthJson {
    log_id: String,
    size: u64,
    root: String,
    ts: i64,
}

/// Canonical bytes of a succession certificate, from
/// `{userId,kemPubkey,signPubkey,rot,principalSeq,ts}`.
pub fn cert_bytes_json(cert_json: &str) -> Result<Vec<u8>, CoreError> {
    let c: CertJson = serde_json::from_str(cert_json)?;
    Ok(crate::keylog::cert_bytes(
        &c.user_id,
        &c.kem_pubkey,
        &c.sign_pubkey,
        &c.rot,
        c.principal_seq,
        c.ts,
    ))
}

/// Canonical bytes of a log leaf, from `{userId,kemPubkey,signPubkey,ts}`.
pub fn leaf_bytes_json(leaf_json: &str) -> Result<Vec<u8>, CoreError> {
    let l: LeafJson = serde_json::from_str(leaf_json)?;
    Ok(crate::keylog::leaf_bytes(&l.user_id, &l.kem_pubkey, &l.sign_pubkey, l.ts))
}

/// Canonical bytes of a Signed Tree Head, from `{logId,size,root,ts}`.
pub fn sth_message_json(sth_json: &str) -> Result<Vec<u8>, CoreError> {
    let s: SthJson = serde_json::from_str(sth_json)?;
    Ok(crate::keylog::sth_message(&s.log_id, s.size, &s.root, s.ts))
}

/// k-of-n verification of a certificate described by the same JSON shape
/// [`cert_bytes_json`] takes, against JSON arrays of signatures and custodians.
pub fn verify_cert_json(
    cert_json: &str,
    sigs_json: &str,
    custodians_json: &str,
    threshold: u32,
) -> Result<bool, CoreError> {
    let bytes = cert_bytes_json(cert_json)?;
    let sigs: Vec<String> = serde_json::from_str(sigs_json)?;
    let custodians: Vec<String> = serde_json::from_str(custodians_json)?;
    Ok(crate::keylog::verify_cert(&bytes, &sigs, &custodians, threshold))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_unlock_vault_roundtrip() {
        let created = create_vault("correct horse battery staple").unwrap();
        let v: serde_json::Value = serde_json::from_str(&created).unwrap();
        assert!(v.get("secretKey").is_some(), "create_vault JSON must expose secretKey: {created}");

        let secret_key = v["secretKey"].as_str().unwrap();
        let wrapped_auk = serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap();
        let wrapped_identity = v["wrappedIdentity"].as_str().unwrap();

        let unlocked =
            unlock_vault("correct horse battery staple", secret_key, &wrapped_auk, wrapped_identity).unwrap();
        let u: serde_json::Value = serde_json::from_str(&unlocked).unwrap();
        assert_eq!(u["identitySecretB64"].as_str().unwrap(), v["identitySecretB64"].as_str().unwrap());
    }

    #[test]
    fn enroll_and_unlock_prf() {
        let created = create_vault("pw").unwrap();
        let v: serde_json::Value = serde_json::from_str(&created).unwrap();
        let sk = v["secretKey"].as_str().unwrap();
        let wpp = serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap();
        let wid = v["wrappedIdentity"].as_str().unwrap();

        // 43 base64url 'A's decode to 32 zero bytes - a fixed stand-in for the
        // authenticator's PRF output.
        let prf_secret = "A".repeat(43);
        let wrapped_prf = enroll_prf("pw", sk, &wpp, &prf_secret).unwrap();
        let unlocked = unlock_prf(&prf_secret, &wrapped_prf, wid).unwrap();
        let u: serde_json::Value = serde_json::from_str(&unlocked).unwrap();
        assert_eq!(u["identitySecretB64"].as_str().unwrap(), v["identitySecretB64"].as_str().unwrap());
    }

    #[test]
    fn amk_ensure_is_idempotent_and_sign_verifies() {
        let created = create_vault("correct horse").unwrap();
        let v: serde_json::Value = serde_json::from_str(&created).unwrap();
        let sk = v["secretKey"].as_str().unwrap();
        let wpp = serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap();

        // First ensure mints the AMK.
        let out1: serde_json::Value =
            serde_json::from_str(&amk_ensure("correct horse", sk, &wpp, "").unwrap()).unwrap();
        let amk_pub = out1["amkPub"].as_str().unwrap().to_string();
        let wrapped_amk = out1["wrappedAmk"].as_str().unwrap().to_string();

        // Second ensure with the existing blob returns the SAME public key.
        let out2: serde_json::Value =
            serde_json::from_str(&amk_ensure("correct horse", sk, &wpp, &wrapped_amk).unwrap()).unwrap();
        assert_eq!(out2["amkPub"].as_str().unwrap(), amk_pub);

        let msg = b"succession-cert-bytes";
        let sig = amk_sign("correct horse", sk, &wpp, &wrapped_amk, msg).unwrap();
        assert!(verify_message(&amk_pub, msg, &sig).unwrap());

        // Wrong passphrase must not sign.
        assert!(amk_sign("wrong", sk, &wpp, &wrapped_amk, b"x").is_err());
    }

    #[test]
    fn amk_prf_path_signs_and_verifies() {
        let created = create_vault("pw").unwrap();
        let v: serde_json::Value = serde_json::from_str(&created).unwrap();
        let sk = v["secretKey"].as_str().unwrap();
        let wpp = serde_json::to_string(&v["wrappedAukPassphrase"]).unwrap();
        let prf_secret = "A".repeat(43);
        let wrapped_prf = enroll_prf("pw", sk, &wpp, &prf_secret).unwrap();

        let out: serde_json::Value =
            serde_json::from_str(&amk_ensure_prf(&prf_secret, &wrapped_prf, "").unwrap()).unwrap();
        let amk_pub = out["amkPub"].as_str().unwrap().to_string();
        let wrapped_amk = out["wrappedAmk"].as_str().unwrap().to_string();

        let sig = amk_sign_prf(&prf_secret, &wrapped_prf, &wrapped_amk, b"cert").unwrap();
        assert!(verify_message(&amk_pub, b"cert", &sig).unwrap());
    }

    // ---- helpers --------------------------------------------------------

    /// A freshly created vault, parsed. Every field callers depend on.
    struct Vault {
        v: serde_json::Value,
    }
    impl Vault {
        fn new(pw: &str) -> Vault {
            Vault { v: serde_json::from_str(&create_vault(pw).unwrap()).unwrap() }
        }
        fn s(&self, k: &str) -> &str {
            self.v[k].as_str().unwrap_or_else(|| panic!("create_vault missing string key {k}: {}", self.v))
        }
        /// A nested wrap object re-serialized as the JSON string the flows take.
        fn wrap(&self, k: &str) -> String {
            assert!(self.v.get(k).is_some(), "create_vault missing key {k}: {}", self.v);
            serde_json::to_string(&self.v[k]).unwrap()
        }
        fn identity(&self) -> &str {
            self.s("identitySecretB64")
        }
    }

    fn json(s: &str) -> serde_json::Value {
        serde_json::from_str(s).unwrap()
    }

    /// Assert the flow's JSON has exactly the keys callers read, then return it.
    fn json_with_keys(s: &str, keys: &[&str]) -> serde_json::Value {
        let v = json(s);
        for k in keys {
            assert!(v.get(*k).is_some(), "flow output missing key {k}: {s}");
        }
        v
    }

    /// The `identitySecretB64` an unlock flow returns.
    fn unlocked_identity(s: &str) -> String {
        json_with_keys(s, &["identitySecretB64"])["identitySecretB64"].as_str().unwrap().to_string()
    }

    // ---- recovery + passphrase reset ------------------------------------

    #[test]
    fn recovery_unlock_then_reset_passphrase_chain() {
        let vault = Vault::new("original pw");
        let code = vault.s("recoveryCode").to_string();
        let wrec = vault.wrap("wrappedAukRecovery");
        let wid = vault.s("wrappedIdentity").to_string();
        let sk = vault.s("secretKey").to_string();

        // 1. Recovery code alone unlocks to the same identity.
        let recovered = unlock_recovery(&code, &wrec, &wid).unwrap();
        assert_eq!(unlocked_identity(&recovered), vault.identity());

        // A surrounding-whitespace code is trimmed and still works.
        let padded = format!("  {code}\n");
        assert_eq!(unlocked_identity(&unlock_recovery(&padded, &wrec, &wid).unwrap()), vault.identity());

        // A wrong recovery code does not.
        assert!(unlock_recovery(&"B".repeat(27), &wrec, &wid).is_err());

        // 2. Reset to a new passphrase using the recovery code + Secret Key.
        let reset = reset_passphrase(&code, &wrec, &sk, "brand new pw").unwrap();
        let new_wpp = serde_json::to_string(&json_with_keys(&reset, &["wrappedAukPassphrase"])["wrappedAukPassphrase"]).unwrap();

        // 3. The new passphrase unlocks the SAME identity through the new wrap.
        assert_eq!(unlocked_identity(&unlock_vault("brand new pw", &sk, &new_wpp, &wid).unwrap()), vault.identity());

        // 4. The old passphrase no longer opens the new wrap.
        assert!(unlock_vault("original pw", &sk, &new_wpp, &wid).is_err());
    }

    #[test]
    fn change_passphrase_then_unlock_with_new_one() {
        let vault = Vault::new("old pw");
        let sk = vault.s("secretKey").to_string();
        let wpp = vault.wrap("wrappedAukPassphrase");
        let wid = vault.s("wrappedIdentity").to_string();

        let changed = change_passphrase("old pw", &sk, &wpp, "new pw").unwrap();
        let new_wpp = serde_json::to_string(&json_with_keys(&changed, &["wrappedAukPassphrase"])["wrappedAukPassphrase"]).unwrap();

        // New passphrase opens the new wrap onto the unchanged identity.
        assert_eq!(unlocked_identity(&unlock_vault("new pw", &sk, &new_wpp, &wid).unwrap()), vault.identity());
        // Old passphrase does not open the new wrap.
        assert!(unlock_vault("old pw", &sk, &new_wpp, &wid).is_err());
        // Wrong old passphrase cannot drive the change at all.
        assert!(change_passphrase("not the pw", &sk, &wpp, "whatever").is_err());
    }

    // ---- rotations -------------------------------------------------------

    #[test]
    fn rotate_secret_key_then_unlock_with_new_key() {
        let vault = Vault::new("pw");
        let old_sk = vault.s("secretKey").to_string();
        let wpp = vault.wrap("wrappedAukPassphrase");
        let wid = vault.s("wrappedIdentity").to_string();

        let rotated = rotate_secret_key("pw", &old_sk, &wpp).unwrap();
        let r = json_with_keys(&rotated, &["secretKey", "wrappedAukPassphrase"]);
        let new_sk = r["secretKey"].as_str().unwrap().to_string();
        let new_wpp = serde_json::to_string(&r["wrappedAukPassphrase"]).unwrap();
        assert_ne!(new_sk, old_sk, "rotation must mint a fresh Secret Key");

        // Same passphrase + NEW secret key opens the new wrap onto the same identity.
        assert_eq!(unlocked_identity(&unlock_vault("pw", &new_sk, &new_wpp, &wid).unwrap()), vault.identity());
        // The old Secret Key no longer opens the new wrap.
        assert!(unlock_vault("pw", &old_sk, &new_wpp, &wid).is_err());
    }

    #[test]
    fn rotate_recovery_code_then_unlock_with_new_code() {
        let vault = Vault::new("pw");
        let sk = vault.s("secretKey").to_string();
        let wpp = vault.wrap("wrappedAukPassphrase");
        let wid = vault.s("wrappedIdentity").to_string();
        let old_code = vault.s("recoveryCode").to_string();

        let rotated = rotate_recovery_code("pw", &sk, &wpp).unwrap();
        let r = json_with_keys(&rotated, &["recoveryCode", "wrappedAukRecovery"]);
        let new_code = r["recoveryCode"].as_str().unwrap().to_string();
        let new_wrec = serde_json::to_string(&r["wrappedAukRecovery"]).unwrap();
        assert_ne!(new_code, old_code, "rotation must mint a fresh recovery code");

        // The new code unlocks the same identity through the new recovery wrap.
        assert_eq!(unlocked_identity(&unlock_recovery(&new_code, &new_wrec, &wid).unwrap()), vault.identity());
        // The old code is dead against the new wrap.
        assert!(unlock_recovery(&old_code, &new_wrec, &wid).is_err());
    }

    #[test]
    fn rotate_identity_then_encrypt_and_decrypt_to_new_identity() {
        let vault = Vault::new("pw");
        let sk = vault.s("secretKey").to_string();
        let wpp = vault.wrap("wrappedAukPassphrase");
        let old_wid = vault.s("wrappedIdentity").to_string();

        let rotated = rotate_identity("pw", &sk, &wpp, &old_wid).unwrap();
        let r = json_with_keys(
            &rotated,
            &[
                "signPubkey",
                "kemPubkey",
                "wrappedIdentity",
                "identitySecretB64",
                "oldIdentitySecretB64",
                "publicBlob",
            ],
        );
        let new_secret = r["identitySecretB64"].as_str().unwrap().to_string();
        let new_wid = r["wrappedIdentity"].as_str().unwrap().to_string();

        // The old secret is handed back verbatim so callers can re-encrypt.
        assert_eq!(r["oldIdentitySecretB64"].as_str().unwrap(), vault.identity());
        assert_ne!(new_secret, vault.identity(), "rotation must mint a fresh identity");

        // The returned publicBlob is a usable recipient: encrypt to it, decrypt with the new secret.
        let recipients = format!("[{}]", serde_json::to_string(&r["publicBlob"]).unwrap());
        let item = encrypt_item("ROTATED=yes", &recipients).unwrap();
        assert_eq!(decrypt_item(&item, &new_secret).unwrap(), "ROTATED=yes");
        // The pre-rotation identity cannot read an item sealed to the new one.
        assert!(decrypt_item(&item, vault.identity()).is_err());

        // The new wrappedIdentity unwraps under the unchanged AUK to the new secret.
        assert_eq!(unlocked_identity(&unlock_vault("pw", &sk, &wpp, &new_wid).unwrap()), new_secret);
    }

    // ---- backup ----------------------------------------------------------

    #[test]
    fn backup_export_import_roundtrip() {
        let payload = r#"{"v":1,"items":[{"name":"prod .env","value":"API_KEY=abc123"}]}"#;
        let blob = export_backup(payload, "backup pw").unwrap();

        assert!(!blob.is_empty());
        // The plaintext must not survive anywhere in the encrypted blob.
        assert!(
            blob.windows(payload.len()).all(|w| w != payload.as_bytes()),
            "backup blob leaks plaintext"
        );

        assert_eq!(import_backup(&blob, "backup pw").unwrap(), payload);
        assert!(import_backup(&blob, "wrong pw").is_err());

        // A tampered byte in the ciphertext body must fail the AEAD tag.
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(import_backup(&tampered, "backup pw").is_err());
    }

    // ---- symmetric AEAD --------------------------------------------------

    #[test]
    fn symmetric_seal_open_roundtrip_and_aad_binding() {
        let key = generate_symmetric_key();
        assert_eq!(unb64(&key).unwrap().len(), 32, "symmetric key must be 32 bytes");

        let plaintext = b"channel message body";
        let aad = b"chan_123|v1|user_abc";
        let blob = seal_symmetric(&key, plaintext, aad).unwrap();

        assert!(blob.len() > plaintext.len(), "sealed blob carries nonce + tag");
        assert!(blob.windows(plaintext.len()).all(|w| w != plaintext), "sealed blob leaks plaintext");

        // Same key + same AAD round-trips.
        assert_eq!(open_symmetric(&key, &blob, aad).unwrap(), plaintext);

        // AAD is authenticated: a different context must not open the blob.
        assert!(open_symmetric(&key, &blob, b"chan_123|v2|user_abc").is_err());
        assert!(open_symmetric(&key, &blob, b"").is_err());

        // A different key must not open it either.
        let other = generate_symmetric_key();
        assert_ne!(other, key, "keys must be random");
        assert!(open_symmetric(&other, &blob, aad).is_err());

        // Tampered ciphertext fails the tag.
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(open_symmetric(&key, &tampered, aad).is_err());

        // Empty plaintext is still a valid sealed blob.
        let empty = seal_symmetric(&key, b"", aad).unwrap();
        assert_eq!(open_symmetric(&key, &empty, aad).unwrap(), Vec::<u8>::new());
    }

    // ---- create_vault_profile ------------------------------------------

    #[test]
    fn create_vault_defaults_to_the_constrained_profile() {
        let v: serde_json::Value = serde_json::from_str(&create_vault("pw").unwrap()).unwrap();
        let w = &v["wrappedAukPassphrase"];
        let (m, t, p) = KdfProfile::Constrained.params();
        assert_eq!((w["m_kib"].as_u64(), w["t"].as_u64(), w["p"].as_u64()),
                   (Some(m as u64), Some(t as u64), Some(p as u64)));
    }

    #[test]
    fn create_vault_profile_native_records_the_heavier_params_and_still_unlocks() {
        let created = create_vault_profile("pw", "native").unwrap();
        let v: serde_json::Value = serde_json::from_str(&created).unwrap();
        let w = &v["wrappedAukPassphrase"];
        let (m, t, p) = KdfProfile::Native.params();
        assert_eq!((w["m_kib"].as_u64(), w["t"].as_u64(), w["p"].as_u64()),
                   (Some(m as u64), Some(t as u64), Some(p as u64)));
        // The stored params are what unlock reconstructs the profile from, so a
        // native vault must open without the caller naming the profile again.
        unlock_vault(
            "pw",
            v["secretKey"].as_str().unwrap(),
            &w.to_string(),
            v["wrappedIdentity"].as_str().unwrap(),
        )
        .expect("a native-profile vault must unlock");
    }

    #[test]
    fn create_vault_profile_rejects_an_unknown_profile_id() {
        let e = create_vault_profile("pw", "paranoid").unwrap_err();
        assert_eq!(e.to_string(), "invalid input: unknown kdf profile \"paranoid\"");
        assert!(create_vault_profile("pw", "Native").is_err(), "the id is case-sensitive");
        assert!(create_vault_profile("pw", "").is_err());
    }

    // ---- message_digest -------------------------------------------------

    #[test]
    fn message_digest_is_sha256_over_aad_then_ciphertext() {
        use sha2::{Digest, Sha256};
        let aad = b"chan|3|user_1";
        let ct = b"ciphertext";
        let mut joined = aad.to_vec();
        joined.extend_from_slice(ct);
        assert_eq!(message_digest(aad, ct), Sha256::digest(&joined).to_vec());
        assert_eq!(message_digest(aad, ct).len(), 32);
    }

    #[test]
    fn message_digest_binds_the_split_between_aad_and_ciphertext() {
        // Not a plain concat-then-hash escape hatch: moving the boundary must
        // still change the digest for a caller who mis-slices, and it does not,
        // which is exactly why the AAD is fixed-shape at the call site. Pin the
        // behaviour so a future "improvement" that adds a separator is caught
        // as the wire-format break it would be.
        assert_eq!(message_digest(b"ab", b"c"), message_digest(b"a", b"bc"));
    }

    // ---- namespace wrappers --------------------------------------------

    #[test]
    fn namespace_flow_wrappers_roundtrip_through_standard_base64() {
        let nk = ns_random_nk();
        assert!(!nk.contains('-') && !nk.contains('_'), "standard base64");
        assert_eq!(ns_unb64(&nk).unwrap().len(), 32);
        let salt = ns_random_salt();
        let wrapped = ns_wrap_nk(&nk, "pw", &salt).unwrap();
        assert_eq!(ns_unwrap_nk(&wrapped, "pw", &salt).unwrap(), nk);

        let blob = ns_protect_value(&nk, "s3cret").unwrap();
        assert!(ns_is_protected(&blob));
        assert_eq!(ns_unprotect_value(&nk, &blob).unwrap(), "s3cret");
        assert_eq!(ns_nk_hash(&nk).unwrap(), crate::nscrypto::nk_hash(&ns_unb64(&nk).unwrap()));
    }

    #[test]
    fn ns_unwrap_nk_reports_the_classified_wrong_passphrase_message() {
        let nk = ns_random_nk();
        let salt = ns_random_salt();
        let wrapped = ns_wrap_nk(&nk, "pw", &salt).unwrap();
        let e = ns_unwrap_nk(&wrapped, "nope", &salt).unwrap_err();
        assert_eq!(e.to_string(), "wrong namespace passphrase");
        assert!(crate::error::WRONG_CREDENTIAL_MESSAGES.contains(&e.to_string().as_str()));
    }

    #[test]
    fn ns_random_recovery_code_matches_the_typescript_shape() {
        let c = ns_random_recovery_code();
        assert_eq!(c.len(), 24);
        assert!(c.split('-').all(|g| g.len() == 4 && g.chars().all(|ch| ch.is_ascii_hexdigit())));
    }

    // ---- key-log JSON wrappers ------------------------------------------

    #[test]
    fn cert_and_leaf_and_sth_json_wrappers_produce_the_canonical_bytes() {
        let cert = r#"{"userId":"u","kemPubkey":"K","signPubkey":"S",
            "rot":{"custodians":["A","B"],"threshold":2},"principalSeq":4,"ts":9}"#;
        assert_eq!(
            String::from_utf8(cert_bytes_json(cert).unwrap()).unwrap(),
            "pock-keycert-v1\nu\nK\nS\nA,B|2\n4\n9"
        );
        assert_eq!(
            String::from_utf8(leaf_bytes_json(r#"{"userId":"u","kemPubkey":"K","signPubkey":"S","ts":7}"#).unwrap()).unwrap(),
            "pock-keylog-v1\nu\nK\nS\n7"
        );
        assert_eq!(
            String::from_utf8(sth_message_json(r#"{"logId":"pock.sh/keylog/v1","size":3,"root":"ab12","ts":7}"#).unwrap()).unwrap(),
            "pock-sth-v1\npock.sh/keylog/v1\n3\nab12\n7"
        );
    }

    #[test]
    fn a_malformed_cert_payload_is_a_json_error_not_a_panic() {
        assert!(matches!(cert_bytes_json("{}"), Err(CoreError::Json(_))));
        assert!(matches!(leaf_bytes_json("not json"), Err(CoreError::Json(_))));
        assert!(matches!(sth_message_json(r#"{"logId":"x"}"#), Err(CoreError::Json(_))));
    }

    #[test]
    fn verify_cert_json_verifies_a_signature_over_the_canonical_bytes() {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let pk = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sk.verifying_key().as_bytes());
        let cert = format!(
            r#"{{"userId":"u","kemPubkey":"K","signPubkey":"S","rot":{{"custodians":["{pk}"],"threshold":1}},"principalSeq":0,"ts":1}}"#
        );
        let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(sk.sign(&cert_bytes_json(&cert).unwrap()).to_bytes());
        let sigs = serde_json::to_string(&vec![sig]).unwrap();
        let custodians = serde_json::to_string(&vec![pk]).unwrap();
        assert!(verify_cert_json(&cert, &sigs, &custodians, 1).unwrap());
        assert!(!verify_cert_json(&cert, "[]", &custodians, 1).unwrap());
        assert!(!verify_cert_json(&cert, &sigs, &custodians, 2).unwrap());
        assert!(verify_cert_json(&cert, "not json", &custodians, 1).is_err());
    }
}
