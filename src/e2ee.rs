//! End-to-end encryption to the TEE gateway (Obscurify's Encrypted mode).
//!
//! The gateway's attested keyset holds a secp256k1 encryption key
//! (`e2ee_public_keys`, algo [`E2EE_ALGO`]). A client checks the attestation
//! first ([`crate::verify_attestation`]), then encrypts every message's content
//! to that key with a key pair of its own, and sends its public key and the
//! gateway's in the headers [`HEADER_CLIENT_KEY`], [`HEADER_MODEL_KEY`] and
//! [`HEADER_SIGNING_ALGO`]. The gateway decrypts inside its enclave and
//! encrypts each piece of the answer back to the client's key.
//!
//! Each encrypted string is hex of `sender public key (65 bytes, uncompressed)
//! ‖ IV (12 bytes) ‖ AES-256-GCM ciphertext and tag`, where the AES key is
//! HKDF-SHA256 (no salt, info `ecdsa_encryption`) of the ECDH shared point's
//! x-coordinate. The answer uses a fresh sender key for every piece.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use serde_json::Value;
use sha2::Sha256;

/// The keyset entry this module encrypts to.
pub const E2EE_ALGO: &str = "secp256k1-aes-256-gcm-hkdf-sha256";
/// The client's public key (uncompressed, hex).
pub const HEADER_CLIENT_KEY: &str = "X-Client-Pub-Key";
/// The gateway's attested encryption key the request is encrypted to (hex).
pub const HEADER_MODEL_KEY: &str = "X-Model-Pub-Key";
/// Always `ecdsa` (secp256k1) here.
pub const HEADER_SIGNING_ALGO: &str = "X-Signing-Algo";
pub const SIGNING_ALGO: &str = "ecdsa";

const HKDF_INFO: &[u8] = b"ecdsa_encryption";
const KEY_LEN: usize = 65;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// The shortest encrypted string: key, IV and tag of an empty text, as hex.
const MIN_HEX: usize = (KEY_LEN + IV_LEN + TAG_LEN) * 2;

/// Message fields the gateway encrypts in an answer.
const ANSWER_FIELDS: &[&str] = &["content", "reasoning_content", "reasoning"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn err<T>(message: impl Into<String>) -> Result<T, Error> {
    Err(Error(message.into()))
}

fn public_key(hex_key: &str) -> Result<PublicKey, Error> {
    let bytes = hex::decode(hex_key.trim()).map_err(|_| Error("the public key isn't hex".into()))?;
    if bytes.len() != KEY_LEN || bytes[0] != 4 {
        return err("the public key isn't an uncompressed secp256k1 point");
    }
    PublicKey::from_sec1_bytes(&bytes).map_err(|_| Error("the public key isn't on secp256k1".into()))
}

/// Does this look like an encrypted string (hex of key ‖ IV ‖ ciphertext)?
pub fn looks_encrypted(s: &str) -> bool {
    s.len() >= MIN_HEX && s.len().is_multiple_of(2) && s.starts_with("04") && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// One client key pair: encrypts requests to the gateway and decrypts its answers.
/// Keep it (or its [`Session::secret_hex`]) until the answer has been read.
#[derive(Clone)]
pub struct Session {
    secret: SecretKey,
    public_hex: String,
}

impl Session {
    /// A fresh key pair from the system's randomness.
    pub fn new() -> Self {
        loop {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).expect("system randomness");
            if let Ok(secret) = SecretKey::from_slice(&bytes) {
                return Self::from_secret(secret);
            }
        }
    }

    fn from_secret(secret: SecretKey) -> Self {
        let public_hex = hex::encode(secret.public_key().to_encoded_point(false).as_bytes());
        Self { secret, public_hex }
    }

    /// The key pair saved earlier with [`Session::secret_hex`].
    pub fn from_secret_hex(secret_hex: &str) -> Result<Self, Error> {
        let bytes = hex::decode(secret_hex.trim()).map_err(|_| Error("the secret key isn't hex".into()))?;
        let secret = SecretKey::from_slice(&bytes).map_err(|_| Error("not a secp256k1 secret key".into()))?;
        Ok(Self::from_secret(secret))
    }

    /// The private key, hex. Lets a reply picked up later still be read.
    pub fn secret_hex(&self) -> String {
        hex::encode(self.secret.to_bytes())
    }

    /// The public key to send in [`HEADER_CLIENT_KEY`] (uncompressed, hex).
    pub fn public_key_hex(&self) -> &str {
        &self.public_hex
    }

    fn cipher(&self, peer: &PublicKey) -> Aes256Gcm {
        let shared = k256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&[]), shared.raw_secret_bytes())
            .expand(HKDF_INFO, &mut key)
            .expect("32 bytes is a valid HKDF length");
        Aes256Gcm::new(&key.into())
    }

    /// Encrypt one text to the gateway's key.
    pub fn encrypt(&self, model_key_hex: &str, plaintext: &str) -> Result<String, Error> {
        let cipher = self.cipher(&public_key(model_key_hex)?);
        let mut iv = [0u8; IV_LEN];
        getrandom::getrandom(&mut iv).expect("system randomness");
        let sealed = cipher
            .encrypt(Nonce::from_slice(&iv), plaintext.as_bytes())
            .map_err(|_| Error("encryption failed".into()))?;
        let mut out = hex::decode(&self.public_hex).expect("own key is hex");
        out.extend_from_slice(&iv);
        out.extend_from_slice(&sealed);
        Ok(hex::encode(out))
    }

    /// Decrypt one piece of an answer, encrypted to this session's key.
    pub fn decrypt(&self, encrypted_hex: &str) -> Result<String, Error> {
        if !looks_encrypted(encrypted_hex) {
            return err("the answer came back unencrypted");
        }
        let raw = hex::decode(encrypted_hex).map_err(|_| Error("not hex".into()))?;
        let sender = PublicKey::from_sec1_bytes(&raw[..KEY_LEN])
            .map_err(|_| Error("the answer's sender key isn't on secp256k1".into()))?;
        let plain = self
            .cipher(&sender)
            .decrypt(Nonce::from_slice(&raw[KEY_LEN..KEY_LEN + IV_LEN]), &raw[KEY_LEN + IV_LEN..])
            .map_err(|_| Error("couldn't decrypt the answer with this session's key".into()))?;
        String::from_utf8(plain).map_err(|_| Error("the decrypted answer isn't UTF-8".into()))
    }

    /// Encrypt a chat completions request: every message's `content` string.
    /// Messages keep only `role` and `content`; text parts are joined into one
    /// text, and anything else (images, files) is refused: Encrypted mode takes
    /// text only. Returns the body to send and the same request in plain
    /// text, serialized alike; keep the plain one to check the receipt's
    /// request hash ([`crate::Evidence::request`]).
    pub fn encrypt_request(&self, model_key_hex: &str, request_json: &str) -> Result<EncryptedRequest, Error> {
        public_key(model_key_hex)?;
        let mut plain: Value = serde_json::from_str(request_json).map_err(|e| Error(format!("the request isn't JSON: {e}")))?;
        let Some(messages) = plain.get_mut("messages").and_then(Value::as_array_mut) else {
            return err("the request has no messages");
        };
        // Only the role and the (encrypted) content go: any other field of a
        // message (reasoning, tool calls, names) would travel in plain text.
        for message in messages.iter_mut() {
            let role = message.get("role").cloned().unwrap_or(Value::Null);
            let content = match message.get("content").cloned().unwrap_or(Value::Null) {
                // Text parts become one text; anything else (images, audio, files) can't go.
                Value::Array(parts) => {
                    let texts: Option<Vec<&str>> = parts
                        .iter()
                        .map(|p| (p["type"] == "text").then(|| p["text"].as_str()).flatten())
                        .collect();
                    match texts {
                        Some(texts) => Value::String(texts.join("\n\n")),
                        None => return err("Encrypted mode takes text only: remove the image or file"),
                    }
                }
                text @ (Value::String(_) | Value::Null) => text,
                _ => return err("Encrypted mode takes text only: a message's content isn't text"),
            };
            *message = serde_json::json!({ "role": role, "content": content });
        }
        let mut sealed = plain.clone();
        for message in sealed["messages"].as_array_mut().into_iter().flatten() {
            if let Some(Value::String(text)) = message.get_mut("content") {
                *text = self.encrypt(model_key_hex, text)?;
            }
        }
        Ok(EncryptedRequest {
            body: serde_json::to_string(&sealed).map_err(|e| Error(e.to_string()))?,
            plain: serde_json::to_string(&plain).map_err(|e| Error(e.to_string()))?,
        })
    }

    /// Decrypt the encrypted fields of one answer object: a whole completion
    /// (`choices[].message`) or a stream chunk (`choices[].delta`). Fails if
    /// any of them came unencrypted. Returns how many were decrypted.
    pub fn decrypt_answer(&self, answer: &mut Value) -> Result<usize, Error> {
        let mut count = 0;
        let Some(choices) = answer.get_mut("choices").and_then(Value::as_array_mut) else {
            return Ok(0);
        };
        for choice in choices {
            for part in ["delta", "message"] {
                let Some(fields) = choice.get_mut(part).and_then(Value::as_object_mut) else { continue };
                for name in ANSWER_FIELDS {
                    if let Some(Value::String(text)) = fields.get_mut(*name) {
                        // Whitespace-only padding carries no answer text.
                        if text.trim().is_empty() {
                            continue;
                        }
                        *text = self.decrypt(text)?;
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    /// One SSE event of an encrypted stream, decrypted: `data:` lines carrying
    /// a chunk are rewritten with its fields in plain text; comments, `[DONE]`
    /// and anything else pass unchanged.
    pub fn decrypt_event(&self, event: &[u8]) -> Result<Vec<u8>, Error> {
        let Ok(text) = std::str::from_utf8(event) else {
            return Ok(event.to_vec());
        };
        let mut out = String::with_capacity(text.len());
        for line in text.split_inclusive('\n') {
            let body = line.trim_end_matches(['\r', '\n']);
            let ending = &line[body.len()..];
            let Some(data) = body.strip_prefix("data:") else {
                out.push_str(line);
                continue;
            };
            match serde_json::from_str::<Value>(data.trim()) {
                Ok(mut chunk) if chunk.is_object() => {
                    self.decrypt_answer(&mut chunk)?;
                    out.push_str("data: ");
                    out.push_str(&chunk.to_string());
                    out.push_str(ending);
                }
                _ => out.push_str(line),
            }
        }
        Ok(out.into_bytes())
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

/// A request ready to send, and the plain text it stands for.
#[derive(Clone, Debug)]
pub struct EncryptedRequest {
    /// The JSON body to send, every message's content encrypted.
    pub body: String,
    /// The same request unencrypted, serialized the same way.
    pub plain: String,
}

/// The secp256k1 encryption key in an attestation report's keyset (not checked:
/// call [`crate::verify_attestation`], which returns it only when it verifies).
pub fn keyset_e2ee_key(keyset: &Value) -> Option<String> {
    keyset["e2ee_public_keys"]
        .as_array()?
        .iter()
        .find(|k| k["algo"] == E2EE_ALGO)
        .and_then(|k| k["public_key"].as_str())
        .filter(|k| public_key(k).is_ok())
        .map(|k| k.to_ascii_lowercase())
}

/// The request as the gateway hashed it: `plain` with its model id replaced by
/// the one the gateway was asked for (the receipt's `model`). Obscurify swaps
/// its own model id for the gateway's and changes nothing else.
pub(crate) fn request_as_forwarded(plain: &[u8], gateway_model: &str) -> Option<Vec<u8>> {
    const KEY: &[u8] = b"\"model\":\"";
    let at = plain.windows(KEY.len()).position(|w| w == KEY)?;
    if plain[at + 1..].windows(KEY.len()).any(|w| w == KEY) {
        return None;
    }
    let start = at + KEY.len();
    let end = start + plain[start..].iter().position(|&b| b == b'"')?;
    let mut out = plain[..start].to_vec();
    out.extend_from_slice(serde_json::to_string(gateway_model).ok()?.trim_matches('"').as_bytes());
    out.extend_from_slice(&plain[end..]);
    Some(out)
}
