//! The web client's entry points (wasm-bindgen).

use wasm_bindgen::prelude::*;

fn options(pccs_url: Option<String>, base_rpc_url: Option<String>) -> crate::Options {
    crate::Options {
        pccs_url: pccs_url.unwrap_or_else(|| crate::PHALA_PCCS_URL.to_string()),
        base_rpc_url: match base_rpc_url {
            Some(url) if url.is_empty() => None,
            Some(url) => Some(url),
            None => Some(crate::BASE_RPC_URL.to_string()),
        },
        now_secs: None,
    }
}

fn js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// Encrypted mode, before sending: check an attestation report fetched with
/// `nonce`. Resolves to `{verified, checks, e2ee_public_key, ...}`; encrypt
/// only to `e2ee_public_key`, which is set only when `verified`.
#[wasm_bindgen(js_name = verifyAttestation)]
pub async fn verify_attestation(
    attestation_json: String,
    nonce: String,
    pccs_url: Option<String>,
    base_rpc_url: Option<String>,
) -> Result<JsValue, JsValue> {
    let report = crate::verify_attestation(&attestation_json, &nonce, &options(pccs_url, base_rpc_url)).await;
    report
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(js_err)
}

/// One Encrypted-mode key pair (see `e2ee::Session`).
#[wasm_bindgen]
pub struct E2eeSession(crate::e2ee::Session);

#[wasm_bindgen]
impl E2eeSession {
    #[wasm_bindgen(constructor)]
    pub fn new() -> E2eeSession {
        E2eeSession(crate::e2ee::Session::new())
    }

    /// A key pair saved with `secret()`, to read a reply picked up later.
    #[wasm_bindgen(js_name = fromSecret)]
    pub fn from_secret(secret_hex: &str) -> Result<E2eeSession, JsValue> {
        crate::e2ee::Session::from_secret_hex(secret_hex).map(E2eeSession).map_err(js_err)
    }

    pub fn secret(&self) -> String {
        self.0.secret_hex()
    }

    /// For the X-Client-Pub-Key header.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> String {
        self.0.public_key_hex().to_string()
    }

    /// `{body, plain}`: send `body`; keep `plain` for verifyTeeReply's `request`.
    #[wasm_bindgen(js_name = encryptRequest)]
    pub fn encrypt_request(&self, model_key_hex: &str, request_json: &str) -> Result<JsValue, JsValue> {
        let sealed = self.0.encrypt_request(model_key_hex, request_json).map_err(js_err)?;
        let out = js_sys::Object::new();
        js_sys::Reflect::set(&out, &"body".into(), &sealed.body.into())?;
        js_sys::Reflect::set(&out, &"plain".into(), &sealed.plain.into())?;
        Ok(out.into())
    }

    /// One SSE event of an encrypted stream, with its answer fields decrypted.
    #[wasm_bindgen(js_name = decryptEvent)]
    pub fn decrypt_event(&self, event: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        self.0.decrypt_event(&event).map_err(js_err)
    }

    /// A whole (non-streamed) completion's JSON, decrypted.
    #[wasm_bindgen(js_name = decryptCompletion)]
    pub fn decrypt_completion(&self, json: &str) -> Result<String, JsValue> {
        let mut value: serde_json::Value = serde_json::from_str(json).map_err(js_err)?;
        self.0.decrypt_answer(&mut value).map_err(js_err)?;
        Ok(value.to_string())
    }
}

impl Default for E2eeSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify one reply. `pccs_url` defaults to Phala's PCCS; pass an empty
/// `base_rpc_url` to skip the release check. `request`: in Encrypted mode, the
/// `plain` from encryptRequest (adds the request check). Resolves to the report.
#[wasm_bindgen(js_name = verifyTeeReply)]
pub async fn verify_tee_reply(
    body: Vec<u8>,
    receipt_json: String,
    attestation_json: String,
    nonce: String,
    pccs_url: Option<String>,
    base_rpc_url: Option<String>,
    request: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let options = options(pccs_url, base_rpc_url);
    let evidence = crate::Evidence {
        body,
        receipt_json,
        attestation_json,
        nonce,
        request,
    };
    let report = crate::verify(&evidence, &options).await;
    report
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// A fresh 64-hex-character nonce for the attestation request.
#[wasm_bindgen(js_name = newNonce)]
pub fn new_nonce() -> String {
    crate::new_nonce()
}

/// The reply bytes the receipt covers (keepalive frames removed).
#[wasm_bindgen(js_name = stripKeepalives)]
pub fn strip_keepalives(body: Vec<u8>) -> Vec<u8> {
    crate::strip_keepalives(&body)
}

use serde::Serialize;
