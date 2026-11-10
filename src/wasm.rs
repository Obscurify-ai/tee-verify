//! The web client's entry points (wasm-bindgen).

use wasm_bindgen::prelude::*;

/// Verify one reply. `pccs_url` defaults to Phala's PCCS; pass an empty
/// `base_rpc_url` to skip the release check. Resolves to the report object.
#[wasm_bindgen(js_name = verifyTeeReply)]
pub async fn verify_tee_reply(
    body: Vec<u8>,
    receipt_json: String,
    attestation_json: String,
    nonce: String,
    pccs_url: Option<String>,
    base_rpc_url: Option<String>,
) -> Result<JsValue, JsValue> {
    let options = crate::Options {
        pccs_url: pccs_url.unwrap_or_else(|| crate::PHALA_PCCS_URL.to_string()),
        base_rpc_url: match base_rpc_url {
            Some(url) if url.is_empty() => None,
            Some(url) => Some(url),
            None => Some(crate::BASE_RPC_URL.to_string()),
        },
        now_secs: None,
    };
    let evidence = crate::Evidence {
        body,
        receipt_json,
        attestation_json,
        nonce,
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
