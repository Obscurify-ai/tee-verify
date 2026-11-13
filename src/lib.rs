//! Check one Obscurify TEE reply against the gateway's signed receipt and a
//! fresh hardware attestation. See README.md for what each check proves.

mod canonical;
mod collateral;
pub mod e2ee;
#[cfg(feature = "wasm")]
mod wasm;

pub use canonical::canonical;
pub use collateral::PCCS_PATHS;

use dcap_qvl::quote::Quote;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384};

/// The keepalive frame Obscurify's server may put between whole SSE frames
/// while a model is thinking. It isn't part of the signed reply.
pub const KEEPALIVE_FRAME: &[u8] = b": obscurify-keepalive\n\n";

/// Default Base RPC for the release check.
pub const BASE_RPC_URL: &str = "https://mainnet.base.org";

/// Phala's public PCCS, for callers that don't proxy one.
pub const PHALA_PCCS_URL: &str = "https://pccs.phala.network";

/// `allowedComposeHashes(bytes32)` on the gateway's app contract.
const ALLOWED_COMPOSE_HASHES: &str = "2f6622e5";

const NONCE_PURPOSE: &str = "aci.report_data.v1";

/// What the client collected for one reply.
#[derive(Clone, Debug)]
pub struct Evidence {
    /// The reply bytes exactly as received (keepalive frames may be left in).
    pub body: Vec<u8>,
    /// The receipt endpoint's JSON: `{"receipt": {...}, ...}` or the bare receipt.
    pub receipt_json: String,
    /// The attestation endpoint's JSON, fetched with `nonce`.
    pub attestation_json: String,
    /// The 64-hex-character nonce the client sent with the attestation request.
    pub nonce: String,
    /// Encrypted mode: the request in plain text, as [`e2ee::Session::encrypt_request`]
    /// returned it. Adds the `request_bytes` check.
    pub request: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Options {
    /// PCCS base URL for Intel's collateral, e.g. `https://obscurify.ai/tee/pccs`.
    pub pccs_url: String,
    /// Base RPC for the release check; `None` skips it.
    pub base_rpc_url: Option<String>,
    /// Current time in seconds since 1970, for certificate and TCB validity.
    /// `None` reads the clock.
    pub now_secs: Option<u64>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            pccs_url: PHALA_PCCS_URL.to_string(),
            base_rpc_url: Some(BASE_RPC_URL.to_string()),
            now_secs: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    /// The check couldn't run (usually the network); it neither passed nor failed.
    Unchecked,
}

#[derive(Clone, Debug, Serialize)]
pub struct Check {
    /// Stable id: reply_bytes, request_bytes (Encrypted mode), receipt_signature,
    /// nonce_binding, tdx_hardware, gateway_code, approved_release, model_host.
    pub id: &'static str,
    pub status: Status,
    pub label: &'static str,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    /// True when every required check passed and the release check didn't fail.
    pub verified: bool,
    pub checks: Vec<Check>,
    pub receipt_id: Option<String>,
    /// The model id the gateway served.
    pub model: Option<String>,
    /// The model id the model host attested.
    pub upstream_model: Option<String>,
    pub upstream_session: Option<String>,
    pub served_at: Option<u64>,
    pub tcb_status: Option<String>,
    pub advisory_ids: Vec<String>,
    pub compose_hash: Option<String>,
    pub app_id: Option<String>,
    pub os_image_hash: Option<String>,
    /// Declared by the workload, not measured.
    pub source_repo: Option<String>,
    pub source_commit: Option<String>,
}

/// The reply bytes with Obscurify's keepalive frames removed: what the
/// receipt's `response.returned` hash covers.
pub fn strip_keepalives(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    loop {
        while body[i..].starts_with(KEEPALIVE_FRAME) {
            i += KEEPALIVE_FRAME.len();
        }
        match body[i..].windows(2).position(|w| w == b"\n\n") {
            Some(end) => {
                out.extend_from_slice(&body[i..i + end + 2]);
                i += end + 2;
            }
            None => {
                out.extend_from_slice(&body[i..]);
                return out;
            }
        }
    }
}

/// A fresh random nonce for the attestation request: 64 lowercase hex characters.
pub fn new_nonce() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("system randomness");
    hex::encode(bytes)
}

fn sha256_tagged(data: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(data)))
}

fn now_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        (js_sys_now() / 1000.0) as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[cfg(all(target_arch = "wasm32", feature = "wasm"))]
fn js_sys_now() -> f64 {
    js_sys::Date::now()
}

#[cfg(all(target_arch = "wasm32", not(feature = "wasm")))]
fn js_sys_now() -> f64 {
    0.0
}

struct Checks(Vec<Check>);

impl Checks {
    fn push(&mut self, id: &'static str, label: &'static str, result: Result<String, (Status, String)>) {
        let (status, detail) = match result {
            Ok(detail) => (Status::Pass, detail),
            Err((status, detail)) => (status, detail),
        };
        self.0.push(Check { id, status, label, detail });
    }
}

fn fail<T>(detail: impl Into<String>) -> Result<T, (Status, String)> {
    Err((Status::Fail, detail.into()))
}

fn unchecked<T>(detail: impl Into<String>) -> Result<T, (Status, String)> {
    Err((Status::Unchecked, detail.into()))
}

fn parse_json(text: &str, what: &str) -> Result<Value, String> {
    serde_json::from_str(text).map_err(|e| format!("the {what} isn't valid JSON: {e}"))
}

/// A JSON field that may be a JSON document encoded as a string.
fn embedded(value: &Value) -> Option<Value> {
    match value {
        Value::String(s) => serde_json::from_str(s).ok(),
        Value::Null => None,
        other => Some(other.clone()),
    }
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.trim_start_matches("0x")).ok()
}

fn report_body(quote: &Quote) -> Option<&dcap_qvl::quote::TDReport10> {
    quote.report.as_td10()
}

/// Run every check. Never errors: problems become failed or unchecked checks.
pub async fn verify(evidence: &Evidence, options: &Options) -> Report {
    let http = reqwest::Client::new();
    verify_with_client(evidence, options, &http).await
}

pub async fn verify_with_client(
    evidence: &Evidence,
    options: &Options,
    http: &reqwest::Client,
) -> Report {
    let mut report = Report::default();
    let mut checks = Checks(Vec::new());

    let receipt = parse_json(&evidence.receipt_json, "receipt").map(|v| match v.get("receipt") {
        Some(inner) if inner.is_object() => inner.clone(),
        _ => v,
    });
    let attestation_doc = parse_json(&evidence.attestation_json, "attestation report");
    let attestation = attestation_doc
        .as_ref()
        .map(|v| v.get("attestation").cloned().unwrap_or(Value::Null));

    if let Ok(r) = &receipt {
        report.receipt_id = r["receipt_id"].as_str().map(String::from);
        report.model = r["model"].as_str().map(String::from);
        report.served_at = r["served_at"].as_u64();
    }
    let events: Vec<Value> = receipt
        .as_ref()
        .ok()
        .and_then(|r| r["event_log"].as_array().cloned())
        .unwrap_or_default();
    let event = |kind: &str| events.iter().find(|e| e["type"] == kind).cloned();

    // 1. The reply bytes.
    checks.push(
        "reply_bytes",
        "The reply you received is the one the gateway signed",
        (|| {
            receipt.as_ref().map_err(|e| (Status::Fail, e.clone()))?;
            let Some(returned) = event("response.returned") else {
                return fail("the receipt has no response.returned event");
            };
            let expected = returned["body_hash"].as_str().unwrap_or_default();
            let actual = sha256_tagged(&strip_keepalives(&evidence.body));
            if expected == actual {
                Ok(format!("{} bytes hash to {}", evidence.body.len(), actual))
            } else {
                fail(format!(
                    "the reply hashes to {actual}, the receipt signed {expected}: the reply was changed or cut off"
                ))
            }
        })(),
    );

    // 1b. Encrypted mode: the request the enclave decrypted is the one the client wrote.
    if let Some(plain) = &evidence.request {
        checks.push(
            "request_bytes",
            "The enclave received exactly the conversation you sent",
            (|| {
                let receipt = receipt.as_ref().map_err(|e| (Status::Fail, e.clone()))?;
                let Some(received) = event("request.received") else {
                    return fail("the receipt has no request.received event");
                };
                let model = receipt["model"].as_str().unwrap_or_default();
                let Some(forwarded) = e2ee::request_as_forwarded(plain, model) else {
                    return fail("the request you sent has no single model id to compare");
                };
                let expected = received["body_hash"].as_str().unwrap_or_default();
                let actual = sha256_tagged(&forwarded);
                if expected == actual {
                    Ok(format!("your decrypted request for {model} hashes to {actual}"))
                } else {
                    fail(format!(
                        "your request hashes to {actual}, the enclave received {expected}: a message was added, removed or changed"
                    ))
                }
            })(),
        );
    }

    // The keyset the attestation publishes, used by checks 2 and 3.
    let keyset = attestation
        .as_ref()
        .ok()
        .map(|a| a["workload_keyset"].clone())
        .filter(|k| k.is_object());

    // 2. The receipt signature.
    checks.push(
        "receipt_signature",
        "The receipt is signed by the gateway's key",
        (|| {
            let receipt = receipt.as_ref().map_err(|e| (Status::Fail, e.clone()))?;
            let Some(keyset) = &keyset else {
                return fail("the attestation report has no workload keyset");
            };
            let key_id = receipt["key_id"].as_str().unwrap_or_default();
            let Some(key) = keyset["receipt_signing_keys"]
                .as_array()
                .and_then(|keys| keys.iter().find(|k| k["key_id"] == key_id))
            else {
                return fail(format!("the attested keyset has no receipt key {key_id:?}"));
            };
            if key["algo"].as_str() != Some("ed25519") {
                return fail(format!("receipt key uses {}, expected ed25519", key["algo"]));
            }
            let public: [u8; 32] = key["public_key"]
                .as_str()
                .and_then(hex_bytes)
                .and_then(|b| b.try_into().ok())
                .ok_or((Status::Fail, "the receipt key isn't a 32-byte Ed25519 key".to_string()))?;
            let signature: [u8; 64] = receipt["signature"]
                .as_str()
                .and_then(hex_bytes)
                .and_then(|b| b.try_into().ok())
                .ok_or((Status::Fail, "the receipt signature isn't 64 bytes".to_string()))?;
            let mut unsigned = receipt.clone();
            unsigned.as_object_mut().map(|o| o.remove("signature"));
            let verifying = ed25519_dalek::VerifyingKey::from_bytes(&public)
                .map_err(|_| (Status::Fail, "the receipt key isn't a valid Ed25519 point".to_string()))?;
            verifying
                .verify_strict(
                    &canonical(&unsigned),
                    &ed25519_dalek::Signature::from_bytes(&signature),
                )
                .map_err(|_| (Status::Fail, "the signature doesn't match the receipt".to_string()))?;
            Ok(format!("Ed25519 key {key_id} signed receipt {}", report.receipt_id.clone().unwrap_or_default()))
        })(),
    );

    attestation_checks(
        attestation.as_ref().ok(),
        keyset.as_ref(),
        Some(receipt.as_ref().map(|r| r["workload_keyset_digest"].as_str().unwrap_or_default())),
        &evidence.nonce,
        options,
        http,
        &mut report,
        &mut checks,
    )
    .await;

    // 7. The gateway verified the model host before sending your request.
    checks.push(
        "model_host",
        "The gateway verified the model host's attestation",
        (|| {
            receipt.as_ref().map_err(|e| (Status::Fail, e.clone()))?;
            let Some(upstream) = event("upstream.verified") else {
                return fail("the receipt has no upstream.verified event");
            };
            report.upstream_session = upstream["session_id"].as_str().map(String::from);
            report.upstream_model = upstream["model_id"].as_str().map(String::from);
            if upstream["result"] != "verified" || upstream["required"] != true {
                return fail(format!(
                    "upstream result {}, required {}",
                    upstream["result"], upstream["required"]
                ));
            }
            Ok(format!(
                "model {} verified, session {}",
                report.upstream_model.clone().unwrap_or_default(),
                report.upstream_session.clone().unwrap_or_default()
            ))
        })(),
    );

    report.verified = checks.0.iter().all(|c| match c.id {
        "approved_release" => c.status != Status::Fail,
        _ => c.status == Status::Pass,
    });
    report.checks = checks.0;
    report
}

/// What [`verify_attestation`] found: the checks on the attestation report alone.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AttestationReport {
    /// True when every check passed (the release check may be unchecked).
    pub verified: bool,
    pub checks: Vec<Check>,
    /// The gateway's attested secp256k1 encryption key (uncompressed, hex), only
    /// when `verified`: what Encrypted mode encrypts to.
    pub e2ee_public_key: Option<String>,
    /// `sha256:` of the attested keyset; a reply's receipt must name the same.
    pub keyset_digest: Option<String>,
    pub tcb_status: Option<String>,
    pub advisory_ids: Vec<String>,
    pub compose_hash: Option<String>,
    pub app_id: Option<String>,
    pub os_image_hash: Option<String>,
    pub source_repo: Option<String>,
    pub source_commit: Option<String>,
}

/// Check an attestation report fetched with `nonce` before sending anything,
/// and pick out the key Encrypted mode encrypts to. Runs `nonce_binding`,
/// `tdx_hardware`, `gateway_code` and `approved_release` (checks 3 to 6) plus
/// `e2ee_key`: the keyset offers a secp256k1 encryption key. A client must not
/// encrypt to any key but the one returned here.
pub async fn verify_attestation(attestation_json: &str, nonce: &str, options: &Options) -> AttestationReport {
    let http = reqwest::Client::new();
    let doc = parse_json(attestation_json, "attestation report");
    let attestation = doc.as_ref().ok().map(|v| v.get("attestation").cloned().unwrap_or(Value::Null));
    let keyset = attestation.as_ref().map(|a| a["workload_keyset"].clone()).filter(|k| k.is_object());
    let mut report = Report::default();
    let mut checks = Checks(Vec::new());
    attestation_checks(
        attestation.as_ref(),
        keyset.as_ref(),
        None,
        nonce,
        options,
        &http,
        &mut report,
        &mut checks,
    )
    .await;
    let key = keyset.as_ref().and_then(e2ee::keyset_e2ee_key);
    checks.push(
        "e2ee_key",
        "The attested gateway offers an encryption key",
        match &key {
            Some(k) => Ok(format!("{} key {}…", e2ee::E2EE_ALGO, &k[..18])),
            None => fail(format!("the attested keyset has no {} key", e2ee::E2EE_ALGO)),
        },
    );
    let verified = checks.0.iter().all(|c| match c.id {
        "approved_release" => c.status != Status::Fail,
        _ => c.status == Status::Pass,
    });
    AttestationReport {
        verified,
        checks: checks.0,
        e2ee_public_key: key.filter(|_| verified),
        keyset_digest: keyset.as_ref().map(|k| sha256_tagged(&canonical(k))),
        tcb_status: report.tcb_status,
        advisory_ids: report.advisory_ids,
        compose_hash: report.compose_hash,
        app_id: report.app_id,
        os_image_hash: report.os_image_hash,
        source_repo: report.source_repo,
        source_commit: report.source_commit,
    }
}

/// Checks 3 to 6: the attestation report answers `nonce`, comes from genuine
/// TDX hardware running the measured gateway, and that gateway is an approved
/// release. `signed_digest`: the keyset digest a receipt names, when checking
/// a reply (`Some(Err)` when the receipt is unreadable).
#[allow(clippy::too_many_arguments)]
async fn attestation_checks(
    attestation: Option<&Value>,
    keyset: Option<&Value>,
    signed_digest: Option<Result<&str, &String>>,
    nonce: &str,
    options: &Options,
    http: &reqwest::Client,
    report: &mut Report,
    checks: &mut Checks,
) {
    // The quote, parsed (not yet verified).
    let raw_quote: Option<Vec<u8>> = attestation
        .and_then(|a| a["evidence"]["quote"].as_str())
        .and_then(hex_bytes);
    let quote: Option<Quote> = raw_quote.as_deref().and_then(|q| Quote::parse(q).ok());

    // 3. The keyset and the client's nonce are in the quote's report data.
    checks.push(
        "nonce_binding",
        "That key belongs to the attested machine, which answered your fresh nonce",
        (|| {
            let Some(keyset) = keyset else {
                return fail("the attestation report has no workload keyset");
            };
            let digest = sha256_tagged(&canonical(keyset));
            match signed_digest {
                Some(Err(e)) => return fail(e.clone()),
                Some(Ok(signed)) if signed != digest => {
                    return fail(format!("the attested keyset hashes to {digest}, the receipt names {signed}"));
                }
                _ => {}
            }
            let nonce = nonce.trim();
            if nonce.len() != 64 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
                return fail("the nonce must be 64 hex characters");
            }
            let Some(quote) = &quote else {
                return fail("the attestation report has no readable TDX quote");
            };
            let Some(td) = report_body(quote) else {
                return fail("the quote isn't a TDX quote");
            };
            let bound = serde_json::json!({
                "keyset_digest": digest,
                "nonce": nonce.to_ascii_lowercase(),
                "purpose": NONCE_PURPOSE,
            });
            let mut expected = Sha256::digest(canonical(&bound)).to_vec();
            expected.extend_from_slice(&[0u8; 32]);
            if td.report_data[..] != expected[..] {
                return fail("the quote's report data doesn't bind this keyset and your nonce");
            }
            Ok(format!("quote report data = sha256(keyset {digest}, nonce {nonce})"))
        })(),
    );

    // 4. Genuine TDX hardware, via Intel's collateral.
    let mut verified_td: Option<dcap_qvl::quote::TDReport10> = None;
    let hardware = async {
        let (Some(raw), Some(quote)) = (&raw_quote, &quote) else {
            return fail("the attestation report has no readable TDX quote");
        };
        if attestation.and_then(|a| a["tee_type"].as_str()) != Some("tdx") {
            return fail("the attestation isn't a TDX attestation");
        }
        let collateral = match collateral::fetch(http, &options.pccs_url, quote).await {
            Ok(c) => c,
            Err(e) => return unchecked(format!("couldn't get Intel's collateral: {e}")),
        };
        let now = options.now_secs.unwrap_or_else(now_secs);
        let verified = dcap_qvl::verify::QuoteVerifier::new_prod()
            .verify(raw, &collateral, now)
            .map_err(|e| (Status::Fail, format!("Intel's DCAP check rejected the quote: {e:#}")))?;
        let Some(td) = verified.report.as_td10() else {
            return fail("the verified quote isn't a TDX report");
        };
        if Some(td.report_data) != report_body(quote).map(|t| t.report_data) {
            return fail("the verified report data differs from the parsed quote");
        }
        if verified.status == "Revoked" {
            return fail("Intel has revoked this platform's TCB");
        }
        verified_td = Some(*td);
        report.tcb_status = Some(verified.status.clone());
        report.advisory_ids = verified.advisory_ids.clone();
        let advisories = if verified.advisory_ids.is_empty() {
            String::new()
        } else {
            format!(", advisories {}", verified.advisory_ids.join(", "))
        };
        Ok(format!("quote chains to Intel's root CA; TCB status {}{advisories}", verified.status))
    }
    .await;
    checks.push("tdx_hardware", "The machine is genuine Intel TDX hardware", hardware);

    // 5. The measured gateway code (RTMR3 event log, compose hash).
    let mut compose_hash: Option<String> = None;
    checks.push(
        "gateway_code",
        "The gateway's measured code matches the configuration it publishes",
        (|| {
            let Some(att) = attestation else {
                return fail("the attestation report isn't valid JSON");
            };
            let ev = &att["evidence"];
            let Some(log) = embedded(&ev["event_log"]).and_then(|l| l.as_array().cloned()) else {
                return fail("the attestation has no event log");
            };
            let Some(td) = verified_td.as_ref().or(quote.as_ref().and_then(report_body)) else {
                return fail("the attestation has no readable TDX quote");
            };
            let mut rtmr3 = [0u8; 48];
            let mut payloads = std::collections::HashMap::new();
            for event in &log {
                if event["imr"].as_u64() != Some(3) && event["imr"].as_str() != Some("3") {
                    continue;
                }
                let digest = event["digest"]
                    .as_str()
                    .and_then(hex_bytes)
                    .filter(|d| d.len() == 48)
                    .ok_or((Status::Fail, "an RTMR3 event has no 48-byte digest".to_string()))?;
                let name = event["event"].as_str().unwrap_or_default();
                let payload = event["event_payload"]
                    .as_str()
                    .and_then(hex_bytes)
                    .unwrap_or_default();
                let event_type = event["event_type"]
                    .as_u64()
                    .or_else(|| event["event_type"].as_str().and_then(|s| s.parse().ok()))
                    .unwrap_or(0) as u32;
                let mut hasher = Sha384::new();
                hasher.update(event_type.to_le_bytes());
                hasher.update(b":");
                hasher.update(name.as_bytes());
                hasher.update(b":");
                hasher.update(&payload);
                if hasher.finalize()[..] != digest[..] {
                    return fail(format!("the {name} event's digest doesn't match its payload"));
                }
                let mut extend = Sha384::new();
                extend.update(rtmr3);
                extend.update(&digest);
                rtmr3.copy_from_slice(&extend.finalize());
                payloads.insert(name.to_string(), payload);
            }
            if rtmr3 != td.rt_mr3 {
                return fail("replaying the event log doesn't give the quote's RTMR3");
            }
            let Some(app_compose) = ev["app_compose"].as_str() else {
                return fail("the attestation has no app_compose");
            };
            let hash = hex::encode(Sha256::digest(app_compose.as_bytes()));
            let measured = payloads.get("compose-hash").map(hex::encode);
            if measured.as_deref() != Some(hash.as_str()) {
                return fail(format!(
                    "app_compose hashes to {hash}, RTMR3 measured {}",
                    measured.unwrap_or_else(|| "no compose hash".into())
                ));
            }
            report.compose_hash = Some(hash.clone());
            report.app_id = payloads.get("app-id").map(hex::encode);
            report.os_image_hash = payloads.get("os-image-hash").map(hex::encode);
            report.source_repo = att["source_provenance"]["repo_url"].as_str().map(String::from);
            report.source_commit = att["source_provenance"]["repo_commit"].as_str().map(String::from);
            compose_hash = Some(hash.clone());
            let source = match (&report.source_repo, &report.source_commit) {
                (Some(repo), Some(commit)) => format!("; declared source {repo} @ {commit}"),
                _ => String::new(),
            };
            Ok(format!("RTMR3 replays; compose hash {hash}{source}"))
        })(),
    );

    // 6. The compose hash is an approved release on the app contract.
    let release = async {
        let Some(rpc) = &options.base_rpc_url else {
            return unchecked("release check turned off");
        };
        let (Some(hash), Some(app_id)) = (&compose_hash, &report.app_id) else {
            return unchecked("no measured compose hash to look up");
        };
        if app_id.len() != 40 {
            return fail(format!("app id {app_id} isn't a contract address"));
        }
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "eth_call",
            "params": [{"to": format!("0x{app_id}"), "data": format!("0x{ALLOWED_COMPOSE_HASHES}{hash}")}, "latest"],
        });
        let answer: Value = match http.post(rpc).json(&body).send().await {
            Ok(r) => match r.json().await {
                Ok(v) => v,
                Err(e) => return unchecked(format!("{rpc} sent an unreadable answer: {e}")),
            },
            Err(e) => return unchecked(format!("couldn't reach {rpc}: {e}")),
        };
        let Some(result) = answer["result"].as_str() else {
            return unchecked(format!("{rpc} answered {}", answer["error"]));
        };
        let word = result.trim_start_matches("0x");
        if word.len() == 64 && word.ends_with('1') && word[..63].bytes().all(|b| b == b'0') {
            Ok(format!("contract 0x{app_id} on Base allows compose hash {hash}"))
        } else {
            fail(format!("contract 0x{app_id} on Base doesn't allow compose hash {hash}"))
        }
    }
    .await;
    checks.push("approved_release", "That configuration is an approved gateway release", release);

}
