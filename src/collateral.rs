//! Intel's signed collateral (CRLs, TCB info, QE identity) for one TDX
//! quote, fetched from a PCCS. Everything here is signed by Intel and
//! checked by `dcap-qvl`, so the PCCS (or a proxy in front of it) needs no
//! trust: a wrong answer makes verification fail, never pass.

use dcap_qvl::quote::Quote;
use dcap_qvl::QuoteCollateralV3;

/// The PCCS paths a verification requests, relative to the PCCS base URL.
/// `{fmspc}` is upper-case hex from the quote's PCK certificate; `{ca}` is
/// `processor` or `platform`.
pub const PCCS_PATHS: &[&str] = &[
    "/sgx/certification/v4/pckcrl?ca={ca}&encoding=der",
    "/tdx/certification/v4/tcb?fmspc={fmspc}&update=standard",
    "/tdx/certification/v4/qe/identity?update=standard",
    "/sgx/certification/v4/rootcacrl",
];

struct Fetched {
    headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
}

async fn get(http: &reqwest::Client, url: &str) -> Result<Fetched, String> {
    let response = http
        .get(url)
        .send()
        .await
        .map_err(|e| format!("couldn't reach {url}: {e}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("{url} answered HTTP {}", status.as_u16()));
    }
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .map_err(|e| format!("couldn't read {url}: {e}"))?
        .to_vec();
    Ok(Fetched { headers, body })
}

fn header(fetched: &Fetched, names: &[&str]) -> Result<String, String> {
    for name in names {
        if let Some(value) = fetched.headers.get(*name).and_then(|v| v.to_str().ok()) {
            return Ok(percent_decode(value));
        }
    }
    Err(format!("PCCS response is missing the {} header", names[0]))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(b) = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn json_part(body: &[u8], key: &str) -> Result<(String, Vec<u8>), String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("PCCS sent invalid JSON: {e}"))?;
    let part = value
        .get(key)
        .ok_or_else(|| format!("PCCS response has no {key}"))?
        .to_string();
    let signature = value
        .get("signature")
        .and_then(|s| s.as_str())
        .and_then(|s| hex::decode(s).ok())
        .ok_or_else(|| "PCCS response has no valid signature".to_string())?;
    Ok((part, signature))
}

pub async fn fetch(
    http: &reqwest::Client,
    pccs_url: &str,
    quote: &Quote,
) -> Result<QuoteCollateralV3, String> {
    let base = pccs_url
        .trim_end_matches('/')
        .trim_end_matches("/sgx/certification/v4")
        .trim_end_matches("/tdx/certification/v4");
    let fmspc = dcap_qvl::intel::quote_fmspc(quote)
        .map_err(|e| format!("couldn't read the quote's PCK certificate: {e}"))?;
    let fmspc = hex::encode_upper(fmspc);
    let ca = dcap_qvl::intel::quote_ca(quote)
        .map_err(|e| format!("couldn't read the quote's PCK issuer: {e}"))?
        .as_id_str();

    let pck = get(
        http,
        &format!("{base}/sgx/certification/v4/pckcrl?ca={ca}&encoding=der"),
    )
    .await?;
    let tcb = get(
        http,
        &format!("{base}/tdx/certification/v4/tcb?fmspc={fmspc}&update=standard"),
    )
    .await?;
    let qe = get(
        http,
        &format!("{base}/tdx/certification/v4/qe/identity?update=standard"),
    )
    .await?;
    let root = get(http, &format!("{base}/sgx/certification/v4/rootcacrl")).await?;

    let (tcb_info, tcb_info_signature) = json_part(&tcb.body, "tcbInfo")?;
    let (qe_identity, qe_identity_signature) = json_part(&qe.body, "enclaveIdentity")?;
    // A PCCS sends the root CA CRL hex-encoded; Intel's PCS sends DER.
    let root_ca_crl = match std::str::from_utf8(&root.body) {
        Ok(text) => hex::decode(text.trim()).map_err(|_| "root CA CRL is not hex".to_string())?,
        Err(_) => root.body.clone(),
    };

    Ok(QuoteCollateralV3 {
        pck_crl_issuer_chain: header(&pck, &["SGX-PCK-CRL-Issuer-Chain"])?,
        root_ca_crl,
        pck_crl: pck.body,
        tcb_info_issuer_chain: header(&tcb, &["TCB-Info-Issuer-Chain", "SGX-TCB-Info-Issuer-Chain"])?,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain: header(&qe, &["SGX-Enclave-Identity-Issuer-Chain"])?,
        qe_identity,
        qe_identity_signature,
        pck_certificate_chain: None,
    })
}
