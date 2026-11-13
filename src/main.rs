//! `obscurify-tee-verify`: check Obscurify TEE replies from the command line.

use clap::{Parser, Subcommand};
use obscurify_tee_verify::e2ee::{self, Session};
use obscurify_tee_verify::{
    new_nonce, verify, verify_attestation, AttestationReport, Check, Evidence, Options, Report, Status,
    BASE_RPC_URL, PHALA_PCCS_URL,
};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "obscurify-tee-verify",
    version,
    about = "Check that an Obscurify TEE reply came from an attested gateway",
    long_about = "Check that an Obscurify TEE reply came from an attested confidential-computing gateway.\n\n\
`chat` sends a prompt end-to-end encrypted (Encrypted mode): it checks the gateway's\n\
attestation, encrypts to its attested key, decrypts the answer and checks the receipt.\n\
`check` checks a reply you saved earlier (chat --save).\n\n\
Exit status: 0 verified, 1 not verified, 2 usage or network error."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// PCCS for Intel's collateral (signed by Intel, so any PCCS will do).
    #[arg(long, global = true, default_value = PHALA_PCCS_URL)]
    pccs: String,
    /// Base RPC used to check the gateway release; "off" skips that check.
    #[arg(long, global = true, default_value = BASE_RPC_URL)]
    base_rpc: String,
    /// Print the report as JSON.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Encrypted mode: verify the gateway's attestation, encrypt the prompt to its
    /// attested key, stream and decrypt the answer, then check the receipt
    /// (including that the enclave got exactly the request you encrypted).
    Chat {
        /// Obscurify API key (sk-obs1_...). Also read from OBSCURIFY_API_KEY.
        #[arg(long, env = "OBSCURIFY_API_KEY", hide_env_values = true)]
        api_key: String,
        /// A model with "e2ee": true in GET /v1/models, e.g. tee/glm-5.3.
        #[arg(long)]
        model: String,
        #[arg(long)]
        prompt: String,
        /// An optional system prompt (encrypted too).
        #[arg(long)]
        system: Option<String>,
        /// Sent as reasoning_effort, e.g. none for a model's plain variant.
        #[arg(long)]
        reasoning_effort: Option<String>,
        #[arg(long, default_value = "https://obscurify.ai/v1")]
        base: String,
        /// Save the reply bytes, receipt, attestation, nonce and plain request here.
        #[arg(long)]
        save: Option<PathBuf>,
    },
    /// Check saved files.
    Check {
        /// The reply bytes exactly as received.
        #[arg(long)]
        body: PathBuf,
        /// The receipt endpoint's JSON.
        #[arg(long)]
        receipt: PathBuf,
        /// The attestation endpoint's JSON.
        #[arg(long)]
        attestation: PathBuf,
        /// The nonce sent with the attestation request (64 hex characters).
        #[arg(long)]
        nonce: String,
        /// The plain request you encrypted (request.json from chat --save): adds the request check.
        #[arg(long)]
        request: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let options = Options {
        pccs_url: cli.pccs.clone(),
        base_rpc_url: (cli.base_rpc != "off").then(|| cli.base_rpc.clone()),
        now_secs: None,
    };
    let evidence = match cli.command {
        Command::Check { body, receipt, attestation, nonce, request } => {
            let request = match request.map(|p| std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))).transpose() {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            };
            let read = |p: &PathBuf| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
            match (read(&body), read(&receipt), read(&attestation)) {
                (Ok(body), Ok(receipt), Ok(attestation)) => Evidence {
                    body,
                    receipt_json: String::from_utf8_lossy(&receipt).into_owned(),
                    attestation_json: String::from_utf8_lossy(&attestation).into_owned(),
                    nonce,
                    request,
                },
                (a, b, c) => {
                    for e in [a.err(), b.err(), c.err()].into_iter().flatten() {
                        eprintln!("{e}");
                    }
                    return ExitCode::from(2);
                }
            }
        }
        Command::Chat { api_key, model, prompt, system, reasoning_effort, base, save } => {
            let ask = Ask { api_key: &api_key, model: &model, base: base.trim_end_matches('/') };
            match encrypted_chat(&ask, system.as_deref(), &prompt, reasoning_effort.as_deref(), &options, cli.json).await {
                Ok(evidence) => {
                    if let Some(dir) = save {
                        if let Err(e) = save_evidence(&dir, &evidence) {
                            eprintln!("couldn't save to {}: {e}", dir.display());
                        }
                    }
                    evidence
                }
                Err(Refused(code, message)) => {
                    eprintln!("{message}");
                    return ExitCode::from(code);
                }
            }
        }
    };
    let report = verify(&evidence, &options).await;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
    } else {
        print_report(&report);
    }
    if report.verified { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

fn save_evidence(dir: &PathBuf, e: &Evidence) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("body.sse"), &e.body)?;
    std::fs::write(dir.join("receipt.json"), &e.receipt_json)?;
    std::fs::write(dir.join("attestation.json"), &e.attestation_json)?;
    if let Some(request) = &e.request {
        std::fs::write(dir.join("request.json"), request)?;
    }
    std::fs::write(dir.join("nonce.txt"), &e.nonce)
}

struct Ask<'a> {
    api_key: &'a str,
    model: &'a str,
    base: &'a str,
}

/// Why nothing (more) can be done: exit code and message.
struct Refused(u8, String);

impl From<String> for Refused {
    fn from(message: String) -> Self {
        Refused(2, message)
    }
}

/// The route header that sends attestation and receipt requests to the
/// gateway that answers encrypted requests.
const E2EE_ROUTE: &str = "e2ee";

async fn encrypted_chat(
    ask: &Ask<'_>,
    system: Option<&str>,
    prompt: &str,
    reasoning_effort: Option<&str>,
    options: &Options,
    quiet: bool,
) -> Result<Evidence, Refused> {
    use futures_util::StreamExt;
    let http = reqwest::Client::new();
    let get = |url: String| http.get(url).bearer_auth(ask.api_key).header("X-Obscurify-TEE-Route", E2EE_ROUTE);
    let model = urlencode(ask.model);

    // 1. The gateway's attestation, fresh for our nonce, checked before anything is sent.
    let nonce = new_nonce();
    let r = get(format!("{}/tee/attestation?model={model}&nonce={nonce}", ask.base))
        .send()
        .await
        .map_err(|e| format!("couldn't fetch the attestation: {e}"))?;
    let code = r.status().as_u16();
    let attestation_json = r.text().await.unwrap_or_default();
    if code != 200 {
        return Err(format!("attestation: HTTP {code}: {attestation_json}").into());
    }
    let attested = verify_attestation(&attestation_json, &nonce, options).await;
    let Some(model_key) = attested.e2ee_public_key.clone() else {
        print_attestation(&attested);
        return Err(Refused(1, "NOT SENT: the gateway's attestation didn't verify, so there is no key to trust".into()));
    };
    if !quiet {
        eprintln!("attestation verified; encrypting to {}…", &model_key[..18]);
    }

    // 2. Encrypt every message to the attested key.
    let session = Session::new();
    let mut messages = Vec::new();
    if let Some(system) = system {
        messages.push(serde_json::json!({"role": "system", "content": system}));
    }
    messages.push(serde_json::json!({"role": "user", "content": prompt}));
    let mut request = serde_json::json!({
        "model": ask.model,
        "messages": messages,
        "stream": true,
        "stream_options": {"include_usage": true},
    });
    if let Some(effort) = reasoning_effort {
        request["reasoning_effort"] = effort.into();
    }
    let sealed = session
        .encrypt_request(&model_key, &request.to_string())
        .map_err(|e| e.to_string())?;

    // 3. Send it; the answer streams back encrypted to our key.
    let response = http
        .post(format!("{}/chat/completions", ask.base))
        .bearer_auth(ask.api_key)
        .header("Content-Type", "application/json")
        .header(e2ee::HEADER_CLIENT_KEY, session.public_key_hex())
        .header(e2ee::HEADER_MODEL_KEY, &model_key)
        .header(e2ee::HEADER_SIGNING_ALGO, e2ee::SIGNING_ALGO)
        .body(sealed.body.clone())
        .send()
        .await
        .map_err(|e| format!("couldn't reach {}: {e}", ask.base))?;
    let status = response.status();
    let header = |name: &str| response.headers().get(name).and_then(|v| v.to_str().ok()).map(String::from);
    let receipt_id = header("x-obscurify-tee-receipt");
    let route = header("x-obscurify-tee-route").unwrap_or_else(|| E2EE_ROUTE.to_string());
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(format!("HTTP {}: {text}", status.as_u16()).into());
    }
    let mut body = Vec::new();
    let mut pending = Vec::new();
    let mut stream = response.bytes_stream();
    let mut answer_started = false;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("the reply was cut off: {e}"))?;
        body.extend_from_slice(&chunk);
        pending.extend_from_slice(&chunk);
        while let Some(end) = pending.windows(2).position(|w| w == b"\n\n") {
            let event: Vec<u8> = pending.drain(..end + 2).collect();
            let plain = session.decrypt_event(&event).map_err(|e| Refused(1, format!("NOT ENCRYPTED: {e}")))?;
            if !quiet {
                print_event(&plain, &mut answer_started);
            }
        }
    }
    if !quiet {
        println!();
    }
    let receipt_id = receipt_id.ok_or("the reply has no X-Obscurify-TEE-Receipt header".to_string())?;

    // 4. The receipt, checked with the same attestation and our plain request.
    let mut receipt_json = None;
    for attempt in 0..10 {
        let r = get(format!("{}/tee/receipts/{receipt_id}?model={model}", ask.base))
            .header("X-Obscurify-TEE-Route", &route)
            .send()
            .await
            .map_err(|e| format!("couldn't fetch the receipt: {e}"))?;
        let code = r.status().as_u16();
        let text = r.text().await.unwrap_or_default();
        if code == 200 {
            receipt_json = Some(text);
            break;
        }
        if ![404, 502, 503].contains(&code) || attempt == 9 {
            return Err(format!("receipt {receipt_id}: HTTP {code}: {text}").into());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Ok(Evidence {
        body,
        receipt_json: receipt_json.unwrap_or_default(),
        attestation_json,
        nonce,
        request: Some(sealed.plain.into_bytes()),
    })
}

/// The answer text of one decrypted event: reasoning to stderr, content to stdout.
fn print_event(event: &[u8], answer_started: &mut bool) {
    use std::io::Write;
    let text = String::from_utf8_lossy(event);
    for data in text.lines().filter_map(|l| l.strip_prefix("data:")) {
        let Ok(chunk) = serde_json::from_str::<serde_json::Value>(data.trim()) else { continue };
        for choice in chunk["choices"].as_array().into_iter().flatten() {
            let delta = &choice["delta"];
            for key in ["reasoning_content", "reasoning"] {
                if let Some(t) = delta[key].as_str() {
                    eprint!("{t}");
                }
            }
            if let Some(t) = delta["content"].as_str() {
                if !*answer_started && !t.is_empty() {
                    eprintln!();
                    *answer_started = true;
                }
                print!("{t}");
                std::io::stdout().flush().ok();
            }
        }
    }
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn print_attestation(report: &AttestationReport) {
    println!("{}", if report.verified { "ATTESTATION VERIFIED" } else { "ATTESTATION NOT VERIFIED" });
    print_checks(&report.checks);
}

fn print_checks(checks: &[Check]) {
    for check in checks {
        let mark = match check.status {
            Status::Pass => "pass",
            Status::Fail => "FAIL",
            Status::Unchecked => "skip",
        };
        println!("  [{mark}] {}", check.label);
        println!("         {}", check.detail);
    }
}

fn print_report(report: &Report) {
    println!("{}", if report.verified { "VERIFIED" } else { "NOT VERIFIED" });
    print_checks(&report.checks);
    let field = |name: &str, value: &Option<String>| {
        if let Some(v) = value {
            println!("  {name}: {v}");
        }
    };
    field("receipt", &report.receipt_id);
    field("model", &report.model);
    field("TCB status", &report.tcb_status);
    field("compose hash", &report.compose_hash);
}
