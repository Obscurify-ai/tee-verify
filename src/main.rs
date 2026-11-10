//! `obscurify-tee-verify`: check Obscurify TEE replies from the command line.

use clap::{Parser, Subcommand};
use obscurify_tee_verify::{new_nonce, verify, Evidence, Options, Report, Status, BASE_RPC_URL, PHALA_PCCS_URL};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "obscurify-tee-verify",
    version,
    about = "Check that an Obscurify TEE reply came from an attested gateway",
    long_about = "Check that an Obscurify TEE reply came from an attested confidential-computing gateway.\n\n\
`run` sends a prompt to a TEE model with verification on and checks the reply.\n\
`check` checks a reply you saved earlier.\n\n\
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
    /// Send a prompt with "tee_verify": true, then fetch and check the receipt.
    Run {
        /// Obscurify API key (sk-obs1_...). Also read from OBSCURIFY_API_KEY.
        #[arg(long, env = "OBSCURIFY_API_KEY", hide_env_values = true)]
        api_key: String,
        /// A TEE model id, e.g. tee/glm-5.3-flash.
        #[arg(long)]
        model: String,
        #[arg(long)]
        prompt: String,
        #[arg(long, default_value = "https://obscurify.ai/v1")]
        base: String,
        /// Save the reply bytes, receipt, attestation and nonce in this directory.
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
        Command::Check { body, receipt, attestation, nonce } => {
            let read = |p: &PathBuf| std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()));
            match (read(&body), read(&receipt), read(&attestation)) {
                (Ok(body), Ok(receipt), Ok(attestation)) => Evidence {
                    body,
                    receipt_json: String::from_utf8_lossy(&receipt).into_owned(),
                    attestation_json: String::from_utf8_lossy(&attestation).into_owned(),
                    nonce,
                },
                (a, b, c) => {
                    for e in [a.err(), b.err(), c.err()].into_iter().flatten() {
                        eprintln!("{e}");
                    }
                    return ExitCode::from(2);
                }
            }
        }
        Command::Run { api_key, model, prompt, base, save } => {
            match fetch(&api_key, &model, &prompt, base.trim_end_matches('/')).await {
                Ok(evidence) => {
                    if let Some(dir) = save {
                        if let Err(e) = save_evidence(&dir, &evidence) {
                            eprintln!("couldn't save to {}: {e}", dir.display());
                        }
                    }
                    evidence
                }
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
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
    std::fs::write(dir.join("nonce.txt"), &e.nonce)
}

async fn fetch(api_key: &str, model: &str, prompt: &str, base: &str) -> Result<Evidence, String> {
    let http = reqwest::Client::new();
    let response = http
        .post(format!("{base}/chat/completions"))
        .bearer_auth(api_key)
        .json(&serde_json::json!({
            "model": model,
            "stream": true,
            "tee_verify": true,
            "messages": [{"role": "user", "content": prompt}],
        }))
        .send()
        .await
        .map_err(|e| format!("couldn't reach {base}: {e}"))?;
    let status = response.status();
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    };
    let receipt_id = header("x-obscurify-tee-receipt");
    let route = header("x-obscurify-tee-route");
    let body = response
        .bytes()
        .await
        .map_err(|e| format!("the reply was cut off: {e}"))?
        .to_vec();
    if !status.is_success() {
        return Err(format!("HTTP {}: {}", status.as_u16(), String::from_utf8_lossy(&body)));
    }
    let receipt_id = receipt_id.ok_or("the reply has no X-Obscurify-TEE-Receipt header")?;

    let get = |url: String| {
        let mut request = http.get(url).bearer_auth(api_key);
        if let Some(route) = &route {
            request = request.header("X-Obscurify-TEE-Route", route);
        }
        request
    };
    // The receipt is written when the stream ends; it can take a moment to appear.
    let mut receipt_json = None;
    for attempt in 0..10 {
        let r = get(format!("{base}/tee/receipts/{receipt_id}?model={model}"))
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
            return Err(format!("receipt {receipt_id}: HTTP {code}: {text}"));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let nonce = new_nonce();
    let r = get(format!("{base}/tee/attestation?model={model}&nonce={nonce}"))
        .send()
        .await
        .map_err(|e| format!("couldn't fetch the attestation: {e}"))?;
    let code = r.status().as_u16();
    let attestation_json = r.text().await.unwrap_or_default();
    if code != 200 {
        return Err(format!("attestation: HTTP {code}: {attestation_json}"));
    }
    Ok(Evidence {
        body,
        receipt_json: receipt_json.unwrap_or_default(),
        attestation_json,
        nonce,
    })
}

fn print_report(report: &Report) {
    println!("{}", if report.verified { "VERIFIED" } else { "NOT VERIFIED" });
    for check in &report.checks {
        let mark = match check.status {
            Status::Pass => "pass",
            Status::Fail => "FAIL",
            Status::Unchecked => "skip",
        };
        println!("  [{mark}] {}", check.label);
        println!("         {}", check.detail);
    }
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
