//! The command-line tool's `check` path. Needs `--features cli`; the live
//! ones also need the network (`-- --ignored`). `TEE_VERIFY_LIVE_DIR` may
//! point at a directory saved by `chat --save` (body.sse, receipt.json,
//! attestation.json, nonce.txt) to check a freshly captured reply instead.
#![cfg(feature = "cli")]

use std::process::Command;

fn dir() -> String {
    std::env::var("TEE_VERIFY_LIVE_DIR")
        .unwrap_or_else(|_| format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR")))
}

fn check(body: &str) -> (i32, String) {
    let d = dir();
    let nonce = std::fs::read_to_string(format!("{d}/nonce.txt")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_obscurify-tee-verify"))
        .args(["check", "--json", "--body", body])
        .args(["--receipt", &format!("{d}/receipt.json")])
        .args(["--attestation", &format!("{d}/attestation.json")])
        .args(["--nonce", nonce.trim()])
        .output()
        .unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
#[ignore = "needs the network"]
fn live_check_verifies_a_saved_reply() {
    let (code, out) = check(&format!("{}/body.sse", dir()));
    assert_eq!(code, 0, "{out}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["verified"], true);
}

#[test]
#[ignore = "needs the network"]
fn live_check_rejects_a_changed_reply_with_exit_1() {
    let mut body = std::fs::read(format!("{}/body.sse", dir())).unwrap();
    let n = body.len();
    body[n / 2] ^= 1;
    let path = std::env::temp_dir().join(format!("tee-verify-changed-{}.sse", std::process::id()));
    std::fs::write(&path, body).unwrap();
    let (code, out) = check(path.to_str().unwrap());
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("\"verified\": false"));
}

#[test]
fn a_missing_file_is_a_usage_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_obscurify-tee-verify"))
        .args(["check", "--body", "/nonexistent", "--receipt", "/nonexistent"])
        .args(["--attestation", "/nonexistent", "--nonce", "00"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
