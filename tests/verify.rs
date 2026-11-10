//! Behaviour of the verifier on a real reply captured from a TEE model
//! (tests/fixtures). Tests marked `#[ignore]` need the network (Intel's
//! collateral through Phala's PCCS, and Base): `cargo test -- --ignored`.

use obscurify_tee_verify::{verify, Evidence, Options, Report, Status, KEEPALIVE_FRAME};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn evidence() -> Evidence {
    Evidence {
        body: fixture("body.sse"),
        receipt_json: String::from_utf8(fixture("receipt.json")).unwrap(),
        attestation_json: String::from_utf8(fixture("attestation.json")).unwrap(),
        nonce: String::from_utf8(fixture("nonce.txt")).unwrap(),
    }
}

/// No network: the PCCS is unreachable and the release check is off.
fn offline() -> Options {
    Options {
        pccs_url: "http://127.0.0.1:9".into(),
        base_rpc_url: None,
        now_secs: None,
    }
}

fn status(report: &Report, id: &str) -> Status {
    report.checks.iter().find(|c| c.id == id).unwrap().status
}

#[tokio::test]
async fn offline_checks_pass_and_hardware_stays_unchecked() {
    let report = verify(&evidence(), &offline()).await;
    for id in ["reply_bytes", "receipt_signature", "nonce_binding", "gateway_code", "model_host"] {
        assert_eq!(status(&report, id), Status::Pass, "{id}: {:?}", report.checks);
    }
    assert_eq!(status(&report, "tdx_hardware"), Status::Unchecked);
    assert_eq!(status(&report, "approved_release"), Status::Unchecked);
    assert!(!report.verified, "a reply whose hardware wasn't checked isn't verified");
    assert_eq!(
        report.compose_hash.as_deref(),
        Some("66e91ac6c2325537851bc95fc0e4489df119b7b0204d27f2bae91ec1324ecf1f")
    );
    assert_eq!(report.model.as_deref(), Some("z-ai/glm-5.3-flash"));
    assert_eq!(report.receipt_id.as_deref(), Some("rcpt-427e82e62e719906781db6a7"));
}

#[tokio::test]
async fn one_changed_byte_in_the_reply_fails_the_reply_check_only() {
    let mut e = evidence();
    let at = e.body.windows(2).position(|w| w == b"ok").unwrap_or(200);
    e.body[at] ^= 0x01;
    let report = verify(&e, &offline()).await;
    assert_eq!(status(&report, "reply_bytes"), Status::Fail);
    assert_eq!(status(&report, "receipt_signature"), Status::Pass);
    assert!(!report.verified);
}

#[tokio::test]
async fn a_cut_off_reply_fails() {
    let mut e = evidence();
    e.body.truncate(e.body.len() - 20);
    let report = verify(&e, &offline()).await;
    assert_eq!(status(&report, "reply_bytes"), Status::Fail);
}

#[tokio::test]
async fn keepalive_frames_between_frames_are_ignored() {
    let mut e = evidence();
    let body = e.body.clone();
    let mut spliced = KEEPALIVE_FRAME.to_vec();
    for frame in body.split_inclusive(|&b| b == b'\n') {
        spliced.extend_from_slice(frame);
        if frame == b"\n" {
            spliced.extend_from_slice(KEEPALIVE_FRAME);
            spliced.extend_from_slice(KEEPALIVE_FRAME);
        }
    }
    e.body = spliced;
    let report = verify(&e, &offline()).await;
    assert_eq!(status(&report, "reply_bytes"), Status::Pass, "{:?}", report.checks);
}

#[tokio::test]
async fn a_keepalive_inside_a_frame_is_a_change() {
    let mut e = evidence();
    let mut body = e.body[..40].to_vec();
    body.extend_from_slice(KEEPALIVE_FRAME);
    body.extend_from_slice(&e.body[40..]);
    e.body = body;
    let report = verify(&e, &offline()).await;
    assert_eq!(status(&report, "reply_bytes"), Status::Fail);
}

#[tokio::test]
async fn a_changed_receipt_fails_the_signature() {
    let mut e = evidence();
    e.receipt_json = e.receipt_json.replace("\"served_at\":1794342020", "\"served_at\":1794342021");
    assert!(e.receipt_json.contains("1794342021"), "fixture changed shape");
    let report = verify(&e, &offline()).await;
    assert_eq!(status(&report, "receipt_signature"), Status::Fail);
    assert!(!report.verified);
}

#[tokio::test]
async fn a_receipt_naming_another_reply_hash_fails_the_signature() {
    let mut e = evidence();
    // Someone swaps the signed hash for the hash of a different reply.
    e.receipt_json = e.receipt_json.replace(
        "4ce51c6376b5d18cfc688e1a8d3393d179af106d0b958edc630376b8ea3a48b9\"",
        "0000000000000000000000000000000000000000000000000000000000000000\"",
    );
    let report = verify(&e, &offline()).await;
    assert_eq!(status(&report, "receipt_signature"), Status::Fail);
    assert_eq!(status(&report, "reply_bytes"), Status::Fail);
}

#[tokio::test]
async fn a_different_nonce_fails_the_binding() {
    let mut e = evidence();
    e.nonce = obscurify_tee_verify::new_nonce();
    let report = verify(&e, &offline()).await;
    assert_eq!(status(&report, "nonce_binding"), Status::Fail);
    assert_eq!(status(&report, "receipt_signature"), Status::Pass);
    assert!(!report.verified);
}

#[tokio::test]
async fn a_changed_app_compose_fails_the_code_check() {
    let mut e = evidence();
    e.attestation_json = e.attestation_json.replacen("allowed_envs", "allowed_envz", 1);
    let report = verify(&e, &offline()).await;
    assert_eq!(status(&report, "gateway_code"), Status::Fail);
}

#[tokio::test]
async fn garbage_is_a_failure_not_a_panic() {
    let e = Evidence {
        body: b"data: hi\n\n".to_vec(),
        receipt_json: "not json".into(),
        attestation_json: "{}".into(),
        nonce: "zz".into(),
    };
    let report = verify(&e, &offline()).await;
    assert!(!report.verified);
    assert_eq!(report.checks.len(), 7);
}

#[tokio::test]
#[ignore = "needs the network: Intel collateral via Phala's PCCS, and Base"]
async fn live_the_captured_reply_is_fully_verified() {
    let report = verify(&evidence(), &Options::default()).await;
    assert!(report.verified, "{:#?}", report.checks);
    assert!(report.checks.iter().all(|c| c.status == Status::Pass), "{:#?}", report.checks);
    assert!(report.tcb_status.is_some());
}

#[tokio::test]
#[ignore = "needs the network"]
async fn live_an_unreachable_release_rpc_leaves_the_reply_verified() {
    let options = Options {
        base_rpc_url: Some("http://127.0.0.1:9".into()),
        ..Options::default()
    };
    let report = verify(&evidence(), &options).await;
    assert_eq!(status(&report, "approved_release"), Status::Unchecked);
    assert!(report.verified, "{:#?}", report.checks);
}
