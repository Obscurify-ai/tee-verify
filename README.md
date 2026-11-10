# obscurify-tee-verify

Checks one reply from an Obscurify TEE model. Obscurify's web chat and Android app run it after each reply when TEE verification is on, and API users can run the same checks with the command-line tool.

TEE models on Obscurify are served through RedPill's private AI gateway, which runs in an Intel TDX confidential VM (dstack). For each reply the gateway signs a receipt with the hashes of what it received and what it sent back. This crate takes three things the client collected itself:

- the reply bytes exactly as they arrived,
- the receipt for that reply,
- the gateway's attestation report, fetched with a random nonce the client just made,

and runs seven checks on them.

## The checks

| Id | What it checks | What a pass means |
|---|---|---|
| `reply_bytes` | SHA-256 of the reply equals `response.returned.body_hash` in the receipt | Nobody between the gateway and you changed or cut the reply. Obscurify's keepalive frames (`: obscurify-keepalive`), sent between SSE frames while a model is thinking, are removed first. |
| `receipt_signature` | Ed25519 signature over the RFC 8785 canonical receipt, with the receipt key from the attested keyset | The receipt came from the holder of the gateway's receipt key. |
| `nonce_binding` | The keyset hashes to the receipt's `workload_keyset_digest`, and the quote's report data is `sha256({"keyset_digest","nonce","purpose":"aci.report_data.v1"})` followed by 32 zero bytes | That key belongs to the machine that produced the quote, and the quote is fresh: it answers your nonce, so it can't be an old recording. |
| `tdx_hardware` | Full Intel DCAP verification of the quote with [dcap-qvl](https://github.com/Phala-Network/dcap-qvl), using Intel's collateral from a PCCS | The quote was signed by a genuine Intel TDX CPU whose firmware Intel hasn't revoked. The TCB status and any Intel advisories are reported. Debug VMs are rejected. |
| `gateway_code` | Replays the RTMR3 event log, recomputing each event's digest from its payload, and compares it with the quote's RTMR3; then checks the `compose-hash` event equals `sha256(app_compose)` | The configuration the attestation shows (`app_compose`: container images pinned by digest) is the one the hardware measured at boot. |
| `approved_release` | `allowedComposeHashes(compose hash)` on the gateway's app contract on Base (address = the measured `app-id`) | The gateway's operators published this configuration as a release. Their KMS only gives keys to VMs running an allowed configuration. A network failure here leaves the check unchecked rather than failed. |
| `model_host` | The receipt's `upstream.verified` event has result `verified` and `required: true` | The gateway checked the attestation of the GPU machine that ran the model before sending your request, and would have refused an unverified one. The session id is reported. |

A reply counts as verified when every check passes, except that `approved_release` may be unchecked.

## What it doesn't prove

- Your text passes through Obscurify's server in the clear on its way to the gateway, and the gateway reads it inside its enclave. Obscurify not logging it is a policy, not something this crate can check.
- `request.received` in the receipt covers the request as it reached the gateway, which isn't byte for byte what you sent, so this crate doesn't check the request side.
- The `model_host` check trusts the attested gateway's own verification of the model host. It doesn't fetch and appraise the host's GPU evidence itself.
- `source_provenance` (repository and commit) is a label the workload declares. The measured values are the compose hash and the images it pins.
- It doesn't check the OS image against a published list. The OS image hash is reported.
- It checks one reply. Each reply needs its own receipt.

## Library

```rust
use obscurify_tee_verify::{verify, Evidence, Options, new_nonce, strip_keepalives};

let report = verify(&Evidence { body, receipt_json, attestation_json, nonce }, &Options {
    pccs_url: "https://obscurify.ai/tee/pccs".into(),   // or PHALA_PCCS_URL
    base_rpc_url: Some("https://mainnet.base.org".into()), // None skips approved_release
    now_secs: None,
}).await;
println!("{}", serde_json::to_string_pretty(&report)?);
```

`verify` never returns an error: anything wrong becomes a failed or unchecked check. Collateral from the PCCS is signed by Intel, so any PCCS works, including a proxy; it can make verification fail but not pass. The PCCS paths requested are in `PCCS_PATHS`.

## Command line

```bash
cargo install --path . --features cli

# Ask a TEE model something with verification on, then check the reply
OBSCURIFY_API_KEY=sk-obs1_... obscurify-tee-verify run --model tee/glm-5.3-flash --prompt "Hello"

# Check a reply saved earlier (run --save DIR writes these four files)
obscurify-tee-verify check --body body.sse --receipt receipt.json \
  --attestation attestation.json --nonce "$(cat nonce.txt)"
```

Add `--json` for the full report. Exit status: 0 verified, 1 not verified, 2 usage or network error.

## Web

```bash
./build-wasm.sh OUT_DIR   # writes tee_verify.js and tee_verify_bg.wasm
```

```js
import init, { verifyTeeReply, newNonce } from './tee_verify.js';
await init();
const report = await verifyTeeReply(bodyBytes, receiptJson, attestationJson, nonce,
  'https://obscurify.ai/tee/pccs', undefined /* default Base RPC; '' skips */);
```

## Tests

```bash
cargo test --features cli                 # offline: tampering, keepalives, bad input
cargo test --features cli -- --ignored    # also the live checks (PCCS and Base)
```

The fixtures in `tests/fixtures` are one real streamed reply from `tee/glm-5.3-flash` with its receipt and an attestation fetched with the nonce in `nonce.txt`. Set `TEE_VERIFY_LIVE_DIR` to a directory written by `run --save` to run the command-line tests on a fresh reply.

## License

GPL-3.0-or-later.
