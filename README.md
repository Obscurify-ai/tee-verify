# obscurify-tee-verify

Checks one reply from an Obscurify TEE model, and does the client side of Obscurify's Encrypted mode: end-to-end encryption between your device and the enclave. Obscurify's web chat and Android app use it for every Encrypted chat, and API users can do the same with the command-line tool or the library.

TEE models on Obscurify are served through RedPill's private AI gateway, which runs in an Intel TDX confidential VM (dstack). For each reply the gateway signs a receipt with the hashes of what it received and what it sent back. This crate takes three things the client collected itself:

- the reply bytes exactly as they arrived,
- the receipt for that reply,
- the gateway's attestation report, fetched with a random nonce the client just made,

and runs seven checks on them.

## The checks

| Id | What it checks | What a pass means |
|---|---|---|
| `request_bytes` | Encrypted mode only: SHA-256 of the request you encrypted (in plain text, with Obscurify's model id swapped for the gateway's, which is the receipt's `model`) equals `request.received.body_hash`, which the gateway takes over the request after decrypting it | The enclave got exactly the conversation you wrote. Obscurify couldn't add, drop or change a message, even though anyone can encrypt to the gateway's public key. |
| `reply_bytes` | SHA-256 of the reply equals `response.returned.body_hash` in the receipt | Nobody between the gateway and you changed or cut the reply. Obscurify's keepalive frames (`: obscurify-keepalive`), sent between SSE frames while a model is thinking, are removed first. |
| `receipt_signature` | Ed25519 signature over the RFC 8785 canonical receipt, with the receipt key from the attested keyset | The receipt came from the holder of the gateway's receipt key. |
| `nonce_binding` | The keyset hashes to the receipt's `workload_keyset_digest`, and the quote's report data is `sha256({"keyset_digest","nonce","purpose":"aci.report_data.v1"})` followed by 32 zero bytes | That key belongs to the machine that produced the quote, and the quote is fresh: it answers your nonce, so it can't be an old recording. |
| `tdx_hardware` | Full Intel DCAP verification of the quote with [dcap-qvl](https://github.com/Phala-Network/dcap-qvl), using Intel's collateral from a PCCS | The quote was signed by a genuine Intel TDX CPU whose firmware Intel hasn't revoked. The TCB status and any Intel advisories are reported. Debug VMs are rejected. |
| `gateway_code` | Replays the RTMR3 event log, recomputing each event's digest from its payload, and compares it with the quote's RTMR3; then checks the `compose-hash` event equals `sha256(app_compose)` | The configuration the attestation shows (`app_compose`: container images pinned by digest) is the one the hardware measured at boot. |
| `approved_release` | `allowedComposeHashes(compose hash)` on the gateway's app contract on Base (address = the measured `app-id`) | The gateway's operators published this configuration as a release. Their KMS only gives keys to VMs running an allowed configuration. A network failure here leaves the check unchecked rather than failed. |
| `model_host` | The receipt's `upstream.verified` event has result `verified` and `required: true` | The gateway checked the attestation of the GPU machine that ran the model before sending your request, and would have refused an unverified one. The session id is reported. |

A reply counts as verified when every check passes, except that `approved_release` may be unchecked.

## Encrypted mode

The gateway's attested keyset also holds encryption keys (`e2ee_public_keys`). Encrypted mode uses the secp256k1 one (`secp256k1-aes-256-gcm-hkdf-sha256`):

1. Before sending anything, fetch the attestation report with a fresh nonce (`GET /v1/tee/attestation?model=...&nonce=...` with `X-Obscurify-TEE-Route: e2ee`) and run `verify_attestation`. It runs checks 3 to 6 on the report alone and returns the encryption key only when they pass. Encrypt to no other key: a key that didn't come from a verified report could be anyone's, including Obscurify's.
2. Make a key pair (`e2ee::Session`) and encrypt every message's `content` to the gateway's key (`encrypt_request`). Each encrypted string is hex of your 65-byte uncompressed public key, a 12-byte IV and the AES-256-GCM ciphertext with its tag. The AES key is HKDF-SHA256 of the ECDH shared point's x-coordinate, with no salt and info `ecdsa_encryption`.
3. Send the body with `X-Client-Pub-Key` (yours), `X-Model-Pub-Key` (the gateway's) and `X-Signing-Algo: ecdsa`. Streams need `"stream_options": {"include_usage": true}`: token counts stay in plain text for billing. No tools, web search or held threads.
4. Every `content`, `reasoning_content` or `reasoning` in the answer comes back as an encrypted string with a fresh sender key in its first 65 bytes. `decrypt_event` (one SSE event) and `decrypt_answer` (a JSON object) decrypt them with your session key, and fail if any came back unencrypted.
5. Check the reply with `verify`, passing the attestation from step 1 and the plain request `encrypt_request` returned as `Evidence::request`. That adds `request_bytes`.

What Encrypted mode doesn't hide: which model you use, when, how long the messages and answers are, the token counts, and your account. The receipt's request hash is visible to Obscurify too, so a very short message could be confirmed by guessing it; the whole conversation is hashed together.

## What it doesn't prove

- Without Encrypted mode, your text passes through Obscurify's server in the clear on its way to the gateway. Obscurify not logging it is a policy, not something this crate can check. In Encrypted mode only the gateway's enclave (and the model host it verified) can read it.
- Without Encrypted mode the request side isn't checked: `request.received` covers the request as it reached the gateway, which isn't byte for byte what you sent.
- The `model_host` check trusts the attested gateway's own verification of the model host. It doesn't fetch and appraise the host's GPU evidence itself.
- `source_provenance` (repository and commit) is a label the workload declares. The measured values are the compose hash and the images it pins.
- It doesn't check the OS image against a published list. The OS image hash is reported.
- It checks one reply. Each reply needs its own receipt.

## Library

```rust
use obscurify_tee_verify::{verify, Evidence, Options, new_nonce, strip_keepalives};

let report = verify(&Evidence { body, receipt_json, attestation_json, nonce, request: None }, &Options {
    pccs_url: "https://obscurify.ai/tee/pccs".into(),   // or PHALA_PCCS_URL
    base_rpc_url: Some("https://mainnet.base.org".into()), // None skips approved_release
    now_secs: None,
}).await;
println!("{}", serde_json::to_string_pretty(&report)?);
```

Encrypted mode:

```rust
use obscurify_tee_verify::{verify_attestation, e2ee::Session};

let attested = verify_attestation(&attestation_json, &nonce, &options).await;
let key = attested.e2ee_public_key.expect("attestation didn't verify: don't send");
let session = Session::new();
let sealed = session.encrypt_request(&key, r#"{"model":"tee/glm-5.3","stream":true,
  "stream_options":{"include_usage":true},"messages":[{"role":"user","content":"Hello"}]}"#)?;
// POST sealed.body with X-Client-Pub-Key: session.public_key_hex(), X-Model-Pub-Key: key,
// X-Signing-Algo: ecdsa; decrypt each SSE event with session.decrypt_event(&event)?;
// then verify(&Evidence { ..., request: Some(sealed.plain.into_bytes()) }, &options).
```

`verify` never returns an error: anything wrong becomes a failed or unchecked check. Collateral from the PCCS is signed by Intel, so any PCCS works, including a proxy; it can make verification fail but not pass. The PCCS paths requested are in `PCCS_PATHS`.

## Command line

```bash
cargo install --path . --features cli

# Ask a TEE model something with verification on, then check the reply
OBSCURIFY_API_KEY=sk-obs1_... obscurify-tee-verify run --model tee/glm-5.3-flash --prompt "Hello"

# Chat end to end encrypted: check the attestation, encrypt, decrypt the answer, check the receipt
OBSCURIFY_API_KEY=sk-obs1_... obscurify-tee-verify chat --model tee/glm-5.3 --prompt "Hello"

# Check a reply saved earlier (run --save DIR writes these four files)
obscurify-tee-verify check --body body.sse --receipt receipt.json \
  --attestation attestation.json --nonce "$(cat nonce.txt)"
```

Add `--json` for the full report. Exit status: 0 verified, 1 not verified (for `chat`, also: the attestation didn't verify, so nothing was sent, or the answer came back unencrypted), 2 usage or network error.

## Web

```bash
./build-wasm.sh OUT_DIR   # writes tee_verify.js and tee_verify_bg.wasm
```

```js
import init, { verifyTeeReply, newNonce } from './tee_verify.js';
await init();
const report = await verifyTeeReply(bodyBytes, receiptJson, attestationJson, nonce,
  'https://obscurify.ai/tee/pccs', undefined /* default Base RPC; '' skips */);

// Encrypted mode
import { verifyAttestation, E2eeSession } from './tee_verify.js';
const attested = await verifyAttestation(attestationJson, nonce, pccsUrl);
if (!attested.verified) throw new Error('not sending');
const session = new E2eeSession();            // or E2eeSession.fromSecret(saved)
const { body, plain } = session.encryptRequest(attested.e2ee_public_key, JSON.stringify(request));
// ... fetch with the three headers, then for each SSE event: session.decryptEvent(eventBytes)
const report = await verifyTeeReply(bodyBytes, receiptJson, attestationJson, nonce, pccsUrl,
  undefined, new TextEncoder().encode(plain));
```

## Tests

```bash
cargo test --features cli                 # offline: tampering, keepalives, bad input
cargo test --features cli -- --ignored    # also the live checks (PCCS and Base)
```

The fixtures in `tests/fixtures` are one real streamed reply from `tee/glm-5.3-flash` with its receipt and an attestation fetched with the nonce in `nonce.txt`. Set `TEE_VERIFY_LIVE_DIR` to a directory written by `run --save` to run the command-line tests on a fresh reply.

## License

GPL-3.0-or-later.
