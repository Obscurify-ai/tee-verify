#!/usr/bin/env bash
# Builds the web client's verifier: an ES module plus its .wasm.
# Usage: ./build-wasm.sh OUT_DIR   (e.g. ../obscurify/static/vendor/tee-verify)
set -euo pipefail
out="${1:?usage: $0 OUT_DIR}"
cd "$(dirname "$0")"
wasm-pack build --release --target web --no-typescript --no-pack \
  --out-dir "$PWD/pkg" --out-name tee_verify -- --features wasm
mkdir -p "$out"
cp pkg/tee_verify.js pkg/tee_verify_bg.wasm "$out/"
ls -l "$out/tee_verify.js" "$out/tee_verify_bg.wasm"
