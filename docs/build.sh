#!/usr/bin/env bash
# Rebuild docs/trust_issues.wasm, the browser demo's engine, from src/.
#
# It's the real checking core and the five demo scenes (src/demo/), built
# without the `server` feature: no Tor, no network, no RPC server.
#
# Needs Rust from rust-toolchain.toml. The first run adds the wasm target and
# llvm-tools (for llvm-ar, which can archive the secp256k1 C code for wasm).
set -euo pipefail
cd "$(dirname "$0")/.."

rustup target add wasm32-unknown-unknown >/dev/null
rustup component add llvm-tools >/dev/null
AR_wasm32_unknown_unknown="$(ls "$(rustc --print sysroot)"/lib/rustlib/*/bin/llvm-ar)"
export AR_wasm32_unknown_unknown

# Keep local folder names (and so usernames) out of the published file.
REGISTRY="${CARGO_HOME:-$HOME/.cargo}/registry/src"
export RUSTFLAGS="--remap-path-prefix=$REGISTRY=crates --remap-path-prefix=$PWD=trust-issues"

cargo rustc --locked --lib --release \
    --target wasm32-unknown-unknown --no-default-features --crate-type cdylib \
    --config 'profile.release.opt-level="s"' \
    --config 'profile.release.lto=true' \
    --config 'profile.release.codegen-units=1' \
    --config 'profile.release.strip=true' \
    --config 'profile.release.panic="abort"'

cp target/wasm32-unknown-unknown/release/trust_issues.wasm docs/trust_issues.wasm
if strings -n 6 docs/trust_issues.wasm | grep -q "$HOME"; then
    echo "error: docs/trust_issues.wasm still contains a local path" >&2
    exit 1
fi
shasum -a 256 docs/trust_issues.wasm
