#!/usr/bin/env bash
# build.sh — Build Agent Shield Core for all targets.
#
# Usage:
#   ./build.sh          Build all targets
#   ./build.sh native   Build native only
#   ./build.sh wasm     Build WASM only
#   ./build.sh node     Build Node.js NAPI only
#   ./build.sh python   Build Python PyO3 only

set -euo pipefail

TARGET="${1:-all}"

build_native() {
    echo "==> Building native (release)..."
    cargo build --release
    echo "    Done: target/release/libagent_shield_core.*"
}

build_wasm() {
    echo "==> Building WASM..."
    if ! rustup target list --installed | grep -q wasm32-unknown-unknown; then
        echo "    Adding wasm32-unknown-unknown target..."
        rustup target add wasm32-unknown-unknown
    fi
    cargo build --release --features wasm --target wasm32-unknown-unknown
    echo "    Done: target/wasm32-unknown-unknown/release/agent_shield_core.wasm"
}

build_node() {
    echo "==> Building Node.js NAPI addon..."
    cargo build --release --features node
    echo "    Done: target/release/libagent_shield_core.*"
}

build_python() {
    echo "==> Building Python PyO3 extension..."
    cargo build --release --features python
    echo "    Done: target/release/libagent_shield_core.*"
}

case "$TARGET" in
    native)  build_native ;;
    wasm)    build_wasm ;;
    node)    build_node ;;
    python)  build_python ;;
    all)
        build_native
        echo
        build_wasm
        echo
        build_node
        echo
        build_python
        echo
        echo "==> All targets built successfully."
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Usage: $0 [native|wasm|node|python|all]"
        exit 1
        ;;
esac
