#!/usr/bin/env bash
# Compile shai-hulud-guard pour Intel et Apple Silicon puis fusionne les deux
# binaires en un exécutable universel via lipo (SPEC-T03).
set -euo pipefail

cd "$(dirname "$0")/.."

BIN_NAME="shai-hulud-guard"
TARGETS=(x86_64-apple-darwin aarch64-apple-darwin)

for target in "${TARGETS[@]}"; do
    rustup target add "$target" >/dev/null
    echo "==> cargo build --release --target $target"
    cargo build --release --target "$target"
done

OUT_DIR="target/universal/release"
mkdir -p "$OUT_DIR"

lipo -create \
    "target/x86_64-apple-darwin/release/$BIN_NAME" \
    "target/aarch64-apple-darwin/release/$BIN_NAME" \
    -output "$OUT_DIR/$BIN_NAME"

echo "==> binaire universel : $OUT_DIR/$BIN_NAME"
lipo -info "$OUT_DIR/$BIN_NAME"
