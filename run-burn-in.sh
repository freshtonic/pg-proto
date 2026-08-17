#!/usr/bin/env bash
set -euo pipefail

# Run from the pg-proto repository root.
# Requires Rust and a Docker-compatible container runtime.

SOAK_SECONDS="${SOAK_SECONDS:-3600}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_DIR="${OUTPUT_DIR:-${ARTIFACTS:-target/burn-in/manual-${STAMP}}}"
BIN="target/debug/pg-proto-burn-in"

mkdir -p "$OUTPUT_DIR"
cargo build -p pg-proto-burn-in

"$BIN" --run-all \
  --soak-duration-seconds "$SOAK_SECONDS" \
  --output-dir "$OUTPUT_DIR"

echo
echo "All burn-in permutations passed."
echo "Artifacts and REPORT.md: $OUTPUT_DIR"
