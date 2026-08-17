#!/usr/bin/env bash
set -euo pipefail

# Run from the pg-proto repository root.
# Requires Rust and a Docker-compatible container runtime.

SOAK_SECONDS="${SOAK_SECONDS:-3600}"
SEED="${SEED:-8675309}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_DIR="${OUTPUT_DIR:-${ARTIFACTS:-target/burn-in/manual-${STAMP}}}"
BIN="target/debug/pg-proto-burn-in"

mkdir -p "$OUTPUT_DIR"
cargo build -p pg-proto-burn-in

run() {
  echo
  echo ">>> $*"
  "$@"
}

# Full PostgreSQL compatibility matrix.
for version in 14 15 16 17 18; do
  run "$BIN" conformance \
    --profile smoke \
    --postgres-version "$version" \
    --output-dir "$OUTPUT_DIR/smoke-pg${version}"
done

# Specialized conformance permutations.
for profile in authentication replication rewrites; do
  run "$BIN" conformance \
    --profile "$profile" \
    --output-dir "$OUTPUT_DIR/$profile"
done

# Synthetic/unreachable protocol exchanges and malformed traffic.
run "$BIN" conformance \
  --profile scripted \
  --output-dir "$OUTPUT_DIR/scripted"

# Destructive scenarios run against isolated PostgreSQL containers.
run "$BIN" faults \
  --output-dir "$OUTPUT_DIR/faults"

# Approximately one hour of deterministic soak traffic.
run "$BIN" soak \
  --profile overnight \
  --seed "$SEED" \
  --duration-seconds "$SOAK_SECONDS" \
  --output-dir "$OUTPUT_DIR/soak"

# Verify the complete catalogue and its dispositions.
run "$BIN" catalogue \
  --approved \
  --as-of "$(date -u +%F)" \
  --output-dir "$OUTPUT_DIR/catalogue"

run "$BIN" make-report --dir "$OUTPUT_DIR"

echo
echo "All burn-in permutations passed."
echo "Artifacts and REPORT.md: $OUTPUT_DIR"
