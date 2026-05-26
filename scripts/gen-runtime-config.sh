#!/usr/bin/env bash
# Generate frontend/js/config.runtime.js from environment variables.
# Usage: set API_BASE env var, then run this script before building the frontend.

set -euo pipefail

OUT_DIR="$(dirname "$0")/..../frontend/js"
# adjust OUT_DIR to repo-relative path
OUT_DIR="$(pwd)/frontend/js"
OUT_FILE="$OUT_DIR/config.runtime.js"

if [ -z "${API_BASE-}" ]; then
  echo "ERROR: API_BASE environment variable is not set."
  echo "Set API_BASE (e.g. https://akili.fly.dev) and re-run."
  exit 1
fi

mkdir -p "$OUT_DIR"
cat > "$OUT_FILE" <<EOF
window.AKILI_RUNTIME = { API_BASE: "${API_BASE}" };
EOF
echo "Wrote $OUT_FILE"
