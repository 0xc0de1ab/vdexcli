#!/usr/bin/env bash
# build_demo.sh — Build the browser-based VDEX analyzer demo
#
# Output: demo/vdex.wasm and demo/wasm_exec.js
# Serve:  cd demo && python3 -m http.server 8080
#         then open http://localhost:8080
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEMO_DIR="$SCRIPT_DIR"

echo "▶ Building WASM binary…"
GOOS=js GOARCH=wasm go build \
  -trimpath \
  -ldflags="-s -w" \
  -o "$DEMO_DIR/vdex.wasm" \
  "$REPO_ROOT/wasm/"

echo "▶ Copying wasm_exec.js from Go standard library…"
GOROOT="$(go env GOROOT)"
cp "$GOROOT/lib/wasm/wasm_exec.js" "$DEMO_DIR/wasm_exec.js"

echo ""
echo "✅  Demo build complete!"
echo ""
echo "   WASM size: $(du -sh "$DEMO_DIR/vdex.wasm" | cut -f1)"
echo ""
echo "   To serve locally:"
echo "   cd demo && python3 -m http.server 8080"
echo "   Then open http://localhost:8080"
echo ""
