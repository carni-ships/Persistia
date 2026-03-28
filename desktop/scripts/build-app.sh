#!/bin/bash
# Build the Persistia desktop app for macOS.
# Produces: src-tauri/target/release/bundle/macos/Persistia.app
#           src-tauri/target/release/bundle/dmg/Persistia_0.1.0_aarch64.dmg

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DESKTOP_DIR="$(dirname "$SCRIPT_DIR")"

cd "$DESKTOP_DIR"

echo "=== Persistia Desktop Build ==="
echo ""

# Step 1: Bundle resources
echo "--- Bundling resources ---"
bash scripts/bundle-resources.sh
echo ""

# Step 2: Install frontend deps
echo "--- Installing frontend dependencies ---"
npm install
echo ""

# Step 3: Build
echo "--- Building Tauri app ---"
npx tauri build

echo ""
echo "=== Build complete ==="
echo ""
ls -la src-tauri/target/release/bundle/macos/*.app 2>/dev/null || echo "App bundle not found"
ls -la src-tauri/target/release/bundle/dmg/*.dmg 2>/dev/null || echo "DMG not found"
