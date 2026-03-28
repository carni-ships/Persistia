#!/bin/bash
# Bundle all runtime resources for the Persistia desktop app.
# Run this once before `cargo tauri dev` or before building.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DESKTOP_DIR="$(dirname "$SCRIPT_DIR")"
TAURI_DIR="$DESKTOP_DIR/src-tauri"
REPO_ROOT="$(dirname "$DESKTOP_DIR")"
ZKMETAL_DIR="$(dirname "$REPO_ROOT")/zkMetal"

ARCH="$(uname -m)"
if [ "$ARCH" = "arm64" ]; then
  RUST_TARGET="aarch64-apple-darwin"
  NODE_ARCH="arm64"
else
  RUST_TARGET="x86_64-apple-darwin"
  NODE_ARCH="x64"
fi

echo "=== Persistia Desktop Resource Bundler ==="
echo "Architecture: $ARCH ($RUST_TARGET)"
echo ""

# --- 1. Node.js binary ---
NODE_VERSION="v22.15.0"
NODE_DIR="$TAURI_DIR/bin"
NODE_BIN="$NODE_DIR/node-$RUST_TARGET"
mkdir -p "$NODE_DIR"

if [ ! -f "$NODE_BIN" ]; then
  echo "[1/6] Downloading Node.js $NODE_VERSION ($NODE_ARCH)..."
  TARBALL="node-$NODE_VERSION-darwin-$NODE_ARCH.tar.gz"
  curl -sL "https://nodejs.org/dist/$NODE_VERSION/$TARBALL" -o "/tmp/$TARBALL"
  tar -xzf "/tmp/$TARBALL" -C /tmp "node-$NODE_VERSION-darwin-$NODE_ARCH/bin/node"
  mv "/tmp/node-$NODE_VERSION-darwin-$NODE_ARCH/bin/node" "$NODE_BIN"
  chmod +x "$NODE_BIN"
  rm -rf "/tmp/$TARBALL" "/tmp/node-$NODE_VERSION-darwin-$NODE_ARCH"
  echo "  -> $NODE_BIN"
else
  echo "[1/6] Node.js binary already exists"
fi

# --- 2. bb binary ---
BB_BIN="$NODE_DIR/bb-$RUST_TARGET"
BB_SOURCE="$HOME/.bb/bb"

if [ ! -f "$BB_BIN" ]; then
  if [ -f "$BB_SOURCE" ]; then
    echo "[2/6] Copying bb binary..."
    cp "$BB_SOURCE" "$BB_BIN"
    chmod +x "$BB_BIN"
    echo "  -> $BB_BIN"
  else
    echo "[2/6] WARNING: bb not found at $BB_SOURCE. Install with: bbup -v 4.1.2"
  fi
else
  echo "[2/6] bb binary already exists"
fi

# --- 3. Compiled circuits ---
CIRCUITS_DIR="$TAURI_DIR/resources/circuits"
mkdir -p "$CIRCUITS_DIR"

echo "[3/6] Copying compiled circuits..."
CIRCUIT_SRC="$REPO_ROOT/contracts/zk-noir/target"
for f in persistia_state_proof.json persistia_incremental_proof.json; do
  if [ -f "$CIRCUIT_SRC/$f" ]; then
    cp "$CIRCUIT_SRC/$f" "$CIRCUITS_DIR/"
    echo "  -> $f ($(du -h "$CIRCUITS_DIR/$f" | cut -f1))"
  else
    echo "  WARNING: $f not found at $CIRCUIT_SRC"
  fi
done

# Copy VK cache if it exists
if [ -d "$CIRCUIT_SRC/bb_vk" ]; then
  cp -r "$CIRCUIT_SRC/bb_vk" "$CIRCUITS_DIR/"
  echo "  -> bb_vk/"
fi

# --- 4. Vendor zkMetal SDK ---
PROVER_DIR="$TAURI_DIR/resources/prover"
VENDOR_DIR="$PROVER_DIR/vendor/zkmetal"
mkdir -p "$VENDOR_DIR"

echo "[4/6] Vendoring zkMetal SDK..."
rsync -a --exclude node_modules --exclude .git --exclude target \
  "$ZKMETAL_DIR/prover/" "$VENDOR_DIR/"
echo "  -> vendor/zkmetal/"

# --- 5. Copy prover source ---
echo "[5/6] Copying prover source..."
mkdir -p "$PROVER_DIR/src"
cp "$REPO_ROOT/contracts/zk-noir/prover/src/prover.ts" "$PROVER_DIR/src/"
cp "$REPO_ROOT/contracts/zk-noir/prover/src/witness.ts" "$PROVER_DIR/src/"
cp "$REPO_ROOT/contracts/zk-noir/prover/src/sparse-merkle-tree.ts" "$PROVER_DIR/src/"

# Create package.json with vendored zkmetal path
cat > "$PROVER_DIR/package.json" << 'PKGJSON'
{
  "name": "persistia-noir-prover",
  "version": "0.1.0",
  "type": "module",
  "dependencies": {
    "zkmetal": "file:./vendor/zkmetal",
    "@aztec/bb.js": "4.1.2",
    "@noir-lang/noir_js": "1.0.0-beta.19",
    "@noir-lang/types": "1.0.0-beta.19",
    "@noir-lang/acvm_js": "1.0.0-beta.19",
    "tsx": "^4.21.0"
  }
}
PKGJSON

# Install dependencies
echo "  Installing prover dependencies..."
(cd "$PROVER_DIR" && npm install --production 2>&1 | tail -1)
echo "  -> prover/node_modules/"

# --- 6. Copy event generator ---
SCRIPTS_DIR="$TAURI_DIR/resources/scripts"
mkdir -p "$SCRIPTS_DIR"

echo "[6/6] Copying event generator..."
cp "$REPO_ROOT/scripts/generate-events.ts" "$SCRIPTS_DIR/"
echo "  -> scripts/generate-events.ts"

# --- Done ---
echo ""
echo "=== Bundle complete ==="
TOTAL_SIZE=$(du -sh "$TAURI_DIR/bin" "$TAURI_DIR/resources" 2>/dev/null | tail -1 | cut -f1)
echo "Total resource size: ~$TOTAL_SIZE"
echo ""
echo "Next steps:"
echo "  cd $DESKTOP_DIR && npm install && cargo tauri dev"
