#!/bin/bash
# ─── Persistia Node Setup ─────────────────────────────────────────────────────
# Run this script to join the Persistia network as a validator node.
#
# Prerequisites:
#   - Node.js 18+
#   - npm
#   - Cloudflare account (free tier works)
#
# Usage:
#   cd join/
#   chmod +x setup.sh
#   ./setup.sh
# ──────────────────────────────────────────────────────────────────────────────

set -e

SEED_URL="https://persistia.carnation-903.workers.dev"
WORKER_NAME="persistia-node"

echo "═══════════════════════════════════════════════════════"
echo "  Persistia Node Setup"
echo "═══════════════════════════════════════════════════════"
echo ""

# 1. Check prerequisites
command -v node >/dev/null 2>&1 || { echo "Error: Node.js required. Install from https://nodejs.org"; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "Error: npm required."; exit 1; }

# 2. Must be in the join/ directory inside the repo
if [ ! -f "../src/index.ts" ]; then
  echo "Error: Run this script from the join/ directory inside the Persistia repo."
  echo "  git clone https://github.com/carni-ships/Persistia && cd Persistia/join && ./setup.sh"
  exit 1
fi

# 3. Install dependencies
echo "[1/8] Installing dependencies..."
cd ..
npm install
cd join

# 4. Check Cloudflare auth
echo "[2/8] Checking Cloudflare authentication..."
if ! npx wrangler whoami 2>/dev/null | grep -q "Account"; then
  echo ""
  echo "You need to log in to Cloudflare first."
  echo "Run: npx wrangler login"
  echo "Then re-run this script."
  exit 1
fi

# 5. Get the worker subdomain
echo "[3/8] Detecting your Cloudflare subdomain..."
SUBDOMAIN=$(npx wrangler whoami 2>/dev/null | grep -o '[a-zA-Z0-9_-]*\.workers\.dev' | head -1 || echo "")
if [ -z "$SUBDOMAIN" ]; then
  echo "Could not auto-detect subdomain. Enter your workers.dev subdomain:"
  echo "  (e.g., if your URL is https://foo.bar.workers.dev, enter 'bar')"
  read -r SUBDOMAIN
fi

NODE_URL="https://${WORKER_NAME}.${SUBDOMAIN}"
echo "  Your node URL: $NODE_URL"

# 6. Create Cloudflare resources (R2 bucket + optional queue)
echo "[4/8] Creating Cloudflare resources..."

# R2 bucket for snapshots + WASM blobs (enables fast sync)
BUCKET_NAME="${WORKER_NAME}-blobs"
R2_ENABLED=false
if npx wrangler r2 bucket create "$BUCKET_NAME" 2>/dev/null; then
  echo "  ✓ R2 bucket '$BUCKET_NAME' created"
  R2_ENABLED=true
else
  # Check if bucket already exists
  if npx wrangler r2 bucket list 2>/dev/null | grep -q "$BUCKET_NAME"; then
    echo "  ✓ R2 bucket '$BUCKET_NAME' already exists"
    R2_ENABLED=true
  else
    echo "  ⚠ R2 not enabled on your account (optional — node works without it)"
    echo "    To enable: Cloudflare Dashboard → R2 Object Storage → Get Started"
    echo "    R2 enables snapshot-based fast sync and offloads WASM/proof storage"
  fi
fi

# 7. Update wrangler.toml with node URL and R2 config
echo "[5/8] Configuring wrangler.toml..."

# Start with a fresh config from template
cat > wrangler.toml << TOML
name = "${WORKER_NAME}"
main = "../src/index.ts"
compatibility_date = "2026-03-01"
compatibility_flags = ["nodejs_compat"]

# ─── Static Assets (HTML served from CDN edge) ────────────────────────
[assets]
directory = "../public"
binding = "ASSETS"

[[durable_objects.bindings]]
name = "PERSISTIA_WORLD"
class_name = "PersistiaWorldV4"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["PersistiaWorldV4"]
TOML

# Add R2 if available
if [ "$R2_ENABLED" = true ]; then
  cat >> wrangler.toml << TOML

# ─── R2 Object Storage (WASM blobs + state snapshots) ────────────────
[[r2_buckets]]
binding = "BLOB_STORE"
bucket_name = "${BUCKET_NAME}"
TOML
  echo "  ✓ R2 blob storage configured"
fi

# Add vars
cat >> wrangler.toml << TOML

# ─── Node Configuration ──────────────────────────────────────────────
[vars]
NODE_URL = "${NODE_URL}"
SEED_NODES = "https://persistia.carnation-903.workers.dev/?shard=node-1,https://persistia.carnation-903.workers.dev/?shard=node-2,https://persistia.carnation-903.workers.dev/?shard=node-3"
TOML

echo "  ✓ wrangler.toml configured"

# 8. Deploy
echo "[6/8] Deploying your Persistia node..."
cd ..
npx wrangler deploy -c join/wrangler.toml
cd join

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Node deployed! Joining network..."
echo "═══════════════════════════════════════════════════════"

# 9. Wait for node to initialize
echo ""
echo "Waiting for node to initialize..."
sleep 5

# 10. Get the node's identity (pubkey) for registration
echo "[7/8] Registering with the network..."
NODE_INFO=$(curl -s "${NODE_URL}/dag/status" 2>/dev/null)
NODE_PUBKEY=$(echo "$NODE_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('node_pubkey',''))" 2>/dev/null || echo "")

if [ -z "$NODE_PUBKEY" ]; then
  echo "Warning: Could not fetch node pubkey from $NODE_URL/dag/status"
  echo "Node may still be initializing. Registering as peer only..."

  JOIN_RESULT=$(curl -s -X POST "${SEED_URL}/join" \
    -H "Content-Type: application/json" \
    -d "{\"url\":\"${NODE_URL}\"}")
  echo "$JOIN_RESULT" | python3 -m json.tool 2>/dev/null || echo "$JOIN_RESULT"
else
  echo "  Node pubkey: ${NODE_PUBKEY:0:16}..."

  # Get PoW difficulty from seed
  echo "  Fetching PoW requirements..."
  POW_INFO=$(curl -s "${SEED_URL}/validator/registration-info?shard=node-1" 2>/dev/null)
  echo "  $POW_INFO"

  # Join as peer (validator registration requires PoW — done separately)
  JOIN_RESULT=$(curl -s -X POST "${SEED_URL}/join" \
    -H "Content-Type: application/json" \
    -d "{\"url\":\"${NODE_URL}\",\"pubkey\":\"${NODE_PUBKEY}\"}")
  echo "$JOIN_RESULT" | python3 -m json.tool 2>/dev/null || echo "$JOIN_RESULT"

  echo ""
  echo "  To register as a validator, you need to solve a Proof-of-Work."
  echo "  Run this from your node:"
  echo ""
  echo "    curl -X POST ${NODE_URL}/validator/register \\"
  echo "      -H 'Content-Type: application/json' \\"
  echo "      -d '{\"pubkey\":\"${NODE_PUBKEY}\",\"url\":\"${NODE_URL}\",\"pow_nonce\":\"<nonce>\",\"signature\":\"<sig>\"}'"
  echo ""
  echo "  Then re-register on the seed with the same PoW:"
  echo ""
  echo "    curl -X POST ${SEED_URL}/join \\"
  echo "      -H 'Content-Type: application/json' \\"
  echo "      -d '{\"url\":\"${NODE_URL}\",\"pubkey\":\"${NODE_PUBKEY}\",\"pow_nonce\":\"<nonce>\",\"signature\":\"<sig>\"}'"
fi

# 11. Verify
echo ""
echo "[8/8] Verifying node status..."
sleep 3
STATUS=$(curl -s "${NODE_URL}/dag/status")
echo "$STATUS" | python3 -m json.tool 2>/dev/null || echo "$STATUS"

# Check if snapshot bootstrap will happen
if [ "$R2_ENABLED" = true ]; then
  SNAP_CHECK=$(curl -s "${SEED_URL}/snapshot/latest?shard=node-1" 2>/dev/null)
  SNAP_SEQ=$(echo "$SNAP_CHECK" | python3 -c "import sys,json; print(json.load(sys.stdin).get('finalized_seq',0))" 2>/dev/null || echo "0")
  if [ "$SNAP_SEQ" -gt 0 ] 2>/dev/null; then
    echo ""
    echo "  ⚡ Snapshot available (seq=$SNAP_SEQ) — your node will fast-sync!"
  fi
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Setup complete!"
echo ""
echo "  Node URL:     $NODE_URL"
echo "  Dashboard:    $NODE_URL/dashboard"
echo "  Game:         $NODE_URL/"
if [ "$R2_ENABLED" = true ]; then
  echo "  R2 Storage:   $BUCKET_NAME (snapshots + WASM blobs)"
fi
echo ""
echo "  Your node will sync from seeds automatically."
if [ "$R2_ENABLED" = true ]; then
  echo "  With R2 enabled, it will use snapshot-based fast sync"
  echo "  instead of replaying every event from genesis."
else
  echo "  Enable R2 in Cloudflare Dashboard for faster sync via snapshots."
fi
echo ""
echo "  Once synced, your node will participate in consensus"
echo "  by creating and gossiping DAG vertices each round."
echo "═══════════════════════════════════════════════════════"
