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
echo "[1/6] Installing dependencies..."
cd ..
npm install
cd join

# 4. Check Cloudflare auth
echo "[2/6] Checking Cloudflare authentication..."
if ! npx wrangler whoami 2>/dev/null | grep -q "Account"; then
  echo ""
  echo "You need to log in to Cloudflare first."
  echo "Run: npx wrangler login"
  echo "Then re-run this script."
  exit 1
fi

# 5. Get the worker subdomain
echo "[3/6] Detecting your Cloudflare subdomain..."
SUBDOMAIN=$(npx wrangler whoami 2>/dev/null | grep -o '[a-zA-Z0-9_-]*\.workers\.dev' | head -1 || echo "")
if [ -z "$SUBDOMAIN" ]; then
  echo "Could not auto-detect subdomain. Enter your workers.dev subdomain:"
  echo "  (e.g., if your URL is https://foo.bar.workers.dev, enter 'bar')"
  read -r SUBDOMAIN
fi

NODE_URL="https://persistia-node.${SUBDOMAIN}"
echo "  Your node URL: $NODE_URL"

# 6. Update wrangler.toml with node URL
echo "[4/6] Configuring wrangler.toml..."
if grep -q "# NODE_URL" wrangler.toml; then
  sed "s|# NODE_URL.*|NODE_URL = \"${NODE_URL}\"|" wrangler.toml > wrangler.toml.tmp
  mv wrangler.toml.tmp wrangler.toml
fi

# 7. Deploy
echo "[5/6] Deploying your Persistia node..."
cd ..
npx wrangler deploy -c join/wrangler.toml
cd join

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Node deployed! Joining network..."
echo "═══════════════════════════════════════════════════════"

# 8. Wait for node to initialize
echo ""
echo "Waiting for node to initialize..."
sleep 5

# 9. Get the node's identity (pubkey) for registration
echo "[6/6] Registering with the network..."
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

# 10. Verify
echo ""
echo "Verifying node status..."
sleep 3
STATUS=$(curl -s "${NODE_URL}/dag/status")
echo "$STATUS" | python3 -m json.tool 2>/dev/null || echo "$STATUS"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Setup complete!"
echo ""
echo "  Node URL:     $NODE_URL"
echo "  Dashboard:    $NODE_URL/dashboard"
echo "  Game:         $NODE_URL/"
echo ""
echo "  Your node will sync the existing chain state from seeds."
echo "  It may take several minutes to fully catch up."
echo ""
echo "  Once synced, your node will participate in consensus"
echo "  by creating and gossiping DAG vertices each round."
echo "═══════════════════════════════════════════════════════"
