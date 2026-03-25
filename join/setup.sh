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

# 2. Clone the repo if not already in it
if [ ! -f "../src/index.ts" ]; then
  echo "Error: Run this script from the join/ directory inside the Persistia repo."
  echo "  git clone https://github.com/carni-ships/Persistia && cd Persistia/join && ./setup.sh"
  exit 1
fi

# 3. Install dependencies
echo "[1/5] Installing dependencies..."
cd ..
npm install
cd join

# 4. Check Cloudflare auth
echo "[2/5] Checking Cloudflare authentication..."
if ! npx wrangler whoami 2>/dev/null | grep -q "Account"; then
  echo ""
  echo "You need to log in to Cloudflare first."
  echo "Run: npx wrangler login"
  echo "Then re-run this script."
  exit 1
fi

# 5. Get the worker subdomain
echo "[3/5] Detecting your Cloudflare subdomain..."
SUBDOMAIN=$(npx wrangler whoami 2>/dev/null | grep -o '[a-zA-Z0-9_-]*\.workers\.dev' | head -1 || echo "")
if [ -z "$SUBDOMAIN" ]; then
  echo "Could not auto-detect subdomain. Enter your workers.dev subdomain:"
  echo "  (e.g., if your URL is https://foo.bar.workers.dev, enter 'bar')"
  read -r SUBDOMAIN
fi

NODE_URL="https://persistia-node.${SUBDOMAIN}"
echo "  Your node URL: $NODE_URL"

# 6. Update wrangler.toml with node URL
echo "[4/5] Configuring wrangler.toml..."
if grep -q "# NODE_URL" wrangler.toml; then
  # sed -i works differently on macOS vs Linux; use temp file for portability
  sed "s|# NODE_URL.*|NODE_URL = \"${NODE_URL}\"|" wrangler.toml > wrangler.toml.tmp
  mv wrangler.toml.tmp wrangler.toml
fi

# 7. Deploy
echo "[5/5] Deploying your Persistia node..."
cd ..
npx wrangler deploy -c join/wrangler.toml
cd join

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Node deployed! Joining network..."
echo "═══════════════════════════════════════════════════════"

# 8. Join the network
echo ""
echo "Registering with seed nodes..."
JOIN_RESULT=$(curl -s -X POST "${SEED_URL}/join" \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"${NODE_URL}\",\"shard\":\"global-world\"}")
echo "$JOIN_RESULT" | python3 -m json.tool 2>/dev/null || echo "$JOIN_RESULT"

# 9. Verify
echo ""
echo "Verifying node status..."
sleep 5
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
echo "  Your node will sync with the network automatically."
echo "  It may take a few rounds (12s each) to fully catch up."
echo "═══════════════════════════════════════════════════════"
