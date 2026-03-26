#!/bin/bash
# ─── Deploy Persistia Seed Node ──────────────────────────────────────────────
# Creates required Cloudflare resources and deploys the seed worker.
#
# Usage:
#   chmod +x scripts/deploy.sh
#   ./scripts/deploy.sh
# ─────────────────────────────────────────────────────────────────────────────

set -e

echo "═══════════════════════════════════════════════════════"
echo "  Persistia Seed Node Deploy"
echo "═══════════════════════════════════════════════════════"
echo ""

# 1. Check auth
echo "[1/4] Checking Cloudflare authentication..."
if ! npx wrangler whoami 2>/dev/null | grep -q "Account"; then
  echo "Run: npx wrangler login"
  exit 1
fi

# 2. Create R2 bucket
echo "[2/4] Ensuring R2 bucket exists..."
BUCKET_NAME="persistia-blobs"
if npx wrangler r2 bucket create "$BUCKET_NAME" 2>/dev/null; then
  echo "  ✓ Created R2 bucket '$BUCKET_NAME'"
elif npx wrangler r2 bucket list 2>/dev/null | grep -q "$BUCKET_NAME"; then
  echo "  ✓ R2 bucket '$BUCKET_NAME' already exists"
else
  echo ""
  echo "  R2 Object Storage is not enabled on your account."
  echo "  Enable it (free): https://dash.cloudflare.com → R2 Object Storage → Get Started"
  echo ""
  read -r -p "  Press Enter after enabling R2, or type 'skip': " R2_RESPONSE
  if [ "$R2_RESPONSE" != "skip" ]; then
    if npx wrangler r2 bucket create "$BUCKET_NAME" 2>/dev/null; then
      echo "  ✓ Created R2 bucket '$BUCKET_NAME'"
    else
      echo "  ⚠ R2 still not available — deploying without snapshots"
    fi
  fi
fi

# 3. Create Queue
echo "[3/4] Ensuring relay queue exists..."
QUEUE_NAME="persistia-relay"
if npx wrangler queues create "$QUEUE_NAME" 2>/dev/null; then
  echo "  ✓ Created queue '$QUEUE_NAME'"
elif npx wrangler queues list 2>/dev/null | grep -q "$QUEUE_NAME"; then
  echo "  ✓ Queue '$QUEUE_NAME' already exists"
else
  echo "  ⚠ Could not create queue (deploying without async relay)"
fi

# 4. Deploy
echo "[4/4] Deploying worker..."
npx wrangler deploy

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Deploy complete!"
echo "═══════════════════════════════════════════════════════"
