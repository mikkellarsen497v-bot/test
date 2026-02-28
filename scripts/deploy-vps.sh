#!/usr/bin/env bash
# VPS deploy script — run from the server (e.g. in app directory or after git pull).
# Usage: ./scripts/deploy-vps.sh   or   bash scripts/deploy-vps.sh
set -e
cd "$(dirname "$0")/.."
echo "Installing dependencies..."
npm ci --omit=dev
echo "Restarting PM2 app..."
pm2 reload ecosystem.config.cjs --env production || pm2 start ecosystem.config.cjs --env production
pm2 save
echo "Done. Check: pm2 status"
