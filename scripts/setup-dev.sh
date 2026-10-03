#!/usr/bin/env bash
# CYBERSPLOI Development Environment Setup (Linux/macOS)
# Usage: bash scripts/setup-dev.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "==> CYBERSPLOI Dev Setup"
echo "    Root: $ROOT"

echo ""
echo "[1/5] Locating Python..."
PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)
if [[ -z "$PYTHON" ]]; then
  echo "ERROR: Python 3 not found. Install Python 3.10+ and rerun." >&2
  exit 1
fi
echo "    Using: $PYTHON  ($($PYTHON --version))"

echo ""
echo "[2/5] Setting up Python virtual environment..."
VENV="$ROOT/.venv"
if [[ ! -f "$VENV/bin/python" ]]; then
  "$PYTHON" -m venv "$VENV"
fi
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r "$ROOT/ai-engine/requirements.txt"
echo "    Python venv ready."

echo ""
echo "[3/5] Checking Node.js..."
if ! command -v node &>/dev/null; then
  echo "ERROR: Node.js not found. Install Node 18 LTS and rerun." >&2
  exit 1
fi
echo "    Node: $(node --version)  npm: $(npm --version)"

echo ""
echo "[4/5] Installing npm dependencies..."
echo "    backend/..."
(cd "$ROOT/backend"  && npm install --prefer-offline --no-fund --no-audit --silent)
echo "    frontend/..."
(cd "$ROOT/frontend" && npm install --prefer-offline --no-fund --no-audit --silent)

echo ""
echo "[5/5] Generating Prisma client..."
(cd "$ROOT/backend" && npx prisma generate)

echo ""
echo "==> Setup complete."
echo "   Start services:"
echo "     API:      cd backend  && npm run dev"
echo "     AI:       $VENV/bin/uvicorn main:app --app-dir ai-engine --port 8001 --reload"
echo "     Frontend: cd frontend && npm run dev"
echo "   Or use Docker: docker compose up --build"
