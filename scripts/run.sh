#!/usr/bin/env bash
# Start the API, seed the sample queue, and start the dashboard.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -d backend/.venv ]]; then
  python3 -m venv backend/.venv
fi
# shellcheck disable=SC1091
source backend/.venv/bin/activate
python -m pip install --upgrade pip
pip install -r backend/requirements.txt
if [[ ! -f .env ]]; then
  cp .env.example .env
fi

(
  cd backend
  python -m app.seed
  exec uvicorn app.main:app --host 127.0.0.1 --port 8741
) &
API_PID=$!
cleanup() {
  kill "$API_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cd "$ROOT/frontend"
if [[ ! -d node_modules ]]; then
  npm install
fi
npm run dev
