#!/usr/bin/env bash
set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$POC_DIR"

# Disable telemetry to avoid sandbox/permission errors
export ASTRO_TELEMETRY_DISABLED=1

# Load nvm or fnm if installed in user home
if [ -s "$HOME/.nvm/nvm.sh" ]; then
    # shellcheck disable=SC1090
    source "$HOME/.nvm/nvm.sh"
fi
export PATH="$HOME/.local/share/fnm:$HOME/.fnm:$HOME/.bun/bin:$HOME/.local/bin:$PATH"

if ! command -v npm >/dev/null 2>&1; then
    echo "=================================================================="
    echo " [!] Node.js (npm)가 감지되지 않음."
    echo "     Ubuntu/Debian 환경에서는 아래 명령으로 즉시 설치 가능함:"
    echo "     sudo apt-get update && sudo apt-get install -y nodejs npm"
    echo "=================================================================="
    exit 1
fi

if [ ! -d "node_modules" ]; then
    echo "[*] Installing Astro Starlight dependencies..."
    npm install
fi

echo "[*] Synchronizing docs/ with Astro Starlight content directory..."
python3 ../scripts/sync_docs_to_starlight.py

echo "=================================================================="
echo " [*] Launching Astro Starlight on http://localhost:4321"
echo "     (MkDocs http://127.0.0.1:8000 과 동시에 띄워 비교 가능함)"
echo "=================================================================="
if [ "${1:-}" = "build" ]; then
    npm run build
else
    npm run dev
fi


