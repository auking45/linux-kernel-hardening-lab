#!/usr/bin/env bash
# Download and extract official Linux LTS kernel source

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"

mkdir -p "${DOWNLOADS_DIR}"

if [[ -d "${KERNEL_SRC_DIR}" ]]; then
    echo "[+] Kernel source already extracted at: ${KERNEL_SRC_DIR}"
    exit 0
fi

TARBALL_PATH="${DOWNLOADS_DIR}/${KERNEL_TARBALL}"

if [[ ! -f "${TARBALL_PATH}" ]]; then
    echo "[*] Downloading Linux LTS kernel ${KERNEL_VERSION} from ${KERNEL_URL}..."
    if command -v curl >/dev/null 2>&1; then
        curl -L --progress-bar -o "${TARBALL_PATH}" "${KERNEL_URL}"
    elif command -v wget >/dev/null 2>&1; then
        wget --show-progress -O "${TARBALL_PATH}" "${KERNEL_URL}"
    else
        echo "[-] Error: Neither curl nor wget found." >&2
        exit 1
    fi
    echo "[+] Download completed."
fi

echo "[*] Extracting ${TARBALL_PATH} into ${DOWNLOADS_DIR}..."
tar -xf "${TARBALL_PATH}" -C "${DOWNLOADS_DIR}"
echo "[+] Extraction completed: ${KERNEL_SRC_DIR}"

