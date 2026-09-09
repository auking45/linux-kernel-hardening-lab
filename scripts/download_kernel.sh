#!/usr/bin/env bash
# Download and extract official Linux LTS kernel source

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"

download_tarball() {
    local tarball_path="$1"
    local kernel_url="$2"

    echo "[*] Downloading Linux LTS kernel ${KERNEL_VERSION} from ${kernel_url}..."
    if command -v curl >/dev/null 2>&1; then
        curl -L --progress-bar -o "${tarball_path}" "${kernel_url}"
    elif command -v wget >/dev/null 2>&1; then
        wget --show-progress -O "${tarball_path}" "${kernel_url}"
    else
        echo "[-] Error: Neither curl nor wget found on host." >&2
        exit 1
    fi
    echo "[+] Download completed."
}

extract_tarball() {
    local tarball_path="$1"
    local dest_dir="$2"

    echo "[*] Extracting ${tarball_path} into ${dest_dir}..."
    tar -xf "${tarball_path}" -C "${dest_dir}"
    echo "[+] Extraction completed: ${KERNEL_SRC_DIR}"
}

main() {
    mkdir -p "${DOWNLOADS_DIR}"

    if [[ -d "${KERNEL_SRC_DIR}" ]]; then
        echo "[+] Kernel source already extracted at: ${KERNEL_SRC_DIR}"
        exit 0
    fi

    local tarball_path="${DOWNLOADS_DIR}/${KERNEL_TARBALL}"

    if [[ ! -f "${tarball_path}" ]]; then
        download_tarball "${tarball_path}" "${KERNEL_URL}"
    fi

    extract_tarball "${tarball_path}" "${DOWNLOADS_DIR}"
}

main "$@"
