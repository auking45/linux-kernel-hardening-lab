#!/usr/bin/env bash
# Build Linux kernel for x86_64 and arm64 with optional hardening feature fragments

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"

TARGET_ARCH="x86_64"
FEATURE_NAME="base"
BUILD_JOBS="$(nproc)"
CLEAN_BUILD=0

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --arch <x86_64|arm64>      Target architecture (default: x86_64)"
    echo "  --feature <feature_name>   Hardening feature fragment from configs/features/ (default: base)"
    echo "  --jobs <N>                 Parallel make jobs (default: $(nproc))"
    echo "  --clean                    Clean build output directory before compiling"
    echo "  -h, --help                 Show this help message"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            TARGET_ARCH="$2"
            shift 2
            ;;
        --feature)
            FEATURE_NAME="$2"
            shift 2
            ;;
        --jobs)
            BUILD_JOBS="$2"
            shift 2
            ;;
        --clean)
            CLEAN_BUILD=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "[-] Error: Unknown argument '$1'" >&2
            usage
            ;;
    esac
done

setup_arch_env "${TARGET_ARCH}"

# Ensure kernel source is available
if [[ ! -d "${KERNEL_SRC_DIR}" ]]; then
    echo "[*] Kernel source not found. Triggering automated download..."
    "${SCRIPT_DIR}/download_kernel.sh"
fi

# Define build output directory for this arch and feature
TARGET_BUILD_DIR="${BUILD_DIR}/${TARGET_ARCH}-${FEATURE_NAME}"
mkdir -p "${TARGET_BUILD_DIR}"

if [[ "${CLEAN_BUILD}" -eq 1 ]]; then
    echo "[*] Cleaning build directory: ${TARGET_BUILD_DIR}"
    rm -rf "${TARGET_BUILD_DIR}"/*
fi

echo "========================================================="
echo "  Building Linux Kernel (${KERNEL_VERSION})"
echo "  Architecture:  ${TARGET_ARCH}"
echo "  Feature:       ${FEATURE_NAME}"
echo "  Build Dir:     ${TARGET_BUILD_DIR}"
echo "  Compiler:      ${CROSS_COMPILE}gcc"
echo "  Parallel Jobs: ${BUILD_JOBS}"
echo "========================================================="

BASE_CONFIG="${CONFIGS_DIR}/base/${TARGET_ARCH}_defconfig"
if [[ ! -f "${BASE_CONFIG}" ]]; then
    echo "[-] Error: Base defconfig not found at ${BASE_CONFIG}" >&2
    exit 1
fi

FEATURE_CONFIG="${CONFIGS_DIR}/features/${FEATURE_NAME}.config"

# Prepare .config
if [[ "${FEATURE_NAME}" == "base" || ! -f "${FEATURE_CONFIG}" ]]; then
    echo "[*] Applying base defconfig: ${BASE_CONFIG}"
    cp "${BASE_CONFIG}" "${TARGET_BUILD_DIR}/.config"
    make -C "${KERNEL_SRC_DIR}" O="${TARGET_BUILD_DIR}" ARCH="${KERNEL_ARCH}" CROSS_COMPILE="${CROSS_COMPILE}" olddefconfig
else
    echo "[*] Merging base defconfig with feature fragment: ${FEATURE_CONFIG}"
    "${KERNEL_SRC_DIR}/scripts/kconfig/merge_config.sh" \
        -m -O "${TARGET_BUILD_DIR}" \
        "${BASE_CONFIG}" \
        "${FEATURE_CONFIG}"
    make -C "${KERNEL_SRC_DIR}" O="${TARGET_BUILD_DIR}" ARCH="${KERNEL_ARCH}" CROSS_COMPILE="${CROSS_COMPILE}" olddefconfig
fi

# Compile kernel binary
echo "[*] Starting kernel compilation..."
make -C "${KERNEL_SRC_DIR}" \
    O="${TARGET_BUILD_DIR}" \
    ARCH="${KERNEL_ARCH}" \
    CROSS_COMPILE="${CROSS_COMPILE}" \
    -j"${BUILD_JOBS}"

KERNEL_IMAGE="${TARGET_BUILD_DIR}/${KERNEL_IMAGE_REL}"

if [[ -f "${KERNEL_IMAGE}" ]]; then
    echo ""
    echo "[+] Kernel build successful!"
    echo "    Output binary: ${KERNEL_IMAGE}"
    ls -lh "${KERNEL_IMAGE}"
else
    echo "[-] Error: Expected kernel image not found at ${KERNEL_IMAGE}" >&2
    exit 1
fi
