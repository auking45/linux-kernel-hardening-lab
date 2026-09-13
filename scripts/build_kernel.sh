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

parse_args() {
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
}

check_kernel_source() {
    if [[ ! -d "${KERNEL_SRC_DIR}" ]]; then
        echo "[*] Kernel source not found. Triggering automated download..."
        "${SCRIPT_DIR}/download_kernel.sh"
    fi
}

prepare_build_dir() {
    local target_build_dir="$1"
    mkdir -p "${target_build_dir}"

    if [[ "${CLEAN_BUILD}" -eq 1 ]]; then
        echo "[*] Cleaning build directory: ${target_build_dir}"
        rm -rf "${target_build_dir:?}"/*
    fi
}

configure_kernel() {
    local target_build_dir="$1"
    local base_config="${CONFIGS_DIR}/base/${TARGET_ARCH}_defconfig"

    if [[ ! -f "${base_config}" ]]; then
        echo "[-] Error: Base defconfig not found at ${base_config}" >&2
        exit 1
    fi

    local feature_config="${CONFIGS_DIR}/features/${FEATURE_NAME}.config"

    if [[ "${FEATURE_NAME}" == "base" || ! -f "${feature_config}" ]]; then
        echo "[*] Applying base defconfig: ${base_config}"
        cp "${base_config}" "${target_build_dir}/.config"
        make -C "${KERNEL_SRC_DIR}" \
            O="${target_build_dir}" \
            ARCH="${KERNEL_ARCH}" \
            CROSS_COMPILE="${CROSS_COMPILE}" \
            HOSTCC="${HOSTCC}" \
            olddefconfig
    else
        echo "[*] Merging base defconfig with feature fragment: ${feature_config}"
        "${KERNEL_SRC_DIR}/scripts/kconfig/merge_config.sh" \
            -m -O "${target_build_dir}" \
            "${base_config}" \
            "${feature_config}"
        make -C "${KERNEL_SRC_DIR}" \
            O="${target_build_dir}" \
            ARCH="${KERNEL_ARCH}" \
            CROSS_COMPILE="${CROSS_COMPILE}" \
            HOSTCC="${HOSTCC}" \
            olddefconfig
    fi
}

compile_kernel() {
    local target_build_dir="$1"

    echo "========================================================="
    echo "  Building Linux Kernel (${KERNEL_VERSION})"
    echo "  Architecture:  ${TARGET_ARCH}"
    echo "  Feature:       ${FEATURE_NAME}"
    echo "  Build Dir:     ${target_build_dir}"
    echo "  Compiler:      ${CROSS_COMPILE}gcc"
    echo "  Parallel Jobs: ${BUILD_JOBS}"
    echo "========================================================="

    echo "[*] Starting kernel compilation..."
    make -C "${KERNEL_SRC_DIR}" \
        O="${target_build_dir}" \
        ARCH="${KERNEL_ARCH}" \
        CROSS_COMPILE="${CROSS_COMPILE}" \
        HOSTCC="${HOSTCC}" \
        -j"${BUILD_JOBS}"
}

verify_output() {
    local kernel_image="$1"

    if [[ -f "${kernel_image}" ]]; then
        echo ""
        echo "[+] Kernel build successful!"
        echo "    Output binary: ${kernel_image}"
        ls -lh "${kernel_image}"
    else
        echo "[-] Error: Expected kernel image not found at ${kernel_image}" >&2
        exit 1
    fi
}

main() {
    parse_args "$@"
    setup_arch_env "${TARGET_ARCH}"
    check_kernel_source

    local target_build_dir="${BUILD_DIR}/${TARGET_ARCH}-${FEATURE_NAME}"
    local kernel_image="${target_build_dir}/${KERNEL_IMAGE_REL}"

    prepare_build_dir "${target_build_dir}"
    configure_kernel "${target_build_dir}"
    compile_kernel "${target_build_dir}"
    verify_output "${kernel_image}"
}

main "$@"
