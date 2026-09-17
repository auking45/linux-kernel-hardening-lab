#!/usr/bin/env bash
# End-to-End One-Click Automation Runner for Linux Kernel Hardening Lab
# Checks dependencies, downloads kernel, builds rootfs & kernel, and launches QEMU.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"

TARGET_ARCH="x86_64"
FEATURE_NAME="base"
BUILD_ONLY=0
REBUILD=0
AUTO_TEST=""
EXTRA_CMDLINE=""
USE_KVM=1
TIMEOUT_SEC=0

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "One-click runner that prepares everything and boots into QEMU."
    echo ""
    echo "Options:"
    echo "  --arch <x86_64|arm64>      Target architecture (default: x86_64)"
    echo "  --feature <name>           Hardening feature from configs/features/ (default: base)"
    echo "  --build-only               Compile components without launching QEMU"
    echo "  --rebuild                  Force recompilation of the kernel"
    echo "  --test <script_name>       Run automated in-guest test script and poweroff"
    echo "  --cmdline <string>         Extra kernel boot command-line arguments"
    echo "  --no-kvm                   Disable KVM acceleration (force TCG emulation)"
    echo "  --timeout <seconds>        Kill QEMU after specified seconds"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                      # Boot x86_64 baseline kernel in QEMU"
    echo "  $0 --arch arm64                         # Boot ARM64 baseline kernel in QEMU"
    echo "  $0 --feature stack-protector            # Build & run stack-protector hardened kernel"
    echo "  $0 --feature stack-protector-disabled   # Build & run vulnerable baseline kernel"
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
            --build-only)
                BUILD_ONLY=1
                shift
                ;;
            --rebuild)
                REBUILD=1
                shift
                ;;
            --test)
                AUTO_TEST="$2"
                shift 2
                ;;
            --cmdline)
                EXTRA_CMDLINE="$2"
                shift 2
                ;;
            --no-kvm)
                USE_KVM=0
                shift
                ;;
            --timeout)
                TIMEOUT_SEC="$2"
                shift 2
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

check_host_prerequisites() {
    echo "[1/5] Checking host prerequisites..."
    local missing_tools=()

    for tool in make python3 tar gzip cpio; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            missing_tools+=("${tool}")
        fi
    done

    if ! command -v "${QEMU_BIN}" >/dev/null 2>&1; then
        missing_tools+=("${QEMU_BIN}")
    fi

    if [[ -n "${CROSS_COMPILE}" ]]; then
        if ! command -v "${CROSS_COMPILE}gcc" >/dev/null 2>&1; then
            missing_tools+=("${CROSS_COMPILE}gcc")
        fi
    else
        if ! command -v gcc >/dev/null 2>&1 && ! command -v x86_64-linux-gnu-gcc >/dev/null 2>&1; then
            missing_tools+=("gcc")
        fi
    fi

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo "[-] Error: Missing required host tools: ${missing_tools[*]}" >&2
        echo "    Run: sudo apt-get install build-essential qemu-system-x86 qemu-system-arm gcc-aarch64-linux-gnu" >&2
        exit 1
    fi
    echo "[+] All prerequisite tools verified."
}

ensure_kernel_source() {
    echo "[2/5] Ensuring kernel source code..."
    if [[ ! -d "${KERNEL_SRC_DIR}" ]]; then
        "${SCRIPT_DIR}/download_kernel.sh"
    else
        echo "[+] Kernel source ready at: ${KERNEL_SRC_DIR}"
    fi
}

ensure_rootfs() {
    echo "[3/5] Ensuring initramfs rootfs for ${TARGET_ARCH}..."
    local rootfs_archive="${ROOTFS_DIR}/initramfs-${TARGET_ARCH}.cpio.gz"
    local needs_rebuild=0

    if [[ ! -f "${rootfs_archive}" || "${REBUILD}" -eq 1 ]]; then
        needs_rebuild=1
    else
        # Check freshness against build scripts and lab files
        if [[ "${SCRIPT_DIR}/build_rootfs.sh" -nt "${rootfs_archive}" ]] || \
           [[ "${SCRIPT_DIR}/env.sh" -nt "${rootfs_archive}" ]]; then
            echo "[*] Rootfs build scripts modified. Triggering rootfs rebuild..."
            needs_rebuild=1
        else
            for src in "${LAB_ROOT_DIR}/labs"/*/*; do
                if [[ -f "${src}" && "${src}" -nt "${rootfs_archive}" ]]; then
                    echo "[*] Detected updated lab component ($(basename "${src}")). Triggering rootfs rebuild..."
                    needs_rebuild=1
                    break
                fi
            done
        fi
    fi

    # Verify requested test script exists in the cpio archive if --test is specified
    if [[ "${needs_rebuild}" -eq 0 && -n "${AUTO_TEST}" ]]; then
        if ! zcat "${rootfs_archive}" 2>/dev/null | cpio -t 2>/dev/null | grep -q "bin/${AUTO_TEST}$"; then
            echo "[-] Warning: Requested test '${AUTO_TEST}' missing from current initramfs. Rebuilding..."
            needs_rebuild=1
        fi
    fi

    if [[ "${needs_rebuild}" -eq 1 ]]; then
        "${SCRIPT_DIR}/build_rootfs.sh" --arch "${TARGET_ARCH}" --force
    else
        echo "[+] Initramfs ready at: ${rootfs_archive}"
    fi
}

ensure_kernel_binary() {
    echo "[4/5] Ensuring kernel binary for ${TARGET_ARCH} (feature: ${FEATURE_NAME})..."
    local target_build_dir="${BUILD_DIR}/${TARGET_ARCH}-${FEATURE_NAME}"
    local kernel_image="${target_build_dir}/${KERNEL_IMAGE_REL}"

    local needs_kernel_rebuild=0
    if [[ ! -f "${kernel_image}" || "${REBUILD}" -eq 1 ]]; then
        needs_kernel_rebuild=1
    else
        for vuln in "${LAB_ROOT_DIR}/labs"/*/*vuln*.c; do
            if [[ -f "${vuln}" && "${vuln}" -nt "${kernel_image}" ]]; then
                echo "[*] Detected updated kernel lab driver ($(basename "${vuln}")). Triggering incremental kernel build..."
                needs_kernel_rebuild=1
                break
            fi
        done
    fi

    if [[ "${needs_kernel_rebuild}" -eq 1 ]]; then
        local build_args=("--arch" "${TARGET_ARCH}" "--feature" "${FEATURE_NAME}")
        if [[ "${REBUILD}" -eq 1 ]]; then
            build_args+=("--clean")
        fi
        "${SCRIPT_DIR}/build_kernel.sh" "${build_args[@]}"
    else
        echo "[+] Kernel binary ready at: ${kernel_image}"
    fi
}

launch_virtual_machine() {
    echo "[5/5] Launching QEMU virtual machine..."
    local target_build_dir="${BUILD_DIR}/${TARGET_ARCH}-${FEATURE_NAME}"
    local kernel_image="${target_build_dir}/${KERNEL_IMAGE_REL}"

    local qemu_args=("--arch" "${TARGET_ARCH}" "--kernel" "${kernel_image}")
    if [[ -n "${AUTO_TEST}" ]]; then
        qemu_args+=("--test" "${AUTO_TEST}")
    fi
    if [[ -n "${EXTRA_CMDLINE}" ]]; then
        qemu_args+=("--cmdline" "${EXTRA_CMDLINE}")
    fi
    if [[ "${USE_KVM}" -eq 0 ]]; then
        qemu_args+=("--no-kvm")
    fi
    if [[ "${FEATURE_NAME}" == "randomize-memory-disabled" && "${TARGET_ARCH}" == "arm64" ]]; then
        # ARM64 ties linear mapping randomization directly to KASLR, so baseline requires nokaslr
        :
    elif [[ "${FEATURE_NAME}" == "kaslr" ]] || [[ "${FEATURE_NAME}" == "fgkaslr"* ]] || [[ "${FEATURE_NAME}" == "randomize-memory"* ]] || [[ "${ENABLE_KASLR:-0}" -eq 1 ]]; then
        qemu_args+=("--kaslr")
    fi
    if [[ "${FEATURE_NAME}" == "fgkaslr" ]]; then
        qemu_args+=("--cmdline" "fgkaslr=1")
    elif [[ "${FEATURE_NAME}" == "fgkaslr-disabled" ]]; then
        qemu_args+=("--cmdline" "fgkaslr=0")
    elif [[ "${FEATURE_NAME}" == "strict-rwx" ]]; then
        qemu_args+=("--cmdline" "rodata=on")
    elif [[ "${FEATURE_NAME}" == "strict-rwx-disabled" ]]; then
        qemu_args+=("--cmdline" "rodata=off")
    elif [[ "${FEATURE_NAME}" == "smep-pxn" ]]; then
        qemu_args+=("--cmdline" "smep=on pxn=on")
    elif [[ "${FEATURE_NAME}" == "smep-pxn-disabled" ]]; then
        qemu_args+=("--cmdline" "clearcpuid=smep pxn=off")
    elif [[ "${FEATURE_NAME}" == "smap-pan" ]]; then
        qemu_args+=("--cmdline" "smap=on pan=on")
    elif [[ "${FEATURE_NAME}" == "smap-pan-disabled" ]]; then
        qemu_args+=("--cmdline" "clearcpuid=smap pan=off nosmap")
    elif [[ "${FEATURE_NAME}" == "page-table-check" ]]; then
        qemu_args+=("--cmdline" "page_table_check=on")
    elif [[ "${FEATURE_NAME}" == "page-table-check-disabled" ]]; then
        qemu_args+=("--cmdline" "page_table_check=off")
    elif [[ "${FEATURE_NAME}" == "kpti" ]]; then
        if [[ "${TARGET_ARCH}" == "x86_64" ]]; then
            qemu_args+=("--cmdline" "pti=on")
        else
            qemu_args+=("--cmdline" "kpti=on")
        fi
    elif [[ "${FEATURE_NAME}" == "kpti-disabled" ]]; then
        if [[ "${TARGET_ARCH}" == "x86_64" ]]; then
            qemu_args+=("--cmdline" "pti=off nopti")
        else
            qemu_args+=("--cmdline" "kpti=off")
        fi
    fi
    if [[ "${TIMEOUT_SEC}" -gt 0 ]]; then
        qemu_args+=("--timeout" "${TIMEOUT_SEC}")
    fi

    "${SCRIPT_DIR}/run_qemu.sh" "${qemu_args[@]}"
}

main() {
    parse_args "$@"
    setup_arch_env "${TARGET_ARCH}"

    echo "========================================================="
    echo "  Linux Kernel Hardening Lab - All-in-One Orchestrator"
    echo "  Target Architecture: ${TARGET_ARCH}"
    echo "  Feature:             ${FEATURE_NAME}"
    echo "========================================================="

    check_host_prerequisites
    ensure_kernel_source
    ensure_rootfs
    ensure_kernel_binary

    if [[ "${BUILD_ONLY}" -eq 1 ]]; then
        echo ""
        echo "[+] Build completed successfully (--build-only specified). Exiting."
        exit 0
    fi

    launch_virtual_machine
}

main "$@"

