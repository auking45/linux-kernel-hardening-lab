#!/usr/bin/env bash
# Dual-Architecture QEMU Virtual Machine Runner for Linux Kernel Hardening Lab

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"

TARGET_ARCH="x86_64"
KERNEL_IMAGE=""
INITRD_IMAGE=""
MEMORY="1024M"
SMP="2"
EXTRA_CMDLINE=""
AUTO_TEST=""
USE_KVM=1
TIMEOUT_SEC=0

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --arch <x86_64|arm64>      Virtual machine architecture (default: x86_64)"
    echo "  --kernel <path>            Path to kernel binary (bzImage or Image)"
    echo "  --initrd <path>            Path to initramfs archive (default: rootfs/initramfs-<arch>.cpio.gz)"
    echo "  --memory <size>            Memory allocation (default: 1024M)"
    echo "  --smp <N>                  Number of vCPUs (default: 2)"
    echo "  --cmdline <string>         Extra kernel command-line arguments"
    echo "  --test <script_name>       Automated test script to run inside guest before poweroff"
    echo "  --no-kvm                   Disable KVM hardware acceleration (force TCG emulation)"
    echo "  --timeout <seconds>        Kill QEMU after specified seconds (useful for CI/tests)"
    echo "  -h, --help                 Show this help message"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            TARGET_ARCH="$2"
            shift 2
            ;;
        --kernel)
            KERNEL_IMAGE="$2"
            shift 2
            ;;
        --initrd)
            INITRD_IMAGE="$2"
            shift 2
            ;;
        --memory)
            MEMORY="$2"
            shift 2
            ;;
        --smp)
            SMP="$2"
            shift 2
            ;;
        --cmdline)
            EXTRA_CMDLINE="$2"
            shift 2
            ;;
        --test)
            AUTO_TEST="$2"
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

setup_arch_env "${TARGET_ARCH}"

# Check for QEMU binary
if ! command -v "${QEMU_BIN}" >/dev/null 2>&1; then
    echo "[-] Error: Required QEMU emulator '${QEMU_BIN}' is not installed." >&2
    echo "    Run: sudo apt-get install qemu-system-x86 qemu-system-arm" >&2
    exit 1
fi

# Locate kernel image if not specified
if [[ -z "${KERNEL_IMAGE}" ]]; then
    # Look for the most recently built kernel for this arch
    CANDIDATE=$(find "${BUILD_DIR}" -name "$(basename "${KERNEL_IMAGE_REL}")" -path "*${TARGET_ARCH}*" 2>/dev/null | head -n 1 || true)
    if [[ -n "${CANDIDATE}" && -f "${CANDIDATE}" ]]; then
        KERNEL_IMAGE="${CANDIDATE}"
        echo "[*] Auto-selected kernel: ${KERNEL_IMAGE}"
    else
        echo "[-] Error: Kernel image not specified and no candidate found in ${BUILD_DIR}." >&2
        echo "    Specify with --kernel <path_to_kernel>" >&2
        exit 1
    fi
fi

if [[ ! -f "${KERNEL_IMAGE}" ]]; then
    echo "[-] Error: Kernel image not found at ${KERNEL_IMAGE}" >&2
    exit 1
fi

# Locate initrd if not specified
if [[ -z "${INITRD_IMAGE}" ]]; then
    INITRD_IMAGE="${ROOTFS_DIR}/initramfs-${TARGET_ARCH}.cpio.gz"
fi

if [[ ! -f "${INITRD_IMAGE}" ]]; then
    echo "[*] Initramfs not found. Generating default rootfs for ${TARGET_ARCH}..."
    "${SCRIPT_DIR}/build_rootfs.sh" --arch "${TARGET_ARCH}"
fi

# Determine KVM usability
HOST_ARCH="$(uname -m)"
KVM_FLAGS=()
if [[ "${USE_KVM}" -eq 1 && -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
    if [[ "${TARGET_ARCH}" == "${HOST_ARCH}" ]]; then
        KVM_FLAGS=("-enable-kvm" "-cpu" "host")
        echo "[+] KVM hardware acceleration enabled."
    else
        # Cross architecture emulation
        KVM_FLAGS=("-cpu" "${QEMU_CPU}")
        echo "[*] Cross-architecture mode: TCG software emulation enabled."
    fi
else
    KVM_FLAGS=("-cpu" "${QEMU_CPU}")
    echo "[*] TCG software emulation mode enabled (KVM unavailable or disabled)."
fi

# Assemble kernel command line
BOOT_ARGS="console=${CONSOLE_DEV} quiet panic=1 nokaslr"
if [[ -n "${AUTO_TEST}" ]]; then
    BOOT_ARGS="${BOOT_ARGS} lab_test=${AUTO_TEST}"
fi
if [[ -n "${EXTRA_CMDLINE}" ]]; then
    BOOT_ARGS="${BOOT_ARGS} ${EXTRA_CMDLINE}"
fi

echo "========================================================="
echo "  Starting QEMU Virtual Machine"
echo "  Architecture: ${TARGET_ARCH}"
echo "  Kernel:       ${KERNEL_IMAGE}"
echo "  Initrd:       ${INITRD_IMAGE}"
echo "  vCPUs/RAM:    ${SMP} cores / ${MEMORY}"
echo "  Boot args:    ${BOOT_ARGS}"
echo "========================================================="
echo "  (To terminate manually, press Ctrl+A then X)"
echo "---------------------------------------------------------"

QEMU_CMD=(
    "${QEMU_BIN}"
    -machine "${QEMU_MACHINE}"
    "${KVM_FLAGS[@]}"
    -m "${MEMORY}"
    -smp "${SMP}"
    -kernel "${KERNEL_IMAGE}"
    -initrd "${INITRD_IMAGE}"
    -append "${BOOT_ARGS}"
    -nographic
    -no-reboot
)

if [[ "${TIMEOUT_SEC}" -gt 0 ]]; then
    timeout --foreground "${TIMEOUT_SEC}" "${QEMU_CMD[@]}"
else
    "${QEMU_CMD[@]}"
fi
