#!/usr/bin/env bash
# Common environment variables and configuration for Linux Kernel Hardening Lab

set -euo pipefail

# Kernel version (LTS recommended)
export KERNEL_VERSION="${KERNEL_VERSION:-6.6.79}"
export KERNEL_MAJOR="v6.x"
export KERNEL_TARBALL="linux-${KERNEL_VERSION}.tar.xz"
export KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/${KERNEL_MAJOR}/${KERNEL_TARBALL}"

# Directory paths
export LAB_ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DOWNLOADS_DIR="${LAB_ROOT_DIR}/downloads"
export KERNEL_SRC_DIR="${DOWNLOADS_DIR}/linux-${KERNEL_VERSION}"
export BUILD_DIR="${LAB_ROOT_DIR}/build_dir"
export ROOTFS_DIR="${LAB_ROOT_DIR}/rootfs"
export CONFIGS_DIR="${LAB_ROOT_DIR}/configs"

# Architecture specific helper function
setup_arch_env() {
    local target_arch="$1"
    case "${target_arch}" in
        x86_64|amd64)
            export TARGET_ARCH="x86_64"
            export KERNEL_ARCH="x86_64"
            export QEMU_BIN="qemu-system-x86_64"
            export CROSS_COMPILE=""
            export KERNEL_IMAGE_REL="arch/x86/boot/bzImage"
            export CONSOLE_DEV="ttyS0"
            export QEMU_MACHINE="q35"
            export QEMU_CPU="host,migratable=no"
            ;;
        arm64|aarch64)
            export TARGET_ARCH="arm64"
            export KERNEL_ARCH="arm64"
            export QEMU_BIN="qemu-system-aarch64"
            export CROSS_COMPILE="aarch64-linux-gnu-"
            export KERNEL_IMAGE_REL="arch/arm64/boot/Image"
            export CONSOLE_DEV="ttyAMA0"
            export QEMU_MACHINE="virt"
            export QEMU_CPU="cortex-a72"
            ;;
        *)
            echo "[-] Error: Unsupported architecture '${target_arch}'. Choose 'x86_64' or 'arm64'." >&2
            exit 1
            ;;
    esac
}
