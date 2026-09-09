#!/usr/bin/env bash
# Build a minimal, lightweight initramfs rootfs for x86_64 and arm64

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/env.sh"

TARGET_ARCH="x86_64"
FORCE_REBUILD=0

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --arch <x86_64|arm64>   Target architecture (default: x86_64)"
    echo "  --force                 Force rebuild existing initramfs"
    echo "  -h, --help              Show this help message"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            TARGET_ARCH="$2"
            shift 2
            ;;
        --force)
            FORCE_REBUILD=1
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

ROOTFS_WORK_DIR="${ROOTFS_DIR}/rootfs_${TARGET_ARCH}"
OUTPUT_INITRAMFS="${ROOTFS_DIR}/initramfs-${TARGET_ARCH}.cpio.gz"

if [[ -f "${OUTPUT_INITRAMFS}" && "${FORCE_REBUILD}" -eq 0 ]]; then
    echo "[+] Initramfs already exists: ${OUTPUT_INITRAMFS}"
    echo "    (Use --force to rebuild)"
    exit 0
fi

echo "[*] Generating rootfs for ${TARGET_ARCH}..."
mkdir -p "${ROOTFS_DIR}" "${DOWNLOADS_DIR}"
rm -rf "${ROOTFS_WORK_DIR}"
mkdir -p "${ROOTFS_WORK_DIR}"/{bin,sbin,usr/bin,usr/sbin,proc,sys,dev,etc,tmp,root,sys/kernel/debug}

# Download or acquire static BusyBox binary
BUSYBOX_BIN="${DOWNLOADS_DIR}/busybox-${TARGET_ARCH}"
if [[ ! -f "${BUSYBOX_BIN}" ]]; then
    echo "[*] Downloading static BusyBox binary for ${TARGET_ARCH}..."
    if [[ "${TARGET_ARCH}" == "x86_64" ]]; then
        BB_URL="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
    else
        BB_URL="https://busybox.net/downloads/binaries/1.35.0-aarch64-linux-musl/busybox"
    fi

    if command -v curl >/dev/null 2>&1; then
        curl -L --progress-bar -o "${BUSYBOX_BIN}" "${BB_URL}"
    else
        wget --show-progress -O "${BUSYBOX_BIN}" "${BB_URL}"
    fi
    chmod +x "${BUSYBOX_BIN}"
fi

# Copy BusyBox and install symlinks
cp "${BUSYBOX_BIN}" "${ROOTFS_WORK_DIR}/bin/busybox"
chmod 755 "${ROOTFS_WORK_DIR}/bin/busybox"

# Generate BusyBox core symlinks inside rootfs
(
    cd "${ROOTFS_WORK_DIR}/bin"
    for tool in sh ash ls cp mv rm cat echo mkdir rmdir dmesg ps grep id whoami mount umount uname sync sleep poweroff reboot; do
        ln -sf busybox "${tool}"
    done
)

# Create /etc/passwd and /etc/group (root + unprivileged 'lab' user)
cat << 'EOF' > "${ROOTFS_WORK_DIR}/etc/passwd"
root:x:0:0:root:/root:/bin/sh
lab:x:1000:1000:lab user:/home/lab:/bin/sh
EOF

cat << 'EOF' > "${ROOTFS_WORK_DIR}/etc/group"
root:x:0:
lab:x:1000:
EOF

mkdir -p "${ROOTFS_WORK_DIR}/home/lab"
chmod 755 "${ROOTFS_WORK_DIR}/home/lab"

# Create /init script
cat << 'EOF' > "${ROOTFS_WORK_DIR}/init"
#!/bin/sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin

# Mount virtual filesystems
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t tmpfs tmpfs /tmp

echo ""
echo "========================================================="
echo "  Welcome to Linux Kernel Hardening Engineering Lab"
echo "  Architecture: $(uname -m) | Kernel: $(uname -r)"
echo "========================================================="
echo ""

# Check for automated test script passed via kernel commandline
CMDLINE=$(cat /proc/cmdline)
case "$CMDLINE" in
    *lab_test=*)
        TEST_NAME=$(echo "$CMDLINE" | sed -n 's/.*lab_test=\([^ ]*\).*/\1/p')
        echo "[*] Automated test requested: $TEST_NAME"
        if [ -x "/bin/$TEST_NAME" ]; then
            /bin/"$TEST_NAME"
        fi
        echo "[*] Automated test finished. Powering off..."
        poweroff -f
        ;;
esac

# Interactive shell
exec /bin/sh
EOF

chmod 755 "${ROOTFS_WORK_DIR}/init"

# Pack initramfs using cpio and gzip
echo "[*] Packing initramfs cpio archive..."
(
    cd "${ROOTFS_WORK_DIR}"
    find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "${OUTPUT_INITRAMFS}"
)

echo "[+] Successfully created initramfs: ${OUTPUT_INITRAMFS}"
ls -lh "${OUTPUT_INITRAMFS}"
