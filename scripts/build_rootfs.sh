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

parse_args() {
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
}

prepare_directories() {
    local rootfs_work_dir="$1"
    echo "[*] Generating rootfs directory skeleton at ${rootfs_work_dir}..."
    mkdir -p "${ROOTFS_DIR}" "${DOWNLOADS_DIR}"
    rm -rf "${rootfs_work_dir}"
    mkdir -p "${rootfs_work_dir}"/{bin,sbin,usr/bin,usr/sbin,proc,sys,dev,etc,tmp,root,sys/kernel/debug,home/lab}
}

install_busybox() {
    local rootfs_work_dir="$1"
    local busybox_bin="${DOWNLOADS_DIR}/busybox-${TARGET_ARCH}"

    if [[ ! -f "${busybox_bin}" ]]; then
        echo "[*] Downloading static BusyBox binary for ${TARGET_ARCH}..."
        local bb_url=""
        if [[ "${TARGET_ARCH}" == "x86_64" ]]; then
            bb_url="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
        else
            bb_url="https://busybox.net/downloads/binaries/1.35.0-aarch64-linux-musl/busybox"
        fi

        if command -v curl >/dev/null 2>&1; then
            curl -L --progress-bar -o "${busybox_bin}" "${bb_url}"
        else
            wget --show-progress -O "${busybox_bin}" "${bb_url}"
        fi
        chmod +x "${busybox_bin}"
    fi

    cp "${busybox_bin}" "${rootfs_work_dir}/bin/busybox"
    chmod 755 "${rootfs_work_dir}/bin/busybox"

    # Install core symlinks
    (
        cd "${rootfs_work_dir}/bin"
        for tool in sh ash ls cp mv rm cat echo mkdir rmdir dmesg ps grep id whoami mount umount uname sync sleep poweroff reboot; do
            ln -sf busybox "${tool}"
        done
    )
}

setup_users() {
    local rootfs_work_dir="$1"

    cat << 'EOF' > "${rootfs_work_dir}/etc/passwd"
root:x:0:0:root:/root:/bin/sh
lab:x:1000:1000:lab user:/home/lab:/bin/sh
EOF

    cat << 'EOF' > "${rootfs_work_dir}/etc/group"
root:x:0:
lab:x:1000:
EOF

    chmod 755 "${rootfs_work_dir}/home/lab"
}

install_lab_tests() {
    local rootfs_work_dir="$1"
    local labs_dir="${LAB_ROOT_DIR}/labs"

    if [[ -d "${labs_dir}" ]]; then
        echo "[*] Installing in-guest lab test scripts..."
        for test_file in "${labs_dir}"/*/test.sh; do
            if [[ -f "${test_file}" ]]; then
                local feature_dir
                feature_dir="$(basename "$(dirname "${test_file}")")"
                # Strip leading numeric prefix, e.g. 01-stack-protector -> stack-protector -> test_stack_protector
                local clean_name
                clean_name="$(echo "${feature_dir}" | sed -E 's/^[0-9]+-//' | tr '-' '_')"
                local target_bin="${rootfs_work_dir}/bin/test_${clean_name}"

                cp "${test_file}" "${target_bin}"
                chmod 755 "${target_bin}"
                echo "    Installed: /bin/test_${clean_name}"
            fi
        done
    fi
}

create_init_script() {
    local rootfs_work_dir="$1"

    cat << 'EOF' > "${rootfs_work_dir}/init"
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

    chmod 755 "${rootfs_work_dir}/init"
}

package_initramfs() {
    local rootfs_work_dir="$1"
    local output_archive="$2"

    echo "[*] Packing initramfs cpio archive..."
    (
        cd "${rootfs_work_dir}"
        find . -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "${output_archive}"
    )

    echo "[+] Successfully created initramfs: ${output_archive}"
    ls -lh "${output_archive}"
}

main() {
    parse_args "$@"
    setup_arch_env "${TARGET_ARCH}"

    local rootfs_work_dir="${ROOTFS_DIR}/rootfs_${TARGET_ARCH}"
    local output_initramfs="${ROOTFS_DIR}/initramfs-${TARGET_ARCH}.cpio.gz"

    if [[ -f "${output_initramfs}" && "${FORCE_REBUILD}" -eq 0 ]]; then
        echo "[+] Initramfs already exists: ${output_initramfs}"
        echo "    (Use --force to rebuild)"
        exit 0
    fi

    prepare_directories "${rootfs_work_dir}"
    install_busybox "${rootfs_work_dir}"
    setup_users "${rootfs_work_dir}"
    install_lab_tests "${rootfs_work_dir}"
    create_init_script "${rootfs_work_dir}"
    package_initramfs "${rootfs_work_dir}" "${output_initramfs}"
}

main "$@"
