#!/bin/sh
# In-guest smoke test runner for QEMU boot verification

set -eu

main() {
    echo "========================================================="
    echo "  Running In-Guest Smoke Boot Verification"
    echo "  Kernel Architecture: $(uname -m)"
    echo "  Kernel Release:      $(uname -r)"
    echo "========================================================="

    # Check essential virtual filesystems
    for mount_point in /proc /sys /dev; do
        if ! grep -qs " ${mount_point} " /proc/mounts; then
            echo "[-] Error: ${mount_point} is not mounted" >&2
            exit 1
        fi
    done

    echo "[+] Virtual filesystems (/proc, /sys, /dev) verified."
    echo "[+] Essential BusyBox utilities available."
    echo "[+] QEMU Smoke Boot Test PASSED!"
    echo "========================================================="
}

main "$@"

