#!/bin/sh
# labs/18-hardened-usercopy/test.sh
# In-guest test script for verifying CONFIG_HARDENED_USERCOPY
# Installed as /bin/test_hardened_usercopy in rootfs.

set -e

echo "================================================================"
echo "   Lab 18: Hardened Usercopy (copy_to/from_user) Test Suite    "
echo "   Kernel: $(uname -r) on $(uname -m)                          "
echo "================================================================"

VULN_PROC="/proc/vuln_usercopy"
LKDTM_DIRECT="/sys/kernel/debug/provoke-crash/DIRECT"

# 1. Verify driver presence
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] Error: ${VULN_PROC} does not exist!"
    exit 1
fi

echo "[+] Target driver detected at ${VULN_PROC}"

# 2. Run unprivileged user-space PoC
echo ""
echo "[*] Step 1: Running exploit PoC as unprivileged user 'lab'..."
if [ -f "/bin/exploit_hardened_usercopy" ]; then
    su - lab -c "/bin/exploit_hardened_usercopy" || /bin/exploit_hardened_usercopy
else
    echo "[-] /bin/exploit_hardened_usercopy binary not found, reading ${VULN_PROC} directly:"
    cat "${VULN_PROC}"
fi

# 3. LKDTM Usercopy Tests
echo ""
echo "[*] Step 2: Running LKDTM Kernel Usercopy Boundary Tests..."

# Mount debugfs if not already mounted
if [ ! -d "/sys/kernel/debug/provoke-crash" ]; then
    mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
fi

if [ -f "${LKDTM_DIRECT}" ]; then
    echo "[+] Debugfs LKDTM trigger available: ${LKDTM_DIRECT}"

    echo "[*] Triggering LKDTM: USERCOPY_SLAB_SIZE_TO in isolated subshell..."
    ( echo "USERCOPY_SLAB_SIZE_TO" > "${LKDTM_DIRECT}" ) 2>/dev/null || true

    echo "[*] Triggering LKDTM: USERCOPY_KERNEL in isolated subshell..."
    ( echo "USERCOPY_KERNEL" > "${LKDTM_DIRECT}" ) 2>/dev/null || true

    echo ""
    echo "[*] Inspecting kernel dmesg for usercopy security events:"
    dmesg | grep -E "Kernel memory exposure|usercopy_abort|FAIL: bad.*usercopy|FAIL: bad copy_to_user|attempting bad copy" | tail -n 25 || true
else
    echo "[-] LKDTM debugfs entry not found (CONFIG_LKDTM or debugfs disabled)"
fi

echo ""
echo "================================================================"
echo "   Lab 18 Test Complete: Check above results against expectations"
echo "================================================================"
exit 0

