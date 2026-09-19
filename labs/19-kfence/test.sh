#!/bin/sh
# labs/19-kfence/test.sh
# In-guest test script for verifying KFENCE (Kernel Electric Fence)
# Installed as /bin/test_kfence in rootfs.

set -e

echo "================================================================"
echo "   Lab 19: KFENCE (Kernel Electric Fence) Test Suite           "
echo "   Kernel: $(uname -r) on $(uname -m)                          "
echo "================================================================"

VULN_PROC="/proc/vuln_kfence"
KFENCE_STATS="/sys/kernel/debug/kfence/stats"

# 1. Mount debugfs if not mounted
if [ ! -d "/sys/kernel/debug/kfence" ]; then
    mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
fi

# 2. Verify driver presence
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] Error: ${VULN_PROC} does not exist!"
    exit 1
fi

echo "[+] Target driver detected at ${VULN_PROC}"

# 3. Inspect initial KFENCE stats
if [ -f "${KFENCE_STATS}" ]; then
    echo "[+] KFENCE debugfs statistics interface available:"
    cat "${KFENCE_STATS}"
else
    echo "[-] KFENCE debugfs interface not available (KFENCE disabled or debugfs unmounted)"
fi

# 4. Run unprivileged PoC exploit
echo ""
echo "[*] Step 1: Running exploit PoC as unprivileged user 'lab'..."
if [ -f "/bin/exploit_kfence" ]; then
    su - lab -c "/bin/exploit_kfence" || /bin/exploit_kfence
else
    echo "[-] /bin/exploit_kfence binary not found, triggering directly via proc:"
    echo "oob" > "${VULN_PROC}"
    echo "uaf" > "${VULN_PROC}"
fi

# 5. Inspect kernel dmesg for KFENCE reports
echo ""
echo "[*] Step 2: Inspecting kernel dmesg for KFENCE detection reports:"
dmesg | grep -E "BUG: KFENCE|Out-of-bounds|Use-after-free|kfence-#|kfence: " | tail -n 35 || true

echo ""
echo "================================================================"
echo "   Lab 19 Test Complete: Check above results against expectations"
echo "================================================================"
exit 0

