#!/bin/sh
# labs/20-structleak/test.sh
# In-guest test script for verifying Task 8-1: STRUCTLEAK / INIT_STACK_ALL_ZERO
# Installed as /bin/test_structleak in rootfs.

set -e

echo "================================================================"
echo "   Lab 20: STRUCTLEAK / Stack Variable Zeroing Test Suite      "
echo "   Kernel: $(uname -r) on $(uname -m)                          "
echo "================================================================"

VULN_PROC="/proc/vuln_structleak"

# 1. Verify driver presence
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] Error: ${VULN_PROC} does not exist!"
    exit 1
fi

echo "[+] Target driver detected at ${VULN_PROC}"

# 2. Inspect kernel feature status from driver
echo ""
echo "[*] Step 1: Querying driver status report..."
cat "${VULN_PROC}"

# 3. Run unprivileged PoC exploit
echo ""
echo "[*] Step 2: Running exploit PoC as unprivileged user 'lab'..."
if [ -f "/bin/exploit_structleak" ]; then
    su - lab -c "/bin/exploit_structleak" || true
else
    echo "[-] /bin/exploit_structleak binary not found!"
    exit 1
fi

# 4. Inspect kernel dmesg for driver messages
echo ""
echo "[*] Step 3: Inspecting kernel dmesg for vuln_structleak messages:"
dmesg | grep -E "vuln_structleak|INIT_STACK|STRUCTLEAK" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 20 Test Complete: Check above results against expectations"
echo "================================================================"
exit 0

