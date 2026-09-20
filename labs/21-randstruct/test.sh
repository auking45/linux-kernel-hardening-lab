#!/bin/sh
# labs/21-randstruct/test.sh
# In-guest test script for verifying Task 8-2: RANDSTRUCT (Structure Layout Randomization)
# Installed as /bin/test_randstruct in rootfs.

set -e

echo "================================================================"
echo "   Lab 21: RANDSTRUCT (Structure Layout Randomization) Suite   "
echo "   Kernel: $(uname -r) on $(uname -m)                          "
echo "================================================================"

VULN_PROC="/proc/vuln_randstruct"

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
if [ -f "/bin/exploit_randstruct" ]; then
    su - lab -c "/bin/exploit_randstruct" || true
else
    echo "[-] /bin/exploit_randstruct binary not found!"
    exit 1
fi

# 4. Inspect kernel dmesg for driver messages
echo ""
echo "[*] Step 3: Inspecting kernel dmesg for vuln_randstruct messages:"
dmesg | grep -E "vuln_randstruct|randstruct|RANDSTRUCT" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 21 Test Complete: Check above results against expectations"
echo "================================================================"
exit 0

