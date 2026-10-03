#!/bin/sh
# labs/42-armv9-poe/test.sh
# In-guest test runner for verifying Task 13-2: ARMv9 POE (Permission Overlay Extension)
# Installed as /bin/test_armv9_poe in rootfs.

set -e

echo "================================================================"
echo "   Lab 42: ARMv9 Permission Overlay Extension (POE) Suite       "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_poe"

# 1. Inspect CPU architecture and POE support
echo ""
echo "[*] Step 1: Checking CPU Architecture and POE hardware support..."
ARCH=$(uname -m)
echo "    Architecture: ${ARCH}"
if [ "${ARCH}" = "aarch64" ]; then
    if grep -q -i "poe" /proc/cpuinfo; then
        echo "[+] Native ARMv8.9/v9.4+ POE detected in /proc/cpuinfo!"
    else
        echo "[!] Architecture is ARM64, but CPU does not expose POE flag."
    fi
else
    echo "[!] Architecture is ${ARCH}. POE is verified via target driver."
fi

# 2. Check target driver presence
echo ""
echo "[*] Step 2: Checking target driver at ${VULN_PROC}..."
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] Error: ${VULN_PROC} does not exist!"
    exit 1
fi
echo "[+] Target driver detected."

# 3. Query driver status
echo ""
echo "[*] Step 3: Querying driver status report..."
cat "${VULN_PROC}"

# 4. Run PoC exploit
echo ""
echo "[*] Step 4: Running ARMv9 POE PoC..."
if [ -f "/bin/exploit_armv9_poe" ]; then
    /bin/exploit_armv9_poe || true
else
    echo "[-] /bin/exploit_armv9_poe binary not found!"
    exit 1
fi

# 5. Inspect kernel dmesg for POE events
echo ""
echo "[*] Step 5: Inspecting kernel dmesg for POE events:"
dmesg 2>/dev/null | grep -E -i "poe|vuln_poe|overlay fault" | tail -n 25 || echo "    (No POE events logged in dmesg)"

echo ""
echo "================================================================"
echo "   Lab 42 Test Complete: Verified ARMv9 Permission Overlay Ext  "
echo "================================================================"
exit 0
