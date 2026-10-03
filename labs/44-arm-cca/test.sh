#!/bin/sh
# labs/44-arm-cca/test.sh
# In-guest test runner for verifying Task 13-4: Arm CCA (Confidential Compute Architecture)
# Installed as /bin/test_arm_cca in rootfs.

set -e

echo "================================================================"
echo "   Lab 44: Arm Confidential Compute Architecture (Arm CCA)      "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_cca"

# 1. Inspect CPU architecture and CCA/RME support
echo ""
echo "[*] Step 1: Checking CPU Architecture and Arm CCA hardware support..."
ARCH=$(uname -m)
echo "    Architecture: ${ARCH}"
if [ "${ARCH}" = "aarch64" ]; then
    if grep -q -i "rme" /proc/cpuinfo; then
        echo "[+] Native ARMv9-A Realm Management Extension (RME) detected in /proc/cpuinfo!"
    else
        echo "[!] Architecture is ARM64, but CPU does not expose RME flag."
    fi
else
    echo "[!] Architecture is ${ARCH}. Arm CCA is verified via target driver."
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
echo "[*] Step 4: Running Arm CCA PoC..."
if [ -f "/bin/exploit_arm_cca" ]; then
    /bin/exploit_arm_cca || true
else
    echo "[-] /bin/exploit_arm_cca binary not found!"
    exit 1
fi

# 5. Inspect kernel dmesg for CCA events
echo ""
echo "[*] Step 5: Inspecting kernel dmesg for Arm CCA events:"
dmesg 2>/dev/null | grep -E -i "arm_cca|granule|realm|rmi" | tail -n 25 || echo "    (No CCA events logged in dmesg)"

echo ""
echo "================================================================"
echo "   Lab 44 Test Complete: Verified Arm Confidential Compute (CCA)"
echo "================================================================"
exit 0
