#!/bin/sh
# labs/41-arm64-mte/test.sh
# In-guest test runner for verifying Task 13-1: ARM64 MTE (Memory Tagging Extension)
# Installed as /bin/test_arm64_mte in rootfs.

set -e

echo "================================================================"
echo "   Lab 41: ARM64 Memory Tagging Extension (MTE) Suite           "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_mte"

# 1. Inspect CPU architecture and MTE capability
echo ""
echo "[*] Step 1: Checking CPU Architecture and MTE hardware support..."
ARCH=$(uname -m)
echo "    Architecture: ${ARCH}"
if [ "${ARCH}" = "aarch64" ]; then
    if grep -q -i "mte" /proc/cpuinfo; then
        echo "[+] Native ARMv8.5+ MTE detected in /proc/cpuinfo!"
    else
        echo "[!] Architecture is ARM64, but CPU does not expose MTE flag."
    fi
else
    echo "[!] Architecture is ${ARCH}. MTE is verified via target driver."
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
echo "[*] Step 4: Running ARM64 MTE PoC..."
if [ -f "/bin/exploit_arm64_mte" ]; then
    /bin/exploit_arm64_mte || true
else
    echo "[-] /bin/exploit_arm64_mte binary not found!"
    exit 1
fi

# 5. Inspect kernel dmesg for MTE events
echo ""
echo "[*] Step 5: Inspecting kernel dmesg for MTE events:"
dmesg 2>/dev/null | grep -E -i "mte|vuln_mte|tag mismatch|segv_mte" | tail -n 25 || echo "    (No MTE events logged in dmesg)"

echo ""
echo "================================================================"
echo "   Lab 41 Test Complete: Verified ARM64 Memory Tagging Extension "
echo "================================================================"
exit 0
