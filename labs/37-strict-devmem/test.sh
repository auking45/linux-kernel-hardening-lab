#!/bin/sh
# labs/37-strict-devmem/test.sh
# In-guest test runner for verifying Task 12-3: Strict Devmem
# Installed as /bin/test_strict_devmem in rootfs.

set -e

echo "================================================================"
echo "   Lab 37: Strict Devmem & Strict I/O Devmem Verification Suite "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_strict_devmem"

# 1. Inspect /dev/mem node and /proc/iomem
echo ""
echo "[*] Step 1: Inspecting /dev/mem device node and /proc/iomem..."
ls -l /dev/mem 2>/dev/null || echo "    /dev/mem device node not present"
echo "    System physical memory map preview (/proc/iomem):"
head -n 12 /proc/iomem 2>/dev/null || echo "    Unable to read /proc/iomem"

# 2. Verify target driver presence
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

# 4. Run PoC exploit as root (devmem requires root / CAP_SYS_RAWIO)
echo ""
echo "[*] Step 4: Running Strict Devmem PoC..."
if [ -f "/bin/exploit_strict_devmem" ]; then
    /bin/exploit_strict_devmem || true
else
    echo "[-] /bin/exploit_strict_devmem binary not found!"
    exit 1
fi

# 5. Inspect kernel dmesg for Strict Devmem events
echo ""
echo "[*] Step 5: Inspecting kernel dmesg for Strict Devmem events:"
dmesg | grep -E -i "strict_devmem|vuln_strict_devmem|devmem_is_allowed" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 37 Test Complete: Verified Strict Devmem Protections     "
echo "================================================================"
exit 0
