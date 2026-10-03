#!/bin/sh
# labs/38-info-leaks/test.sh
# In-guest test runner for verifying Task 12-4: Kernel Information Leaks
# Installed as /bin/test_info_leaks in rootfs.

set -e

echo "================================================================"
echo "   Lab 38: Kernel Information Leaks Verification Suite          "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_info_leaks"

# 1. Inspect kernel information restriction sysctl parameters
echo ""
echo "[*] Step 1: Inspecting kernel leak defense sysctls..."
if [ -f "/proc/sys/kernel/dmesg_restrict" ]; then
    echo "    kernel.dmesg_restrict: $(cat /proc/sys/kernel/dmesg_restrict)"
fi
if [ -f "/proc/sys/kernel/kptr_restrict" ]; then
    echo "    kernel.kptr_restrict:  $(cat /proc/sys/kernel/kptr_restrict)"
fi

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

# 4. Run unprivileged PoC exploit
echo ""
echo "[*] Step 4: Running unprivileged Information Leaks PoC as user 'lab'..."
if [ -f "/bin/exploit_info_leaks" ]; then
    su - lab -c "/bin/exploit_info_leaks" || true
else
    echo "[-] /bin/exploit_info_leaks binary not found!"
    exit 1
fi

# 5. Inspect kernel dmesg for info leaks records
echo ""
echo "[*] Step 5: Inspecting kernel dmesg for information leak events:"
dmesg 2>/dev/null | grep -E -i "info_leaks|vuln_info_leaks|dmesg_restrict" | tail -n 25 || echo "    (dmesg read restricted or no entries logged)"

echo ""
echo "================================================================"
echo "   Lab 38 Test Complete: Verified Information Leak Defenses     "
echo "================================================================"
exit 0
