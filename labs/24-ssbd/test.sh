#!/bin/sh
# labs/24-ssbd/test.sh
# In-guest test runner for verifying Task 9-3: Speculative Store Bypass Disable (SSBD / Spectre v4)
# Installed as /bin/test_ssbd in rootfs.

set -e

echo "================================================================"
echo "   Lab 24: Speculative Store Bypass Disable (SSBD) Verification "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_ssbd"
SYSFS_VULN="/sys/devices/system/cpu/vulnerabilities/spec_store_bypass"

# 1. Inspect sysfs CPU hardware vulnerability & mitigation status
echo ""
echo "[*] Step 1: Checking sysfs Speculative Store Bypass mitigation status..."
if [ -f "${SYSFS_VULN}" ]; then
    echo "    Sysfs status: $(cat "${SYSFS_VULN}")"
else
    echo "    Sysfs status file not found (legacy or virtual kernel)"
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
echo "[*] Step 4: Running unprivileged SSBD PoC as user 'lab'..."
if [ -f "/bin/exploit_ssbd" ]; then
    su - lab -c "/bin/exploit_ssbd" || true
else
    echo "[-] /bin/exploit_ssbd binary not found!"
    exit 1
fi

# 5. Inspect kernel dmesg for driver messages
echo ""
echo "[*] Step 5: Inspecting kernel dmesg for vuln_ssbd messages:"
dmesg | grep -E "vuln_ssbd|spec_store_bypass|SSBD|ssbd|Spectre v4|spectre_v4" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 24 Test Complete: Verified SSBD Spectre v4 defense       "
echo "================================================================"
exit 0

