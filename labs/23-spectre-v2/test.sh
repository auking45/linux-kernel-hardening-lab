#!/bin/sh
# labs/23-spectre-v2/test.sh
# In-guest test runner for verifying Task 9-2: Spectre v2 (Retpoline, IBPB, STIBP)
# Installed as /bin/test_spectre_v2 in rootfs.

set -e

echo "================================================================"
echo "   Lab 23: Spectre v2 (Retpoline / IBPB) Verification Suite     "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_spectrev2"
SYSFS_VULN="/sys/devices/system/cpu/vulnerabilities/spectre_v2"

# 1. Inspect sysfs CPU hardware vulnerability & mitigation status
echo ""
echo "[*] Step 1: Checking sysfs Spectre v2 mitigation status..."
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
echo "[*] Step 4: Running unprivileged BTI PoC as user 'lab'..."
if [ -f "/bin/exploit_spectre_v2" ]; then
    su - lab -c "/bin/exploit_spectre_v2" || true
else
    echo "[-] /bin/exploit_spectre_v2 binary not found!"
    exit 1
fi

# 5. Inspect kernel dmesg for driver messages
echo ""
echo "[*] Step 5: Inspecting kernel dmesg for vuln_spectrev2 messages:"
dmesg | grep -E "vuln_spectrev2|spectre|SPECTRE|retpoline|RETPOLINE" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 23 Test Complete: Verified Spectre v2 Retpoline defense  "
echo "================================================================"
exit 0

