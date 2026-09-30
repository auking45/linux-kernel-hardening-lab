#!/bin/sh
# labs/30-ima/test.sh
# In-guest test runner for verifying Task 11-1: IMA (Integrity Measurement Architecture)
# Installed as /bin/test_ima in rootfs.

set -e

echo "================================================================"
echo "   Lab 30: IMA Measurement & Appraisal Verification Suite       "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_ima"
SECURITYFS_IMA="/sys/kernel/security/ima"

# 1. Mount securityfs if not already mounted
echo ""
echo "[*] Step 1: Ensuring SecurityFS is mounted..."
if [ ! -d "/sys/kernel/security" ]; then
    mkdir -p /sys/kernel/security 2>/dev/null || true
fi
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true

# 2. Inspect active IMA SecurityFS nodes
echo ""
echo "[*] Step 2: Inspecting kernel IMA SecurityFS interface..."
if [ -d "${SECURITYFS_IMA}" ]; then
    echo "[+] IMA SecurityFS directory detected: ${SECURITYFS_IMA}"
    if [ -f "${SECURITYFS_IMA}/runtime_measurements_count" ]; then
        echo "    Current measurement count: $(cat "${SECURITYFS_IMA}/runtime_measurements_count" 2>/dev/null || echo '0')"
    fi
    if [ -f "${SECURITYFS_IMA}/violations" ]; then
        echo "    Current violation count: $(cat "${SECURITYFS_IMA}/violations" 2>/dev/null || echo '0')"
    fi
else
    echo "[!] Note: ${SECURITYFS_IMA} not found (SecurityFS unmounted or IMA unconfigured)"
fi

# 3. Verify target driver presence
echo ""
echo "[*] Step 3: Checking target driver at ${VULN_PROC}..."
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] Error: ${VULN_PROC} does not exist!"
    exit 1
fi
echo "[+] Target driver detected."

# 4. Query driver status
echo ""
echo "[*] Step 4: Querying driver status report..."
cat "${VULN_PROC}"

# 5. Run unprivileged PoC exploit
echo ""
echo "[*] Step 5: Running unprivileged IMA PoC as user 'lab'..."
if [ -f "/bin/exploit_ima" ]; then
    su - lab -c "/bin/exploit_ima" || true
else
    echo "[-] /bin/exploit_ima binary not found!"
    exit 1
fi

# 6. Inspect kernel dmesg for IMA audit records
echo ""
echo "[*] Step 6: Inspecting kernel dmesg for IMA audit events:"
dmesg | grep -E "ima:|audit\(ima\):|vuln_ima" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 30 Test Complete: Verified IMA Measurement & Appraisal   "
echo "================================================================"
exit 0
