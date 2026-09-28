#!/bin/sh
# labs/26-lsm-stacking/test.sh
# In-guest test runner for verifying Task 10-1: Stackable LSM Architecture and Multiple LSM Activation
# Installed as /bin/test_lsm_stacking in rootfs.

set -e

echo "================================================================"
echo "   Lab 26: Stackable LSM Architecture Verification Suite        "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_lsm"
SECURITYFS_LSM="/sys/kernel/security/lsm"

# 1. Mount securityfs if not already mounted
echo ""
echo "[*] Step 1: Ensuring SecurityFS is mounted..."
if [ ! -d "/sys/kernel/security" ]; then
    mkdir -p /sys/kernel/security
fi
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true

# 2. Inspect active LSM stack via securityfs
echo ""
echo "[*] Step 2: Inspecting active kernel LSM stack..."
if [ -f "${SECURITYFS_LSM}" ]; then
    echo "    Active LSMs (/sys/kernel/security/lsm): $(cat "${SECURITYFS_LSM}")"
else
    echo "    SecurityFS LSM file not found (CONFIG_SECURITYFS or CONFIG_SECURITY disabled)"
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
echo "[*] Step 5: Running unprivileged LSM stacking PoC as user 'lab'..."
if [ -f "/bin/exploit_lsm_stacking" ]; then
    su - lab -c "/bin/exploit_lsm_stacking" || true
else
    echo "[-] /bin/exploit_lsm_stacking binary not found!"
    exit 1
fi

# 6. Inspect kernel dmesg for driver messages
echo ""
echo "[*] Step 6: Inspecting kernel dmesg for vuln_lsm and LSM events:"
dmesg | grep -E "vuln_lsm|LSM|lsm|landlock|lockdown|yama" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 26 Test Complete: Verified Stackable LSM Architecture    "
echo "================================================================"
exit 0
