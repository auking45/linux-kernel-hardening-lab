#!/bin/sh
# labs/33-lockdown/test.sh
# In-guest test runner for verifying Task 11-4: Kernel Lockdown LSM
# Installed as /bin/test_lockdown in rootfs.

set -e

echo "================================================================"
echo "   Lab 33: Kernel Lockdown LSM Verification Suite               "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_lockdown"
SECURITYFS_LOCKDOWN="/sys/kernel/security/lockdown"

# 1. Mount securityfs if not already mounted
echo ""
echo "[*] Step 1: Ensuring SecurityFS is mounted..."
if [ ! -d "/sys/kernel/security" ]; then
    mkdir -p /sys/kernel/security 2>/dev/null || true
fi
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true

# 2. Inspect active Lockdown SecurityFS node
echo ""
echo "[*] Step 2: Inspecting kernel Lockdown SecurityFS interface..."
if [ -f "${SECURITYFS_LOCKDOWN}" ]; then
    echo "    Lockdown SecurityFS node found at ${SECURITYFS_LOCKDOWN}"
    echo "    Current Lockdown state: $(cat "${SECURITYFS_LOCKDOWN}" 2>/dev/null || echo 'unknown')"
else
    echo "    Lockdown SecurityFS node not active (kernel built without CONFIG_SECURITY_LOCKDOWN_LSM or securityfs unmounted)"
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
echo "[*] Step 5: Running unprivileged Lockdown PoC as user 'lab'..."
if [ -f "/bin/exploit_lockdown" ]; then
    su - lab -c "/bin/exploit_lockdown" || true
else
    echo "[-] /bin/exploit_lockdown binary not found!"
    exit 1
fi

# 6. Inspect kernel dmesg for Lockdown records
echo ""
echo "[*] Step 6: Inspecting kernel dmesg for Lockdown events:"
dmesg | grep -E -i "Lockdown|vuln_lockdown" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 33 Test Complete: Verified Kernel Lockdown LSM           "
echo "================================================================"
exit 0
