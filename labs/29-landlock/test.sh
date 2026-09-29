#!/bin/sh
# labs/29-landlock/test.sh
# In-guest test runner for verifying Task 10-4: Landlock Unprivileged Application Sandboxing
# Installed as /bin/test_landlock in rootfs.

set -e

echo "================================================================"
echo "   Lab 29: Landlock Unprivileged Sandboxing Verification Suite  "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_landlock"
SECURITYFS_LSM="/sys/kernel/security/lsm"

# 1. Mount securityfs if not already mounted
echo ""
echo "[*] Step 1: Ensuring SecurityFS is mounted..."
if [ ! -d "/sys/kernel/security" ]; then
    mkdir -p /sys/kernel/security 2>/dev/null || true
fi
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true

# 2. Inspect active LSM stack
echo ""
echo "[*] Step 2: Inspecting kernel LSM stack..."
if [ -f "${SECURITYFS_LSM}" ]; then
    echo "    Active LSMs (/sys/kernel/security/lsm): $(cat "${SECURITYFS_LSM}")"
fi

# 3. Setup test files with appropriate permissions for user 'lab'
echo ""
echo "[*] Step 3: Setting up test directories and secret files..."
mkdir -p /tmp/sandbox
echo "HOST_SUPER_SECRET_TOKEN" > /tmp/host_secret
echo "SANDBOX_ALLOWED_DATA" > /tmp/sandbox/allowed_file.txt
chmod 644 /tmp/host_secret /tmp/sandbox/allowed_file.txt
chown -R lab:lab /tmp/sandbox /tmp/host_secret 2>/dev/null || true
echo "[+] Test environment prepared: /tmp/host_secret and /tmp/sandbox/."

# 4. Verify target driver presence
echo ""
echo "[*] Step 4: Checking target driver at ${VULN_PROC}..."
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] Error: ${VULN_PROC} does not exist!"
    exit 1
fi
echo "[+] Target driver detected."

# 5. Query driver status
echo ""
echo "[*] Step 5: Querying driver status report..."
cat "${VULN_PROC}"

# 6. Run unprivileged PoC exploit
echo ""
echo "[*] Step 6: Running unprivileged Landlock PoC as user 'lab'..."
if [ -f "/bin/exploit_landlock" ]; then
    su - lab -c "/bin/exploit_landlock" || true
else
    echo "[-] /bin/exploit_landlock binary not found!"
    exit 1
fi

# 7. Inspect kernel dmesg for driver messages
echo ""
echo "[*] Step 7: Inspecting kernel dmesg for Landlock events:"
dmesg | grep -E "vuln_landlock|landlock:" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 29 Test Complete: Verified Landlock Sandboxing           "
echo "================================================================"
exit 0
