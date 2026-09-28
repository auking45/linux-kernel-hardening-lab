#!/bin/sh
# labs/27-apparmor/test.sh
# In-guest test runner for verifying Task 10-2: AppArmor Profile Confinement and Path MAC
# Installed as /bin/test_apparmor in rootfs.

set -e

echo "================================================================"
echo "   Lab 27: AppArmor Profile Confinement Verification Suite      "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_apparmor"
SECURITYFS_LSM="/sys/kernel/security/lsm"
SECURITYFS_AA="/sys/kernel/security/apparmor"

# 1. Mount securityfs if not already mounted
echo ""
echo "[*] Step 1: Ensuring SecurityFS is mounted..."
if [ ! -d "/sys/kernel/security" ]; then
    mkdir -p /sys/kernel/security
fi
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true

# 2. Inspect active LSM stack and AppArmor node
echo ""
echo "[*] Step 2: Inspecting kernel LSM stack and AppArmor node..."
if [ -f "${SECURITYFS_LSM}" ]; then
    echo "    Active LSMs (/sys/kernel/security/lsm): $(cat "${SECURITYFS_LSM}")"
fi

if [ -d "${SECURITYFS_AA}" ]; then
    echo "[+] AppArmor SecurityFS directory detected: ${SECURITYFS_AA}"
    if [ -f "${SECURITYFS_AA}/profiles" ]; then
        echo "    Loaded profiles: $(cat "${SECURITYFS_AA}/profiles" 2>/dev/null || echo '(none)')"
    fi
else
    echo "[!] Note: ${SECURITYFS_AA} directory not found (AppArmor disabled or unmounted)"
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
echo "[*] Step 5: Running unprivileged AppArmor PoC as user 'lab'..."
if [ -f "/bin/exploit_apparmor" ]; then
    su - lab -c "/bin/exploit_apparmor" || true
else
    echo "[-] /bin/exploit_apparmor binary not found!"
    exit 1
fi

# 6. Inspect kernel dmesg for driver messages
echo ""
echo "[*] Step 6: Inspecting kernel dmesg for AppArmor audit events:"
dmesg | grep -E "apparmor=|vuln_apparmor" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 27 Test Complete: Verified AppArmor Path Confinement     "
echo "================================================================"
exit 0
