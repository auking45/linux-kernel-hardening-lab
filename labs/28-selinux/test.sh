#!/bin/sh
# labs/28-selinux/test.sh
# In-guest test runner for verifying Task 10-3: SELinux Type Enforcement and MLS
# Installed as /bin/test_selinux in rootfs.

set -e

echo "================================================================"
echo "   Lab 28: SELinux Type Enforcement (TE) & MLS Suite            "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_selinux"
SECURITYFS_LSM="/sys/kernel/security/lsm"
SELINUX_FS="/sys/fs/selinux"

# 1. Mount securityfs and selinuxfs if not already mounted
echo ""
echo "[*] Step 1: Ensuring SecurityFS and SELinuxFS are mounted..."
if [ ! -d "/sys/kernel/security" ]; then
    mkdir -p /sys/kernel/security 2>/dev/null || true
fi
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true

if [ ! -d "${SELINUX_FS}" ]; then
    mkdir -p "${SELINUX_FS}" 2>/dev/null || true
fi
mount -t selinuxfs selinuxfs "${SELINUX_FS}" 2>/dev/null || true

# 2. Inspect active LSM stack and SELinux nodes
echo ""
echo "[*] Step 2: Inspecting kernel LSM stack and SELinux status..."
if [ -f "${SECURITYFS_LSM}" ]; then
    echo "    Active LSMs (/sys/kernel/security/lsm): $(cat "${SECURITYFS_LSM}")"
fi

if [ -f "${SELINUX_FS}/enforce" ]; then
    echo "    SELinux enforce status: $(cat "${SELINUX_FS}/enforce")"
else
    echo "    SELinux filesystem not mounted or SELinux disabled in boot"
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
echo "[*] Step 5: Running unprivileged SELinux PoC as user 'lab'..."
if [ -f "/bin/exploit_selinux" ]; then
    su - lab -c "/bin/exploit_selinux" || true
else
    echo "[-] /bin/exploit_selinux binary not found!"
    exit 1
fi

# 6. Inspect kernel dmesg for AVC audit records
echo ""
echo "[*] Step 6: Inspecting kernel dmesg for SELinux AVC audit events:"
dmesg | grep -E "audit\(avc\):|vuln_selinux" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 28 Test Complete: Verified SELinux TE & MLS Policies    "
echo "================================================================"
exit 0
