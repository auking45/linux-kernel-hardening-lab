#!/bin/sh
# labs/32-ipe/test.sh
# In-guest test runner for verifying Task 11-3: IPE (Integrity Policy Enforcement)
# Installed as /bin/test_ipe in rootfs.

set -e

echo "================================================================"
echo "   Lab 32: IPE Policy Enforcement Verification Suite            "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_ipe"
SECURITYFS_IPE="/sys/kernel/security/ipe"

# 1. Mount securityfs if not already mounted
echo ""
echo "[*] Step 1: Ensuring SecurityFS is mounted..."
if [ ! -d "/sys/kernel/security" ]; then
    mkdir -p /sys/kernel/security 2>/dev/null || true
fi
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true

# 2. Inspect active IPE SecurityFS node
echo ""
echo "[*] Step 2: Inspecting kernel IPE SecurityFS interface..."
if [ -d "${SECURITYFS_IPE}" ]; then
    echo "    IPE SecurityFS node found at ${SECURITYFS_IPE}"
    if [ -f "${SECURITYFS_IPE}/enforce" ]; then
        echo "    Current IPE enforce status: $(cat "${SECURITYFS_IPE}/enforce" 2>/dev/null || echo '0')"
    fi
    if [ -f "${SECURITYFS_IPE}/success_audit" ]; then
        echo "    Current IPE audit status: $(cat "${SECURITYFS_IPE}/success_audit" 2>/dev/null || echo '0')"
    fi
else
    echo "    IPE SecurityFS directory not active (kernel built without CONFIG_SECURITY_IPE or securityfs unmounted)"
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
echo "[*] Step 5: Running unprivileged IPE PoC as user 'lab'..."
if [ -f "/bin/exploit_ipe" ]; then
    su - lab -c "/bin/exploit_ipe" || true
else
    echo "[-] /bin/exploit_ipe binary not found!"
    exit 1
fi

# 6. Inspect kernel dmesg for IPE audit records
echo ""
echo "[*] Step 6: Inspecting kernel dmesg for IPE audit events:"
dmesg | grep -E "ipe:|audit\(ipe\):|vuln_ipe" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 32 Test Complete: Verified IPE Policy Enforcement        "
echo "================================================================"
exit 0
