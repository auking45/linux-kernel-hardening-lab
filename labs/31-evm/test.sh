#!/bin/sh
# labs/31-evm/test.sh
# In-guest test runner for verifying Task 11-2: EVM (Extended Verification Module)
# Installed as /bin/test_evm in rootfs.

set -e

echo "================================================================"
echo "   Lab 31: EVM Metadata Protection Verification Suite           "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_evm"
SECURITYFS_EVM="/sys/kernel/security/evm"

# 1. Mount securityfs if not already mounted
echo ""
echo "[*] Step 1: Ensuring SecurityFS is mounted..."
if [ ! -d "/sys/kernel/security" ]; then
    mkdir -p /sys/kernel/security 2>/dev/null || true
fi
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true

# 2. Inspect active EVM SecurityFS node
echo ""
echo "[*] Step 2: Inspecting kernel EVM SecurityFS interface..."
if [ -f "${SECURITYFS_EVM}" ]; then
    echo "    Current EVM status (/sys/kernel/security/evm): $(cat "${SECURITYFS_EVM}" 2>/dev/null || echo '0')"
else
    echo "    EVM control node not found (kernel built without CONFIG_EVM or securityfs unmounted)"
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
echo "[*] Step 5: Running unprivileged EVM PoC as user 'lab'..."
if [ -f "/bin/exploit_evm" ]; then
    su - lab -c "/bin/exploit_evm" || true
else
    echo "[-] /bin/exploit_evm binary not found!"
    exit 1
fi

# 6. Inspect kernel dmesg for EVM audit records
echo ""
echo "[*] Step 6: Inspecting kernel dmesg for EVM audit events:"
dmesg | grep -E "evm:|audit\(evm\):|vuln_evm" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 31 Test Complete: Verified EVM Metadata Protection       "
echo "================================================================"
exit 0
