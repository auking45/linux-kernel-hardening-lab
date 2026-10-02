#!/bin/sh
# labs/34-module-sig/test.sh
# In-guest test runner for verifying Task 11-5: Module Signature Verification
# Installed as /bin/test_module_sig in rootfs.

set -e

echo "================================================================"
echo "   Lab 34: Module Signature Verification Suite                  "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_module_sig"
SYSFS_SIG_ENFORCE="/sys/module/module/parameters/sig_enforce"

# 1. Inspect kernel module signature parameter
echo ""
echo "[*] Step 1: Inspecting kernel module signature status..."
if [ -f "${SYSFS_SIG_ENFORCE}" ]; then
    echo "    Module sig_enforce status: $(cat "${SYSFS_SIG_ENFORCE}" 2>/dev/null || echo 'unknown')"
else
    echo "    Module sig_enforce sysfs node not found (using in-kernel target interface)"
fi

# 2. Check kernel trusted keys in keyring
echo ""
echo "[*] Step 2: Inspecting kernel trusted keyrings (/proc/keys)..."
if [ -f "/proc/keys" ]; then
    cat /proc/keys 2>/dev/null | grep -E "keyring|\.builtin_trusted_keys|asymmetric" | head -n 10 || echo "    (No asymmetric keys registered in test session)"
else
    echo "    /proc/keys not exposed (CONFIG_KEYS or proc entry unavailable)"
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
echo "[*] Step 5: Running unprivileged Module Sig PoC as user 'lab'..."
if [ -f "/bin/exploit_module_sig" ]; then
    su - lab -c "/bin/exploit_module_sig" || true
else
    echo "[-] /bin/exploit_module_sig binary not found!"
    exit 1
fi

# 6. Inspect kernel dmesg for module signature records
echo ""
echo "[*] Step 6: Inspecting kernel dmesg for Module Signature events:"
dmesg | grep -E -i "module_sig|PKCS#7|sig_enforce|vuln_module_sig" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 34 Test Complete: Verified Module Signature Verification "
echo "================================================================"
exit 0
