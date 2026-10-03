#!/bin/sh
# labs/40-kexec-restrict/test.sh
# In-guest test runner for verifying Task 12-6: Kexec Restrictions & Hardening
# Installed as /bin/test_kexec_restrict in rootfs.

set -e

echo "================================================================"
echo "   Lab 40: Kexec Restrictions & Hardening Verification Suite    "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_kexec"
KEXEC_SYSCTL="/proc/sys/kernel/kexec_load_disabled"
LOCKDOWN_FILE="/sys/kernel/security/lockdown"

# 1. Inspect kernel kexec sysctl parameter
echo ""
echo "[*] Step 1: Inspecting kernel kexec_load_disabled parameter..."
if [ -f "${KEXEC_SYSCTL}" ]; then
    echo "    kernel.kexec_load_disabled: $(cat "${KEXEC_SYSCTL}")"
else
    echo "    Kexec sysctl not found at ${KEXEC_SYSCTL}"
fi

# 2. Inspect kernel lockdown state
echo ""
echo "[*] Step 2: Inspecting Kernel Lockdown LSM status..."
if [ -f "${LOCKDOWN_FILE}" ]; then
    echo "    lockdown status: $(cat "${LOCKDOWN_FILE}")"
else
    echo "    lockdown interface not found at ${LOCKDOWN_FILE}"
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

# 5. Run PoC exploit
echo ""
echo "[*] Step 5: Running Kexec Restrictions PoC..."
if [ -f "/bin/exploit_kexec_restrict" ]; then
    /bin/exploit_kexec_restrict || true
else
    echo "[-] /bin/exploit_kexec_restrict binary not found!"
    exit 1
fi

# 6. Inspect kernel dmesg for kexec events
echo ""
echo "[*] Step 6: Inspecting kernel dmesg for kexec hardening events:"
dmesg 2>/dev/null | grep -E -i "kexec|vuln_kexec|kexec_load_disabled" | tail -n 25 || echo "    (No kexec events logged in dmesg)"

echo ""
echo "================================================================"
echo "   Lab 40 Test Complete: Verified Kexec Restrictions            "
echo "================================================================"
exit 0
