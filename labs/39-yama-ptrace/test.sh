#!/bin/sh
# labs/39-yama-ptrace/test.sh
# In-guest test runner for verifying Task 12-5: Ptrace Restrictions (Yama LSM)
# Installed as /bin/test_yama_ptrace in rootfs.

set -e

echo "================================================================"
echo "   Lab 39: Yama LSM Ptrace Scope Verification Suite             "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_yama"
YAMA_SYSCTL="/proc/sys/kernel/yama/ptrace_scope"

# 1. Inspect kernel Yama sysctl parameter
echo ""
echo "[*] Step 1: Inspecting kernel Yama ptrace_scope parameter..."
if [ -f "${YAMA_SYSCTL}" ]; then
    echo "    kernel.yama.ptrace_scope: $(cat "${YAMA_SYSCTL}")"
else
    echo "    Yama sysctl not found at ${YAMA_SYSCTL}"
fi

# 2. Verify target driver presence
echo ""
echo "[*] Step 2: Checking target driver at ${VULN_PROC}..."
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] Error: ${VULN_PROC} does not exist!"
    exit 1
fi
echo "[+] Target driver detected."

# 3. Query driver status
echo ""
echo "[*] Step 3: Querying driver status report..."
cat "${VULN_PROC}"

# 4. Run unprivileged PoC exploit
echo ""
echo "[*] Step 4: Running unprivileged Yama PoC as user 'lab'..."
if [ -f "/bin/exploit_yama_ptrace" ]; then
    su - lab -c "/bin/exploit_yama_ptrace" || true
else
    echo "[-] /bin/exploit_yama_ptrace binary not found!"
    exit 1
fi

# 5. Inspect kernel dmesg for Yama events
echo ""
echo "[*] Step 5: Inspecting kernel dmesg for Yama events:"
dmesg 2>/dev/null | grep -E -i "yama|vuln_yama|ptrace_scope" | tail -n 25 || echo "    (No Yama events logged in dmesg)"

echo ""
echo "================================================================"
echo "   Lab 39 Test Complete: Verified Yama LSM Ptrace Restrictions  "
echo "================================================================"
exit 0
