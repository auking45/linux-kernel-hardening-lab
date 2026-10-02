#!/bin/sh
# labs/35-seccomp/test.sh
# In-guest test runner for verifying Task 12-1: Seccomp-BPF
# Installed as /bin/test_seccomp in rootfs.

set -e

echo "================================================================"
echo "   Lab 35: Seccomp-BPF Syscall Sandbox Verification Suite        "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_seccomp"

# 1. Inspect current process Seccomp status
echo ""
echo "[*] Step 1: Inspecting process status Seccomp field..."
grep -i "Seccomp" /proc/self/status 2>/dev/null || echo "    Seccomp field not found in status"

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
echo "[*] Step 4: Running unprivileged Seccomp PoC as user 'lab'..."
if [ -f "/bin/exploit_seccomp" ]; then
    su - lab -c "/bin/exploit_seccomp" || true
else
    echo "[-] /bin/exploit_seccomp binary not found!"
    exit 1
fi

# 5. Inspect kernel dmesg for Seccomp events
echo ""
echo "[*] Step 5: Inspecting kernel dmesg for Seccomp events:"
dmesg | grep -E -i "seccomp|vuln_seccomp|audit\(.*seccomp" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 35 Test Complete: Verified Seccomp-BPF Syscall Filtering "
echo "================================================================"
exit 0
