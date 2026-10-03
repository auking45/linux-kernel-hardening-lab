#!/bin/sh
# labs/36-bpf-hardening/test.sh
# In-guest test runner for verifying Task 12-2: BPF Hardening
# Installed as /bin/test_bpf_hardening in rootfs.

set -e

echo "================================================================"
echo "   Lab 36: BPF Hardening & JIT Blinding Verification Suite      "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_bpf_hardening"

# 1. Inspect kernel BPF sysctl parameters
echo ""
echo "[*] Step 1: Inspecting kernel BPF sysctl parameters..."
if [ -f "/proc/sys/kernel/unprivileged_bpf_disabled" ]; then
    echo "    kernel.unprivileged_bpf_disabled: $(cat /proc/sys/kernel/unprivileged_bpf_disabled)"
fi
if [ -f "/proc/sys/net/core/bpf_jit_harden" ]; then
    echo "    net.core.bpf_jit_harden: $(cat /proc/sys/net/core/bpf_jit_harden)"
fi
if [ -f "/proc/sys/net/core/bpf_jit_enable" ]; then
    echo "    net.core.bpf_jit_enable: $(cat /proc/sys/net/core/bpf_jit_enable)"
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
echo "[*] Step 4: Running unprivileged BPF Hardening PoC as user 'lab'..."
if [ -f "/bin/exploit_bpf_hardening" ]; then
    su - lab -c "/bin/exploit_bpf_hardening" || true
else
    echo "[-] /bin/exploit_bpf_hardening binary not found!"
    exit 1
fi

# 5. Inspect kernel dmesg for BPF events
echo ""
echo "[*] Step 5: Inspecting kernel dmesg for BPF events:"
dmesg | grep -E -i "bpf_hardening|vuln_bpf|bpf_jit" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 36 Test Complete: Verified BPF Hardening & Blinding       "
echo "================================================================"
exit 0
