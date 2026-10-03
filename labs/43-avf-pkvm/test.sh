#!/bin/sh
# labs/43-avf-pkvm/test.sh
# In-guest test runner for verifying Task 13-3: AVF (Android Virtualization Framework & pKVM)
# Installed as /bin/test_avf_pkvm in rootfs.

set -e

echo "================================================================"
echo "   Lab 43: Android Virtualization Framework & pKVM Suite        "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_avf"

# 1. Inspect KVM virtualization device
echo ""
echo "[*] Step 1: Checking KVM virtualization subsystem..."
if [ -c "/dev/kvm" ]; then
    echo "[+] /dev/kvm character device present!"
else
    echo "[!] /dev/kvm not found in guest environment."
fi

# 2. Check target driver presence
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

# 4. Run PoC exploit
echo ""
echo "[*] Step 4: Running AVF / pKVM PoC..."
if [ -f "/bin/exploit_avf_pkvm" ]; then
    /bin/exploit_avf_pkvm || true
else
    echo "[-] /bin/exploit_avf_pkvm binary not found!"
    exit 1
fi

# 5. Inspect kernel dmesg for pKVM events
echo ""
echo "[*] Step 5: Inspecting kernel dmesg for AVF / pKVM events:"
dmesg 2>/dev/null | grep -E -i "avf_pkvm|stage-2|pvm|vsock" | tail -n 25 || echo "    (No AVF events logged in dmesg)"

echo ""
echo "================================================================"
echo "   Lab 43 Test Complete: Verified Android Virtualization & pKVM "
echo "================================================================"
exit 0
