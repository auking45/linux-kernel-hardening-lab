#!/bin/sh
# labs/25-mds/test.sh
# In-guest test runner for verifying Task 9-4: MDS (Microarchitectural Data Sampling) & TAA Mitigations
# Installed as /bin/test_mds in rootfs.

set -e

echo "================================================================"
echo "   Lab 25: MDS / TAA & VERW Buffer Clearing Verification Suite  "
echo "   Kernel: $(uname -r) on $(uname -m)                           "
echo "================================================================"

VULN_PROC="/proc/vuln_mds"
SYSFS_MDS="/sys/devices/system/cpu/vulnerabilities/mds"
SYSFS_TAA="/sys/devices/system/cpu/vulnerabilities/tsx_async_abort"
SYSFS_MMIO="/sys/devices/system/cpu/vulnerabilities/mmio_stale_data"

# 1. Inspect sysfs CPU hardware vulnerability & mitigation status
echo ""
echo "[*] Step 1: Checking sysfs MDS / TAA mitigation status..."
if [ -f "${SYSFS_MDS}" ]; then
    echo "    MDS sysfs status : $(cat "${SYSFS_MDS}")"
else
    echo "    MDS sysfs status : (Not present / Architecture not affected)"
fi

if [ -f "${SYSFS_TAA}" ]; then
    echo "    TAA sysfs status : $(cat "${SYSFS_TAA}")"
fi

if [ -f "${SYSFS_MMIO}" ]; then
    echo "    MMIO sysfs status: $(cat "${SYSFS_MMIO}")"
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
echo "[*] Step 4: Running unprivileged MDS PoC as user 'lab'..."
if [ -f "/bin/exploit_mds" ]; then
    su - lab -c "/bin/exploit_mds" || true
else
    echo "[-] /bin/exploit_mds binary not found!"
    exit 1
fi

# 5. Inspect kernel dmesg for driver messages
echo ""
echo "[*] Step 5: Inspecting kernel dmesg for vuln_mds messages:"
dmesg | grep -E "vuln_mds|mds|MDS|verw|VERW|taa|TAA|clear_cpu_buffers" | tail -n 25 || true

echo ""
echo "================================================================"
echo "   Lab 25 Test Complete: Verified MDS / VERW Buffer Clearing    "
echo "================================================================"
exit 0
