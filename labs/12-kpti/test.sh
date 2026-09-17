#!/bin/sh
# Task 5-5: KPTI (Kernel Page Table Isolation) In-Guest Verification Runner
# Verifies user/kernel page table separation and Meltdown side-channel mitigation

set -eu

VULN_PROC="/proc/vuln_kpti"
EXPLOIT_BIN="/bin/exploit_kpti"
SYSFS_MELTDOWN="/sys/devices/system/cpu/vulnerabilities/meltdown"

echo "========================================================="
echo "  [Test 1/3] Kernel Command Line & Sysfs Vulnerability Status"
echo "========================================================="
if [ -f /proc/cmdline ]; then
    echo "Kernel cmdline: $(cat /proc/cmdline)"
fi

if [ -f "${SYSFS_MELTDOWN}" ]; then
    echo "Meltdown status: $(cat "${SYSFS_MELTDOWN}")"
fi

if grep -qE "pti=off|nopti|kpti=off" /proc/cmdline 2>/dev/null; then
    echo "KPTI Configuration: DISABLED (boot override active)"
else
    echo "KPTI Configuration: ACTIVE (pti=on / kpti=on enforced)"
fi
echo ""

echo "========================================================="
echo "  [Test 2/3] Kernel KPTI Hardware Telemetry (${VULN_PROC})"
echo "========================================================="
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] ERROR: ${VULN_PROC} not found! Is vuln_kpti driver compiled?"
    exit 1
fi
cat "${VULN_PROC}"
echo ""

echo "========================================================="
echo "  [Test 3/3] Non-Privileged User PoC Demonstration"
echo "  Target: ${VULN_PROC}"
echo "  Runner: lab (UID 1000, non-privileged)"
echo "========================================================="
if [ ! -x "${EXPLOIT_BIN}" ]; then
    echo "[-] ERROR: ${EXPLOIT_BIN} not found!"
    exit 1
fi

su - lab -c "${EXPLOIT_BIN}" || true
echo ""

echo "========================================================="
echo "  Kernel Ring Buffer (dmesg) Security Events"
echo "========================================================="
dmesg | grep -E "page_tables_isolation|kpti|vuln_kpti|PTI" | tail -n 15 || true
echo ""

echo "========================================================="
echo "  Task 5-5: KPTI Verification Completed!"
echo "========================================================="
exit 0

