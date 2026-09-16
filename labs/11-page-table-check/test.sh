#!/bin/sh
# CONFIG_PAGE_TABLE_CHECK In-Guest Verification Runner
# Tests kernel page table integrity validation and illegal mapping detection

set -eu

VULN_PROC="/proc/vuln_page_table_check"
EXPLOIT_BIN="/bin/exploit_page_table_check"

echo "========================================================="
echo "  [Test 1/3] Kernel Command Line & Feature Configuration"
echo "========================================================="
if [ -f /proc/cmdline ]; then
    echo "Kernel cmdline: $(cat /proc/cmdline)"
fi

if grep -q "page_table_check=off" /proc/cmdline 2>/dev/null; then
    echo "Page Table Check Status: DISABLED (page_table_check=off active)"
else
    echo "Page Table Check Status: ACTIVE (page_table_check=on enforced)"
fi
echo ""

echo "========================================================="
echo "  [Test 2/3] Kernel Page Table Check Telemetry (${VULN_PROC})"
echo "========================================================="
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] ERROR: ${VULN_PROC} not found! Is vuln_page_table_check driver compiled?"
    exit 1
fi
cat "${VULN_PROC}"
echo ""

echo "========================================================="
echo "  [Test 3/3] Page Table Mapping Integrity Demonstration"
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
dmesg | grep -E "page_table_check|vuln_page_table_check|page_ext" | tail -n 15 || true
echo ""

echo "========================================================="
echo "  CONFIG_PAGE_TABLE_CHECK Verification Completed!"
echo "========================================================="
exit 0

