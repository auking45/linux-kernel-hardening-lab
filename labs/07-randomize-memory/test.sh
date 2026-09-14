#!/bin/sh
# CONFIG_RANDOMIZE_MEMORY In-Guest Verification Runner
# Tests direct physical mapping predictability vs randomized memory sections

set -eu

VULN_PROC="/proc/vuln_randmem"
EXPLOIT_BIN="/bin/exploit_randomize_memory"

echo "========================================================="
echo "  [Test 1/3] Kernel Command Line & Memory Randomization"
echo "========================================================="
if [ -f /proc/cmdline ]; then
    echo "Kernel cmdline: $(cat /proc/cmdline)"
fi

if grep -q "nokaslr" /proc/cmdline 2>/dev/null; then
    echo "Memory Randomization: DISABLED (nokaslr active)"
else
    echo "Memory Randomization: ACTIVE (KASLR enabled)"
fi
echo ""

echo "========================================================="
echo "  [Test 2/3] Memory Section Telemetry (${VULN_PROC})"
echo "========================================================="
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] ERROR: ${VULN_PROC} not found! Is vuln_randmem driver compiled?"
    exit 1
fi
cat "${VULN_PROC}"
echo ""

echo "========================================================="
echo "  [Test 3/3] Real-World ret2dir Exploit Demonstration"
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
echo "  CONFIG_RANDOMIZE_MEMORY Hardening Verification Completed!"
echo "========================================================="
exit 0
