#!/bin/sh
# CONFIG_STRICT_KERNEL_RWX In-Guest Verification Runner
# Tests W^X memory invariants across .text, .rodata, and __ro_after_init

set -eu

VULN_PROC="/proc/vuln_strict_rwx"
EXPLOIT_BIN="/bin/exploit_strict_rwx"

echo "========================================================="
echo "  [Test 1/3] Kernel Command Line & Boot Protection State"
echo "========================================================="
if [ -f /proc/cmdline ]; then
    echo "Kernel cmdline: $(cat /proc/cmdline)"
fi

if grep -q "rodata=off" /proc/cmdline 2>/dev/null; then
    echo "W^X Protection: DISABLED (rodata=off active)"
else
    echo "W^X Protection: ACTIVE (CONFIG_STRICT_KERNEL_RWX enabled)"
fi
echo ""

echo "========================================================="
echo "  [Test 2/3] Kernel Memory Layout Telemetry (${VULN_PROC})"
echo "========================================================="
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] ERROR: ${VULN_PROC} not found! Is vuln_strict_rwx driver compiled?"
    exit 1
fi
cat "${VULN_PROC}"
echo ""

echo "========================================================="
echo "  [Test 3/3] Real-World W^X Tampering Demonstration"
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
dmesg | grep -E "vuln_strict_rwx|Kernel memory protection|Freeing unused" | tail -n 15 || true
echo ""

echo "========================================================="
echo "  CONFIG_STRICT_KERNEL_RWX Hardening Verification Completed!"
echo "========================================================="
exit 0

