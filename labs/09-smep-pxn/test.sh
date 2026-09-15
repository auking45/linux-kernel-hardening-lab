#!/bin/sh
# SMEP (x86) & PXN (ARM64) In-Guest Verification Runner
# Tests hardware supervisor mode execution prevention of user-space memory

set -eu

VULN_PROC="/proc/vuln_smep"
EXPLOIT_BIN="/bin/exploit_smep_pxn"

echo "========================================================="
echo "  [Test 1/3] Kernel Command Line & CPU Protection State"
echo "========================================================="
if [ -f /proc/cmdline ]; then
    echo "Kernel cmdline: $(cat /proc/cmdline)"
fi

if grep -qE "clearcpuid=smep|pxn=off" /proc/cmdline 2>/dev/null; then
    echo "Hardware Execution Protection: DISABLED (clearcpuid=smep / pxn=off active)"
else
    echo "Hardware Execution Protection: ACTIVE (SMEP / PXN enabled)"
fi

if [ -f /proc/cpuinfo ]; then
    if grep -q "smep" /proc/cpuinfo 2>/dev/null; then
        echo "CPU Flags: SMEP is present in /proc/cpuinfo"
    elif grep -q "CPU architecture" /proc/cpuinfo 2>/dev/null; then
        echo "CPU Architecture: ARM64 (PXN is architecturally mandatory)"
    else
        echo "CPU Flags: SMEP not reported in /proc/cpuinfo (disabled or cleared)"
    fi
fi
echo ""

echo "========================================================="
echo "  [Test 2/3] Kernel Hardware Telemetry (${VULN_PROC})"
echo "========================================================="
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] ERROR: ${VULN_PROC} not found! Is vuln_smep driver compiled?"
    exit 1
fi
cat "${VULN_PROC}"
echo ""

echo "========================================================="
echo "  [Test 3/3] Real-World ret2usr Attack Demonstration"
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
dmesg | grep -E "vuln_smep|SMEP|PXN|clearcpuid" | tail -n 15 || true
echo ""

echo "========================================================="
echo "  SMEP / PXN Hardening Verification Completed!"
echo "========================================================="
exit 0

