#!/bin/sh
# SMAP (x86) & PAN (ARM64) In-Guest Verification Runner
# Tests hardware supervisor mode access prevention to user-space memory

set -eu

VULN_PROC="/proc/vuln_smap"
EXPLOIT_BIN="/bin/exploit_smap_pan"

echo "========================================================="
echo "  [Test 1/3] Kernel Command Line & CPU Protection State"
echo "========================================================="
if [ -f /proc/cmdline ]; then
    echo "Kernel cmdline: $(cat /proc/cmdline)"
fi

if grep -qE "clearcpuid=smap|pan=off|nosmap" /proc/cmdline 2>/dev/null; then
    echo "Hardware Access Protection: DISABLED (clearcpuid=smap / pan=off active)"
else
    echo "Hardware Access Protection: ACTIVE (SMAP / PAN enabled)"
fi

if [ -f /proc/cpuinfo ]; then
    if grep -q "smap" /proc/cpuinfo 2>/dev/null; then
        echo "CPU Flags: SMAP is present in /proc/cpuinfo"
    elif grep -q "CPU architecture" /proc/cpuinfo 2>/dev/null; then
        echo "CPU Architecture: ARM64 (PAN supported via HW MMU or SW TTBR0)"
    else
        echo "CPU Flags: SMAP not reported in /proc/cpuinfo (disabled or cleared)"
    fi
fi
echo ""

echo "========================================================="
echo "  [Test 2/3] Kernel Hardware Telemetry (${VULN_PROC})"
echo "========================================================="
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] ERROR: ${VULN_PROC} not found! Is vuln_smap driver compiled?"
    exit 1
fi
cat "${VULN_PROC}"
echo ""

echo "========================================================="
echo "  [Test 3/3] Confused-Deputy Fake Object Attack Demonstration"
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
dmesg | grep -E "vuln_smap|SMAP|PAN|clearcpuid" | tail -n 15 || true
echo ""

echo "========================================================="
echo "  SMAP / PAN Hardening Verification Completed!"
echo "========================================================="
exit 0

