#!/bin/sh
# FG-KASLR In-Guest Verification Runner
# Validates Monolithic KASLR relative-offset vulnerability vs FG-KASLR defense

set -e

VULN_PROC="/proc/vuln_fgkaslr"
EXPLOIT_BIN="/bin/exploit_fgkaslr"

echo "========================================================="
echo "  [Test 1/3] Kernel Command Line & FG-KASLR State Check"
echo "========================================================="
if [ -f /proc/cmdline ]; then
    echo "Kernel cmdline: $(cat /proc/cmdline)"
fi

if grep -q "fgkaslr=1" /proc/cmdline 2>/dev/null; then
    echo "Boot Mode: FG-KASLR ENABLED via boot param (fgkaslr=1)"
elif grep -q "fgkaslr=0" /proc/cmdline 2>/dev/null; then
    echo "Boot Mode: FG-KASLR DISABLED via boot param (fgkaslr=0)"
else
    echo "Boot Mode: Default configuration"
fi
echo ""

echo "========================================================="
echo "  [Test 2/3] Kernel Telemetry Analysis (${VULN_PROC})"
echo "========================================================="
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] ERROR: ${VULN_PROC} not found! Is vuln_fgkaslr driver compiled?"
    exit 1
fi
cat "${VULN_PROC}"
echo ""

echo "========================================================="
echo "  [Test 3/3] Real-World Relative Offset Exploit Demonstration"
echo "  Runner: lab (UID 1000, non-privileged)"
echo "========================================================="
if [ ! -x "${EXPLOIT_BIN}" ]; then
    echo "[-] ERROR: ${EXPLOIT_BIN} not found!"
    exit 1
fi

# Run exploit as unprivileged user 'lab'
su lab -c "${EXPLOIT_BIN}"
echo ""

echo "========================================================="
echo "  Interactive Dynamic Mode Switching Demonstration"
echo "========================================================="
echo "[*] Testing runtime toggle via ${VULN_PROC}..."
if [ -w "${VULN_PROC}" ]; then
    echo "fgkaslr=0" > "${VULN_PROC}" 2>/dev/null || true
    echo "--> Switched to Monolithic mode. Verification:"
    cat "${VULN_PROC}" | grep -E "FGKASLR_STATUS|DELTA_MISMATCH" || true

    echo "fgkaslr=1" > "${VULN_PROC}" 2>/dev/null || true
    echo "--> Switched to FG-KASLR mode. Verification:"
    cat "${VULN_PROC}" | grep -E "FGKASLR_STATUS|DELTA_MISMATCH" || true
fi

echo ""
echo "========================================================="
echo "  FG-KASLR Hardening Verification Completed!"
echo "========================================================="
exit 0
