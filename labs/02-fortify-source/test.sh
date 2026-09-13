#!/bin/sh
# In-guest test runner for CONFIG_FORTIFY_SOURCE verification
# Tests both real-world C Exploit PoC and LKDTM FORTIFY triggers.

set -eu

TRIGGER_FILE="/sys/kernel/debug/provoke-crash/DIRECT"
VULN_PROC="/proc/vuln_fortify"
EXPLOIT_BIN="/bin/exploit_fortify_source"

run_realworld_fortify_exploit() {
    if [ -e "${VULN_PROC}" ] && [ -x "${EXPLOIT_BIN}" ]; then
        echo "========================================================="
        echo "  [Test 1/2] Real-World Kernel FORTIFY_SOURCE Exploit PoC"
        echo "  Target:       ${VULN_PROC} (memcpy Bounds Overflow)"
        echo "  Exploit:      ${EXPLOIT_BIN}"
        echo "  Runner:       lab (UID 1000, non-privileged)"
        echo "========================================================="
        echo "[*] Launching overflow payload against 64-byte memcpy target..."
        echo "[*] If CONFIG_FORTIFY_SOURCE is active, kernel will panic in memcpy()!"
        echo ""

        # Execute exploit as non-root 'lab' user
        su - lab -c "${EXPLOIT_BIN}" || true
        echo ""
        dmesg | grep "vuln_fortify" | tail -n 10 || true
        echo ""
    fi
}

run_lkdtm_test() {
    if [ ! -d "/sys/kernel/debug" ]; then
        mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    fi

    if [ -f "${TRIGGER_FILE}" ]; then
        echo "========================================================="
        echo "  [Test 2/2] Triggering LKDTM FORTIFY_MEM_OBJECT Test"
        echo "  Kernel Architecture: $(uname -m)"
        echo "  Kernel Release:      $(uname -r)"
        echo "========================================================="
        echo "[*] Injecting memcpy overflow payload via LKDTM..."
        echo FORTIFY_MEM_OBJECT > "${TRIGGER_FILE}"
    fi
}

main() {
    run_realworld_fortify_exploit
    run_lkdtm_test
}

main "$@"

