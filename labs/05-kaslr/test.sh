#!/bin/sh
# In-guest test runner for KASLR verification
# Tests:
# 1. Kernel command line parameters (/proc/cmdline)
# 2. Kernel text base & KASLR slide telemetry (/proc/vuln_kaslr)
# 3. Static vs dynamic address dispatch Exploit PoC (/bin/exploit_kaslr)

set -eu

VULN_PROC="/proc/vuln_kaslr"
EXPLOIT_BIN="/bin/exploit_kaslr"

check_cmdline() {
    echo "========================================================="
    echo "  [Test 1/3] Kernel Command Line & Boot Configuration"
    echo "========================================================="
    echo "[*] /proc/cmdline: $(cat /proc/cmdline)"
    if grep -q "nokaslr" /proc/cmdline; then
        echo "[!] 'nokaslr' parameter detected: KASLR is explicitly DISABLED."
    else
        echo "[+] No 'nokaslr' detected: KASLR is active."
    fi
    echo ""
}

check_telemetry() {
    echo "========================================================="
    echo "  [Test 2/3] Kernel Memory Layout Telemetry"
    echo "========================================================="
    if [ -f "${VULN_PROC}" ]; then
        cat "${VULN_PROC}"
    else
        echo "[-] ${VULN_PROC} not found"
    fi
    echo ""
}

run_exploit_poc() {
    if [ -e "${VULN_PROC}" ] && [ -x "${EXPLOIT_BIN}" ]; then
        echo "========================================================="
        echo "  [Test 3/3] Real-World KASLR Exploit PoC"
        echo "  Target:       ${VULN_PROC}"
        echo "  Exploit:      ${EXPLOIT_BIN}"
        echo "  Runner:       lab (UID 1000, non-privileged)"
        echo "========================================================="
        su - lab -c "${EXPLOIT_BIN}" || true
        echo ""
    fi
}

main() {
    check_cmdline
    check_telemetry
    run_exploit_poc
}

main "$@"

