#!/bin/sh
# In-guest test runner for CONFIG_GCC_PLUGIN_STACKLEAK verification
# Tests:
# 1. Real-world stack information leak exploit PoC (UID 1000 'lab' user)
# 2. Kernel stack metrics & sysctl interface (/proc/<pid>/stack_depth)
# 3. LKDTM STACKLEAK_ERASING test probe

set -eu

TRIGGER_FILE="/sys/kernel/debug/provoke-crash/DIRECT"
VULN_PROC="/proc/vuln_stackleak"
EXPLOIT_BIN="/bin/exploit_stackleak"

run_exploit_poc() {
    if [ -e "${VULN_PROC}" ] && [ -x "${EXPLOIT_BIN}" ]; then
        echo "========================================================="
        echo "  [Test 1/3] Real-World Stack Information Leak PoC"
        echo "  Target:       ${VULN_PROC}"
        echo "  Exploit:      ${EXPLOIT_BIN}"
        echo "  Runner:       lab (UID 1000, non-privileged)"
        echo "========================================================="
        echo "[*] Executing unprivileged stack memory leak PoC..."
        su - lab -c "${EXPLOIT_BIN}" || true
        echo ""
    fi
}

check_stackleak_metrics() {
    echo "========================================================="
    echo "  [Test 2/3] Inspecting STACKLEAK Interfaces"
    echo "========================================================="
    if [ -f "/proc/sys/kernel/stack_erasing" ]; then
        echo "[+] /proc/sys/kernel/stack_erasing = $(cat /proc/sys/kernel/stack_erasing)"
    else
        echo "[-] /proc/sys/kernel/stack_erasing: Not supported"
    fi

    if [ -f "/proc/$$/stack_depth" ]; then
        echo "[+] /proc/$$/stack_depth = $(cat /proc/$$/stack_depth)"
    else
        echo "[-] /proc/<pid>/stack_depth: Not supported"
    fi
    echo ""
}

run_lkdtm_test() {
    if [ ! -d "/sys/kernel/debug" ]; then
        mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    fi

    if [ -f "${TRIGGER_FILE}" ]; then
        echo "========================================================="
        echo "  [Test 3/3] Triggering LKDTM STACKLEAK_ERASING Test"
        echo "  Kernel Architecture: $(uname -m)"
        echo "  Kernel Release:      $(uname -r)"
        echo "========================================================="
        echo "[*] Triggering STACKLEAK_ERASING via LKDTM direct interface..."
        echo STACKLEAK_ERASING > "${TRIGGER_FILE}" || true
        echo ""
        echo "[*] Recent kernel log messages (dmesg | tail -n 10):"
        dmesg | tail -n 10
    fi
}

main() {
    run_exploit_poc
    check_stackleak_metrics
    run_lkdtm_test
}

main "$@"

