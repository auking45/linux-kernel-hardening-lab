#!/bin/sh
# In-guest test runner for Stack Protector Strong verification
# Tests both real-world ROP Exploit PoC and LKDTM CORRUPT_STACK trigger.

set -eu

TRIGGER_FILE="/sys/kernel/debug/provoke-crash/DIRECT"
VULN_PROC="/proc/vuln_stack"
EXPLOIT_BIN="/bin/exploit_stack_protector"

run_realworld_rop_exploit() {
    if [ -e "${VULN_PROC}" ] && [ -x "${EXPLOIT_BIN}" ]; then
        echo "========================================================="
        echo "  [Test 1/2] Real-World Kernel ROP Exploit PoC"
        echo "  Target:       ${VULN_PROC} (Stack Buffer Overflow)"
        echo "  Exploit:      ${EXPLOIT_BIN}"
        echo "  Runner:       lab (UID 1000, non-privileged)"
        echo "========================================================="
        echo "[*] Launching ROP payload against vulnerable kernel stack..."
        echo "[*] If Stack Protector Strong is active, kernel will panic here!"
        echo ""

        # Execute exploit as non-root 'lab' user
        su - lab -c "${EXPLOIT_BIN}" || true
        echo ""
    fi
}

run_lkdtm_test() {
    if [ ! -d "/sys/kernel/debug" ]; then
        mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    fi

    if [ -f "${TRIGGER_FILE}" ]; then
        echo "========================================================="
        echo "  [Test 2/2] Triggering LKDTM CORRUPT_STACK Test"
        echo "  Kernel Architecture: $(uname -m)"
        echo "  Kernel Release:      $(uname -r)"
        echo "========================================================="
        echo "[*] Injecting stack corruption payload via LKDTM..."
        echo CORRUPT_STACK > "${TRIGGER_FILE}"
    fi
}

main() {
    run_realworld_rop_exploit
    run_lkdtm_test
}

main "$@"
