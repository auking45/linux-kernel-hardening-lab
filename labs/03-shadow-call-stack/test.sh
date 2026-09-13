#!/bin/sh
# In-guest test runner for CONFIG_SHADOW_CALL_STACK verification
# Tests both real-world C Exploit PoC and LKDTM CFI_BACKWARD trigger.

set -eu

TRIGGER_FILE="/sys/kernel/debug/provoke-crash/DIRECT"
VULN_PROC="/proc/vuln_scs"
EXPLOIT_BIN="/bin/exploit_shadow_call_stack"

run_realworld_scs_exploit() {
    if [ -e "${VULN_PROC}" ] && [ -x "${EXPLOIT_BIN}" ]; then
        echo "========================================================="
        echo "  [Test 1/2] Real-World Kernel Shadow Call Stack Exploit PoC"
        echo "  Target:       ${VULN_PROC} (Return Address / LR Hijack)"
        echo "  Exploit:      ${EXPLOIT_BIN}"
        echo "  Runner:       lab (UID 1000, non-privileged)"
        echo "========================================================="
        echo "[*] Launching stack overwrite payload against 32-byte worker target..."
        echo "[*] If CONFIG_SHADOW_CALL_STACK is active, pristine LR restored from x18!"
        echo ""

        # Execute exploit as non-root 'lab' user
        su - lab -c "${EXPLOIT_BIN}" || true
        echo ""
        dmesg | grep "vuln_scs" | tail -n 15 || true
        echo ""
    fi
}

run_lkdtm_test() {
    if [ ! -d "/sys/kernel/debug" ]; then
        mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    fi

    if [ -f "${TRIGGER_FILE}" ]; then
        echo "========================================================="
        echo "  [Test 2/2] Triggering LKDTM CFI_BACKWARD Test"
        echo "  Kernel Architecture: $(uname -m)"
        echo "  Kernel Release:      $(uname -r)"
        echo "========================================================="
        echo "[*] Triggering checked stack return address redirection via LKDTM..."
        echo CFI_BACKWARD > "${TRIGGER_FILE}" 2>/dev/null || true
        echo ""
        dmesg | grep -E "lkdtm|CFI|redirected|unchanged" | tail -n 10 || true
        echo ""
    fi
}

main() {
    run_realworld_scs_exploit
    run_lkdtm_test
}

main "$@"

