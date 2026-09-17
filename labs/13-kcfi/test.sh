#!/bin/sh
# In-guest test runner for Clang kCFI (CONFIG_CFI_CLANG) verification
# Tests both real-world C exploit PoC and LKDTM CFI_FORWARD_PROTO trigger.

set -eu

TRIGGER_FILE="/sys/kernel/debug/provoke-crash/DIRECT"
VULN_PROC="/proc/vuln_kcfi"
EXPLOIT_BIN="/bin/exploit_kcfi"

run_realworld_kcfi_exploit() {
    if [ -e "${VULN_PROC}" ] && [ -x "${EXPLOIT_BIN}" ]; then
        echo "========================================================="
        echo "  [Test 1/2] Real-World Clang kCFI Exploit PoC"
        echo "  Target:       ${VULN_PROC} (Indirect Function Pointer)"
        echo "  Exploit:      ${EXPLOIT_BIN}"
        echo "  Runner:       lab (UID 1000, non-privileged)"
        echo "========================================================="
        echo "[*] Launching user-space PoC to test matched and mismatched indirect calls..."
        echo ""

        # Execute exploit as non-root 'lab' user
        su - lab -c "${EXPLOIT_BIN}" || true
        echo ""
        echo "[*] In-kernel driver and CFI trap telemetry:"
        dmesg | grep -E "vuln_kcfi|CFI failure" | tail -n 20 || true
        echo ""
    fi
}

run_lkdtm_test() {
    if [ ! -d "/sys/kernel/debug" ]; then
        mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    fi

    if [ -f "${TRIGGER_FILE}" ]; then
        echo "========================================================="
        echo "  [Test 2/2] Triggering LKDTM CFI_FORWARD_PROTO Test"
        echo "  Kernel Architecture: $(uname -m)"
        echo "  Kernel Release:      $(uname -r)"
        echo "========================================================="
        echo "[*] Invoking checked indirect call with mismatched prototype via LKDTM..."
        echo CFI_FORWARD_PROTO > "${TRIGGER_FILE}" 2>/dev/null || true
        echo ""
        dmesg | grep -E "lkdtm|CFI|mismatched|survived" | tail -n 15 || true
        echo ""
    fi
}

main() {
    run_realworld_kcfi_exploit
    run_lkdtm_test
}

main "$@"

