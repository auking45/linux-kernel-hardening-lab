#!/bin/sh
# In-guest test runner for ARM64 BTI & PAC (CONFIG_ARM64_BTI & CONFIG_ARM64_PTR_AUTH)
# Tests both real-world C exploit PoC and LKDTM CFI_BACKWARD triggers.

set -eu

TRIGGER_FILE="/sys/kernel/debug/provoke-crash/DIRECT"
VULN_PROC="/proc/vuln_bti_pac"
EXPLOIT_BIN="/bin/exploit_bti_pac"

run_realworld_bti_pac_exploit() {
    if [ -e "${VULN_PROC}" ] && [ -x "${EXPLOIT_BIN}" ]; then
        echo "========================================================="
        echo "  [Test 1/2] Real-World ARM64 BTI & PAC Exploit PoC"
        echo "  Target:       ${VULN_PROC}"
        echo "  Exploit:      ${EXPLOIT_BIN}"
        echo "  Runner:       lab (UID 1000, non-privileged)"
        echo "========================================================="
        echo "[*] Launching user-space PoC to test PAC and BTI..."
        echo ""

        # Execute exploit as non-root 'lab' user
        su - lab -c "${EXPLOIT_BIN}" || true
        echo ""
        echo "[*] In-kernel driver and BTI/PAC telemetry:"
        dmesg | grep -E "vuln_bti_pac|paciasp|autiasp|BTI|PAC|Branch Target" | tail -n 25 || true
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
        echo "[*] Invoking checked return address manipulation via LKDTM..."
        echo CFI_BACKWARD > "${TRIGGER_FILE}" 2>/dev/null || true
        echo ""
        dmesg | grep -E "lkdtm|CFI|return address" | tail -n 15 || true
        echo ""
    fi
}

main() {
    run_realworld_bti_pac_exploit
    run_lkdtm_test
}

main "$@"

