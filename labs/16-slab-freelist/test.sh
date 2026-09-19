#!/bin/sh
# In-guest test runner for SLAB Freelist Hardening & Randomization
# Tests both real-world C exploit PoC and LKDTM SLAB_FREE_DOUBLE triggers.

set -eu

TRIGGER_FILE="/sys/kernel/debug/provoke-crash/DIRECT"
VULN_PROC="/proc/vuln_slab_freelist"
EXPLOIT_BIN="/bin/exploit_slab_freelist"

run_realworld_slab_exploit() {
    if [ -e "${VULN_PROC}" ] && [ -x "${EXPLOIT_BIN}" ]; then
        echo "========================================================="
        echo "  [Test 1/2] Real-World SLUB Freelist Hardening PoC"
        echo "  Target:       ${VULN_PROC}"
        echo "  Exploit:      ${EXPLOIT_BIN}"
        echo "  Runner:       lab (UID 1000, non-privileged)"
        echo "========================================================="
        echo "[*] Launching user-space PoC to evaluate freelist randomization & obfuscation..."
        echo ""

        # Execute exploit as non-root 'lab' user
        su - lab -c "${EXPLOIT_BIN}" || true
        echo ""
        echo "[*] In-kernel driver telemetry:"
        dmesg | grep -E "vuln_slab_freelist|kmem_cache|freelist" | tail -n 20 || true
        echo ""
    fi
}

run_lkdtm_test() {
    if [ ! -d "/sys/kernel/debug" ]; then
        mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    fi

    if [ -f "${TRIGGER_FILE}" ]; then
        echo "========================================================="
        echo "  [Test 2/2] Triggering LKDTM SLAB_FREE_DOUBLE Test"
        echo "  Kernel Architecture: $(uname -m)"
        echo "  Kernel Release:      $(uname -r)"
        echo "========================================================="
        echo "[*] Invoking double free test via LKDTM..."
        echo SLAB_FREE_DOUBLE > "${TRIGGER_FILE}" 2>/dev/null || true
        echo ""
        dmesg | grep -E "lkdtm|double.*free|SLAB|Free pointer corrupt" | tail -n 15 || true
        echo ""
    fi
}

main() {
    run_realworld_slab_exploit
    run_lkdtm_test
}

main "$@"

