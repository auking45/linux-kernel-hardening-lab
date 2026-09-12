#!/bin/sh
# In-guest test runner for Stack Protector verification (LKDTM)

set -eu

TRIGGER_FILE="/sys/kernel/debug/provoke-crash/DIRECT"

check_debugfs() {
    if [ ! -d "/sys/kernel/debug" ]; then
        echo "[*] Mounting debugfs at /sys/kernel/debug..."
        mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    fi

    if [ ! -f "${TRIGGER_FILE}" ]; then
        echo "[-] Error: LKDTM trigger interface not found at ${TRIGGER_FILE}"
        echo "    Ensure CONFIG_LKDTM=y is enabled in kernel config."
        exit 1
    fi
}

trigger_stack_overflow() {
    echo "========================================================="
    echo "  Triggering LKDTM CORRUPT_STACK Test"
    echo "  Kernel Architecture: $(uname -m)"
    echo "  Kernel Release:      $(uname -r)"
    echo "========================================================="
    echo "[*] Injecting stack corruption payload..."
    echo "[*] If Stack Protector is enabled, kernel will panic immediately."
    echo "[*] If disabled, memory will be silently corrupted or crash arbitrarily."
    echo ""

    # Provoke direct stack corruption
    echo CORRUPT_STACK > "${TRIGGER_FILE}"
}

main() {
    check_debugfs
    trigger_stack_overflow
}

main "$@"

