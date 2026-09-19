#!/bin/sh
# labs/17-heap-init/test.sh
# In-guest test script for verifying Heap Initialization & Zeroing (CONFIG_INIT_ON_ALLOC & CONFIG_INIT_ON_FREE)
# Installed as /bin/test_heap_init in rootfs.

set -e

echo "================================================================"
echo "   Lab 17: Heap Initialization (Alloc & Free) Test Suite       "
echo "   Kernel: $(uname -r) on $(uname -m)                          "
echo "================================================================"

VULN_PROC="/proc/vuln_heap_init"
LKDTM_DIRECT="/sys/kernel/debug/provoke-crash/DIRECT"

# 1. Verify driver presence
if [ ! -f "${VULN_PROC}" ]; then
    echo "[-] Error: ${VULN_PROC} does not exist!"
    exit 1
fi

echo "[+] Target driver detected at ${VULN_PROC}"

# 2. Run unprivileged user-space PoC
echo ""
echo "[*] Step 1: Running exploit PoC as unprivileged user 'lab'..."
if [ -f "/bin/exploit_heap_init" ]; then
    su - lab -c "/bin/exploit_heap_init" || /bin/exploit_heap_init
else
    echo "[-] /bin/exploit_heap_init binary not found, reading ${VULN_PROC} directly:"
    cat "${VULN_PROC}"
fi

# 3. LKDTM Heap Tests
echo ""
echo "[*] Step 2: Running LKDTM Kernel Heap Initialization Tests..."

# Mount debugfs if not already mounted
if [ ! -d "/sys/kernel/debug/provoke-crash" ]; then
    mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
fi

if [ -f "${LKDTM_DIRECT}" ]; then
    echo "[+] Debugfs LKDTM trigger available: ${LKDTM_DIRECT}"

    echo "[*] Triggering LKDTM: SLAB_INIT_ON_ALLOC..."
    echo "SLAB_INIT_ON_ALLOC" > "${LKDTM_DIRECT}" 2>/dev/null || true

    echo "[*] Triggering LKDTM: BUDDY_INIT_ON_ALLOC..."
    echo "BUDDY_INIT_ON_ALLOC" > "${LKDTM_DIRECT}" 2>/dev/null || true

    echo "[*] Triggering LKDTM: READ_AFTER_FREE..."
    echo "READ_AFTER_FREE" > "${LKDTM_DIRECT}" 2>/dev/null || true

    echo "[*] Triggering LKDTM: READ_BUDDY_AFTER_FREE..."
    echo "READ_BUDDY_AFTER_FREE" > "${LKDTM_DIRECT}" 2>/dev/null || true

    echo ""
    echo "[*] Inspecting kernel dmesg for LKDTM verification output:"
    dmesg | grep -E "lkdtm:.*(initialized|poisoned|FAIL)" | tail -n 20 || true
else
    echo "[-] LKDTM debugfs entry not found (CONFIG_LKDTM or debugfs disabled)"
fi

echo ""
echo "================================================================"
echo "   Lab 17 Test Complete: Check above results against expectations"
echo "================================================================"
exit 0

