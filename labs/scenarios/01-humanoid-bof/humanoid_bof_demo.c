// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux Kernel Hardening Lab - Attack Scenario 01
 * Humanoid Robot BLE Daemon Buffer Overflow & Defense Simulation (CVE-2026-76640)
 *
 * Demonstrates:
 * 1. Vulnerable BLE Wi-Fi provisioning buffer overflow (500B buffer vs 1,050B payload)
 * 2. Cyber-physical disaster alert logs (interlock bypass, torque override, botnet beacon)
 * 3. Post-exploitation: Root shell asset exfiltration (Wi-Fi PSK, calibration, IPC socket)
 * 4. Architectural contrast: Rooting (UID 0 / Ring 3) vs Kernel Space (Ring 0 / Supervisor)
 * 5. Stack Canary intercept & Fail-Safe motor locking
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define BLE_BUFFER_SIZE      500
#define ATTACK_PAYLOAD_SIZE  1050

/* ANSI Color Escape Codes for Terminal Telemetry */
#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_RED     "\033[1;31m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_BLUE    "\033[1;34m"
#define CLR_MAGENTA "\033[1;35m"
#define CLR_CYAN    "\033[1;36m"

/* Mock Humanoid Robot Telemetry State */
typedef struct {
    char ssid[BLE_BUFFER_SIZE];
    uint64_t simulated_canary;
    void (*event_callback)(void);
} daemon_context_t;

/* Global state for simulation tracking */
static bool g_canary_protection_enabled = false;
static uint64_t g_master_canary = 0xDEADC0DEBEEFCAFEULL;

/* Forward Declarations */
static void normal_event_loop(void);
static void hijacked_root_shell(void);

/* Normal event callback */
static void normal_event_loop(void)
{
    printf("  [%s✓%s] Normal BLE Event Callback invoked: Wireless profile updated successfully.\n",
           CLR_GREEN, CLR_RESET);
}

/* Post-Exploitation: Root Shell and Cyber-Physical Hazard Actions */
static void hijacked_root_shell(void)
{
    printf("\n%s======================================================================%s\n", CLR_RED, CLR_RESET);
    printf("%s [💥 CRITICAL EXPLOIT DETONATION] Locomotion PC Hijacked! %s\n", CLR_RED, CLR_RESET);
    printf("%s======================================================================%s\n", CLR_RED, CLR_RESET);
    printf("  [*] Attacker control flow reached: %s__builtin_return_address(0)%s hijacked!\n", CLR_BOLD, CLR_RESET);
    printf("  [*] Current Context: UID = %d, EUID = %d (%sroot / Locomotion Daemon%s)\n\n",
           getuid(), geteuid(), CLR_RED, CLR_RESET);

    /* 1. Cyber-Physical Hazards */
    printf("%s--- [PHASE 1: CYBER-PHYSICAL HAZARDS & SAFETY OVERRIDE] ---%s\n", CLR_YELLOW, CLR_RESET);
    printf("  %s[🔴 PHYSICAL HAZARD]%s Collision Avoidance Safety Interlock (Radar Loop): %sDEACTIVATED%s\n",
           CLR_RED, CLR_RESET, CLR_RED, CLR_RESET);
    printf("  %s[🔴 PHYSICAL HAZARD]%s Actuator Torque Limit modified: %s120.0 Nm -> 350.0 Nm (OVERLOAD)%s\n",
           CLR_RED, CLR_RESET, CLR_RED, CLR_RESET);
    printf("  %s[🔴 PHYSICAL HAZARD]%s Gait Trajectory: High-speed instability injected -> %sRisk of Violent Tip-over%s\n",
           CLR_RED, CLR_RESET, CLR_RED, CLR_RESET);
    printf("  %s[🔴 BOTNET BEACON]%s BLE Transmitter reconfigured: Broadcasting worm beacon on GATT 0xFFE2\n\n",
           CLR_MAGENTA, CLR_RESET);

    /* 2. Asset Exfiltration */
    printf("%s--- [PHASE 2: LOCAL SENSITIVE ASSET EXFILTRATION] ---%s\n", CLR_YELLOW, CLR_RESET);
    printf("  %s[🔓 ASSET DUMP]%s /etc/unitree/wpa_supplicant.conf -> %sPSK: \"Corp_Secret_Robotics_2026!\"%s\n",
           CLR_CYAN, CLR_RESET, CLR_BOLD, CLR_RESET);
    printf("  %s[🔓 ASSET DUMP]%s /opt/unitree/calibration.json    -> Joint Zero-Offsets & Kinematic Matrix exfiltrated\n",
           CLR_CYAN, CLR_RESET);
    printf("  %s[🔓 ASSET DUMP]%s /var/run/unitree/locomotion.sock  -> Direct IPC socket connection established\n\n",
           CLR_CYAN, CLR_RESET);

    /* 3. Architectural Clarification: Root (UID 0) vs Kernel (Ring 0) */
    printf("%s--- [PHASE 3: ARCHITECTURAL BOUNDARY: UID 0 (Ring 3) vs Ring 0 (Kernel)] ---%s\n", CLR_BLUE, CLR_RESET);
    printf("  [*] Common Misconception: %s\"Rooting (UID 0) grants omnipotent control over everything!\"%s\n",
           CLR_BOLD, CLR_RESET);
    printf("  [*] %sReality Check%s: The attacker is in %sUser Space (Ring 3 / EL0)%s, NOT Kernel Space (Ring 0)!\n",
           CLR_YELLOW, CLR_RESET, CLR_RED, CLR_RESET);

    printf("  [*] Testing UID 0 boundary against Linux Kernel Hardening:\n");

    // Attempt 1: Direct Physical Memory Tampering (/dev/mem)
    printf("      - Attempting write to /dev/mem (Physical Memory / Page Tables)... ");
    int fd_mem = open("/dev/mem", O_RDWR);
    if (fd_mem < 0) {
        printf("%sBLOCKED%s (Lockdown LSM / CONFIG_STRICT_DEVMEM: %s)\n",
               CLR_GREEN, CLR_RESET, strerror(errno));
    } else {
        close(fd_mem);
        printf("%sWARNING: /dev/mem accessible%s\n", CLR_RED, CLR_RESET);
    }

    // Attempt 2: Loading unsigned arbitrary kernel rootkit module
    printf("      - Attempting execution of privileged init_module() syscall... ");
    // Simulated capability/lockdown check
    printf("%sBLOCKED%s (Module Signature Enforcement / Lockdown Integrity: EPERM)\n",
           CLR_GREEN, CLR_RESET);

    // Attempt 3: Direct CPU Control Register Modification (CR0, CR4, SCTLR_EL1)
    printf("      - Attempting direct CPU Ring 0 instructions (e.g. mov %%cr4, %%rax)... ");
    printf("%sTRAPPED%s (Hardware Fault: Ring 3 cannot execute Ring 0 opcode -> SIGILL)\n\n",
           CLR_GREEN, CLR_RESET);

    printf("  %s[Key Insight]%s Even if an attacker achieves Root (UID 0) via daemon BOF, modern\n"
           "  kernel hardening (Lockdown LSM, Module Signing, Strict Devmem, Seccomp) confines\n"
           "  the attacker to User Space, preventing permanent firmware or kernel rootkit persistence!\n"
           "  To breach Ring 0, a secondary kernel vulnerability (e.g. ret2usr) is mandatory.\n",
           CLR_GREEN, CLR_RESET);
}

/* Vulnerable BLE Packet Processing Handler */
static void handle_ble_packet(const char *input_data, size_t input_len)
{
    daemon_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.event_callback = normal_event_loop;

    if (g_canary_protection_enabled) {
        ctx.simulated_canary = g_master_canary;
    }

    printf("[*] Processing incoming BLE GATT packet (Length: %zu bytes, Buffer capacity: %d bytes)...\n",
           input_len, BLE_BUFFER_SIZE);

    /*
     * VULNERABILITY (CVE-2026-76640):
     * Unbounded memcpy/strcpy exceeding 500-byte buffer into adjacent memory.
     */
    if (input_len <= BLE_BUFFER_SIZE) {
        // Safe length
        memcpy(ctx.ssid, input_data, input_len);
        printf("    Buffer copy complete within bounds (%zu bytes).\n", input_len);
    } else {
        // Overflow occurrence
        printf("    %s[!] BUFFER OVERFLOW TRIGGERED:%s copying %zu bytes into %d-byte stack buffer!\n",
               CLR_RED, CLR_RESET, input_len, BLE_BUFFER_SIZE);

        // Copy up to buffer
        memcpy(ctx.ssid, input_data, BLE_BUFFER_SIZE);

        if (g_canary_protection_enabled) {
            // Overwriting canary slot
            ctx.simulated_canary = 0x4141414141414141ULL; // Corrupted by 'A'*8
        } else {
            // No canary: Directly corrupts function pointer / return address
            ctx.event_callback = hijacked_root_shell;
        }
    }

    /* Epilogue Integrity Verification */
    if (g_canary_protection_enabled) {
        printf("[*] Function Epilogue: Validating Stack Canary (XOR with master guard)...\n");
        if (ctx.simulated_canary != g_master_canary) {
            printf("\n%s======================================================================%s\n",
                   CLR_GREEN, CLR_RESET);
            printf("%s [🛡️ STACK PROTECTOR TRAP DETONATED] __stack_chk_fail() invoked! %s\n",
                   CLR_GREEN, CLR_RESET);
            printf("%s======================================================================%s\n",
                   CLR_GREEN, CLR_RESET);
            printf("  [!] Canary Mismatch Detected: Expected 0x%016llX, Found 0x%016llX\n",
                   (unsigned long long)g_master_canary, (unsigned long long)ctx.simulated_canary);
            printf("  [!] Execution aborted: ret instruction withheld. Arbitrary code execution: %s0%%%s\n",
                   CLR_GREEN, CLR_RESET);
            printf("  %s[FAIL-SAFE ACTIVE]%s Motor driver power cut (0V) -> Robotic joints locked safely!\n\n",
                   CLR_GREEN, CLR_RESET);
            return;
        }
    }

    // Call callback
    if (ctx.event_callback) {
        ctx.event_callback();
    }
}

int main(int argc, char *argv[])
{
    printf("\n");
    printf("%s======================================================================%s\n", CLR_CYAN, CLR_RESET);
    printf("%s 🤖 Humanoid Robot BLE Daemon BOF & Hardening Laboratory (CVE-2026-76640) %s\n", CLR_BOLD, CLR_RESET);
    printf("%s======================================================================%s\n", CLR_CYAN, CLR_RESET);

    int mode = 1;
    if (argc > 1) {
        mode = atoi(argv[1]);
    }

    if (mode == 1) {
        printf("\n%s[MODE 1: NORMAL BLE PROVISIONING - VALID 32-BYTE PACKET]%s\n", CLR_BOLD, CLR_RESET);
        char normal_payload[32] = "G1_Unitree_WiFi_Internal_5G";
        handle_ble_packet(normal_payload, sizeof(normal_payload));
    }
    else if (mode == 2) {
        printf("\n%s[MODE 2: ATTACK INJECTION WITHOUT STACK CANARY (EXPLOIT SUCCEEDS)]%s\n", CLR_BOLD, CLR_RESET);
        g_canary_protection_enabled = false;

        char attack_payload[ATTACK_PAYLOAD_SIZE];
        memset(attack_payload, 'A', sizeof(attack_payload));
        handle_ble_packet(attack_payload, sizeof(attack_payload));
    }
    else if (mode == 3) {
        printf("\n%s[MODE 3: ATTACK INJECTION WITH STACK CANARY ACTIVE (ATTACK INTERCEPTED)]%s\n", CLR_BOLD, CLR_RESET);
        g_canary_protection_enabled = true;

        char attack_payload[ATTACK_PAYLOAD_SIZE];
        memset(attack_payload, 'A', sizeof(attack_payload));
        handle_ble_packet(attack_payload, sizeof(attack_payload));
    }
    else {
        printf("Usage: %s [mode]\n", argv[0]);
        printf("  mode 1: Normal BLE Provisioning\n");
        printf("  mode 2: Buffer Overflow Attack without Stack Canary (Exploit & Post-Exploitation)\n");
        printf("  mode 3: Buffer Overflow Attack with Stack Canary (Hardware Fail-Safe Intercept)\n");
    }

    return 0;
}
