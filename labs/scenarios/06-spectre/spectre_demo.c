/*
 * Linux Kernel Hardening Lab - Scenario 06
 * Speculative Execution Side-Channel Leaks (Spectre v1/v2) & array_index_nospec / Retpoline Defense
 *
 * Educational Cyber-Physical Simulation (Modeled after CVE-2017-5753 / CVE-2017-5715)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_BOLD    "\033[1m"

#define CACHE_STRIDE  512
#define PROBE_SIZE    (256 * CACHE_STRIDE)

/* Simulated Kernel Mission Security Enclave Structure */
typedef struct {
    char mission_geofence_id[32];   /* "ZONE_RESTRICTED_HUMANOID_LAB" */
    char secret_auth_token[16];     /* "NAV_SEC_8F3A" (Leaked via Side-Channel) */
    uint32_t safety_interlock_hash; /* 0x9AF03C28 */
} robot_mission_enclave_t;

static robot_mission_enclave_t g_mission_enclave = {
    .mission_geofence_id = "ZONE_RESTRICTED_HUMANOID_LAB",
    .secret_auth_token = "NAV_SEC_8F3A",
    .safety_interlock_hash = 0x9AF03C28
};

/* Public Array in Kernel Driver Memory */
static const uint8_t g_public_array[16] = {
    10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160
};
static const size_t g_public_array_size = sizeof(g_public_array);

/* Side-channel simulated probe array cache state */

/* Simulated CPU Cache State (0 = Evicted/DRAM, 1 = L1/L2 Cache Hit) */
static uint8_t g_simulated_cache_lines[256];

/*
 * Linux Kernel Speculation Barrier: array_index_nospec
 * Linux kernel mm/nospec.c equivalent implementation
 */
static inline size_t array_index_nospec(size_t index, size_t size) {
    /* If index < size: mask = 0. If index >= size: mask = ~0UL */
    uintptr_t mask = ~(uintptr_t)0;
    if (index < size) {
        mask = 0;
    }
    return index & ~mask;
}

/* Evict / Flush probe array from cache */
static void flush_probe_array(void) {
    memset(g_simulated_cache_lines, 0, sizeof(g_simulated_cache_lines));
}

/* Simulated Speculative Access Routine */
static void speculative_read_kernel(size_t malicious_index, bool nospec_enabled) {
    size_t safe_index;

    if (nospec_enabled) {
        /* HARDENED: array_index_nospec clamps index unconditionally */
        safe_index = array_index_nospec(malicious_index, g_public_array_size);
        if (malicious_index < g_public_array_size) {
            uint8_t val = g_public_array[safe_index];
            g_simulated_cache_lines[val] = 1;
        } else {
            /* Clamped to index 0: No out-of-bounds speculative cache access */
            uint8_t val = g_public_array[safe_index];
            g_simulated_cache_lines[val] = 1;
        }
    } else {
        /* VULNERABLE: CPU BPU mispredicts (malicious_index < g_public_array_size) is TRUE */
        /* During transient speculative execution window before branch retires: */
        const char *secret_base = g_mission_enclave.secret_auth_token;
        size_t offset_to_secret = (size_t)(secret_base - (const char *)g_public_array);

        if (malicious_index >= offset_to_secret && 
            malicious_index < offset_to_secret + strlen(g_mission_enclave.secret_auth_token)) {
            size_t secret_idx = malicious_index - offset_to_secret;
            uint8_t secret_byte = (uint8_t)g_mission_enclave.secret_auth_token[secret_idx];

            /* Microarchitectural side-channel side effect: loads secret_byte cache line */
            g_simulated_cache_lines[secret_byte] = 1;
        }
    }
}

/* Flush+Reload Side-Channel Measurement */
static int measure_cache_hit_differential(void) {
    int detected_byte = -1;
    for (int i = 1; i < 256; i++) {
        if (g_simulated_cache_lines[i] == 1) {
            /* Cache Hit detected! */
            detected_byte = i;
            break;
        }
    }
    return detected_byte;
}

/* Simulation Functions */
static void run_normal_mode(void) {
    printf("%s[MODE 1: NORMAL KERNEL MEMORY ACCESS & GEOFENCE TELEMETRY]%s\n", COLOR_CYAN, COLOR_RESET);
    printf("[*] Mission Security Enclave Active: Zone = '%s'\n", g_mission_enclave.mission_geofence_id);
    printf("[*] Vision AI requesting legitimate public telemetry index (idx=5)...\n");

    flush_probe_array();
    size_t in_bounds_idx = 5;

    if (in_bounds_idx < g_public_array_size) {
        uint8_t val = g_public_array[in_bounds_idx];
        printf("    -> In-bounds value read: %d\n", val);
        printf("%s[SUCCESS] Normal bounds check passed. Zero speculative microarchitectural leak.%s\n\n",
               COLOR_GREEN, COLOR_RESET);
    }
}

static void run_attack_mode(void) {
    printf("%s[MODE 2: SPECTRE V1 FLUSH+RELOAD SIDE-CHANNEL LEAK (NOSPEC=n)]%s\n", COLOR_RED, COLOR_RESET);
    printf("[*] Simulating CVE-2017-5753: Branch Predictor training & speculative bounds bypass...\n");
    printf("[*] Attacker targets Kernel Mission Secret Token located beyond public array boundary...\n\n");

    const char *secret_base = g_mission_enclave.secret_auth_token;
    size_t offset_to_secret = (size_t)(secret_base - (const char *)g_public_array);
    size_t secret_len = strlen(g_mission_enclave.secret_auth_token);

    char recovered_token[32] = {0};

    printf("    [!] Training BPU with 1000 in-bounds iterations (idx < 16)...\n");
    printf("    [!] Flushing cache lines for probe array (clflush simulation)...\n");
    printf("    [!] Launching transient speculative read for secret byte offsets...\n\n");

    for (size_t i = 0; i < secret_len; i++) {
        flush_probe_array();
        size_t oob_target_index = offset_to_secret + i;

        /* Speculative read executed without nospec barrier */
        speculative_read_kernel(oob_target_index, false);

        /* Measure cache latency (Flush+Reload) */
        int leaked_byte = measure_cache_hit_differential();
        if (leaked_byte > 0 && leaked_byte < 127) {
            recovered_token[i] = (char)leaked_byte;
            printf("    -> Offset +%02zu: Measured Latency = 42 CPU cycles (L1 HIT!) -> Leaked Byte: '%c' (0x%02X)\n",
                   i, (char)leaked_byte, leaked_byte);
        } else {
            recovered_token[i] = '?';
        }
    }

    printf("\n%s======================================================================%s\n", COLOR_RED, COLOR_RESET);
    printf("%s [💥 CRITICAL SIDE-CHANNEL COMPROMISE] Kernel Secret Exfiltrated! %s\n", COLOR_RED, COLOR_RESET);
    printf("%s======================================================================%s\n", COLOR_RED, COLOR_RESET);
    printf("  [*] Recovered Auth Token = '%s%s%s' (100%% Match with Enclave)\n",
           COLOR_RED, recovered_token, COLOR_RESET);
    printf("  [*] Attack Method = Spectre Variant 1 (Bounds Check Bypass) + FLUSH+RELOAD\n");
    printf("  [*] Architectural Privilege Violation: 0 (No #PF / No Segfault triggered!)\n\n");

    printf("--- [PHASE 1: CYBER-PHYSICAL HAZARDS & GEOFENCE OVERRIDE] ---\n");
    printf("  %s[🔴 PHYSICAL HAZARD]%s Geofence Authorization Token Forged by Attacker!\n", COLOR_RED, COLOR_RESET);
    printf("  %s[🔴 PHYSICAL HAZARD]%s Autonomous Safety Boundary Disarmed: Robot entering forbidden high-voltage zone!\n", COLOR_RED, COLOR_RESET);
    printf("  %s[🔴 PHYSICAL HAZARD]%s Locomotion Planner Hijacked: High-speed unauthorized trajectory executed!\n\n", COLOR_RED, COLOR_RESET);
}

static void run_hardened_mode(void) {
    printf("%s[MODE 3: SIDE-CHANNEL THWARTED BY ARRAY_INDEX_NOSPEC & RETPOLINE]%s\n", COLOR_GREEN, COLOR_RESET);
    printf("[*] Initializing Hardened Kernel Environment (CONFIG_RETPOLINE=y, array_index_nospec active)...\n");

    const char *secret_base = g_mission_enclave.secret_auth_token;
    size_t offset_to_secret = (size_t)(secret_base - (const char *)g_public_array);
    size_t secret_len = strlen(g_mission_enclave.secret_auth_token);

    printf("[*] Attacker attempts speculative bounds bypass on target offsets...\n");
    printf("[*] array_index_nospec() arithmetic mask clamps speculative index to 0...\n\n");

    int leaks_detected = 0;
    for (size_t i = 0; i < secret_len; i++) {
        flush_probe_array();
        size_t oob_target_index = offset_to_secret + i;

        /* Speculative read executed WITH nospec barrier */
        speculative_read_kernel(oob_target_index, true);

        /* Measure cache latency */
        int leaked_byte = measure_cache_hit_differential();
        if (leaked_byte == g_mission_enclave.secret_auth_token[i]) {
            leaks_detected++;
        }
    }

    printf("    [*] Cache Probe Measurement Result:\n");
    printf("        - Cache Hit Timing for Secret Bytes = %d hits (All reads DRAM latency > 240 cycles)\n", leaks_detected);
    printf("        - Clamped Index Access = index 0 access only (Benign public data)\n\n");

    printf("%s======================================================================%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("%s [🛡️ SPECULATIVE SIDE-CHANNEL NEUTRALIZED] array_index_nospec Mask Active! %s\n", COLOR_YELLOW, COLOR_RESET);
    printf("%s======================================================================%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  [!] Forensic Analysis:\n");
    printf("      Secret Recovery Rate = 0%% (Side-Channel Timing Signal Neutralized)\n");
    printf("      Defense Mechanism    = Speculation barrier arithmetic clamping (sbb mask)\n");
    printf("      Spectre v2 Defense   = CONFIG_RETPOLINE + IBRS Speculative Branch Trap\n");
    printf("  [!] Mission Enclave Secure: Geofence token remained intact.\n\n");

    printf("  %s[FAIL-SAFE ACTIVE]%s Perception Watchdog flagged abnormal timing probing pattern!\n", COLOR_GREEN, COLOR_RESET);
    printf("  %s[FAIL-SAFE ACTIVE]%s Autonomous Navigation halted: Locomotion locked in deterministic Hold Mode!\n", COLOR_GREEN, COLOR_RESET);
    printf("\n");
}

int main(int argc, char **argv) {
    printf("\n%s======================================================================%s\n", COLOR_BOLD, COLOR_RESET);
    printf("%s 🤖 Humanoid Robot Speculative Side-Channel & array_index_nospec Lab (Spectre) %s\n", COLOR_BOLD, COLOR_RESET);
    printf("%s======================================================================%s\n\n", COLOR_BOLD, COLOR_RESET);

    if (argc < 2) {
        run_normal_mode();
        run_attack_mode();
        run_hardened_mode();
        return 0;
    }

    if (strcmp(argv[1], "--normal") == 0) {
        run_normal_mode();
    } else if (strcmp(argv[1], "--attack") == 0) {
        run_attack_mode();
    } else if (strcmp(argv[1], "--hardened") == 0) {
        run_hardened_mode();
    } else {
        fprintf(stderr, "Usage: %s [--normal | --attack | --hardened]\n", argv[0]);
        return 1;
    }

    return 0;
}
