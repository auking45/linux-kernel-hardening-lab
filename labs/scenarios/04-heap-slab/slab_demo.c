/*
 * Linux Kernel Hardening Lab - Scenario 04
 * Kernel Heap Buffer Overflow, Freelist Poisoning & SLAB Hardening / KFENCE Defense
 *
 * Educational Cyber-Physical Simulation (Modeled after CVE-2022-0185 / CVE-2021-22555)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_BOLD    "\033[1m"

/* Byte Swap helper for 64-bit addresses (similar to kernel swab64) */
static inline uint64_t swab64(uint64_t val) {
    return ((val & 0x00000000000000FFULL) << 56) |
           ((val & 0x000000000000FF00ULL) << 40) |
           ((val & 0x0000000000FF0000ULL) << 24) |
           ((val & 0x00000000FF000000ULL) << 8)  |
           ((val & 0x000000FF00000000ULL) >> 8)  |
           ((val & 0x0000FF0000000000ULL) >> 24) |
           ((val & 0x00FF000000000000ULL) >> 40) |
           ((val & 0xFF00000000000000ULL) >> 56);
}

/* Simulated Robot Gait Balance Stabilizer PID State */
typedef struct {
    uint32_t magic;           /* 0x47414954 ("GAIT") */
    float    kp_pitch;        /* Proportional gain: Normal = 150.0 */
    float    kd_pitch;        /* Derivative damping: Normal = 12.0 */
    float    yaw_rate_limit;  /* Max yaw oscillation (rad/s): Normal = 1.2 */
    char     controller_name[32];
} robot_gait_config_t;

/* SLUB Chunk Simulation (kmalloc-128 cache) */
typedef struct slab_object {
    union {
        uint64_t freelist_ptr;  /* Pointer to next free object (plaintext or obfuscated) */
        char     data[128];     /* Payload data when active */
    };
} slab_object_t;

/* Simulated SLUB Cache */
typedef struct {
    uint64_t random_cookie;     /* kmem_cache CSPRNG secret (CONFIG_SLAB_FREELIST_HARDENED) */
    bool     hardened_enabled;  /* Freelist Obfuscation active */
    slab_object_t objects[4];   /* Pool of 4 slab chunks */
    slab_object_t *freelist;    /* Head of freelist */
} mock_kmem_cache_t;

/* Obfuscate freelist pointer (Linux Kernel mm/slub.c logic) */
static inline uint64_t encode_freepointer(mock_kmem_cache_t *cache, uint64_t next_obj_addr, uint64_t slot_addr) {
    if (!cache->hardened_enabled) {
        return next_obj_addr; /* Baseline: Plaintext pointer */
    }
    return next_obj_addr ^ cache->random_cookie ^ swab64(slot_addr);
}

/* De-obfuscate and validate freelist pointer */
static inline uint64_t decode_freepointer(mock_kmem_cache_t *cache, uint64_t stored_val, uint64_t slot_addr) {
    if (!cache->hardened_enabled) {
        return stored_val; /* Baseline: Plaintext */
    }
    return stored_val ^ cache->random_cookie ^ swab64(slot_addr);
}

/* Initialize mock SLUB cache */
static void init_cache(mock_kmem_cache_t *cache, bool hardened) {
    memset(cache, 0, sizeof(mock_kmem_cache_t));
    cache->random_cookie = 0x9AF03C281D47E5B6ULL;
    cache->hardened_enabled = hardened;

    /* Build free list: Slot 0 -> Slot 1 -> Slot 2 -> Slot 3 -> NULL */
    for (int i = 0; i < 3; i++) {
        uint64_t next_addr = (uint64_t)&cache->objects[i + 1];
        uint64_t slot_addr = (uint64_t)&cache->objects[i];
        cache->objects[i].freelist_ptr = encode_freepointer(cache, next_addr, slot_addr);
    }
    uint64_t slot_3_addr = (uint64_t)&cache->objects[3];
    cache->objects[3].freelist_ptr = encode_freepointer(cache, 0, slot_3_addr);

    cache->freelist = &cache->objects[0];
}

/* Simulation Functions */
static void run_normal_mode(void) {
    printf("%s[MODE 1: NORMAL SLUB HEAP ALLOCATION & INTEGRITY]%s\n", COLOR_CYAN, COLOR_RESET);
    printf("[*] Initializing kmalloc-128 cache (CONFIG_SLAB_FREELIST_HARDENED=y)...\n");

    mock_kmem_cache_t cache;
    init_cache(&cache, true);

    printf("[*] Allocating Chunk 0 for motion telemetry buffer...\n");
    slab_object_t *chunk0 = cache.freelist;
    uint64_t next_raw = decode_freepointer(&cache, chunk0->freelist_ptr, (uint64_t)chunk0);
    cache.freelist = (slab_object_t *)next_raw;

    printf("    -> Chunk 0 allocated at: %p\n", (void *)chunk0);
    printf("    -> Validated next freelist head: %p\n", (void *)cache.freelist);

    robot_gait_config_t *gait = (robot_gait_config_t *)chunk0->data;
    gait->magic = 0x47414954;
    gait->kp_pitch = 150.0f;
    gait->kd_pitch = 12.0f;
    gait->yaw_rate_limit = 1.2f;
    strncpy(gait->controller_name, "Safe_PD_Stabilizer", 31);

    printf("%s[SUCCESS] Gait Stabilizer active: Kp=%.1f, Kd=%.1f, Yaw Limit=%.1f rad/s%s\n\n",
           COLOR_GREEN, gait->kp_pitch, gait->kd_pitch, gait->yaw_rate_limit, COLOR_RESET);
}

static void run_attack_mode(void) {
    printf("%s[MODE 2: HEAP OVERFLOW & FREELIST POISONING WITHOUT HARDENING (SLAB_HARDENED=n)]%s\n", COLOR_RED, COLOR_RESET);
    printf("[*] Initializing baseline SLUB cache: Plaintext freelist pointers...\n");

    mock_kmem_cache_t cache;
    init_cache(&cache, false); /* Plaintext mode */

    /* Active victim structure placed adjacent in heap */
    robot_gait_config_t victim_gait = {
        .magic = 0x47414954,
        .kp_pitch = 150.0f,
        .kd_pitch = 12.0f,
        .yaw_rate_limit = 1.2f,
        .controller_name = "Primary_Locomotion_PID"
    };

    printf("[*] Attacker triggers CVE-2022-0185 1-byte heap out-of-bounds write on Chunk 0...\n");
    printf("    [!] Vulnerable write overflows Chunk 0 boundary into Free Slot 1's freelist pointer!\n");

    /* Attacker overwrites plaintext freelist_ptr of Slot 1 with victim_gait address */
    uint64_t target_victim_addr = (uint64_t)&victim_gait;
    cache.objects[1].freelist_ptr = target_victim_addr;
    printf("    [!] Freelist poisoned: Slot 1 -> freelist_ptr overwritten to %p (Victim Gait Config)\n",
           (void *)target_victim_addr);

    /* Normal alloc pop 0 */
    cache.freelist = (slab_object_t *)cache.objects[0].freelist_ptr;
    /* Next alloc pop 1 */
    cache.freelist = (slab_object_t *)cache.objects[1].freelist_ptr;

    printf("[*] Attacker requests kmalloc-128: Allocator returns hijacked address: %p!\n", (void *)cache.freelist);
    printf("[*] Attacker writes malicious kinematics configuration directly into kernel heap memory...\n");

    robot_gait_config_t *corrupted = (robot_gait_config_t *)cache.freelist;
    corrupted->kp_pitch = 9500.0f;     /* Lethal gain runaway */
    corrupted->kd_pitch = 0.0f;        /* Zero damping -> Extreme resonance */
    corrupted->yaw_rate_limit = 32.5f; /* 32.5 rad/s violent spin */

    printf("\n%s======================================================================%s\n", COLOR_RED, COLOR_RESET);
    printf("%s [💥 CRITICAL EXPLOIT DETONATION] Kernel Heap Arbitrary Overwrite! %s\n", COLOR_RED, COLOR_RESET);
    printf("%s======================================================================%s\n", COLOR_RED, COLOR_RESET);
    printf("  [*] SLUB Freelist Hijacked: Target object allocated into arbitrary kernel struct!\n");
    printf("  [*] Current Memory: Kernel Heap Space (SLUB kmalloc-128)\n\n");

    printf("--- [PHASE 1: CYBER-PHYSICAL HAZARDS & BIPEDAL BALANCE COLLAPSE] ---\n");
    printf("  %s[🔴 PHYSICAL HAZARD]%s Pitch Axis Proportional Gain: 150.0 -> %.1f (RESONANCE RUNAWAY)\n",
           COLOR_RED, COLOR_RESET, corrupted->kp_pitch);
    printf("  %s[🔴 PHYSICAL HAZARD]%s Damping Factor (Kd): 12.0 -> %.1f (ZERO DAMPING: UNDAMPED OSCILLATION)\n",
           COLOR_RED, COLOR_RESET, corrupted->kd_pitch);
    printf("  %s[🔴 PHYSICAL HAZARD]%s Yaw Spin Oscillation: 1.2 -> %.1f rad/s (HIGH-SPEED DISORIENTING TIP-OVER)\n",
           COLOR_RED, COLOR_RESET, corrupted->yaw_rate_limit);
    printf("  %s[🔴 ROBOT COLLAPSE]%s Bipedal balance loop failed: Violent ground impact & gear breakage!\n\n",
           COLOR_RED, COLOR_RESET);
}

static void run_hardened_mode(void) {
    printf("%s[MODE 3: HEAP ATTACK INTERCEPTED BY SLAB FREELIST HARDENING & KFENCE]%s\n", COLOR_GREEN, COLOR_RESET);
    printf("[*] Initializing Hardened SLUB cache (CONFIG_SLAB_FREELIST_HARDENED=y)...\n");

    mock_kmem_cache_t cache;
    init_cache(&cache, true); /* Hardened mode with random cookie */

    printf("[*] Attacker triggers CVE-2022-0185 heap overflow: Attempts to poison Slot 1's freelist pointer...\n");
    uint64_t target_victim_addr = 0xFFFF888012345678ULL; /* Arbitrary kernel target */

    /* Attacker writes arbitrary pointer into obfuscated slot */
    cache.objects[1].freelist_ptr = target_victim_addr;
    printf("    [!] Slot 1 poisoned with plaintext address: 0x%lx\n", target_victim_addr);

    printf("[*] Kernel executes kmalloc-128: Attempting to de-obfuscate Slot 1 freelist pointer...\n");
    uint64_t decoded_addr = decode_freepointer(&cache, cache.objects[1].freelist_ptr, (uint64_t)&cache.objects[1]);

    printf("    [*] Decoded address using XOR cookie & byte-swap: 0x%lx\n\n", decoded_addr);

    /* Validation: Valid kernel heap address must be aligned and non-canonical/reasonable */
    bool is_valid = (decoded_addr != 0) &&
                    ((decoded_addr & 0x7) == 0) &&
                    (decoded_addr >= (uint64_t)&cache.objects[0]) &&
                    (decoded_addr <= (uint64_t)&cache.objects[3]);

    if (!is_valid) {
        printf("%s======================================================================%s\n", COLOR_YELLOW, COLOR_RESET);
        printf("%s [🛡️ SLUB FREELIST CORRUPTION DETECTED] kmem_cache_alloc Trap! %s\n", COLOR_YELLOW, COLOR_RESET);
        printf("%s======================================================================%s\n", COLOR_YELLOW, COLOR_RESET);
        printf("  [!] SLUB INTEGRITY TRAP: Freelist pointer corrupt detected in cache 'kmalloc-128'!\n");
        printf("  [!] Forensic Analysis:\n");
        printf("      Expected Pointer Pattern = Valid decoded slab offset within page\n");
        printf("      Found Pointer = 0x%lx (Non-canonical / Corrupted Entropy Garbage)\n", decoded_addr);
        printf("      Defense Mechanism = CONFIG_SLAB_FREELIST_HARDENED XOR Cookie Validation\n");
        printf("  [!] Allocation aborted: Arbitrary write hijacked: 0%%. Kernel Panic / Oops triggered.\n\n");

        printf("  %s[FAIL-SAFE ACTIVE]%s Hardware Safety Relay engaged: Motor Bus Power cut to 0.0V!\n", COLOR_GREEN, COLOR_RESET);
        printf("  %s[FAIL-SAFE ACTIVE]%s Spring-loaded parking brakes LOCKED. Robotic joints secured safely!\n", COLOR_GREEN, COLOR_RESET);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    printf("\n%s======================================================================%s\n", COLOR_BOLD, COLOR_RESET);
    printf("%s 🤖 Humanoid Robot Kernel Heap Overflow & SLAB Hardening Lab (CVE-2022-0185) %s\n", COLOR_BOLD, COLOR_RESET);
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
