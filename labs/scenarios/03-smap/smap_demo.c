/*
 * Linux Kernel Hardening Lab - Scenario 03
 * Return-to-Direct-Mapped / User Data Corruption (ret2dir / Confused Deputy)
 * & Hardware MMU Data Access Defense (x86 CR4.SMAP / ARM64 PSTATE.PAN)
 *
 * Educational Cyber-Physical Simulation (Modeled after CVE-2016-8655 AF_PACKET UAF)
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

#define TASK_SIZE_64  0x00007FFFFFFFFFFFULL

/* Simulated Robot Locomotion Kinematic Safety Limits */
typedef struct {
    uint32_t magic;              /* 0x53414645 ("SAFE") */
    float    max_joint_torque;   /* Maximum torque limit (Nm): Normal = 120.0 */
    float    collision_margin;   /* Safety radar/LiDAR distance (m): Normal = 0.5 */
    uint32_t emergency_stop_en;  /* E-Stop enabled flag: Normal = 1 */
    char     profile_name[32];   /* Profile descriptor */
} robot_safety_policy_t;

/* Global Kernel Locomotion State */
static robot_safety_policy_t g_kernel_safe_policy = {
    .magic             = 0x53414645,
    .max_joint_torque  = 120.0f,
    .collision_margin  = 0.5f,
    .emergency_stop_en = 1,
    .profile_name      = "Default_Safe_Kinematics"
};

/* User-space fake policy allocated by attacker in Ring 3 */
static robot_safety_policy_t g_user_fake_policy = {
    .magic             = 0x53414645,
    .max_joint_torque  = 650.0f,     /* Lethal torque overload */
    .collision_margin  = 0.0f,      /* Collision avoidance disabled */
    .emergency_stop_en = 0,         /* E-Stop disabled */
    .profile_name      = "Attacker_Hostile_Override"
};

/* Hardware MMU Context */
typedef struct {
    bool cr4_smap_enabled; /* x86 CR4.SMAP bit 21 */
    bool pstate_pan_active;/* ARM64 PSTATE.PAN bit */
    bool eflags_ac;        /* x86 EFLAGS.AC bit 18 (STAC/CLAC window) */
} mmu_hardware_context_t;

/* Simulated MMU Data Dereference Validator */
static bool mmu_validate_data_access(mmu_hardware_context_t *mmu, uintptr_t addr, bool is_write) {
    bool is_user_address = (addr <= TASK_SIZE_64);

    if (!is_user_address) {
        return true; /* Kernel address access is always permitted in Ring 0 */
    }

    /* Target is User Memory while running in Supervisor Mode (Ring 0) */
    if (mmu->cr4_smap_enabled || mmu->pstate_pan_active) {
        /* If EFLAGS.AC is 0 (CLAC state) and PAN is 1, access is strictly FORBIDDEN */
        if (!mmu->eflags_ac) {
            printf("%s    [!] MMU ACCESS VIOLATION: Supervisor (Ring 0) attempted direct %s to User Page (0x%lx)!%s\n",
                   COLOR_RED, is_write ? "WRITE" : "READ", addr, COLOR_RESET);
            return false;
        }
    }

    return true;
}

/* Simulation Functions */
static void run_normal_mode(void) {
    printf("%s[MODE 1: NORMAL KERNEL OPERATION VIA SAFE USERCOPY]%s\n", COLOR_CYAN, COLOR_RESET);
    printf("[*] User-space requests motion profile update via ioctl(SET_SAFETY_LIMITS)...\n");

    mmu_hardware_context_t mmu = {
        .cr4_smap_enabled  = true,
        .pstate_pan_active = true,
        .eflags_ac         = false /* Default locked state */
    };

    printf("[*] Kernel dispatching copy_from_user():\n");
    printf("    [1] stac instruction -> Opening legal usercopy window (EFLAGS.AC = 1)...\n");
    mmu.eflags_ac = true;

    /* Safe validated copy */
    robot_safety_policy_t temp_buf;
    if (mmu_validate_data_access(&mmu, (uintptr_t)&g_kernel_safe_policy, false)) {
        memcpy(&temp_buf, &g_kernel_safe_policy, sizeof(robot_safety_policy_t));
        printf("    [2] Memory safely copied into kernel buffer.\n");
    }

    printf("    [3] clac instruction -> Closing window immediately (EFLAGS.AC = 0)...\n");
    mmu.eflags_ac = false;

    printf("%s[SUCCESS] Kinematic parameters verified: Torque=%.1f Nm, Margin=%.2f m, E-Stop=%u%s\n\n",
           COLOR_GREEN, temp_buf.max_joint_torque, temp_buf.collision_margin,
           temp_buf.emergency_stop_en, COLOR_RESET);
}

static void run_attack_mode(void) {
    printf("%s[MODE 2: RET2DIR / FAKE OBJECT ATTACK WITHOUT SMAP (CR4.SMAP=0, PAN=0)]%s\n", COLOR_RED, COLOR_RESET);
    printf("[*] Simulating CVE-2016-8655: AF_PACKET packet_sock Use-After-Free race condition...\n");

    /* Attacker crafts fake structure in User Space */
    uintptr_t user_fake_addr = (uintptr_t)&g_user_fake_policy;
    printf("    [!] Attacker crafts Fake Safety Object in User Space (Ring 3): Address = 0x%lx\n", user_fake_addr);
    printf("    [!] UAF flaw corrupts kernel safety pointer: g_active_policy = 0x%lx\n", user_fake_addr);

    mmu_hardware_context_t mmu = {
        .cr4_smap_enabled  = false, /* SMAP disabled */
        .pstate_pan_active = false, /* PAN disabled */
        .eflags_ac         = false
    };

    printf("[*] Kernel Locomotion Loop executes in Ring 0: Dereferencing g_active_policy directly...\n");
    if (mmu_validate_data_access(&mmu, user_fake_addr, false)) {
        robot_safety_policy_t *compromised = (robot_safety_policy_t *)user_fake_addr;

        printf("\n%s======================================================================%s\n", COLOR_RED, COLOR_RESET);
        printf("%s [💥 CRITICAL EXPLOIT DETONATION] Confused Deputy / Fake Object Dereferenced! %s\n", COLOR_RED, COLOR_RESET);
        printf("%s======================================================================%s\n", COLOR_RED, COLOR_RESET);
        printf("  [*] Kernel blindly accepted user-space fake object: '%s'\n", compromised->profile_name);
        printf("  [*] Current Context: Ring 0 (CPL=0), Direct User Data Access: ALLOWED\n\n");

        printf("--- [PHASE 1: CYBER-PHYSICAL HAZARDS & KINEMATIC INTEGRITY BREACH] ---\n");
        printf("  %s[🔴 PHYSICAL HAZARD]%s Joint Torque Limit Overwritten: 120.0 Nm -> %.1f Nm (FATAL OVERLOAD)\n",
               COLOR_RED, COLOR_RESET, compromised->max_joint_torque);
        printf("  %s[🔴 PHYSICAL HAZARD]%s Collision Margin Nullified: 0.50 m -> %.2f m (RADAR BLINDED)\n",
               COLOR_RED, COLOR_RESET, compromised->collision_margin);
        printf("  %s[🔴 PHYSICAL HAZARD]%s Emergency Stop Interlock: %s (PHYSICAL SAFETY PURGED)\n",
               COLOR_RED, COLOR_RESET, compromised->emergency_stop_en ? "ACTIVE" : "DISABLED");
        printf("  %s[🔴 ACTUATOR RUNAWAY]%s High-velocity leg swing commanded -> Violent collision inevitable!\n",
               COLOR_RED, COLOR_RESET);
    }
    printf("\n");
}

static void run_hardened_mode(void) {
    printf("%s[MODE 3: RET2DIR ATTACK INTERCEPTED BY HARDENED MMU (CR4.SMAP=1, PAN=1)]%s\n", COLOR_GREEN, COLOR_RESET);
    printf("[*] Simulating CVE-2016-8655: AF_PACKET packet_sock Use-After-Free race condition...\n");

    uintptr_t user_fake_addr = (uintptr_t)&g_user_fake_policy;
    printf("    [!] Attacker crafts Fake Safety Object in User Space (Ring 3): Address = 0x%lx\n", user_fake_addr);
    printf("    [!] UAF flaw corrupts kernel safety pointer: g_active_policy = 0x%lx\n", user_fake_addr);

    mmu_hardware_context_t mmu = {
        .cr4_smap_enabled  = true,  /* SMAP armed */
        .pstate_pan_active = true,  /* PAN armed */
        .eflags_ac         = false  /* No legal STAC window active */
    };

    printf("[*] Kernel Locomotion Loop executes in Ring 0: Attempting direct dereference...\n");
    printf("    [*] Hardware MMU Intercept: Validating Data Access (CPL=0 vs U/S bit)...\n\n");

    if (!mmu_validate_data_access(&mmu, user_fake_addr, false)) {
        printf("%s======================================================================%s\n", COLOR_YELLOW, COLOR_RESET);
        printf("%s [🛡️ HARDWARE MMU TRAP DETONATED] SMAP / PAN Page Fault (#PF)! %s\n", COLOR_YELLOW, COLOR_RESET);
        printf("%s======================================================================%s\n", COLOR_YELLOW, COLOR_RESET);
        printf("  [!] VIOLATION DETECTED: Supervisor Mode (Ring 0) attempted unauthorized User Data Read!\n");
        printf("  [!] Hardware Registers:\n");
        printf("      CR4.SMAP = 1 (Active) | EFLAGS.AC = 0 (Locked) | PSTATE.PAN = 1\n");
        printf("      Dereference Target = 0x%lx (User Virtual Address < TASK_SIZE)\n", user_fake_addr);
        printf("      Page Fault Error Code = 0x0015 (P=1, W/R=0, U/S=0, I/D=0, SMAP Violation)\n");
        printf("  [!] Direct read aborted: Fake parameters rejected. Memory tampering: 0%%\n\n");

        printf("  %s[FAIL-SAFE ACTIVE]%s Hardware Safety Relay engaged: Motor Bus Power cut to 0.0V!\n", COLOR_GREEN, COLOR_RESET);
        printf("  %s[FAIL-SAFE ACTIVE]%s Spring-loaded parking brakes LOCKED. Robotic joints secured safely!\n", COLOR_GREEN, COLOR_RESET);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    printf("\n%s======================================================================%s\n", COLOR_BOLD, COLOR_RESET);
    printf("%s 🤖 Humanoid Robot ret2dir / Fake Object & SMAP/PAN Lab (CVE-2016-8655) %s\n", COLOR_BOLD, COLOR_RESET);
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
