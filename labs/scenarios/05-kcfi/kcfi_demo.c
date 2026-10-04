/*
 * Linux Kernel Hardening Lab - Scenario 05
 * Kernel Control Flow Hijacking & Clang kCFI / Hardware IBT/BTI Defense
 *
 * Educational Cyber-Physical Simulation (Modeled after CVE-2021-4154 Type Confusion)
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

/* 
 * Clang kCFI 32-bit Type Signatures (Calculated from function prototypes)
 * void (*joint_kinematics_fn)(uint32_t joint_id, float target_angle, float max_velocity);
 */
#define KCFI_TYPE_KINEMATICS    0x5A8E3F21U  /* Expected prototype hash */
#define KCFI_TYPE_UNTAGGED      0x00000000U  /* Arbitrary / shellcode target */
#define KCFI_TYPE_MISMATCH      0x1B449A02U  /* Different signature */

/* Landing Pad Signature (Simulating x86 ENDBR64 / ARM64 BTI c) */
#define LANDING_PAD_ENDBR64     0xF30F1EFAU  /* x86-64 ENDBR64 instruction opcode */

/* Aligned Function Header with Preamble Type ID */
typedef struct __attribute__((packed)) {
    uint32_t kcfi_typeid;     /* 4-byte preamble type hash placed before entry */
    uint32_t landing_pad;     /* 4-byte landing pad (ENDBR64 / BTI c) */
} kcfi_preamble_t;

/* Simulated Robot Joint Actuator State */
typedef struct {
    uint32_t joint_id;             /* Joint ID: 0..11 */
    float    current_angle;        /* Current joint angle in radians */
    float    target_angle;         /* Commanded target angle */
    float    commanded_velocity;   /* Commanded velocity (rad/s): Normal <= 2.5 */
    char     status_msg[64];
} robot_joint_actuator_t;

/* Function pointer types */
typedef void (*joint_kinematics_fn)(robot_joint_actuator_t *actuator, float target_angle, float max_velocity);
typedef void (*arbitrary_payload_fn)(robot_joint_actuator_t *actuator);

/* Function Tables with kCFI Preamble Headers */
static const kcfi_preamble_t preamble_valid = {
    .kcfi_typeid = KCFI_TYPE_KINEMATICS,
    .landing_pad = LANDING_PAD_ENDBR64
};

static const kcfi_preamble_t preamble_attacker = {
    .kcfi_typeid = KCFI_TYPE_UNTAGGED,   /* No kCFI tag */
    .landing_pad = 0x90909090U           /* NOP sled / raw shellcode */
};

/* Legitimate kinematics control function */
static void safe_joint_kinematics(robot_joint_actuator_t *actuator, float target_angle, float max_velocity) {
    actuator->target_angle = target_angle;
    actuator->commanded_velocity = max_velocity;
    strncpy(actuator->status_msg, "Nominal Kinematics Trajectory Executed", 63);
}

/* Attacker hostile function: Causes gear shear and actuator burnout */
static void malicious_actuator_overload(robot_joint_actuator_t *actuator, float target_angle, float max_velocity) {
    (void)target_angle;
    (void)max_velocity;
    actuator->target_angle = 3.14159f;
    actuator->commanded_velocity = 48.5f; /* 48.5 rad/s: Lethal overload velocity */
    strncpy(actuator->status_msg, "CRITICAL: ACTUATOR VELOCITY OVERLOAD / GEAR SHEAR", 63);
}

/* Dynamic Function Dispatcher Container */
typedef struct {
    char name[32];
    joint_kinematics_fn dispatch_fn;
    const kcfi_preamble_t *preamble;
} joint_controller_ops_t;

/* Validate indirect branch using Clang kCFI and Hardware Landing Pad */
static bool verify_indirect_call(joint_controller_ops_t *ops, uint32_t expected_type, bool kcfi_enabled, bool ibt_enabled) {
    if (!kcfi_enabled && !ibt_enabled) {
        return true; /* Baseline: Unhardened indirect dispatch */
    }

    /* 1. Hardware IBT / BTI Check (Landing Pad Validation) */
    if (ibt_enabled) {
        if (!ops->preamble || ops->preamble->landing_pad != LANDING_PAD_ENDBR64) {
            printf("%s[HARDWARE FAULT: #CP / BTI]%s Indirect branch target missing valid landing pad (ENDBR64/BTI)!\n",
                   COLOR_YELLOW, COLOR_RESET);
            return false;
        }
    }

    /* 2. Clang kCFI Software Hash Check */
    if (kcfi_enabled) {
        if (!ops->preamble || ops->preamble->kcfi_typeid != expected_type) {
            printf("%s[KCFI TRAP: #UD / PANIC]%s Indirect call target type mismatch! Expected: 0x%08X, Found: 0x%08X\n",
                   COLOR_YELLOW, COLOR_RESET, expected_type, ops->preamble ? ops->preamble->kcfi_typeid : 0);
            return false;
        }
    }

    return true;
}

/* Simulation Functions */
static void run_normal_mode(void) {
    printf("%s[MODE 1: NORMAL INDIRECT DISPATCH WITH VALID KCFI TYPE MATCH]%s\n", COLOR_CYAN, COLOR_RESET);
    printf("[*] Initializing robot knee actuator controller ops...\n");

    robot_joint_actuator_t knee = {
        .joint_id = 4,
        .current_angle = 0.25f,
        .target_angle = 0.25f,
        .commanded_velocity = 0.0f,
        .status_msg = "Idle Ready"
    };

    joint_controller_ops_t ops = {
        .name = "Knee_Pitch_Controller",
        .dispatch_fn = safe_joint_kinematics,
        .preamble = &preamble_valid
    };

    printf("    -> Controller: %s\n", ops.name);
    printf("    -> Dispatch Target: %p\n", (void *)ops.dispatch_fn);
    printf("    -> Target kCFI Type Hash: 0x%08X (Expected: 0x%08X)\n",
           ops.preamble->kcfi_typeid, KCFI_TYPE_KINEMATICS);

    /* Verify and dispatch */
    bool allowed = verify_indirect_call(&ops, KCFI_TYPE_KINEMATICS, true, true);
    if (allowed) {
        ops.dispatch_fn(&knee, 0.85f, 1.8f);
        printf("%s[SUCCESS] Kinematics dispatched safely: Target=%.2f rad, Velocity=%.2f rad/s%s\n\n",
               COLOR_GREEN, knee.target_angle, knee.commanded_velocity, COLOR_RESET);
    }
}

static void run_attack_mode(void) {
    printf("%s[MODE 2: TYPE CONFUSION & INDIRECT CALL HIJACK WITHOUT CFI (CONFIG_CFI=n)]%s\n", COLOR_RED, COLOR_RESET);
    printf("[*] Simulating CVE-2021-4154: Kernel Type Confusion corrupting function pointer in ops struct...\n");

    robot_joint_actuator_t knee = {
        .joint_id = 4,
        .current_angle = 0.25f,
        .target_angle = 0.25f,
        .commanded_velocity = 0.0f,
        .status_msg = "Idle Ready"
    };

    /* Attacker hijacks function pointer to hostile overload function */
    joint_controller_ops_t hijacked_ops = {
        .name = "Compromised_Actuator_Ops",
        .dispatch_fn = malicious_actuator_overload,
        .preamble = &preamble_attacker /* Untagged payload */
    };

    printf("    [!] Attacker overwrites ops->dispatch_fn with hostile payload: %p\n", (void *)hijacked_ops.dispatch_fn);
    printf("    [!] Baseline kernel executes: (*ops->dispatch_fn)(actuator, target, vel) without validation...\n");

    /* Execute without CFI */
    hijacked_ops.dispatch_fn(&knee, 0.85f, 1.8f);

    printf("\n%s======================================================================%s\n", COLOR_RED, COLOR_RESET);
    printf("%s [💥 CRITICAL EXPLOIT DETONATION] Control Flow Hijacking Succeeded! %s\n", COLOR_RED, COLOR_RESET);
    printf("%s======================================================================%s\n", COLOR_RED, COLOR_RESET);
    printf("  [*] Forward-edge indirect branch hijacked to untrusted memory!\n");
    printf("  [*] Current Context: Ring 0 Kernel Execution (Arbitrary Function Detonated)\n\n");

    printf("--- [PHASE 1: CYBER-PHYSICAL HAZARDS & MECHANICAL DAMAGE] ---\n");
    printf("  %s[🔴 PHYSICAL HAZARD]%s Commanded Velocity: 1.8 rad/s -> %.1f rad/s (LETHAL OVERSPEED)\n",
           COLOR_RED, COLOR_RESET, knee.commanded_velocity);
    printf("  %s[🔴 PHYSICAL HAZARD]%s Joint Harmonic Drive: Mechanical Gear Teeth Sheared!\n",
           COLOR_RED, COLOR_RESET);
    printf("  %s[🔴 PHYSICAL HAZARD]%s Stator Coil Overcurrent: Brushless Servo Motor Burnout!\n\n",
           COLOR_RED, COLOR_RESET);
}

static void run_hardened_mode(void) {
    printf("%s[MODE 3: HIJACK ATTEMPT INTERCEPTED BY CLANG KCFI & HARDWARE IBT/BTI]%s\n", COLOR_GREEN, COLOR_RESET);
    printf("[*] Initializing Hardened Kernel Environment (CONFIG_CFI_CLANG=y, CONFIG_X86_KERNEL_IBT=y)...\n");

    joint_controller_ops_t hijacked_ops = {
        .name = "Compromised_Actuator_Ops",
        .dispatch_fn = malicious_actuator_overload,
        .preamble = &preamble_attacker
    };

    printf("[*] Kernel initiates indirect branch to ops->dispatch_fn (%p)...\n", (void *)hijacked_ops.dispatch_fn);
    printf("[*] Clang kCFI and CPU Instruction Tracker inspect branch target...\n\n");

    /* Verification enabled */
    bool allowed = verify_indirect_call(&hijacked_ops, KCFI_TYPE_KINEMATICS, true, true);

    if (!allowed) {
        printf("%s======================================================================%s\n", COLOR_YELLOW, COLOR_RESET);
        printf("%s [🛡️ CONTROL FLOW VIOLATION DETECTED] Clang kCFI Type Hash Abort! %s\n", COLOR_YELLOW, COLOR_RESET);
        printf("%s======================================================================%s\n", COLOR_YELLOW, COLOR_RESET);
        printf("  [!] CFI INTERCEPTION FORENSICS:\n");
        printf("      Expected Type Hash  = 0x%08X (void (*)(actuator_t*, float, float))\n", KCFI_TYPE_KINEMATICS);
        printf("      Found Type Hash     = 0x%08X (Untagged / Mismatched Function Signature)\n", hijacked_ops.preamble->kcfi_typeid);
        printf("      Hardware LandingPad = 0x%08X (Invalid / Missing ENDBR64)\n", hijacked_ops.preamble->landing_pad);
        printf("  [!] Kernel Action: Immediate #UD Trap -> Kernel Panic / Oops triggered.\n");
        printf("  [!] Indirect Call Executed: 0%%. Hostile payload neutralized.\n\n");

        printf("  %s[FAIL-SAFE ACTIVE]%s Hardware Safety Relay engaged: Motor Bus Power cut to 0.0V!\n", COLOR_GREEN, COLOR_RESET);
        printf("  %s[FAIL-SAFE ACTIVE]%s Actuator parking brake clamped. Robotic limbs immobilized safely!\n", COLOR_GREEN, COLOR_RESET);
    }
    printf("\n");
}

int main(int argc, char **argv) {
    printf("\n%s======================================================================%s\n", COLOR_BOLD, COLOR_RESET);
    printf("%s 🤖 Humanoid Robot Control Flow Hijacking & Clang kCFI Lab (CVE-2021-4154) %s\n", COLOR_BOLD, COLOR_RESET);
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
