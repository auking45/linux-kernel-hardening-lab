# RANDSTRUCT: Kernel Structure Member Layout Randomization

## 1. Overview and Threat Model

In traditional operating system kernels written in C, structure members are laid out in linear, sequential order according to their source code declarations. While deterministic layouts optimize compiler indexing and hardware memory access, they present an attractive and reliable target for exploitation.

Attackers routinely exploit fixed memory layouts through several techniques:
1. **Fixed-Offset Privilege Escalation Overwrites**:
   - The security credentials of every running task are maintained in `struct cred`, linked via `task_struct->cred`.
   - In standard kernel builds, members such as `uid`, `gid`, and `euid` reside at predictable offsets (e.g., offsets 8, 12, and 24).
   - Once an arbitrary write primitive is acquired, an attacker simply writes 32 bits of zeroes (`0x00000000`) into the known `uid` offset, elevating the current process to root.
2. **Function Pointer Hijacking**:
   - In structures consisting entirely of function pointers (`struct file_operations`, protocol dispatch vectors, driver hooks), an attacker overwrites a specific offset (such as `write` or `ioctl`) with a ROP gadget or malicious payload to seize control flow.

Crucially, standard KASLR (Kernel Address Space Layout Randomization) does not prevent fixed-offset exploitation. While KASLR randomizes the base address where a structure is allocated, **the relative internal offsets between structure members remain completely unchanged**.

To neutralize this class of attacks, the Linux kernel originally ported PaX/Grsecurity's **`CONFIG_GCC_PLUGIN_RANDSTRUCT`**, and in modern kernels (v6.x LTS) with Clang 16+, standardized native compiler layout randomization via **`-frandomize-layout-seed-file` (`CONFIG_RANDSTRUCT_FULL=y`)**.

---

## 2. Real-World Analogy: Randomizing Safe-Deposit Box Numbers

The principle of `CONFIG_RANDSTRUCT` can be compared to **reassigning safe-deposit box numbers in a bank vault**:

```
[ Vulnerable Approach (Baseline: CONFIG_RANDSTRUCT_NONE) ]
  Safe-deposit boxes arranged in strictly published blueprint order
  ┌────────────────────────────────────────────────────────┐
  │ [Box 1: Public Docs] │ [Box 2: Manager Key] │ [Box 3: Gold Bars]│
  └────────────────────────────────────────────────────────┘
                           ▲
          Burglar: "Drill Box 3 directly according to blueprint!" ──► Success!

[ Hardened Approach (Hardened: CONFIG_RANDSTRUCT) ]
  Bank randomly shuffles the internal locations for every building build
  ┌────────────────────────────────────────────────────────┐
  │ [Box 3: Wastebasket] │ [Box 1: Alarm Switch] │ [Box 2: Manager Key]│
  └────────────────────────────────────────────────────────┘
                           ▲
          Burglar: "Drills location 3 blindly!" ──► Alarm sounds & caught!
```

1. **Baseline Kernel (Predictable Vault)**:
   - A public blueprint (kernel headers and symbols) states that gold bars (`uid`) always reside at location 3 (Offset 16).
   - Even in pitch-black darkness (KASLR), the attacker measures 3 units from the vault entrance, drills through, and steals root privileges with 100% reliability.
2. **RANDSTRUCT-Hardened Kernel (Shuffled Vault)**:
   - Each kernel build rolls a 256-bit cryptographic die to rearrange the box locations.
   - When the attacker blindly drills location 3, they hit an alarm switch (kernel panic trap) or wastebasket (innocuous token), leaving `uid` untouched and preventing privilege escalation.

---

## 3. Architecture and Implementation Details

### 3.1 Targeted Structure Classes

Under `CONFIG_RANDSTRUCT`, the compiler automatically randomizes two major categories of structures (`security/Kconfig.hardening`):

1. **Explicitly Annotated Structures (`__randomize_layout`)**:
   - High-value target structures:
     - `struct cred` (`include/linux/cred.h`): `uid`, `gid`, `suid`, `euid`, `cap_effective`.
     - `struct file` (`include/linux/fs.h`): File handles and permissions.
     - `struct inode` (`include/linux/fs.h`): VFS inode metadata.
     - Key scheduling and namespace structures within `task_struct`.
2. **Pure Function Pointer Structures**:
   - Any structure composed entirely of function pointers (`struct file_operations`, `struct inode_operations`, `struct proto_ops`).
   - Automatically shuffled unless explicitly tagged with `__no_randomize_layout`.

### 3.2 256-bit Random Seed Generation

During the kernel build process (`scripts/basic/Makefile`), `scripts/gen-randstruct-seed.sh` generates a cryptographically random seed:
```bash
# scripts/gen-randstruct-seed.sh
SEED=$(od -A n -t x8 -N 32 /dev/urandom | tr -d ' \n')
echo "$SEED" > "$1"
HASH=$(echo -n "$SEED" | sha256sum | cut -d" " -f1)
echo "#define RANDSTRUCT_HASHED_SEED \"$HASH\"" > "$2"
```
1. 32 bytes (256 bits) of entropy are extracted from `/dev/urandom` and written to `scripts/basic/randstruct.seed`.
2. The seed is passed to the compiler:
   - **Clang (LLVM=1)**: `-frandomize-layout-seed-file=$(objtree)/scripts/basic/randstruct.seed`
   - **GCC Plugin**: `-fplugin=randomize_layout_plugin.so`
3. The compiler initializes a pseudo-random number generator (PRNG) seeded with each type's hash combined with the build seed, then executes a Fisher-Yates shuffle on the member declarations.

### 3.3 Comparison: GCC Plugin vs Clang 16+ Native

| Feature | GCC Plugin (`GCC_PLUGIN_RANDSTRUCT`) | Clang Native (`CC_HAS_RANDSTRUCT`) |
| :--- | :--- | :--- |
| **Architecture** | Out-of-tree host C++ plugin (`.so`) | Native compiler frontend option |
| **Bitfield Handling** | Splits bitfields into separate variables | Groups adjacent bitfields, shuffles order |
| **Performance Mode** | Supports `RANDSTRUCT_PERFORMANCE` | Defaults to full randomization |
| **Cross Compilation** | Requires host `gcc-plugin-dev` packages | Clang cross-compiles natively for ARM64 & x86_64 |

---

## 4. Interactive Architecture Simulator

Below is the dynamic simulator illustrating how fixed-offset overwrite attacks hit unintended targets when structure members are randomized:

<iframe src="../../assets/diagrams/randstruct/architecture.html" width="100%" height="680" frameborder="0" style="border-radius: 8px; border: 1px solid #3a506b; margin: 16px 0;"></iframe>

---

## 5. Lab Practice and Exploit Verification

### 5.1 Vulnerability Driver (`vuln_randstruct.c`)

Exposes `/proc/vuln_randstruct` (mode 0666) with:
- **Member Offset Inspection (`cat /proc/vuln_randstruct`)**:
  - Displays actual offsets for `struct victim_struct` and `struct cred`.
- **Fixed-Offset UID Attack (`echo exploit_fixed_uid > /proc/vuln_randstruct`)**:
  - Injects `0x00000000` into baseline offset 16.
  - In baseline, `g_victim.uid` becomes 0 (root privilege escalation).
  - In hardened kernel, offset 16 hits `session_token`; `g_victim.uid` remains 1000.
- **Fixed-Offset Function Pointer Hijack (`echo exploit_fixed_callback > /proc/vuln_randstruct`)**:
  - Injects malicious function pointer into baseline offset 40.
  - In hardened kernel, offset 40 misses `callback`, preventing hijack.

### 5.2 Exploit PoC (`exploit.c`)

Executed as non-privileged user `lab` (UID 1000):
```bash
/bin/exploit_randstruct
```
- **Baseline (Vulnerable)**:
  - Fixed-offset overwrite at offset 16 successfully changes `uid` to 0.
  - Returns exit code `42`.
- **Hardened (Protected)**:
  - `g_victim.uid` remains 1000; fixed-offset attack fails completely.
  - Returns exit code `0`.

---

## 6. Dual-Architecture Verification Matrix

| Architecture | Configuration | `victim->uid` Offset | `cred->uid` Offset | Fixed-Offset Exploit | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ARM64** | `CONFIG_RANDSTRUCT_FULL=y` | 🛡️ **Randomized (≠16)** | 🛡️ **Randomized (≠8)** | 🛡️ **Blocked (UID=1000)** | ✅ **PASS** |
| **ARM64** | `CONFIG_RANDSTRUCT_NONE=y` | ❌ **16 (Sequential)** | ❌ **8 (Sequential)** | ❌ **Succeeded (UID=0)** | ⚠️ **FAIL** |
| **x86_64** | `CONFIG_RANDSTRUCT_FULL=y` | 🛡️ **Randomized (≠16)** | 🛡️ **Randomized (≠8)** | 🛡️ **Blocked (UID=1000)** | ✅ **PASS** |
| **x86_64** | `CONFIG_RANDSTRUCT_NONE=y` | ❌ **16 (Sequential)** | ❌ **8 (Sequential)** | ❌ **Succeeded (UID=0)** | ⚠️ **FAIL** |

---

## 7. Production Guidelines and Considerations

1. **Performance Overhead**:
   - Shuffling members may slightly degrade L1/L2 cache locality, incurring approximately **0.5% to 1.5% CPU overhead**.
   - Negligible impact on typical cloud and mobile workloads relative to the security benefit.
2. **Out-of-Tree (OOT) Module Compatibility**:
   - Because member offsets differ on every build, out-of-tree kernel modules must be compiled against the exact same `randstruct.seed` generated during the original kernel build.
3. **Forensic Tools**:
   - Standard forensic tools (e.g., Volatility profiles) will fail unless supplied with the matching `vmlinux` debug symbols for that specific build.

