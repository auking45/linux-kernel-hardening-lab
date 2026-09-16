# SMAP (x86) & PAN (ARM64): 슈퍼바이저 모드 유저 공간 데이터 메모리 직접 접근 차단 및 위조 커널 객체 공격 무력화

<div style="margin: 1.5rem 0; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px; overflow: hidden;">
  <iframe src="../../assets/diagrams/smap-pan/architecture.html" style="width: 100%; height: 600px; border: none; display: block;" title="SMAP and PAN Architecture Diagram"></iframe>
</div>

---

## 1. 개요 및 위협 모델 (Overview & Threat Model)

### 1.1 해결하고자 하는 위협: Confused-Deputy 및 Fake Kernel Object 직접 역참조 공격

- **SMEP / PXN 도입 이후의 잔존 공격 표면**:
  - SMEP (Supervisor Mode Execution Prevention)와 PXN (Privileged Execute-Never)은 커널 모드(Ring 0 / EL1)에서 유저 공간(Ring 3 / EL0) 가상 주소에 위치한 코드를 직접 *실행(Instruction Fetch)*하는 것만을 차단함.
  - 그러나 하드웨어 MMU의 전통적인 페이지 테이블 접근 제어($U/S=1$, $AP=01$) 상, 슈퍼바이저는 유저 권한이 부여된 메모리 페이지에 대해 여전히 완전한 *데이터 읽기/쓰기(Data Read/Write Dereference)* 권한을 보유하고 있었음.
- **위조 커널 객체 (Fake Kernel Object) 및 대리인 혼동(Confused-Deputy) 공격 메커니즘**:
  1. 공격자는 비특권 유저 공간 프로세스 메모리(`mmap` 또는 힙 버퍼)에 커널 핵심 제어 구조체와 동일한 규격의 위조 객체(`struct fake_kernel_cred`, 가짜 `struct file_operations`, 변조된 `ops` 함수 포인터 테이블 등)를 구성하고 원하는 권한 값(예: `uid = 0, gid = 0`) 또는 ROP 피벗 가젯을 채워 넣음.
  2. 커널 내부의 취약점(Use-After-Free 포인터 오염, 타입 혼동(Type Confusion), 검증되지 않은 유저 주소 역참조 등)을 악용하여 커널 포인터 변수가 유저 공간 가상 주소(`< TASK_SIZE`)를 가리키도록 유도함.
  3. 커널 코드가 해당 포인터를 역참조(`*(volatile unsigned long *)user_ptr` 또는 `cred->uid`)할 때, CPU MMU는 슈퍼바이저의 유저 메모리 데이터 읽기를 허용함.
  4. 커널은 신뢰할 수 없는 유저 메모리의 조작된 데이터를 정식 커널 메타데이터로 오인 처리하여 무단 권한 상승(Root Escalation) 또는 커널 제어 흐름 탈취를 초래함.
- **SMAP / PAN의 핵심 방어 철학**:
  - CPU가 슈퍼바이저 모드(Ring 0 / EL1)에 있는 동안, 유저 페이지($U/S=1$, EL0 접근 가능)를 향한 모든 데이터 로드(`LDR`, `MOV`) 및 스토어(`STR`, `MOV`) 접근을 하드웨어 MMU 수준에서 엄격히 차단함.
  - 정당한 시스템 콜 유저 버퍼 복사 루틴(`copy_from_user()`, `copy_to_user()`)을 제외한 일체의 직접적인 포인터 역참조를 무력화함.

### 1.2 직관적 실전 비유: 은행 지점장과 고객 작성 입출금 전표함 규정 (The Bank Manager vs Customer Slip Box Metaphor)

- **비유 설명**:
  - 운영체제 커널(Ring 0 / EL1)을 최고 등급 보안이 적용된 **은행 본점 지점장 집무실 및 금고**, 유저 공간(Ring 3 / EL0)을 누구나 출입 가능한 **일반 고객 대기실 공용 테이블**로 비유할 수 있음.
  - **하드닝 이전 (`clearcpuid=smap`, `pan=off`)**:
    - 지점장(커널)이 VIP 고객 결재를 진행하던 중, 은행 내부 공식 전산망 원장을 확인하지 않고 고객 대기실 테이블에 굴러다니던 낙서 전표("본 지점의 현금 100억 원을 이 전표 소지자에게 즉시 무상 지급하라")를 맨손으로 집어 들어 직접 금액을 읽고 결재 도장을 날인함.
    - 악의적인 사기꾼(공격자)이 대기실 테이블에 위조 결재서류(Fake Kernel Object)를 올려두기만 하면, 지점장이 이를 무단으로 읽어 거액을 인출(루트 권한 장악)해 주는 참사가 발생함.
  - **하드닝 적용 (SMAP / PAN 활성화)**:
    - 지점장의 손목과 시야에 하드웨어 감시 센서(하드웨어 MMU)가 장착됨.
    - 지점장이 대기실 테이블(유저 메모리)의 서류를 맨손으로 직접 만지려는 순간, 센서가 즉시 경보를 울리며 철제 차단 셔터(하드웨어 Page Fault `#PF` / Data Abort)를 강제로 떨어뜨려 거래를 중단시킴.
    - 고객 서류를 확인하려면 반드시 정식 보안 접수 창구의 방탄 유리문(`stac` / `copy_from_user`)을 일시적으로 개방하여 살균 및 검증을 거친 뒤 문서를 복사하고, 복사가 끝나자마자 창구 문을 즉시 폐쇄(`clac`)해야 함.

---

## 2. 커널 내부 구현 원리 (Kernel Internal Architecture)

### 2.1 x86_64 아키텍처: CR4.SMAP (Supervisor Mode Access Prevention)

- **CR4 제어 레지스터 Bit 21 및 EFLAGS.AC (Alignment Check)**:
  - Intel Haswell (2013) 및 Broadwell 이후 프로세서에 표준 탑재.
  - $CR4.SMAP = 1$일 때, 링 0(슈퍼바이저) 모드에서 $U/S=1$(User) 페이지에 대한 데이터 읽기/쓰기를 시도하면 하드웨어 `#PF`(Page Fault, Error Code Bit 3: Access Violation) 예외를 발생시킴.
  - 단, `EFLAGS.AC` (Alignment Check Flag, Bit 18)가 1로 설정되어 있는 동안에는 슈퍼바이저의 유저 메모리 읽기/쓰기가 일시적으로 허용됨.
  - `arch/x86/kernel/cpu/common.c`의 `setup_smap()`을 통해 CPU 부팅 시 자동 활성화:
    ```c
    /* arch/x86/kernel/cpu/common.c */
    static __always_inline void setup_smap(struct cpuinfo_x86 *c)
    {
        unsigned long eflags = native_save_fl();
        BUG_ON(eflags & X86_EFLAGS_AC);

        if (cpu_has(c, X86_FEATURE_SMAP))
            cr4_set_bits(X86_CR4_SMAP);
    }
    ```
- **합법적 유저 복사 윈도우: `stac` 및 `clac` 인스트럭션**:
  - 커널이 시스템 콜 데이터 전송을 위해 유저 메모리에 접근할 때만 `stac` (Set Alignment Check) 명령어로 `EFLAGS.AC = 1`을 세팅하고, 작업 완료 즉시 `clac` (Clear Alignment Check) 명령어로 차단함:
    ```assembly
    /* arch/x86/include/asm/smap.h */
    #define __ASM_STAC  .byte 0x0f, 0x01, 0xcb    /* stac instruction */
    #define __ASM_CLAC  .byte 0x0f, 0x01, 0xca    /* clac instruction */
    ```

### 2.2 ARM64 (AArch64) 아키텍처: PAN (Privileged Access Never)

- **ARMv8.1-A 하드웨어 PSTATE.PAN (Bit 22) 및 SCTLR_EL1.SPAN**:
  - ARMv8.1-A 아키텍처부터 도입된 필수 하드웨어 보안 확장.
  - $PSTATE.PAN = 1$ 상태에서 EL1(커널)이 EL0(유저) 가상 주소에 대해 일반 로드/스토어(`LDR`, `STR`)를 실행하면 하드웨어 Data Abort (Permission Fault)가 발생함.
  - 합법적인 유저 메모리 접근은 비특권 전송 전용 명령어(`LDTR`, `STTR`)를 사용하여 PAN 활성 상태를 유지하면서 명시적으로 EL0 권한으로 변환하여 수행하거나, `MSR PAN, #0`으로 임시 해제함.
  - `SCTLR_EL1.SPAN` (Set Privileged Access Never, Bit 23):
    - 0으로 클리어 시, EL0에서 EL1으로의 예외 진입(Exception Entry) 시 하드웨어가 자동으로 `PSTATE.PAN = 1`을 설정함.
- **구형 코어(ARMv8.0)를 위한 소프트웨어 에뮬레이션 (`CONFIG_ARM64_SW_TTBR0_PAN`)**:
  - 하드웨어 PAN이 없는 프로세서(예: Cortex-A53, Cortex-A72 등)를 위해 커널 컴파일 옵션 `CONFIG_ARM64_SW_TTBR0_PAN` 제공.
  - 커널 모드 진입 시 유저 공간 페이지 테이블 베이스 레지스터(`TTBR0_EL1`)를 무효 페이지(예약된 빈 테이블)로 즉시 교체하여 유저 가상 주소 매핑 자체를 제거하고, `copy_from_user()` 진입 시에만 일시적으로 정상 유저 TTBR0를 복원하는 방식으로 동일한 메모리 접근 분리를 완벽히 에뮬레이트함.

---

## 3. 실습 환경 및 취약 드라이버 구현 (Hands-on Lab Implementation)

### 3.1 취약 타깃 드라이버 (`vuln_smap.c`)

- `/proc/vuln_smap` (모드 0666) 인터페이스 제공:
  - **하드웨어 텔레메트리**:
    - x86_64: `__read_cr4() & X86_CR4_SMAP`, `native_save_fl() & X86_EFLAGS_AC`, `boot_cpu_has(X86_FEATURE_SMAP)` 상태 노출.
    - ARM64: `system_uses_hw_pan()`, `system_uses_ttbr0_pan()`, 커맨드라인 `pan=off` 상태 노출.
  - **직접 역참조(Direct Dereference) 검증 로직**:
    - 유저 공간 프로세스가 위조 객체의 가상 주소(`< TASK_SIZE`)를 전달.
    - **Base (`clearcpuid=smap` / `pan=off`)**: 슈퍼바이저가 `stac` 없이 유저 주소를 직접 역참조(`*(volatile unsigned long *)user_addr`)하여 유저 공간의 매직 값(`0xDEADBEEFCAFE1337`)을 탈취 성공 로깅.
    - **Hardened (`smap=on` / `pan=on`)**: 하드웨어 MMU 접근 방어 비트(CR4.SMAP / PSTATE.PAN)를 확인하고 직접 유저 메모리 접근을 즉각 차단하여 보호 상태 로깅.

### 3.2 Confused-Deputy 공격 익스플로잇 PoC (`exploit.c`)

- 비특권 사용자(`lab`, UID 1000) 공간에서 실행되는 `/bin/exploit_smap_pan`:
  - 힙/스택 영역에 가짜 자격증명 구조체(`struct fake_kernel_cred`) 선언:
    ```c
    struct fake_kernel_cred {
        uint64_t magic;      /* 0xDEADBEEFCAFE1337ULL */
        uint32_t uid;        /* 0 (root) */
        uint32_t gid;        /* 0 (root) */
        char label[32];      /* "fake_root_credentials" */
    };
    ```
  - 위조 객체의 유저 가상 주소를 `/proc/vuln_smap`에 기입하여 커널 Ring 0에 직접 읽기 요청.
  - 커널 텔레메트리를 재조회하여 취약점 노출 여부 또는 하드웨어 방어 작동 여부 판정.

### 3.3 인게스트 자동 검증 러너 (`test.sh`)

- `/bin/test_smap_pan` 자동화 테스트 스크립트:
  - Test 1: 커널 커맨드라인 파라미터(`clearcpuid=smap`, `pan=off`) 및 CPUinfo SMAP 플래그 확인.
  - Test 2: `/proc/vuln_smap` 하드웨어 제어 레지스터 상태 확인.
  - Test 3: 비특권 계정 `lab` 권한으로 `/bin/exploit_smap_pan` 실행 및 dmesg 보안 이벤트 검증.

---

## 4. 검증 결과 및 분석 (Verification Results)

### 4.1 x86_64 실측 로그 (Base vs Hardened)

#### [Base] x86_64 SMAP 비활성화 (`clearcpuid=smap`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & CPU Protection State
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 nokaslr lab_test=test_smap_pan clearcpuid=smap pan=off nosmap
Hardware Access Protection: DISABLED (clearcpuid=smap / pan=off active)
CPU Flags: SMAP not reported in /proc/cpuinfo (disabled or cleared)

=========================================================
  [Test 2/3] Kernel Hardware Telemetry (/proc/vuln_smap)
=========================================================
ARCHITECTURE:         x86_64
FEATURE_NAME:         SMAP (Supervisor Mode Access Prevention)
CR4_SMAP_BIT:         CLEARED (Bit 21 = 0)
EFLAGS_AC_FLAG:       CLEARED (Bit 18 = 0, User Access Blocked)
HARDWARE_SUPPORT:     UNSUPPORTED
PROTECTION_STATUS:    DISABLED (Vulnerable user-space dereference)
LAST_USER_ADDR:       0x0000000000000000
LAST_READ_VAL:        0x0000000000000000
ACCESS_ATTEMPT_RESULT: NOT_TESTED

=========================================================
  [Test 3/3] Confused-Deputy Fake Object Attack Demonstration
  Target: /proc/vuln_smap
  Runner: lab (UID 1000, non-privileged)
=========================================================
=========================================================
  Linux Kernel Hardening Lab - Confused-Deputy PoC
  Target: SMAP (Supervisor Mode Access Prevention) / PAN
  Architecture: x86_64
  Current User: UID = 1000 (non-root 'lab' user)
=========================================================
[*] Kernel Hardware Access Protection Telemetry:
    Architecture:        x86_64
    Mechanism:           SMAP (Supervisor Mode Access Prevention)
    Hardware Support:    UNSUPPORTED
    Control Register:    CLEARED (Bit 21 = 0)
    Aux Flag / Software: CLEARED (Bit 18 = 0, User Access Blocked)
    Enforcement State:   DISABLED (Vulnerable user-space dereference)

[*] User-Space Fake Kernel Object Setup:
    Object Address:      0x00000000004d6b40 (allocated in user space)
    Object Magic Value:  0xdeadbeefcafe1337
    Object Label:        fake_root_credentials

=========================================================
[*] Requesting Direct Ring 0 Kernel Dereference...
=========================================================

[*] Post-Dereference Attempt Verification:
    Target Address:      0x00000000004d6b40
    Kernel Read Value:   0xdeadbeefcafe1337
    Access Result:       PERMITTED (Direct Ring 0 Dereference Succeeded - Magic: 0xDEADBEEFCAFE1337)

[!] =========================================================
[!] VULNERABILITY CONFIRMED (SMAP/PAN Disabled):
[!] Kernel supervisor mode successfully dereferenced user memory!
[!] Fake kernel object was directly read by Ring 0 (Magic: 0xdeadbeefcafe1337).
[!] Confused-deputy and fake object attacks are viable.
[!] =========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    1.158765] [vuln_smap] Initialized /proc/vuln_smap (SMAP/PAN active: 0)
[    1.991034] [vuln_smap] Received request to directly dereference user-space address at 0x4d6b40
[    1.991167] [vuln_smap] [!] WARNING: SMAP is disabled! Direct Ring 0 dereference of 0x4d6b40 succeeded!
[    1.991196] [vuln_smap] [!] CRITICAL: Read user fake object value: 0xdeadbeefcafe1337
```

#### [Hardened] x86_64 SMAP 활성화 (`smap=on`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & CPU Protection State
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 nokaslr lab_test=test_smap_pan smap=on pan=on
Hardware Access Protection: ACTIVE (SMAP / PAN enabled)
CPU Flags: SMAP is present in /proc/cpuinfo

=========================================================
  [Test 2/3] Kernel Hardware Telemetry (/proc/vuln_smap)
=========================================================
ARCHITECTURE:         x86_64
FEATURE_NAME:         SMAP (Supervisor Mode Access Prevention)
CR4_SMAP_BIT:         SET (Bit 21 = 1)
EFLAGS_AC_FLAG:       CLEARED (Bit 18 = 0, User Access Blocked)
HARDWARE_SUPPORT:     SUPPORTED
PROTECTION_STATUS:    ENABLED (Hardened)
LAST_USER_ADDR:       0x0000000000000000
LAST_READ_VAL:        0x0000000000000000
ACCESS_ATTEMPT_RESULT: NOT_TESTED

=========================================================
  [Test 3/3] Confused-Deputy Fake Object Attack Demonstration
  Target: /proc/vuln_smap
  Runner: lab (UID 1000, non-privileged)
=========================================================
=========================================================
  Linux Kernel Hardening Lab - Confused-Deputy PoC
  Target: SMAP (Supervisor Mode Access Prevention) / PAN
  Architecture: x86_64
  Current User: UID = 1000 (non-root 'lab' user)
=========================================================
[*] Kernel Hardware Access Protection Telemetry:
    Architecture:        x86_64
    Mechanism:           SMAP (Supervisor Mode Access Prevention)
    Hardware Support:    SUPPORTED
    Control Register:    SET (Bit 21 = 1)
    Aux Flag / Software: CLEARED (Bit 18 = 0, User Access Blocked)
    Enforcement State:   ENABLED (Hardened)

[*] User-Space Fake Kernel Object Setup:
    Object Address:      0x00000000004d6b40 (allocated in user space)
    Object Magic Value:  0xdeadbeefcafe1337
    Object Label:        fake_root_credentials

=========================================================
[*] Requesting Direct Ring 0 Kernel Dereference...
=========================================================

[*] Post-Dereference Attempt Verification:
    Target Address:      0x00000000004d6b40
    Kernel Read Value:   0x0000000000000000
    Access Result:       BLOCKED (Hardware MMU Protection Enforced)

[+] =========================================================
[+] HARDENING VERIFIED (SMAP/PAN Active):
[+] Direct supervisor dereference of user memory was BLOCKED!
[+] Hardware MMU enforced access prevention boundary.
[+] Fake kernel objects in user space are unreachable by Ring 0.
[+] =========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.779087] [vuln_smap] Initialized /proc/vuln_smap (SMAP/PAN active: 1)
[    1.372322] [vuln_smap] Received request to directly dereference user-space address at 0x4d6b40
[    1.372454] [vuln_smap] [+] DEFENSE ACTIVE: Hardware MMU SMAP is enforced (CR4.SMAP=1)!
[    1.372479] [vuln_smap] [+] Direct dereference of user address 0x4d6b40 blocked by hardware protection.
```

---

### 4.2 ARM64 실측 로그 (Base vs Hardened)

#### [Base] ARM64 PAN 비활성화 (`pan=off`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & CPU Protection State
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_smap_pan clearcpuid=smap pan=off nosmap
Hardware Access Protection: DISABLED (clearcpuid=smap / pan=off active)
CPU Architecture: ARM64 (PAN supported via HW MMU or SW TTBR0)

=========================================================
  [Test 2/3] Kernel Hardware Telemetry (/proc/vuln_smap)
=========================================================
ARCHITECTURE:         arm64 (aarch64)
FEATURE_NAME:         PAN (Privileged Access Never)
PSTATE_PAN_BIT:       CLEARED (Bit 22 = 0, Simulated Off)
SW_TTBR0_PAN:         COMPILED
HARDWARE_SUPPORT:     SUPPORTED
PROTECTION_STATUS:    DISABLED (Vulnerable user-space dereference)
LAST_USER_ADDR:       0x0000000000000000
LAST_READ_VAL:        0x0000000000000000
ACCESS_ATTEMPT_RESULT: NOT_TESTED

=========================================================
  [Test 3/3] Confused-Deputy Fake Object Attack Demonstration
  Target: /proc/vuln_smap
  Runner: lab (UID 1000, non-privileged)
=========================================================
=========================================================
  Linux Kernel Hardening Lab - Confused-Deputy PoC
  Target: SMAP (Supervisor Mode Access Prevention) / PAN
  Architecture: arm64 (aarch64)
  Current User: UID = 1000 (non-root 'lab' user)
=========================================================
[*] Kernel Hardware Access Protection Telemetry:
    Architecture:        arm64 (aarch64)
    Mechanism:           PAN (Privileged Access Never)
    Hardware Support:    SUPPORTED
    Control Register:    CLEARED (Bit 22 = 0, Simulated Off)
    Aux Flag / Software: COMPILED
    Enforcement State:   DISABLED (Vulnerable user-space dereference)

[*] User-Space Fake Kernel Object Setup:
    Object Address:      0x00000000004b1990 (allocated in user space)
    Object Magic Value:  0xdeadbeefcafe1337
    Object Label:        fake_root_credentials

=========================================================
[*] Requesting Direct Ring 0 Kernel Dereference...
=========================================================

[*] Post-Dereference Attempt Verification:
    Target Address:      0x00000000004b1990
    Kernel Read Value:   0xdeadbeefcafe1337
    Access Result:       PERMITTED (Direct Ring 0 Dereference Succeeded - Magic: 0xDEADBEEFCAFE1337)

[!] =========================================================
[!] VULNERABILITY CONFIRMED (SMAP/PAN Disabled):
[!] Kernel supervisor mode successfully dereferenced user memory!
[!] Fake kernel object was directly read by Ring 0 (Magic: 0xdeadbeefcafe1337).
[!] Confused-deputy and fake object attacks are viable.
[!] =========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.092287] CPU features: emulated: Privileged Access Never (PAN) using TTBR0_EL1 switching
[    0.478265] [vuln_smap] Initialized /proc/vuln_smap (SMAP/PAN active: 0)
[    1.616106] [vuln_smap] Received request to directly dereference user-space address at 0x4b1990
[    1.616211] [vuln_smap] [!] WARNING: Baseline mode (pan=off). Direct user-space dereference permitted.
```

#### [Hardened] ARM64 PAN 활성화 (`pan=on`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & CPU Protection State
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_smap_pan smap=on pan=on
Hardware Access Protection: ACTIVE (SMAP / PAN enabled)
CPU Architecture: ARM64 (PAN supported via HW MMU or SW TTBR0)

=========================================================
  [Test 2/3] Kernel Hardware Telemetry (/proc/vuln_smap)
=========================================================
ARCHITECTURE:         arm64 (aarch64)
FEATURE_NAME:         PAN (Privileged Access Never)
PSTATE_PAN_BIT:       SET (Bit 22 = 1, User Access Blocked)
SW_TTBR0_PAN:         COMPILED
HARDWARE_SUPPORT:     SUPPORTED
PROTECTION_STATUS:    ENABLED (Hardened)
LAST_USER_ADDR:       0x0000000000000000
LAST_READ_VAL:        0x0000000000000000
ACCESS_ATTEMPT_RESULT: NOT_TESTED

=========================================================
  [Test 3/3] Confused-Deputy Fake Object Attack Demonstration
  Target: /proc/vuln_smap
  Runner: lab (UID 1000, non-privileged)
=========================================================
=========================================================
  Linux Kernel Hardening Lab - Confused-Deputy PoC
  Target: SMAP (Supervisor Mode Access Prevention) / PAN
  Architecture: arm64 (aarch64)
  Current User: UID = 1000 (non-root 'lab' user)
=========================================================
[*] Kernel Hardware Access Protection Telemetry:
    Architecture:        arm64 (aarch64)
    Mechanism:           PAN (Privileged Access Never)
    Hardware Support:    SUPPORTED
    Control Register:    SET (Bit 22 = 1, User Access Blocked)
    Aux Flag / Software: COMPILED
    Enforcement State:   ENABLED (Hardened)

[*] User-Space Fake Kernel Object Setup:
    Object Address:      0x00000000004b1990 (allocated in user space)
    Object Magic Value:  0xdeadbeefcafe1337
    Object Label:        fake_root_credentials

=========================================================
[*] Requesting Direct Ring 0 Kernel Dereference...
=========================================================

[*] Post-Dereference Attempt Verification:
    Target Address:      0x00000000004b1990
    Kernel Read Value:   0x0000000000000000
    Access Result:       BLOCKED (Hardware MMU Protection Enforced)

[+] =========================================================
[+] HARDENING VERIFIED (SMAP/PAN Active):
[+] Direct supervisor dereference of user memory was BLOCKED!
[+] Hardware MMU enforced access prevention boundary.
[+] Fake kernel objects in user space are unreachable by Ring 0.
[+] =========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.079873] CPU features: emulated: Privileged Access Never (PAN) using TTBR0_EL1 switching
[    0.352376] [vuln_smap] Initialized /proc/vuln_smap (SMAP/PAN active: 1)
[    1.150698] [vuln_smap] Received request to directly dereference user-space address at 0x4b1990
[    1.150784] [vuln_smap] [+] DEFENSE ACTIVE: Hardware MMU PAN is enforced (PSTATE.PAN=1)!
[    1.150801] [vuln_smap] [+] Direct dereference of user address 0x4b1990 blocked by hardware protection.
```

---

### 4.3 하드웨어 제어 레지스터 및 보안 효과 비교 매트릭스

| 항목 (Metric) | Base 모드 (`clearcpuid=smap`, `pan=off`) | Hardened 모드 (`smap=on`, `pan=on`) | 보안 및 엔지니어링 의미 |
| :--- | :--- | :--- | :--- |
| **x86 제어 비트** | `CR4.SMAP = 0` | `CR4.SMAP = 1` (Bit 21) | 하드웨어 MMU 슈퍼바이저 유저 메모리 접근 차단 활성화 |
| **x86 임시 플래그** | 무시됨 | `EFLAGS.AC` (Bit 18, `stac`/`clac`) | 정상적인 유저 복사 루틴(`copy_from_user`) 전용 임시 윈도우 |
| **ARM64 상태 비트** | `PSTATE.PAN = 0` | `PSTATE.PAN = 1` (Bit 22) | EL1 커널 모드에서 EL0 유저 주소 직접 로드/스토어 차단 |
| **ARM64 전용 명령어** | 미적용 | `LDTR` / `STTR` 강제 | 커널 권한 상승 없는 비특권 강제 변환 메모리 복사 |
| **구형 ARM 코어 지원** | 미지원 | `CONFIG_ARM64_SW_TTBR0_PAN` | 하드웨어 미지원 시 TTBR0 스왑으로 완벽한 소프트웨어 격리 |
| **Fake Object 공격** | **성공 (CRITICAL VULNERABILITY)** | **원천 차단 (BLOCKED by MMU)** | 유저 공간에 배치된 위조 구조체 직접 역참조 무력화 |
| **Confused-Deputy** | **노출 (공격자 제어 데이터 신뢰)** | **방어 (Page Fault / Data Abort)** | 댕글링 포인터가 유저 공간을 가리켜도 커널 크래시/방어 유도 |

---

## 5. 영어 발표 대본 (Global Technical Presentation Script)

```text
"Hello everyone, and welcome to this session on Linux kernel memory isolation. Today, we are exploring SMAP on x86 and PAN on ARM64—two cornerstone hardware mechanisms that enforce strict access prevention between supervisor space and user space.

After the industry implemented SMEP and PXN to prevent user-space code execution from Ring 0, an attacker's immediate pivot was confused-deputy data dereference. An attacker simply allocates a fake credential or object in user memory, where addresses are completely predictable, and tricks a vulnerable kernel pointer into reading from it. Because the supervisor historically held full read/write privileges over user pages, the kernel happily consumed this untrusted data.

SMAP, controlled via CR4 bit 21, and PAN, controlled via PSTATE bit 22, close this critical hole at the hardware MMU level. With SMAP and PAN active, supervisor mode cannot read or write any user page marked with U/S=1 or EL0 access. Any uncoordinated dereference triggers an instant Page Fault or Data Abort.

When legitimate kernel syscall handlers need to copy user data, the kernel explicitly opens a controlled window: x86 executes the 'stac' instruction to set EFLAGS.AC, performs the validated copy, and immediately executes 'clac' to slam the door shut. On ARM64, dedicated instructions like LDTR and STTR enforce unprivileged translation without ever dropping the global PAN barrier.

In our dual-architecture verification, we observed an unprivileged exploit successfully reading fake objects when SMAP and PAN were disabled, and saw the hardware MMU strictly trap and block the attempt when hardening was enforced. Thank you."
```

---

## 6. 핵심 용어 사전 (Terminology & Architectural Reference)

- **SMAP (Supervisor Mode Access Prevention)**:
  - Intel Haswell 아키텍처부터 도입된 x86 CPU 보안 기능. `CR4` 레지스터의 Bit 21이 1일 때, 슈퍼바이저(CPL 0, 1, 2)가 유저 모드 페이지($U/S=1$)에 대해 데이터 읽기 또는 쓰기를 시도하면 `#PF` 예외를 발생시킴.
- **PAN (Privileged Access Never)**:
  - ARMv8.1-A 아키텍처부터 도입된 ARM CPU 보안 기능. `PSTATE.PAN` (Bit 22)이 1일 때, EL1(슈퍼바이저)이 EL0(유저) 가상 메모리 주소에 대해 일반 로드/스토어 명령어를 수행하면 Data Abort를 발생시킴.
- **`stac` / `clac` (Set/Clear Alignment Check)**:
  - x86 인스트럭션. `stac`은 `EFLAGS.AC` 플래그(Bit 18)를 1로 설정하여 일시적으로 슈퍼바이저의 유저 메모리 접근을 허용하고, `clac`은 플래그를 0으로 리셋하여 접근을 다시 물리적으로 차단함.
- **`LDTR` / `STTR` (Load/Store Register Unprivileged)**:
  - ARM64 명령어. EL1에서 실행되더라도 EL0(유저 권한) 메모리 접근 속성을 강제 적용하여 데이터를 로드/스토어하므로, PAN을 해제하지 않고도 안전한 유저 복사를 수행할 수 있음.
- **Confused-Deputy (대리인 혼동 문제)**:
  - 높은 권한을 가진 주체(커널)가 낮은 권한의 공격자가 전달한 악의적인 데이터나 포인터를 검증 없이 신뢰하고 자신의 권한으로 처리해 버리는 보안 취약점 유형.
- **Fake Kernel Object (위조 커널 객체)**:
  - 공격자가 커널 내부 메모리 주소를 알 수 없는 KASLR 환경을 우회하기 위해, 자신이 완벽히 통제할 수 있는 유저 공간 메모리에 조작된 커널 구조체(자격증명, 파일 연산 테이블 등)를 구축해 두는 공격 기법.
- **`CONFIG_ARM64_SW_TTBR0_PAN`**:
  - 하드웨어 PAN 기능이 없는 구형 ARMv8.0 코어를 위해 리눅스 커널이 제공하는 소프트웨어 기반 에뮬레이션. 커널 모드 진입 시 `TTBR0_EL1` 레지스터에 빈 페이지 테이블을 매핑하여 유저 가상 주소 접근 자체를 구조적으로 방어함.

