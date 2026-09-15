# CONFIG_STRICT_KERNEL_RWX & CONFIG_STRICT_MODULE_RWX: 커널 W^X 권한 분리 및 코드/읽기전용 메모리 불변 정책

<div style="margin: 1.5rem 0; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px; overflow: hidden;">
  <iframe src="../../assets/diagrams/strict-rwx/architecture.html" style="width: 100%; height: 600px; border: none; display: block;" title="CONFIG_STRICT_KERNEL_RWX Architecture Diagram"></iframe>
</div>

---

## 1. 개요 및 위협 모델 (Overview & Threat Model)

### 1.1 해결하고자 하는 위협: 커널 텍스트 변조 및 런타임 루트킷 코드 인젝션

- **W^X 불변식 결여 시의 보안 취약점**:
  - 전통적인 운영체제 커널은 성능 및 초기화 편의성을 이유로 커널 메모리 공간 전체를 읽기/쓰기/실행($RWX$)이 모두 가능한 단일 페이지 속성으로 매핑하였음.
  - 이 구조에서는 공격자가 임의 메모리 쓰기(Arbitrary Write) 취약점 하나만 획득하면, 커널 코드(`.text`) 영역에 직접 NOP 슬레드나 쉘코드를 덮어쓰거나(In-memory Code Patching), 시스템 콜 테이블(`sys_call_table`) 및 함수 포인터를 직접 조작하여 완전한 루트킷(Rootkit) 권한을 획득할 수 있음.
- **W^X (Write XOR Execute) 핵심 방어 철학**:
  - 메모리 페이지는 "쓰기 가능($W$)"하거나 "실행 가능($X$)"할 수 있지만, 절대로 두 속성을 동시에 가질 수 없음 ($W \cap X = \emptyset$).
  - **코드 영역(`.text`)**: 실행 및 읽기 전용 ($R-X$)으로 고정하여 런타임 코드 변조 원천 차단.
  - **상수 데이터 영역(`.rodata`)**: 읽기 전용 ($R--$)으로 설정하여 가상 함수 테이블, 보안 매트릭스 변조 차단.
  - **초기화 후 읽기 전용 영역(`__ro_after_init`)**: 부팅 완료 시점에 영구 읽기 전용 ($R--$)으로 동결하여 커널 훅 및 함수 포인터 보호.
  - **일반 데이터/힙/스택 영역(`.data`, `.bss`, kmalloc, stack)**: 읽기/쓰기 가능하지만 실행 절대 불가 ($RW-$).

### 1.2 직관적 실전 비유: 국립중앙도서관 귀중본 열람실 규정 (The Rare Manuscript Library Metaphor)

- **비유 설명**:
  - 운영체제 커널의 가상 메모리 공간을 국가 최고 등급 문서가 보관된 '국립도서관 귀중본 열람실'로 비유할 수 있음.
  - **하드닝 이전 (`rodata=off`, W+X 허용)**:
    - 헌법 원본 및 사법 판례집(커널 `.text` 및 `.rodata`) 열람실에 관람객이 유성 매직과 수정액(임의 쓰기 권한)을 소지하고 자유롭게 입장함.
    - 악의적인 침입자가 헌법 조항을 지우고 "모든 국고를 침입자에게 귀속한다"는 가짜 조항을 직접 써넣음(Syscall Hooking 및 Code Patching). 도서관 경비원(MMU)은 펜 사용을 전혀 제지하지 않음.
  - **하드닝 적용 (`CONFIG_STRICT_KERNEL_RWX=y`, `rodata=on`)**:
    - 전시 서적(`.rodata`, `.text`)은 100% 방탄 유리 진열장($R--$, $R-X$)에 밀봉됨.
    - 관람객이 방탄 유리 위에 펜을 대고 눌러쓰려고 시도하는 순간, 전자 감지 센서(하드웨어 MMU Page Fault / CR0.WP)가 발동하여 경보를 울리고 즉각 손목을 꺾어 체포(EFAULT 발생 및 커널 패닉/차단)함.
    - 도서관 방명록(`.data`, $RW-$)에는 자유롭게 글씨를 쓸 수 있지만, 방명록 종이를 뜯어서 도서관 공식 법률로 집행(실행, $X$)하려 들면 즉시 파쇄됨.

---

## 2. 커널 내부 구현 원리 (Kernel Internal Architecture)

### 2.1 하드웨어 MMU 쓰기 방지 및 권한 비트 구조

- **x86_64 아키텍처 제어 레지스터 및 PTE**:
  - **CR0.WP (Write Protect, Bit 16)**:
    - $CR0.WP = 1$일 때, CPU가 링 0(Supervisor Mode)에서 실행 중이더라도 페이지 테이블 엔트리(PTE)에 Read-Only($R/W=0$) 플래그가 설정된 페이지에 쓰기를 시도하면 하드웨어 `#PF`(Page Fault, Error Code: Supervisor Write Violation) 예외를 강제 발생시킴.
    - $CR0.WP = 0$일 경우, 링 0 코드는 PTE의 $R/W$ 비트와 무관하게 모든 메모리에 무제한 쓰기가 가능해져 보호가 무력화됨.
  - **PTE 비트 레이아웃**:
    - Bit 1 ($R/W$): 0이면 Read-Only, 1이면 Read/Write.
    - Bit 63 ($NX$/$XD$): No-Execute 비트. 1이면 데이터 페이지에서의 코드 인스트럭션 페치를 CPU 레벨에서 하드웨어 트랩으로 차단.
- **ARM64 (AArch64) 아키텍처 권한 제어**:
  - **Stage 1 Block/Page Descriptor AP[2:1] (Data Access Permissions)**:
    - `0b00`: EL1 Read/Write, EL0 No Access.
    - `0b10`: EL1 Read-Only, EL0 No Access (커널 `.text`, `.rodata`, `__ro_after_init`에 적용).
  - **UXN / PXN (User/Privileged Execute-Never)**:
    - 데이터 영역에 $PXN=1$을 마킹하여 커널 링 0에서의 악성 쉘코드 실행을 원천 차단.

### 2.2 커널 부팅 시퀀스와 `mark_rodata_ro()` 라이프사이클

- **단계별 메모리 보호 전이 과정 (`init/main.c`)**:
  1. **초기 부팅 단계**:
     - 커널 압축 해제 및 페이지 테이블 초기 구축 시점에는 초기화 함수들이 코드를 패칭하고 테이블을 작성해야 하므로 잠시 쓰기가 허용됨.
  2. **`mark_readonly()` 호출 (`init/main.c:1434`)**:
     - `kernel_init()` 직전, 초기화 작업이 완료되면 커널은 `mark_readonly()` 함수를 호출함:
     ```c
     /* init/main.c */
     static void mark_readonly(void)
     {
         if (rodata_enabled) {
             mark_rodata_ro();
             rodata_test();
         } else
             pr_info("Kernel memory protection disabled.\n");
     }
     ```
  3. **`mark_rodata_ro()` 실행 (`arch/x86/mm/init_64.c` / `arch/arm64/mm/mmu.c`)**:
     - `.text` 섹션 범위: `set_memory_ro()` 적용 ($R-X$).
     - `.rodata` 섹션 범위: `set_memory_ro()` 및 `set_memory_nx()` 적용 ($R--$).
     - `__init` 섹션: 사용이 끝난 초기화 코드 메모리를 해제(`free_initmem()`)하여 메모리 누수 및 재사용 공격 방지.
  4. **`__ro_after_init` 보호**:
     - 커널 부팅 초기화 단계 중에는 정상적으로 쓰기가 가능하지만, `mark_rodata_ro()` 시점에 영구적으로 $R--$ 속성으로 전환됨.

### 2.3 커널 모듈 보호 (`CONFIG_STRICT_MODULE_RWX`)

- 동적 로딩되는 커널 모듈(`.ko`) 역시 악성 루트킷의 주요 표적임.
- `kernel/module/strict_rwx.c`에 정의된 `module_enable_ro()` 및 `module_enable_nx()`가 모듈 로드 완료 직후 호출되어 모듈의 코드 섹션은 $R-X$, 데이터 섹션은 $RW-$, 모듈의 rodata는 $R--$로 강제 분리함.

---

## 3. 실습 환경 및 취약 드라이버 구현 (Hands-on Lab Implementation)

### 3.1 취약 타깃 드라이버 (`vuln_strict_rwx.c`)

- `/proc/vuln_strict_rwx` (mode 0666) 캐릭터 디바이스 인터페이스 제공:
  - **메모리 보호 상태 텔레메트리**:
    - `STRICT_KERNEL_RWX`: Kconfig 활성화 여부.
    - `RODATA_BOOT_PARAM`: 커널 부팅 파라미터(`rodata=on` vs `rodata=off`).
    - `WX_PROTECTION_STATUS`: 최종 W^X 강제 여부 (`ENABLED` vs `DISABLED`).
    - `TARGET_TEXT_ADDR`: `.text` 섹션 상주 타깃 함수(`vuln_target_function`) 주소.
    - `TARGET_RODATA_ADDR`: `.rodata` 섹션 상주 상수 변수 주소.
    - `TARGET_RO_AFTER_INIT`: `__ro_after_init` 섹션 상주 변수 주소.
  - **안전한 Ring 0 쓰기 검증 로직 (`copy_to_kernel_nofault`)**:
    - 리눅스 커널 공식 자체 테스트(`mm/rodata_test.c`) 표준 함수인 `copy_to_kernel_nofault()`를 활용.
    - 하드웨어 MMU Write Protect 발동 시 커널 패닉을 일으키지 않고, 커널 예외 픽스업 테이블(`extable`)을 통해 안전하게 `-EFAULT`를 반환하도록 설계하여 테스트 자동화 지원.

### 3.2 W^X 무결성 검증 PoC (`exploit.c`)

- 비특권 사용자(`lab`, UID 1000) 공간에서 실행되는 3대 벡터 공격 바이너리 (`/bin/exploit_strict_rwx`):
  - **Vector 1 (.text Patching)**: 커널 코드 영역에 NOP 슬레드(0x90) 쓰기 시도.
  - **Vector 2 (.rodata Overwrite)**: 읽기 전용 상수 영역 변조 시도.
  - **Vector 3 (__ro_after_init Overwrite)**: 초기화 후 읽기 전용 영역 오염 시도.
  - **결과 판정**:
    - `Base (rodata=off)`: 모든 쓰기가 허용되어 심각한 무결성 침해 판정 (`[!] VULNERABILITY CONFIRMED: W^X Memory Protection is DISABLED!`).
    - `Hardened (rodata=on)`: MMU에 의해 모든 쓰기가 차단되어 무결성 유지 판정 (`[+] DEFENSE ACTIVE: CONFIG_STRICT_KERNEL_RWX verified!`).

---

## 4. QEMU 실측 검증 및 분석 (Dual-Architecture Verification)

### 4.1 x86_64 아키텍처 실측 결과

#### Base Kernel (`strict-rwx-disabled`, `rodata=off`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Boot Protection State
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 nokaslr lab_test=test_strict_rwx rodata=off
W^X Protection: DISABLED (rodata=off active)

=========================================================
  [Test 2/3] Kernel Memory Layout Telemetry (/proc/vuln_strict_rwx)
=========================================================
STRICT_KERNEL_RWX:     CONFIGURED
STRICT_MODULE_RWX:     DISABLED
RODATA_BOOT_PARAM:     rodata=off (Disabled)
WX_PROTECTION_STATUS:  DISABLED (Vulnerable W+X)
TARGET_TEXT_ADDR:      0xffffffff813abb50
TARGET_RODATA_ADDR:    0xffffffff8184da38
TARGET_RO_AFTER_INIT:  0xffffffff8198b2f8
TARGET_DATA_ADDR:      0xffffffff81ac2c08
TEXT_WRITE_RESULT:     NOT_TESTED
RODATA_WRITE_RESULT:   NOT_TESTED
RO_AFTER_INIT_RESULT:  NOT_TESTED

=========================================================
  [Test 3/3] Real-World W^X Tampering Demonstration
  Target: /proc/vuln_strict_rwx
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Memory Protection Telemetry:
    Kernel RWX Config:   CONFIGURED
    Module RWX Config:   DISABLED
    Boot Parameter:      rodata=off (Disabled)
    W^X Invariant:       DISABLED (Vulnerable W+X)

[*] Target Kernel Memory Layout:
    .text (Code):        0xffffffff813abb50 (Expected: R-X)
    .rodata (Const):     0xffffffff8184da38 (Expected: R--)
    __ro_after_init:     0xffffffff8198b2f8 (Expected: R--)
    .data (Variables):   0xffffffff81ac2c08 (Expected: RW-)

=========================================================
[*] Launching Memory Tampering Verification Tests...
=========================================================
[*] Test Vector 1: Modifying Kernel Code (.text):
    Target: 0xffffffff813abb50
    Result: PERMITTED (Writable)

[*] Test Vector 2: Overwriting Read-Only Data (.rodata):
    Target: 0xffffffff8184da38
    Result: PERMITTED (Writable)

[*] Test Vector 3: Overwriting Post-Init Data (__ro_after_init):
    Target: 0xffffffff8198b2f8
    Result: PERMITTED (Writable)

=========================================================
[!] VULNERABILITY CONFIRMED: W^X Memory Protection is DISABLED!
[!] Kernel .text and .rodata are WRITABLE in supervisor mode.
[!] Rootkits can easily hook syscall tables, patch kernel opcodes,
    and tamper with sensitive security function pointers.
=========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    1.086158] [vuln_strict_rwx] Initialized /proc/vuln_strict_rwx (STRICT_RWX=1, rodata=0)
[    1.335156] Freeing unused kernel image (initmem) memory: 1484K
[    1.335399] Kernel memory protection disabled.
[    1.778932] [vuln_strict_rwx] Vector 1: Attempting to patch kernel .text at 0xffffffff813abb50...
[    1.779213] [vuln_strict_rwx] [!] CRITICAL: Kernel .text successfully modified! Rootkit code patching confirmed!
[    1.779284] [vuln_strict_rwx] Vector 2: Attempting to overwrite .rodata at 0xffffffff8184da38...
[    1.779391] [vuln_strict_rwx] [!] CRITICAL: .rodata value corrupted to 0x55aa55aa11223344!
[    1.779474] [vuln_strict_rwx] Vector 3: Attempting to overwrite __ro_after_init at 0xffffffff8198b2f8...
[    1.779515] [vuln_strict_rwx] [!] CRITICAL: __ro_after_init value corrupted to 0xdeaddeaddeaddead!
```

#### Hardened Kernel (`strict-rwx`, `CONFIG_STRICT_KERNEL_RWX=y`, `rodata=on`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Boot Protection State
=========================================================
Kernel cmdline: console=ttyS0 quiet panic=1 nokaslr lab_test=test_strict_rwx rodata=on
W^X Protection: ACTIVE (CONFIG_STRICT_KERNEL_RWX enabled)

=========================================================
  [Test 2/3] Kernel Memory Layout Telemetry (/proc/vuln_strict_rwx)
=========================================================
STRICT_KERNEL_RWX:     CONFIGURED
STRICT_MODULE_RWX:     DISABLED
RODATA_BOOT_PARAM:     rodata=on (Active)
WX_PROTECTION_STATUS:  ENABLED (Hardened W^X)
TARGET_TEXT_ADDR:      0xffffffff813abb50
TARGET_RODATA_ADDR:    0xffffffff8184da38
TARGET_RO_AFTER_INIT:  0xffffffff8198b2f8
TARGET_DATA_ADDR:      0xffffffff81ac2c08
TEXT_WRITE_RESULT:     NOT_TESTED
RODATA_WRITE_RESULT:   NOT_TESTED
RO_AFTER_INIT_RESULT:  NOT_TESTED

=========================================================
  [Test 3/3] Real-World W^X Tampering Demonstration
  Target: /proc/vuln_strict_rwx
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Memory Protection Telemetry:
    Kernel RWX Config:   CONFIGURED
    Module RWX Config:   DISABLED
    Boot Parameter:      rodata=on (Active)
    W^X Invariant:       ENABLED (Hardened W^X)

[*] Target Kernel Memory Layout:
    .text (Code):        0xffffffff813abb50 (Expected: R-X)
    .rodata (Const):     0xffffffff8184da38 (Expected: R--)
    __ro_after_init:     0xffffffff8198b2f8 (Expected: R--)
    .data (Variables):   0xffffffff81ac2c08 (Expected: RW-)

=========================================================
[*] Launching Memory Tampering Verification Tests...
=========================================================
[*] Test Vector 1: Modifying Kernel Code (.text):
    Target: 0xffffffff813abb50
    Result: BLOCKED (Read-Only)

[*] Test Vector 2: Overwriting Read-Only Data (.rodata):
    Target: 0xffffffff8184da38
    Result: BLOCKED (Read-Only)

[*] Test Vector 3: Overwriting Post-Init Data (__ro_after_init):
    Target: 0xffffffff8198b2f8
    Result: BLOCKED (Read-Only)

=========================================================
[+] DEFENSE ACTIVE: CONFIG_STRICT_KERNEL_RWX verified!
[+] Hardware MMU Write Protection (CR0.WP / PTE RO) successfully enforced.
[+] All attempts to modify .text, .rodata, and __ro_after_init were BLOCKED!
[+] Kernel W^X invariant holds: W ∩ X = ∅.
=========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    1.271291] [vuln_strict_rwx] Initialized /proc/vuln_strict_rwx (STRICT_RWX=1, rodata=1)
[    1.554383] Freeing unused kernel image (initmem) memory: 1484K
[    1.556505] Freeing unused kernel image (rodata/data gap) memory: 424K
[    1.983431] [vuln_strict_rwx] Vector 1: Attempting to patch kernel .text at 0xffffffff813abb50...
[    1.984250] [vuln_strict_rwx] [+] DEFENSE ACTIVE: Kernel .text write blocked by MMU (EFAULT)!
[    1.984314] [vuln_strict_rwx] Vector 2: Attempting to overwrite .rodata at 0xffffffff8184da38...
[    1.984417] [vuln_strict_rwx] [+] DEFENSE ACTIVE: .rodata write blocked by MMU (EFAULT)!
[    1.984460] [vuln_strict_rwx] Vector 3: Attempting to overwrite __ro_after_init at 0xffffffff8198b2f8...
[    1.984493] [vuln_strict_rwx] [+] DEFENSE ACTIVE: __ro_after_init write blocked by MMU (EFAULT)!
```

---

### 4.2 ARM64 아키텍처 실측 결과

#### Base Kernel (`strict-rwx-disabled`, `rodata=off`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Boot Protection State
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_strict_rwx rodata=off
W^X Protection: DISABLED (rodata=off active)

=========================================================
  [Test 2/3] Kernel Memory Layout Telemetry (/proc/vuln_strict_rwx)
=========================================================
STRICT_KERNEL_RWX:     CONFIGURED
STRICT_MODULE_RWX:     DISABLED
RODATA_BOOT_PARAM:     rodata=off (Disabled)
WX_PROTECTION_STATUS:  DISABLED (Vulnerable W+X)
TARGET_TEXT_ADDR:      0xffff800080313298
TARGET_RODATA_ADDR:    0xffff8000803c2928
TARGET_RO_AFTER_INIT:  0xffff800080471578
TARGET_DATA_ADDR:      0xffff800080630290
TEXT_WRITE_RESULT:     NOT_TESTED
RODATA_WRITE_RESULT:   NOT_TESTED
RO_AFTER_INIT_RESULT:  NOT_TESTED

=========================================================
  [Test 3/3] Real-World W^X Tampering Demonstration
  Target: /proc/vuln_strict_rwx
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Memory Protection Telemetry:
    Kernel RWX Config:   CONFIGURED
    Module RWX Config:   DISABLED
    Boot Parameter:      rodata=off (Disabled)
    W^X Invariant:       DISABLED (Vulnerable W+X)

[*] Target Kernel Memory Layout:
    .text (Code):        0xffff800080313298 (Expected: R-X)
    .rodata (Const):     0xffff8000803c2928 (Expected: R--)
    __ro_after_init:     0xffff800080471578 (Expected: R--)
    .data (Variables):   0xffff800080630290 (Expected: RW-)

=========================================================
[*] Launching Memory Tampering Verification Tests...
=========================================================
[*] Test Vector 1: Modifying Kernel Code (.text):
    Target: 0xffff800080313298
    Result: PERMITTED (Writable)

[*] Test Vector 2: Overwriting Read-Only Data (.rodata):
    Target: 0xffff8000803c2928
    Result: PERMITTED (Writable)

[*] Test Vector 3: Overwriting Post-Init Data (__ro_after_init):
    Target: 0xffff800080471578
    Result: PERMITTED (Writable)

=========================================================
[!] VULNERABILITY CONFIRMED: W^X Memory Protection is DISABLED!
[!] Kernel .text and .rodata are WRITABLE in supervisor mode.
[!] Rootkits can easily hook syscall tables, patch kernel opcodes,
    and tamper with sensitive security function pointers.
=========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.583680] [vuln_strict_rwx] Initialized /proc/vuln_strict_rwx (STRICT_RWX=1, rodata=0)
[    0.669929] Freeing unused kernel memory: 1088K
[    0.672746] Kernel memory protection disabled.
[    1.156748] [vuln_strict_rwx] Vector 1: Attempting to patch kernel .text at 0xffff800080313298...
[    1.156954] [vuln_strict_rwx] [!] CRITICAL: Kernel .text successfully modified! Rootkit code patching confirmed!
[    1.157025] [vuln_strict_rwx] Vector 2: Attempting to overwrite .rodata at 0xffff8000803c2928...
[    1.157098] [vuln_strict_rwx] [!] CRITICAL: .rodata value corrupted to 0x55aa55aa11223344!
[    1.157152] [vuln_strict_rwx] Vector 3: Attempting to overwrite __ro_after_init at 0xffff800080471578...
[    1.157187] [vuln_strict_rwx] [!] CRITICAL: __ro_after_init value corrupted to 0xdeaddeaddeaddead!
```

#### Hardened Kernel (`strict-rwx`, `CONFIG_STRICT_KERNEL_RWX=y`, `rodata=on`)
```text
=========================================================
  [Test 1/3] Kernel Command Line & Boot Protection State
=========================================================
Kernel cmdline: console=ttyAMA0 quiet panic=1 nokaslr lab_test=test_strict_rwx rodata=on
W^X Protection: ACTIVE (CONFIG_STRICT_KERNEL_RWX enabled)

=========================================================
  [Test 2/3] Kernel Memory Layout Telemetry (/proc/vuln_strict_rwx)
=========================================================
STRICT_KERNEL_RWX:     CONFIGURED
STRICT_MODULE_RWX:     DISABLED
RODATA_BOOT_PARAM:     rodata=on (Active)
WX_PROTECTION_STATUS:  ENABLED (Hardened W^X)
TARGET_TEXT_ADDR:      0xffff800080313298
TARGET_RODATA_ADDR:    0xffff8000803c2928
TARGET_RO_AFTER_INIT:  0xffff800080471578
TARGET_DATA_ADDR:      0xffff800080630290
TEXT_WRITE_RESULT:     NOT_TESTED
RODATA_WRITE_RESULT:   NOT_TESTED
RO_AFTER_INIT_RESULT:  NOT_TESTED

=========================================================
  [Test 3/3] Real-World W^X Tampering Demonstration
  Target: /proc/vuln_strict_rwx
  Runner: lab (UID 1000, non-privileged)
=========================================================
[*] Kernel Memory Protection Telemetry:
    Kernel RWX Config:   CONFIGURED
    Module RWX Config:   DISABLED
    Boot Parameter:      rodata=on (Active)
    W^X Invariant:       ENABLED (Hardened W^X)

[*] Target Kernel Memory Layout:
    .text (Code):        0xffff800080313298 (Expected: R-X)
    .rodata (Const):     0xffff8000803c2928 (Expected: R--)
    __ro_after_init:     0xffff800080471578 (Expected: R--)
    .data (Variables):   0xffff800080630290 (Expected: RW-)

=========================================================
[*] Launching Memory Tampering Verification Tests...
=========================================================
[*] Test Vector 1: Modifying Kernel Code (.text):
    Target: 0xffff800080313298
    Result: BLOCKED (Read-Only)

[*] Test Vector 2: Overwriting Read-Only Data (.rodata):
    Target: 0xffff8000803c2928
    Result: BLOCKED (Read-Only)

[*] Test Vector 3: Overwriting Post-Init Data (__ro_after_init):
    Target: 0xffff800080471578
    Result: BLOCKED (Read-Only)

=========================================================
[+] DEFENSE ACTIVE: CONFIG_STRICT_KERNEL_RWX verified!
[+] Hardware MMU Write Protection (CR0.WP / PTE RO) successfully enforced.
[+] All attempts to modify .text, .rodata, and __ro_after_init were BLOCKED!
[+] Kernel W^X invariant holds: W ∩ X = ∅.
=========================================================

=========================================================
  Kernel Ring Buffer (dmesg) Security Events
=========================================================
[    0.486346] [vuln_strict_rwx] Initialized /proc/vuln_strict_rwx (STRICT_RWX=1, rodata=1)
[    0.555212] Freeing unused kernel memory: 1088K
[    0.975107] [vuln_strict_rwx] Vector 1: Attempting to patch kernel .text at 0xffff800080313298...
[    0.975523] [vuln_strict_rwx] [+] DEFENSE ACTIVE: Kernel .text write blocked by MMU (EFAULT)!
[    0.975586] [vuln_strict_rwx] Vector 2: Attempting to overwrite .rodata at 0xffff8000803c2928...
[    0.975645] [vuln_strict_rwx] [+] DEFENSE ACTIVE: .rodata write blocked by MMU (EFAULT)!
[    0.975693] [vuln_strict_rwx] Vector 3: Attempting to overwrite __ro_after_init at 0xffff800080471578...
[    0.975730] [vuln_strict_rwx] [+] DEFENSE ACTIVE: __ro_after_init write blocked by MMU (EFAULT)!
```


---

### 4.3 하드닝 전후 보안 비교 분석표

| 평가 항목 | Base (`rodata=off`) | Hardened (`CONFIG_STRICT_KERNEL_RWX=y`) |
| :--- | :--- | :--- |
| **커널 `.text` 섹션 권한** | $RWX$ (쓰기/실행 동시 허용, 취약) | **$R-X$ (실행 및 읽기 전용, 쓰기 금지)** |
| **커널 `.rodata` 섹션 권한** | $RW-$ 또는 $RWX$ (임의 조작 가능) | **$R--$ (하드웨어 MMU 차단 읽기 전용)** |
| **`__ro_after_init` 보호** | 부팅 후에도 영구 쓰기 가능 | **부팅 완료 시 $R--$로 영구 동결** |
| **루트킷 인메모리 코드 패칭** | **성공 (시스템 콜 테이블 후킹 가능)** | **원천 차단 (MMU Page Fault 즉각 발생)** |
| **W^X 불변식 ($W \cap X = \emptyset$)** | 불변식 파괴 ($W \cap X \ne \emptyset$) | **수학적 불변식 완벽 유지 ($W \cap X = \emptyset$)** |
| **런타임 CPU 성능 영향** | 기준점 | **0% (하드웨어 MMU 페이징 기반)** |

---

## 5. 성능 영향 및 보안 아키텍처 제언 (Trade-offs & Recommendations)

### 5.1 성능 및 엔지니어링 고려사항
- **TLB 분할(Page Splitting)과 메모리 오버헤드**:
  - 커널 공간을 2MB 또는 1GB 대형 페이지(Huge Pages)로 단일 매핑할 경우 TLB 효율이 극대화되나, `.text`, `.rodata`, `.data`의 경계면에서는 4KB 기본 페이지 단위로 분할(PTE Splitting)해야 하므로 약간의 TLB 엔트리 소모가 발생함.
  - 그러나 현대 64비트 CPU에서는 미미한 수준(1% 미만)이며 보안 이점이 압도적이므로 모든 범용 배포판에서 기본 채택됨.
- **kprobes, Ftrace, Jump Label과의 공존 메커니즘**:
  - 커널 디버깅 및 트레이싱 도구가 코드를 패칭해야 할 경우, 일시적으로 특정 코어의 페이지 테이블 속성을 변경(`text_poke()`)한 후 즉시 다시 $R-X$로 복원하는 안전한 인터페이스를 통해 W^X 원칙을 우회하지 않고 공존함.

### 5.2 권장 적용 가이드라인
- 모든 운영 환경(서버, 클라우드, 임베디드 장비)에서 `CONFIG_STRICT_KERNEL_RWX=y` 및 `CONFIG_STRICT_MODULE_RWX=y`를 **필수 기본값으로 상시 활성화**해야 함.
- 부팅 커맨드라인에서 디버깅 목적 외에 `rodata=off` 옵션을 전달하는 행위는 엄격히 금지되어야 함.

---

## 6. 부록 (Appendix)

### 6.1 영문 기술 발표 대본 (Technical Presentation Script)

> "Good morning, everyone. Today we delve into one of the most foundational security invariants of modern operating systems: W-XOR-X, implemented in the Linux kernel via CONFIG_STRICT_KERNEL_RWX and CONFIG_STRICT_MODULE_RWX.
>
> Historically, operating system kernels mapped their entire virtual memory space with combined read, write, and execute permissions. Under this permissive model, any single arbitrary-write vulnerability allowed attackers or rootkits to overwrite kernel opcodes directly in .text, hijack the system call table, or tamper with security function pointers.
>
> CONFIG_STRICT_KERNEL_RWX enforces the invariant that memory must never be simultaneously writable and executable. Code sections are mapped strictly as Read and Execute (R-X), constant data as Read-Only (R--), and post-initialization structures marked with __ro_after_init are permanently frozen after boot.
>
> In our dual-architecture lab, we demonstrated this mechanism using a custom driver and unprivileged exploit. Under a disabled baseline, memory writes succeed silently, opening the door to rootkits. Under our hardened configuration, the hardware MMU triggers immediate write-protection faults, protecting the kernel's integrity with virtually zero runtime performance cost."

### 6.2 보안 용어 사전 (Glossary)

- **W^X (Write XOR Execute)**: 메모리 페이지가 쓰기 가능하거나 실행 가능할 수 있으나, 절대로 두 속성을 동시에 가질 수 없도록 강제하는 보안 설계 원칙 ($W \cap X = \emptyset$).
- **CONFIG_STRICT_KERNEL_RWX**: 커널의 기본 코드(`.text`) 및 읽기 전용 데이터(`.rodata`) 영역에 대해 하드웨어 MMU 레벨의 엄격한 페이지 권한 분리를 활성화하는 Kconfig 옵션.
- **CONFIG_STRICT_MODULE_RWX**: 동적으로 적재되는 커널 모듈(`.ko`)의 코드와 데이터 영역에 W^X 메모리 권한 분리를 강제하는 Kconfig 옵션.
- **CR0.WP (Write Protect Bit)**: x86 아키텍처 제어 레지스터 CR0의 16번째 비트로, CPU가 링 0(커널 모드)에서도 읽기 전용 페이지에 쓰는 것을 금지하는 하드웨어 플래그.
- **`__ro_after_init`**: 커널 부팅 초기화 단계에서만 쓰기가 가능하고, 초기화 완료(`mark_rodata_ro()`) 이후에는 영구 읽기 전용으로 동결되는 커널 데이터 섹션 어트리뷰트.
- **`copy_to_kernel_nofault()`**: 커널 예외 테이블(`extable`)을 통해 페이지 폴트 발생 시 패닉 없이 안전하게 오류 코드(`-EFAULT`)를 반환하며 메모리를 복사하는 커널 안전 함수.

