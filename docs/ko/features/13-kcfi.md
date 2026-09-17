# Clang kCFI (Kernel Control Flow Integrity) - 간접 함수 호출 무결성 및 순방향 제어 흐름 보호

## 1. 개요 및 배경

컴퓨터 시스템 보안에서 제어 흐름 무결성(CFI, Control Flow Integrity)은 소프트웨어의 실행 경로가 컴파일 타임에 생성된 정적 제어 흐름 그래프(CFG, Control Flow Graph)를 엄격히 준수하도록 강제하는 방어 기법임.

전통적인 C 언어와 리눅스 커널 구조상, 함수 포인터를 통한 간접 분기(`indirect call`, 예: `(*func_ptr)(arg)`)는 런타임에 메모리나 레지스터에 로드된 주소로 무조건 분기함:
- x86_64: `call *%rax` 또는 `call *%r11`
- ARM64: `blr x0` 또는 `blr x1`

공격자가 힙 버퍼 오버플로우, UAF(Use-After-Free), 또는 정규 메모리 오염 취약점을 악용하여 구조체 내의 함수 포인터(예: `struct file_operations`, `struct proto_ops`)를 변조할 경우, CPU는 대상 함수의 시그니처나 유효성을 검증하지 못하고 공격자가 지정한 임의의 코드나 ROP/JOP 가젯으로 직행함.

리눅스 커널 6.1부터 공식 채택된 **Clang kCFI (`CONFIG_CFI_CLANG`, `-fsanitize=kcfi`)**는 컴파일러가 각 함수의 정적 프로토타입(반환형 및 매개변수 타입)을 기반으로 고유한 32비트 Type Hash Tag를 생성하고, 간접 호출 직전에 호출 대상 함수의 태그와 기대 태그를 동기 검증하는 순방향(Forward-Edge) CFI 메커니즘임.

---

## 2. 실세계 비유: VIP 연회 초대장 및 암호 대조 (VIP Party Invitation & Passcode Verification)

Clang kCFI의 동작 원리는 **엄격한 보안 구역의 VIP 연회장 입장 절차**에 비유할 수 있음:

1. **전통적 커널 (Pre-CFI / Base)**:
   - 문지기(CPU)는 손님이 건네는 쪽지(함수 포인터 주소)만 보고 문을 열어줌.
   - 사기꾼(공격자)이 VIP 초대권 대신 비밀 금고나 보일러실 주소가 적힌 가짜 쪽지로 바꿔치기해도, 문지기는 묻지도 따지지도 않고 그곳으로 직행함.
2. **Clang kCFI 하드닝 커널 (Post-CFI / Hardened)**:
   - 모든 초대장과 정문 입장자에게는 사전에 합의된 '32비트 인장 암호'(Type Hash Tag)가 발급됨.
   - 예: '외교관 연회실'(시그니처: `void (*)(unsigned long)`) 정문 앞 벽면에는 `0xaecee44b`라는 고유 인장이 음각되어 있음.
   - 손님이 진입하기 1초 전, 문지기는 대상 방 앞의 인장(`-4` 오프셋)을 대조함.
   - 만약 '요리사'(시그니처: `void (*)(int, int)`)의 인장(`0x06d9bc2d`)이 걸려 있거나 인장이 없는 방이라면, 즉각 경보 벨(`ud2` / `brk`)을 울리고 체포 절차(CFI Failure Trap)를 가동하여 불법 침입을 원천 차단함.

---

## 3. 핵심 아키텍처 및 동작 원리

### 3.1 레거시 Clang CFI vs kCFI 아키텍처 비교

| 비교 항목 | 레거시 Clang CFI (LTO 기반) | 현대 Clang kCFI (`-fsanitize=kcfi`) |
| :--- | :--- | :--- |
| **LTO 의존성** | Full LTO 또는 ThinLTO 필수 요구 | **LTO 불필요 (No LTO Required)** |
| **빌드 시간 및 메모리** | 극심한 링킹 오버헤드 (수십 GB 램 소모) | **일반 컴파일과 대등한 빠른 빌드 속도** |
| **외부 커널 모듈 지원** | OOT(Out-of-Tree) 커널 모듈 지원 불가 | **동적 커널 모듈(`.ko`) 완벽 지원** |
| **타깃 검증 방식** | 점프 테이블(Jump Table) 범위 및 비트맵 연산 | **함수 직전 4바이트 Prefix Tag 동기 대조** |
| **하드웨어 지원** | 순수 소프트웨어 에뮬레이션 | **x86 IBT / FineIBT 및 ARM64 BTI 연동 가능** |

### 3.2 컴파일 타임 Type Hash 주입

Clang 컴파일러는 C 코드 파싱 시 각 함수의 프로토타입 타입을 정규화하여 32비트 해시를 계산함:
```text
Type Hash = Hash(Return_Type, Parameter_Type_List)
```

컴파일러는 대상 함수의 어셈블리 생성 시 진입점 바로 앞 4바이트 오프셋(`-4`)에 이 해시를 배치함:
- **x86_64**:
  ```assembly
  __cfi_func:
      movl    $0xb706950e, %eax    ; 4바이트 매직 해시 태그 (또는 패딩 구조)
  func:
      push    %rbp
      mov     %rsp, %rbp
  ```
- **ARM64**:
  ```assembly
      .word   0xaecee44b           ; 진입점 직전 4바이트에 해시 워드 직접 배치
  func:
      paciasp                      ; (PAC 활성화 시)
      stp     x29, x30, [sp, #-16]!
  ```

### 3.3 런타임 간접 호출 프롤로그 검증 시퀀스

호출자(Caller)가 함수 포인터를 역참조하여 호출할 때 컴파일러는 다음과 같은 검증 어셈블리를 삽입함:

- **x86_64 간접 호출 사이트**:
  ```assembly
  movl    $-0xb706950e, %r10d      ; 기대하는 해시값의 2의 보수 로드
  addl    -4(%r11), %r10d          ; 타깃 함수 앞 4바이트 해시와 덧셈 연산
  je      .Lcall_ok                ; 결과가 0이면(해시 일치) 정상 점프
  ud2                              ; 불일치 시 정의되지 않은 명령어(UD2) 트랩 유발!
  .Lcall_ok:
  call    *%r11                    ; 정상 간접 함수 분기
  ```

- **ARM64 간접 호출 사이트**:
  ```assembly
  movk    w16, #0xe44b             ; 기대 해시 하위 16비트
  movk    w16, #0xaece, lsl #16    ; 기대 해시 상위 16비트 (0xaecee44b)
  ldur    w17, [x1, #-4]           ; 타깃 함수 주소 -4 위치에서 4바이트 태그 로드
  cmp     w16, w17                 ; 해시 일치 여부 비교
  b.eq    .Lcall_ok                ; 일치 시 정상 분기
  brk     #0x8000                  ; 불일치 시 BRK 소프트웨어 트랩 발생!
  .Lcall_ok:
  blr     x1                       ; 정상 간접 함수 호출
  ```

### 3.4 예외 처리기 및 진단 모드 (`CONFIG_CFI_PERMISSIVE`)

1. **Strict Production Mode (`CONFIG_CFI_PERMISSIVE=n`)**:
   - `ud2` 또는 `brk` 트랩 발생 시 아키텍처별 트랩 핸들러(`handle_cfi_failure` / `cfi_brk_handler`)가 진입.
   - `report_cfi_failure()`가 호출되어 오류 메시지를 출력하고 `BUG_TRAP_TYPE_BUG` 반환.
   - 커널은 즉시 Kernel Panic 또는 `BUG_ON()`을 발생시켜 공격자의 익스플로잇 체인을 즉각 중단시킴.
2. **Permissive Diagnostic Mode (`CONFIG_CFI_PERMISSIVE=y`)**:
   - 개발 및 진단 환경을 위한 모드로, 위반 발생 시 `dmesg`에 `CFI failure at ...` 에러 및 경고(`WARN`) 스택 트레이스를 기록함.
   - 트랩 명령어를 건너뛰고 실행을 지속하여, 다중 테스트 벡터 및 텔레메트리 파싱을 안전하게 완수할 수 있도록 지원함.

---

## 4. 인터랙티브 아키텍처 다이어그램

아래 다이어그램은 4가지 시나리오(전통적 하이재킹, 컴파일러 태그 주입, 런타임 동기 검증, 보안 매트릭스 비교)를 인터랙티브하게 시각화함:

<iframe src="../../assets/diagrams/kcfi/architecture.html" width="100%" height="650px" style="border: 1px solid var(--card-border, #334155); border-radius: 8px; margin: 16px 0;" title="Clang kCFI Interactive Architecture"></iframe>

---

## 5. 실습 환경 구현 상세

### 5.1 Kconfig 프래그먼트
- [`configs/features/kcfi.config`](file:///home/auking45/repos/linux-kernel-hardening-lab/configs/features/kcfi.config):
  ```kconfig
  CONFIG_CFI_CLANG=y
  CONFIG_CFI_PERMISSIVE=y
  CONFIG_LKDTM=y
  ```
- [`configs/features/kcfi-disabled.config`](file:///home/auking45/repos/linux-kernel-hardening-lab/configs/features/kcfi-disabled.config):
  ```kconfig
  # CONFIG_CFI_CLANG is not set
  CONFIG_LKDTM=y
  ```

### 5.2 빌드 시스템 연동 (`scripts/build_kernel.sh`)
kCFI 기능 빌드 시 호스트 Clang 18 및 LLD를 자동으로 활성화하도록 `scripts/build_kernel.sh`에 `get_llvm_flags` 로직을 추가함:
```bash
get_llvm_flags() {
    local feature_config="${CONFIGS_DIR}/features/${FEATURE_NAME}.config"
    if [[ "${USE_LLVM}" -eq 1 || "${FEATURE_NAME}" =~ ^kcfi ]] || [[ -f "${feature_config}" && $(grep -c "CONFIG_CFI_CLANG" "${feature_config}") -gt 0 ]]; then
        echo "LLVM=1"
    fi
}
```

### 5.3 취약 타깃 드라이버 (`labs/13-kcfi/vuln_kcfi.c`)
- `/proc/vuln_kcfi` 인터페이스(mode 0666) 생성.
- `kcfi_legit_fn_t`(`void (*)(unsigned long)`) 및 `kcfi_mismatched_fn_t`(`void (*)(int, int, const char*)`) 선언.
- 대상 함수 시작 전 4바이트를 직접 읽어 실제 32비트 Type Hash Tag 텔레메트리 제공.
- 쓰기 커맨드(`legit`, `mismatch`, `hijack`)를 통한 간접 호출 디스패치 트리거.

### 5.4 비특권 PoC 익스플로잇 (`labs/13-kcfi/exploit.c`)
- 비특권 계정(`lab`, UID 1000)에서 실행.
- 텔레메트리 파싱 후 정상 호출(Step 1)과 불일치 호출(Step 2)을 순차 실행하여 베이스라인의 하이재킹 성공 및 하드닝 커널의 CFI 트랩 감지 확인.

---

## 6. 듀얼 아키텍처 실측 검증 결과 (QEMU Live Verification)

### 6.1 실측 검증 요약 표

| 아키텍처 | 시나리오 | `CONFIG_CFI_CLANG` | 함수 Type Tag 상태 | 불일치 호출 결과 | LKDTM CFI_FORWARD_PROTO | 최종 판정 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **x86_64** | **Base (kcfi-disabled)** | DISABLED (`cfi=off`) | `0x90909090` (NOPs) | `MISMATCH_HIJACKED_EXECUTED` | `FAIL: survived mismatched prototype call!` | **취약점 확인 (Vulnerable)** |
| **x86_64** | **Hardened (kcfi)** | **ENABLED (`cfi=kcfi`)** | 컴파일러 주입 완료 | **`CFI failure` 트랩 발생 (type: `0xb706950e`)** | **`CFI failure` 트랩 발생 (type: `0x67c423e0`)** | **하드닝 방어 성공 (Hardened)** |
| **ARM64** | **Base (kcfi-disabled)** | DISABLED | `0x9401d066` (Unchecked) | `MISMATCH_HIJACKED_EXECUTED` | `FAIL: survived mismatched prototype call!` | **취약점 확인 (Vulnerable)** |
| **ARM64** | **Hardened (kcfi)** | **ENABLED** | **`Legit: 0xaecee44b`, `Mismatch: 0x06d9bc2d`** | **`CFI failure` 트랩 발생 (type: `0xaecee44b`)** | **`CFI failure` 트랩 발생 (type: `0x7e0c52a5`)** | **하드닝 방어 성공 (Hardened)** |

---

### 6.2 실측 캡처 로그

#### (1) x86_64 Base (kcfi-disabled) 실측 로그
```text
=========================================================
  Linux Kernel Hardening Lab - Clang kCFI PoC
  Target Architecture: x86_64
  Current User:        UID = 1000 (non-root)
=========================================================
[*] Kernel KCFI State:       DISABLED
[*] Permissive Diagnostics:  NO (Panic on violation)
[*] Kernel Compiler:         Clang 18.1.3
[*] Legit Target Address:    0xffffffff813d8450 (Tag: 0x90909090)
[*] Mismatch Target Address: 0xffffffff813d8490 (Tag: 0x90909090)
[*] Hijack Target Address:   0xffffffff813d84e0 (Tag: 0x90909090)
=========================================================

[Step 1] Triggering legitimate indirect call (matching prototype)...
[+] Legitimate call executed cleanly! Last result: LEGIT_MATCHED_SUCCESS

[Step 2] Triggering mismatched indirect call (prototype mismatch)...
[*] Invoking func_ptr(arg) with target pointing to mismatch_target...
[*] Observed result after mismatch call: MISMATCH_HIJACKED_EXECUTED
[!] VULNERABLE: Mismatched function was executed without restriction!
[!] Baseline kernel lacks Clang kCFI indirect call validation.

=========================================================
  [Test 2/2] Triggering LKDTM CFI_FORWARD_PROTO Test
  Kernel Architecture: x86_64
  Kernel Release:      6.12.109
=========================================================
[*] Invoking checked indirect call with mismatched prototype via LKDTM...
[    1.678399] lkdtm: FAIL: survived mismatched prototype function call!
[    1.679127] lkdtm: This is probably expected, since this kernel (6.12.109 x86_64) was built *without* CONFIG_CFI_CLANG=y
```

#### (2) x86_64 Hardened (kcfi) 실측 로그
```text
=========================================================
  Linux Kernel Hardening Lab - Clang kCFI PoC
  Target Architecture: x86_64
  Current User:        UID = 1000 (non-root)
=========================================================
[*] Kernel KCFI State:       ENABLED
[*] Permissive Diagnostics:  YES (Warn on violation)
[*] Kernel Compiler:         Clang 18.1.3
[*] Legit Target Address:    0xffffffff813e3ef0 (Tag: 0x90909090)
[*] Mismatch Target Address: 0xffffffff813e3f30 (Tag: 0x90909090)
[*] Hijack Target Address:   0xffffffff813e3f80 (Tag: 0x90909090)
=========================================================

[Step 1] Triggering legitimate indirect call (matching prototype)...
[+] Legitimate call executed cleanly! Last result: LEGIT_MATCHED_SUCCESS

[Step 2] Triggering mismatched indirect call (prototype mismatch)...
[*] Invoking func_ptr(arg) with target pointing to mismatch_target...
[    1.674999] CFI failure at kcfi_dispatch_call+0x30/0x40 (target: kcfi_mismatch_target+0x0/0x40; expected type: 0xb706950e)
[*] Observed result after mismatch call: MISMATCH_HIJACKED_EXECUTED
[!] Note: Permissive mode permitted mismatched execution after logging warning.
[+] DEFENSE DETECTED: Check dmesg for CFI failure trap log.

=========================================================
  [Test 2/2] Triggering LKDTM CFI_FORWARD_PROTO Test
  Kernel Architecture: x86_64
  Kernel Release:      6.12.109
=========================================================
[*] Invoking checked indirect call with mismatched prototype via LKDTM...
[    1.728253] CFI failure at lkdtm_indirect_call+0x16/0x20 (target: lkdtm_increment_int+0x0/0x20; expected type: 0x67c423e0)
[    1.728503] WARNING: CPU: 1 PID: 47 at lkdtm_indirect_call+0x16/0x20
[    1.728750] RIP: 0010:lkdtm_indirect_call+0x16/0x20
[    1.728880]  lkdtm_CFI_FORWARD_PROTO+0x34/0x60
```

#### (3) ARM64 Base (kcfi-disabled) 실측 로그
```text
=========================================================
  Linux Kernel Hardening Lab - Clang kCFI PoC
  Target Architecture: aarch64 (ARM64)
  Current User:        UID = 1000 (non-root)
=========================================================
[*] Kernel KCFI State:       DISABLED
[*] Permissive Diagnostics:  NO (Panic on violation)
[*] Kernel Compiler:         Clang 18.1.3
[*] Legit Target Address:    0xffff800080325c34 (Tag: 0x9401d066)
[*] Mismatch Target Address: 0xffff800080325c78 (Tag: 0xd65f03c0)
[*] Hijack Target Address:   0xffff800080325cdc (Tag: 0xd65f03c0)
=========================================================

[Step 1] Triggering legitimate indirect call (matching prototype)...
[+] Legitimate call executed cleanly! Last result: LEGIT_MATCHED_SUCCESS

[Step 2] Triggering mismatched indirect call (prototype mismatch)...
[*] Invoking func_ptr(arg) with target pointing to mismatch_target...
[*] Observed result after mismatch call: MISMATCH_HIJACKED_EXECUTED
[!] VULNERABLE: Mismatched function was executed without restriction!
[!] Baseline kernel lacks Clang kCFI indirect call validation.

=========================================================
  [Test 2/2] Triggering LKDTM CFI_FORWARD_PROTO Test
  Kernel Architecture: aarch64
  Kernel Release:      6.12.109
=========================================================
[*] Invoking checked indirect call with mismatched prototype via LKDTM...
[    0.825389] lkdtm: FAIL: survived mismatched prototype function call!
[    0.826231] lkdtm: This is probably expected, since this kernel (6.12.109 aarch64) was built *without* CONFIG_CFI_CLANG=y
```

#### (4) ARM64 Hardened (kcfi) 실측 로그
```text
=========================================================
  Linux Kernel Hardening Lab - Clang kCFI PoC
  Target Architecture: aarch64 (ARM64)
  Current User:        UID = 1000 (non-root)
=========================================================
[*] Kernel KCFI State:       ENABLED
[*] Permissive Diagnostics:  YES (Warn on violation)
[*] Kernel Compiler:         Clang 18.1.3
[*] Legit Target Address:    0xffff80008033da88 (Tag: 0xaecee44b)
[*] Mismatch Target Address: 0xffff80008033dad0 (Tag: 0x06d9bc2d)
[*] Hijack Target Address:   0xffff80008033db38 (Tag: 0xa540670c)
=========================================================

[Step 1] Triggering legitimate indirect call (matching prototype)...
[+] Legitimate call executed cleanly! Last result: LEGIT_MATCHED_SUCCESS

[Step 2] Triggering mismatched indirect call (prototype mismatch)...
[*] Invoking func_ptr(arg) with target pointing to mismatch_target...
[    0.825972] CFI failure at kcfi_dispatch_call+0x44/0x60 (target: kcfi_mismatch_target+0x0/0x68; expected type: 0xaecee44b)
[*] Observed result after mismatch call: MISMATCH_HIJACKED_EXECUTED
[!] Note: Permissive mode permitted mismatched execution after logging warning.
[+] DEFENSE DETECTED: Check dmesg for CFI failure trap log.

=========================================================
  [Test 2/2] Triggering LKDTM CFI_FORWARD_PROTO Test
  Kernel Architecture: aarch64
  Kernel Release:      6.12.109
=========================================================
[*] Invoking checked indirect call with mismatched prototype via LKDTM...
[    0.887079] CFI failure at lkdtm_indirect_call+0x2c/0x44 (target: lkdtm_increment_int+0x0/0x18; expected type: 0x7e0c52a5)
[    0.887889] WARNING: CPU: 1 PID: 46 at lkdtm_indirect_call+0x2c/0x44
[    0.888160] pc : lkdtm_indirect_call+0x2c/0x44
[    0.888172] lr : lkdtm_CFI_FORWARD_PROTO+0x3c/0x6c
```

---

## 7. 영문 발표 대본 (English Presentation Script)

### Slide 1: The Threat of Indirect Call Hijacking
"Hello everyone. Today, we delve into Phase 6: Control Flow Integrity, starting with Clang kCFI in Linux 6.12.
In traditional C binaries and the Linux kernel, function pointers are everywhere—from virtual file system operation tables to driver callbacks. However, indirect branch instructions such as `call *%reg` on x86 or `blr xN` on ARM64 execute blindly. They jump to whatever memory address is stored in the register without validating whether the target function conforms to the intended prototype. If an attacker leverages a heap UAF or out-of-bounds write to tamper with a function pointer, control flow is completely hijacked into arbitrary code gadgets or privileged routines."

### Slide 2: Enter Clang kCFI: Fine-Grained, LTO-Free CFI
"Historically, Clang CFI required Whole-Program LTO, causing massive compilation overhead, heavy memory consumption, and preventing external kernel modules from building. Linux 6.1 introduced kCFI, or Kernel Control Flow Integrity, driven by Clang's `-fsanitize=kcfi`.
kCFI computes a 32-bit type hash tag from the function's static prototype. Crucially, the compiler embeds this 4-byte hash tag immediately before the entry point of every function—at offset negative four. Before issuing an indirect call, the caller emits a tiny prelude that reads the 4-byte tag at `target - 4` and compares it against the expected type hash."

### Slide 3: Live Dual-Architecture Proof of Concept
"In our laboratory, we built both Base and Hardened kernels using Clang 18 for x86_64 and ARM64.
In the vulnerable baseline, our non-root exploit easily triggered mismatched indirect calls, and LKDTM confirmed a survival state.
In the hardened kernel with `CONFIG_CFI_CLANG=y`, the moment our exploit triggered a mismatched call, the CPU instantly trapped execution. On x86_64, a `ud2` instruction tripped `handle_cfi_failure`, logging a mismatch against expected type `0xb706950e`. On ARM64, the CPU hit a `brk #0x8000` trap, detecting that our target tag `0x06d9bc2d` did not match the expected `0xaecee44b`.
kCFI provides deterministic forward-edge protection with negligible runtime overhead and zero LTO friction."

---

## 8. 용어 사전 (Glossary)

- **CFI (Control Flow Integrity)**: 제어 흐름 무결성. 런타임 프로그램 실행 분기가 컴파일 타임에 도출된 정적 제어 흐름 그래프(CFG)를 이탈하지 못하도록 감시하고 강제하는 방어 기술.
- **Forward-Edge CFI (순방향 CFI)**: 간접 함수 호출(`indirect call`) 및 간접 점프(`indirect jump`)의 유효성을 검증하는 CFI 하위 분야.
- **Backward-Edge CFI (역방향 CFI)**: 함수 종료 후 스택 프레임의 리턴 주소(`ret`) 변조를 방어하는 기법 (예: Shadow Call Stack, CET Shadow Stack).
- **kCFI (Kernel Control Flow Integrity)**: Clang `-fsanitize=kcfi`를 기반으로 동작하는 리눅스 커널 공식 순방향 CFI 기법. LTO 없이 동작함.
- **Type Hash Tag**: 함수의 반환형과 매개변수 타입 목록을 암호화 해시 알고리즘으로 축약한 32비트 정수 시그니처 태그.
- **Prefix Tag**: 함수의 기계어 진입점 바로 앞 4바이트(`-4`)에 배치되는 해시 저장 공간.
- **FineIBT**: Intel CET IBT(Indirect Branch Tracking) 하드웨어 명령어(`endbr64`)와 Clang kCFI 소프트웨어 해시 검증을 결합하여 성능과 보안성을 극대화한 x86 전용 하이브리드 CFI 모드.
- **`ud2` (Undefined Instruction 2)**: x86_64에서 의도적으로 유효하지 않은 명령어 예외(#UD)를 일으켜 커널 트랩 핸들러를 호출하는 2바이트 어셈블리 명령어 (`0x0f 0x0b`).
- **`brk #0x8000`**: ARM64에서 소프트웨어 중단점 예외(Breakpoint Exception)를 발생시켜 커널 `cfi_brk_handler`를 트리거하는 명령어.
- **`CONFIG_CFI_PERMISSIVE`**: CFI 검증 불일치 시 커널 패닉 대신 경고(`WARN`) 메시지를 출력하고 실행을 지속시키는 진단용 Kconfig 옵션.
