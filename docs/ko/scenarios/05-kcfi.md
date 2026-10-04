# [Scenario 05] 제어 흐름 하이재킹 & Clang kCFI / 하드웨어 IBT/BTI 방어

!!! abstract "🎯 발표 핵심 요약 (Executive Summary)"
    - **실제 공격 사례**: 리눅스 커널 cgroup 및 파일시스템 서브시스템 타입 혼동(Type Confusion)을 통한 함수 포인터 변조 (**CVE-2021-4154**)
    - **위협 벡터**: 디바이스 드라이버 및 서브시스템의 함수 포인터 테이블(`ops->dispatch_fn`) 메모리를 오염시켜, 합법적 기구학 연산 루틴 대신 악의적인 관절 과부하 루틴 또는 임의 커널 코드로 간접 분기(Indirect Call) 유도
    - **사이버-물리 피해**: 2족 보행 관절 구동 모터 지령 각속도가 정상 1.8 rad/s에서 48.5 rad/s(27배 폭증)로 급변하여 하모닉 드라이브 감속기 기어 치절 전단 파괴(Gear Shear) 및 브러시리스 서보 모터 고정자 권선 소손 발생
    - **1차 소프트웨어 방어선**: 컴파일러 기반 정밀 전방향 제어 흐름 무결성 **`CONFIG_CFI_CLANG=y` (Clang kCFI)** (32비트 프리앰블 타입 해시 검증)
    - **2차 하드웨어 협력 방어선**: CPU 명령어 추적기 **Intel CET IBT (`CONFIG_X86_KERNEL_IBT`)** 및 **ARM64 BTI (`CONFIG_ARM64_BTI`)** (랜딩패드 `ENDBR64` / `BTI c` 강제)

---

## 1. 실제 커널 침해 사례 분석: CVE-2021-4154와 휴머노이드 관절 제어기 파괴

C 언어로 작성된 리눅스 커널은 객체 지향적 다형성을 구현하기 위해 구조체 내부의 함수 포인터(Function Pointer Tables / Ops)를 광범위하게 활용함:

```
[로봇 사용자 공간 (Locomotion Planner / C2: Ring 3)]
                 │
                 │ (1) fs/cgroup 취약점 트리거 (Type Confusion 유발)
                 ▼
[커널 힙/데이터 영역 (Actuator Driver Ops Table)]
 ┌───────────────────────────────────────┐
 │ struct joint_controller_ops           │
 ├───────────────────────────────────────┤
 │ name        : "Knee_Pitch_Controller" │
 │ dispatch_fn : 0x578896262690 (변조됨)  │ <── [CVE-2021-4154로 조작]
 └───────────────────────────────────────┘
                 │
                 │ (2) (*ops->dispatch_fn)(actuator, target, vel) 간접 호출
                 ▼
[변조된 악성 페이로드: malicious_actuator_overload()]
 - Target Angle       : 3.14159 rad (급격한 관절 반전)
 - Commanded Velocity : 48.5 rad/s (정상 허용치 1.8 rad/s 대비 27배 폭주)
                 │
                 ▼
[💥 사이버-물리 파괴 전이: 감속기 치절 전단 파괴 & 서보 모터 소손]
```

### 1.1 침해 경로 및 근본 원인 (Root Cause)

- **CVE-2021-4154 (커널 타입 혼동 및 포인터 오염)**:
    - 리눅스 cgroup 및 fs 서브시스템에서 객체 타입 캐스팅 검증 미비로 인해 서로 다른 구조체 오프셋이 중첩 매핑되는 타입 혼동(Type Confusion) 결함 발생함.
    - 공격자는 이 결함을 악용하여 커널 드라이버의 간접 호출 테이블(`ops->dispatch_fn`) 위치에 공격자가 지정한 임의 주소를 덮어씀.
- **간접 호출 취약점 (Indirect Branch Vulnerability)**:
    - 전방향 제어 흐름 무결성(Forward-Edge CFI)이 적용되지 않은 기본 커널(`CONFIG_CFI=n`)에서는 CPU가 `call *%rax` 명령어를 수행할 때 대상 주소가 본래 의도된 프로토타입의 함수인지 전혀 확인하지 않음.
    - 함수 포인터가 가리키는 메모리에 실행 권한(`+X`)만 부여되어 있다면, 공격자가 지정한 악성 루틴이나 임의 커널 함수로 즉시 분기하여 최고 권한(Ring 0) 상태에서 파괴적 행위를 자행함.

### 1.2 사이버-물리적 재난 분석 (Cyber-Physical Hazards)

관절 제어 디스패처의 제어 흐름 탈취는 로봇의 물리 기구부에 치명적인 비가역적 파괴를 초래함:

- 🔴 **관절 각속도 27배 한계 초과 폭주 (Mechanical Overspeed)**:
    - 안전 최대 각속도가 1.8 rad/s인 무릎 피치 축에 48.5 rad/s의 초고속 지령이 인가되어 관절 가동 범위를 한순간에 이탈함.
- 🔴 **하모닉 드라이브 감속기 치절 전단 파괴 (Gear Teeth Shear)**:
    - 감속비 100:1의 정밀 탄성파 감속기 톱니가 급격한 충격 토크를 견디지 못하고 기계적으로 전단(Shear) 파괴되어 유격 발생 및 관절 고정 불능 상태 초래함.
- 🔴 **브러시리스 서보 모터 권선 과전류 소손 (Motor Stator Burnout)**:
    - 모터 인버터에 순간 최대 정격 전류의 400% 이상이 인가되어 고정자(Stator) 코일 피복이 용융되고 영구 단락 화재 발생함.

---

## 2. 간접 분기 탈취 및 kCFI / IBT 방어 메커니즘

제어 흐름 무결성(CFI)은 소프트웨어의 실행 흐름을 컴파일 타임에 생성된 정적 제어 흐름 그래프(CFG) 내로 강제 제한하는 보안 기법임.

### 2.1 Forward-Edge vs Backward-Edge CFI 분류

제어 흐름 공격은 분기 지점의 성격에 따라 2가지로 양분됨:

```
[제어 흐름 분기점]
  ├── 전방향 분기 (Forward-Edge)  : 간접 호출(call *%rax), 간접 점프(jmp *%rax) ──> [Clang kCFI / Intel IBT / ARM64 BTI]
  └── 후방향 분기 (Backward-Edge) : 함수 반환(ret) 명령어 (스택 리턴 주소)     ──> [Shadow Call Stack / Intel SHSTK]
```

1. **전방향 분기 보호 (Forward-Edge CFI)**:
    - 함수 포인터를 통한 동적 분기 지점을 감시함.
    - Clang kCFI는 호출될 함수의 **프로토타입(매개변수 및 반환 타입)이 호출 지점의 기대 규격과 정확히 일치하는지** 검증함.
2. **후방향 분기 보호 (Backward-Edge CFI)**:
    - 함수 종료 시 복귀 주소를 변조하는 ROP(Return-Oriented Programming)를 방어함.
    - 하드웨어 섀도 스택(SHSTK)이나 전용 레지스터 스택(SCS)을 통해 리턴 주소의 무결성을 보장함.

### 2.2 Clang kCFI 프리앰블 타입 해싱 아키텍처

기존의 Clang CFI는 런타임에 전역 점프 테이블(Jump Table)을 참조하여 커널 LTO(Link-Time Optimization)가 필수적이었으며, 동적 커널 모듈 적재 시 호환성 문제가 존재했음.
리눅스 6.1부터 도입된 **kCFI (Kernel Control Flow Integrity)**는 함수 진입점 바로 앞(-4바이트)에 독립적인 32비트 타입 해시를 삽입하는 프리앰블(Preamble) 방식을 채택함:

```
[호출 지점: Caller]                          [대상 함수: Callee (safe_joint_kinematics)]
movl -4(%rax), %r10d  ──(타입 해시 로드)──>  -4B: [ 0x5A8E3F21 ] (32비트 kCFI 타입 해시)
cmpl $0x5A8E3F21, %r10d                      +0B: [ endbr64     ] (하드웨어 랜딩패드)
jne  .Ltrap_abort                            +4B: [ push %rbp   ] (실제 함수 본문)
call *%rax                                         ...
```

- 공격자가 임의의 악성 함수(`malicious_actuator_overload`)나 kCFI 서명이 누락된 쉘코드로 점프를 시도할 경우, 프리앰블의 타입 해시가 불일치(`0x00000000 != 0x5A8E3F21`)하여 즉각 `ud2` 트랩 발동함.

---

## 3. 대화형 인터랙티브 아키텍처 다이어그램 (Interactive Diagrams)

아래 4개 단계별 다이어그램 및 통합 아키텍처 다이어그램을 통해 간접 분기 수행, 공격자의 함수 포인터 변조, kCFI/IBT 하드웨어 트랩, 하드웨어 페일세이프 E-Stop 전 과정을 시각적으로 확인 가능함.

### 3.1 [Phase 1] 정상 간접 함수 분기 및 kCFI 타입 시그니처 일치 (Nominal Flow)

<iframe src="../../assets/diagrams/kcfi/phase1-normal.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.2 [Phase 2] 함수 포인터 변조 & 제어 흐름 하이재킹 공격 (Attack Detonation)

<iframe src="../../assets/diagrams/kcfi/phase2-attack.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.3 [Phase 3] Clang kCFI 타입 해시 불일치 트랩 & 하드웨어 IBT 차단 (Hardened Trap)

<iframe src="../../assets/diagrams/kcfi/phase3-trap.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.4 [Phase 4] 하드웨어 페일세이프 E-Stop 및 관절 긴급 제동 (Deterministic Safe State)

<iframe src="../../assets/diagrams/kcfi/phase4-failsafe.html" width="100%" height="390" frameborder="0" style="border:none; border-radius:10px; margin-bottom:16px;"></iframe>

---

### 3.5 [통합 아키텍처] 제어 흐름 무결성(kCFI & IBT/BTI) 방어 아키텍처 타임라인 (Comprehensive Flow)

<iframe src="../../assets/diagrams/kcfi/architecture.html" width="100%" height="860" frameborder="0" style="border:none; border-radius:10px; margin-bottom:24px;"></iframe>

<script>
window.addEventListener('message', function(e) {
  if (e.data && e.data.type === 'diagram-theme-change') {
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(iframe => {
      iframe.contentWindow.postMessage({
        type: 'set-diagram-theme',
        theme: e.data.theme
      }, '*');
    });
  }
});
</script>

---

## 4. 방어 기법 심층 분석 및 하드닝 매트릭스 (Defense Matrix)

리눅스 커널은 전방향 및 후방향 제어 흐름 왜곡을 원천 봉쇄하기 위해 컴파일러와 하드웨어 CPU 기능을 결합함:

| 방어 기술 | 커널 Kconfig 설정 | 보호 영역 및 검증 방식 | 성능 오버헤드 |
| :--- | :--- | :--- | :--- |
| **Clang kCFI** | `CONFIG_CFI_CLANG=y` | 전방향 간접 호출 (`call *%reg`) 프리앰블 32비트 타입 해시 검증 | **< 1.0% (극저부하, 모듈 완전 지원)** |
| **x86 Indirect Branch Tracking (IBT)** | `CONFIG_X86_KERNEL_IBT=y` | 전방향 간접 분기 타깃에 하드웨어 `ENDBR64` 랜딩패드 강제 (`#CP` 예외) | **0% (Intel 11세대+ 하드웨어 지원)** |
| **ARM64 Branch Target Identification (BTI)** | `CONFIG_ARM64_BTI=y` | ARMv8.5+ 간접 분기 대상에 `BTI c` 명령어 필수 배치 검증 | **0% (ARM64 하드웨어 지원)** |
| **Shadow Call Stack (SCS)** | `CONFIG_SHADOW_CALL_STACK=y` | 후방향 함수 반환 주소(`ret`)를 별도 `x18` 레지스터 섀도 스택에 이중 보관 | **< 2.0% (ROP 100% 방어)** |

### 4.1 [소프트웨어 방어선] Clang kCFI (`CONFIG_CFI_CLANG`)

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **컴파일 타임 타입 해시 산출**:
        - Clang 컴파일러가 각 C 함수 프로토타입의 맹글링된 문자열로부터 32비트 고유 정수 해시를 산출함.
        - 모든 함수의 시작 위치 바로 앞(-4바이트)에 해당 해시값을 상수로 삽입함.
    2.  **인라인 검증 코드 삽입**:
        - 함수 포인터를 통한 간접 호출 직전 대상 주소의 `-4B` 위치에서 해시를 읽어 기대 해시와 대조하는 어셈블리 명령어를 자동 삽입함.
        - 불일치 시 `ud2` 명령어를 실행하여 커널 `#UD` 예외를 격발함.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **타입 불일치 간접 호출 원천 봉쇄**:
        - 공격자가 함수 포인터를 임의의 커널 함수(`commit_creds` 등)나 미인가 코드로 변조하더라도 시그니처가 다르면 0% 실행 차단됨.
    2.  **LTO 불필요 및 완벽한 모듈 호환성**:
        - 기존 Fine-grained CFI와 달리 커널 LTO 없이도 작동하며, 외부 로드 가능 커널 모듈(LKM)과 완벽히 상호 호환됨.

</div>

### 4.2 [하드웨어 방어선] x86 IBT & ARM64 BTI

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **하드웨어 상태 머신 추적**:
        - 간접 분기(`jmp *%rax`, `call *%rax`)가 발생하는 즉시 CPU 코어가 `WAIT_FOR_ENDBR` 상태로 전이됨.
    2.  **랜딩패드 강제 검증**:
        - 다음 페치되는 첫 번째 명령어가 x86의 `ENDBR64` 또는 ARM64의 `BTI c`가 아닐 경우, CPU 하드웨어가 즉각 `#CP`(Control Protection) 또는 BTI 폴트를 격발하여 명령 실행을 정지함.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **함수 내부 임의 위치 가젯(ROP/JOP) 점프 차단**:
        - 정상 함수의 진입점이 아닌 함수 중간의 가젯(Gadget)으로 뛰어드는 분기 시도를 하드웨어 0클록 수준에서 즉각 차단함.

</div>

---

## 5. 실습 환경 및 공격 시뮬레이션 데모 (`kcfi_demo.c`)

본 실습에서는 CVE-2021-4154 타입 혼동 취약점을 모사한 C 언어 시뮬레이터(`kcfi_demo.c`)를 빌드하고, 취약 모드와 하드닝 모드의 동작 차이를 실측 검증함.

### 5.1 시뮬레이터 핵심 아키텍처 (`kcfi_demo.c`)

- **실습 소스 코드**: [`kcfi_demo.c`](../../assets/labs/scenarios/05-kcfi/kcfi_demo.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/scenarios/05-kcfi/kcfi_demo.c)
- **메모리 구조**: 로봇 무릎 피치 축 액추에이터 제어기(`robot_joint_actuator_t`)와 함수 포인터 디스패치 테이블(`joint_controller_ops_t`) 모델링.
- **방어 로직 구현**: Clang kCFI 프리앰블 타입 해시(`0x5A8E3F21`) 검사 및 하드웨어 랜딩패드(`ENDBR64`) 유효성 검증 루틴 구현.

```c
/* labs/scenarios/05-kcfi/kcfi_demo.c 간접 분기 검증 함수 */
static bool verify_indirect_call(joint_controller_ops_t *ops, uint32_t expected_type, bool kcfi_enabled, bool ibt_enabled) {
    if (!kcfi_enabled && !ibt_enabled) {
        return true; /* CFI 미적용 취약 모드 */
    }

    /* 1. 하드웨어 IBT / BTI 랜딩패드 검증 */
    if (ibt_enabled && (!ops->preamble || ops->preamble->landing_pad != LANDING_PAD_ENDBR64)) {
        printf("[HARDWARE FAULT: #CP / BTI] Indirect branch target missing valid landing pad!\n");
        return false;
    }

    /* 2. Clang kCFI 소프트웨어 프리앰블 타입 해시 검증 */
    if (kcfi_enabled && (!ops->preamble || ops->preamble->kcfi_typeid != expected_type)) {
        printf("[KCFI TRAP: #UD / PANIC] Indirect call target type mismatch! Expected: 0x%08X\n", expected_type);
        return false;
    }

    return true;
}
```

---

### 5.2 공격 실행 및 기구부 파괴 경고 로그 (Attack Execution Logs)

CFI 방어가 비활성화된 취약 모드(`CONFIG_CFI=n`)에서 간접 분기 조작을 감행했을 때의 실측 실행 로그는 다음과 같음:

```bash
# 취약 모드 실행 (kCFI 및 IBT 방어선 부재 환경)
cd labs/scenarios/05-kcfi && make run-attack
```

**런타임 경고 텔레메트리 출력 로그**:
```text
======================================================================
 🤖 Humanoid Robot Control Flow Hijacking & Clang kCFI Lab (CVE-2021-4154) 
======================================================================

[MODE 2: TYPE CONFUSION & INDIRECT CALL HIJACK WITHOUT CFI (CONFIG_CFI=n)]
[*] Simulating CVE-2021-4154: Kernel Type Confusion corrupting function pointer in ops struct...
    [!] Attacker overwrites ops->dispatch_fn with hostile payload: 0x578896262690
    [!] Baseline kernel executes: (*ops->dispatch_fn)(actuator, target, vel) without validation...

======================================================================
 [💥 CRITICAL EXPLOIT DETONATION] Control Flow Hijacking Succeeded! 
======================================================================
  [*] Forward-edge indirect branch hijacked to untrusted memory!
  [*] Current Context: Ring 0 Kernel Execution (Arbitrary Function Detonated)

--- [PHASE 1: CYBER-PHYSICAL HAZARDS & MECHANICAL DAMAGE] ---
  [🔴 PHYSICAL HAZARD] Commanded Velocity: 1.8 rad/s -> 48.5 rad/s (LETHAL OVERSPEED)
  [🔴 PHYSICAL HAZARD] Joint Harmonic Drive: Mechanical Gear Teeth Sheared!
  [🔴 PHYSICAL HAZARD] Stator Coil Overcurrent: Brushless Servo Motor Burnout!
```

---

### 5.3 하드닝 모드 검증 및 커널 트랩 로그 (Hardened Defense & Safe E-Stop Logs)

`CONFIG_CFI_CLANG=y` 및 `CONFIG_X86_KERNEL_IBT=y` 환경에서 동일 공격을 감행했을 때의 실측 로그:

```bash
# 하드닝 모드 실행 (kCFI 타입 해시 검증 및 IBT 인터셉트)
cd labs/scenarios/05-kcfi && make run-hardened
```

**런타임 방어 및 페일세이프 텔레메트리 출력 로그**:
```text
======================================================================
 🤖 Humanoid Robot Control Flow Hijacking & Clang kCFI Lab (CVE-2021-4154) 
======================================================================

[MODE 3: HIJACK ATTEMPT INTERCEPTED BY CLANG KCFI & HARDWARE IBT/BTI]
[*] Initializing Hardened Kernel Environment (CONFIG_CFI_CLANG=y, CONFIG_X86_KERNEL_IBT=y)...
[*] Kernel initiates indirect branch to ops->dispatch_fn (0x619fe45ae690)...
[*] Clang kCFI and CPU Instruction Tracker inspect branch target...

[HARDWARE FAULT: #CP / BTI] Indirect branch target missing valid landing pad (ENDBR64/BTI)!
======================================================================
 [🛡️ CONTROL FLOW VIOLATION DETECTED] Clang kCFI Type Hash Abort! 
======================================================================
  [!] CFI INTERCEPTION FORENSICS:
      Expected Type Hash  = 0x5A8E3F21 (void (*)(actuator_t*, float, float))
      Found Type Hash     = 0x00000000 (Untagged / Mismatched Function Signature)
      Hardware LandingPad = 0x90909090 (Invalid / Missing ENDBR64)
  [!] Kernel Action: Immediate #UD Trap -> Kernel Panic / Oops triggered.
  [!] Indirect Call Executed: 0%. Hostile payload neutralized.

  [FAIL-SAFE ACTIVE] Hardware Safety Relay engaged: Motor Bus Power cut to 0.0V!
  [FAIL-SAFE ACTIVE] Actuator parking brake clamped. Robotic limbs immobilized safely!
```

---

### 5.4 아키텍처 핵심 분석: Rooting (UID 0 / Ring 3) vs Kernel Space Control (Ring 0)의 결정적 차이

제어 흐름 장악(Control Flow Hijack)은 단순 유저 공간 루트 권한 획득(Rooting)과 시스템 장악 차원에서 본질적인 격리 장벽 차이를 가짐:

```
[보안 평가 축]               [루팅 권한 (UID 0 / Ring 3)]          [제어 흐름 장악 (Ring 0 kCFI Hijack)]
명령어 실행 레벨            CPU Ring 3 (유저 공간 모드)           CPU Ring 0 (커널 슈퍼바이저 모드)
간접 분기 대상 자산         유저 프로세스 주소 공간에 국한됨      전체 물리 메모리 및 커널 내부 미공개 함수
하드웨어 MMIO 버스 제어      /dev 노드 통신 API 제약 준수          서보 모터 CAN/EtherCAT 컨트롤러 직통 변조
LSM 보안 검증 무력화         SELinux MAC 정책에 의해 차단 가능     security_hook_heads 자체를 우회 분기
워치독 인터록 해제          하드웨어 인터록 우회 불가능           타이머 인터럽트 핸들러 무력화 가능
```

1. **루팅 권한(UID 0)의 격리 한계**:
    - 루트 사용자는 시스템 파일을 조작할 수 있으나, CPU는 여전히 **Ring 3**에서 동작하므로 커널 내부의 정적 함수 포인터나 MMU 레지스터를 직접 조작할 수 없음.
2. **커널 제어 흐름 장악(Ring 0 kCFI Hijack)의 전면 파괴력**:
    - 공격자가 커널 모드 간접 호출을 탈취하는 데 성공하면, CPU가 **Ring 0** 권한으로 공격자가 원하는 커널 내부 코드를 무제한 실행함.
    - 하드웨어 세이프티 가드 해제, 모터 구동 버스 오버볼티지 인가, 디스크 펌웨어 변조 등 되돌릴 수 없는 물리적 재해를 유발할 수 있으므로 kCFI와 IBT를 통한 1차 방어가 절대적으로 필수적임.

---

## 6. 엔지니어링 심층 분석 (Engineering Deep Dive)

### 6.1 Clang kCFI 어셈블리 생성 및 타입 해시 인라인 검증

Clang이 `-fsanitize=kcfi` 옵션으로 컴파일할 때 간접 호출 지점에 삽입하는 실제 x86-64 어셈블리:

```nasm
# 호출 대상 함수: safe_joint_kinematics
    .section .text
    .p2align 4
    .long   0x5a8e3f21              # __kcfi_typeid_kinematics (-4B 오프셋)
safe_joint_kinematics:
    endbr64                         # x86 IBT Landing Pad (+0B 오프셋)
    pushq   %rbp
    movq    %rsp, %rbp
    ...

# 간접 호출 지점: caller (actuator.c)
    movq    ops(%rip), %rax
    movq    16(%rax), %r11          # r11 = ops->dispatch_fn 주소
    movl    -4(%r11), %r10d         # r10d = 대상 함수의 프리앰블 해시 로드
    cmpl    $0x5a8e3f21, %r10d      # 기대 프로토타입 해시와 대조
    je      .Lcall_valid
    ud2                             # 불일치 시 하드웨어 #UD 트랩 발생!
.Lcall_valid:
    callq   *%r11
```

- **타입 해시 유일성**: 매개변수 타입(`uint32_t`, `float`, `float`)과 반환형(`void`)의 맹글링 문자열을 암호학적으로 해싱하여 32비트 정수로 축약하므로 서로 다른 시그니처 간 충돌 확률이 $2^{-32}$로 극히 낮음.

### 6.2 하드웨어 IBT 상태 머신 및 `#CP` 예외 벡터

인텔 간접 분기 추적기(IBT)의 하드웨어 마이크로아키텍처 동작 원리:

```
[간접 분기 전]          [간접 점프 발생]              [다음 명령어 페치]
IDLE 상태      ───>   WAIT_FOR_ENDBR 상태    ───>  첫 명령어 != ENDBR64 ?
                      (간접 점프 완료 직후)              │
                                                        ├── YES : #CP 예외 발생 (Vector 21)
                                                        └── NO  : IDLE 복귀 (정상 실행)
```

- **예외 발생 시 동작**: CPU가 인터럽트 디스크립터 테이블(IDT)의 벡터 21번(`#CP`) 핸들러를 즉각 호출하여 공격 코드가 단 1개의 인스트럭션도 실행하지 못하도록 하드웨어 파이프라인을 동결함.

### 6.3 ARM64 BTI & PAC 하드웨어 협력

ARM64 아키텍처는 두 가지 하드웨어 기술을 결합하여 완벽한 CFI를 달성함:

1. **BTI (Branch Target Identification)**:
   - x86 IBT와 동일하게 간접 분기 타깃에 `BTI c` 명령어가 없으면 즉각 `Branch Target Exception`을 발생시킴.
2. **PAC (Pointer Authentication Code)**:
   - 함수 포인터를 저장할 때 상위 16비트에 64비트 비밀키와 컨텍스트 기반 암호화 서명(`PACIA`)을 주입함.
   - 호출 시 `AUTIA` 명령어로 서명을 검증하며, 메모리가 변조되었을 경우 유효하지 않은 주소로 붕괴시켜 즉각 `#PF` 크래시를 유도함.

### 6.4 로봇 사이버-물리 페일세이프 아키텍처

제어 흐름 이상 감지 시 물리적 파손을 차단하는 2선 방어 체계:

1. **하드웨어 안전 워치독 인터럽트(Hardware Watchdog)**:
   - kCFI `#UD` 트랩 또는 IBT `#CP` 예외 발생 시 커널 패닉 핸들러가 80 μs 이내에 전용 GPIO 핀을 통해 워치독 펄스를 차단함.
2. **서보 모터 버스 전원 차단 및 기계식 락**:
   - 모터 릴레이 전원을 소자하여 48V 전원을 0.0V로 강제 컷오프(Depower)함.
   - 무여자 작동형 스프링 브레이크가 5ms 이내 물리 체결되어 로봇 관절의 회전 운동 에너지를 100% 흡수하고 정지시킴.

---

## 7. 공식 커널 문서 및 표준 보안 레퍼런스

- [Linux Kernel Documentation - Control Flow Integrity (kCFI)](https://www.kernel.org/doc/html/latest/security/kcfi.html)
- [Linux Kernel Documentation - x86 Indirect Branch Tracking (IBT)](https://www.kernel.org/doc/html/latest/arch/x86/ibt.html)
- [ARM Architecture Reference Manual - Branch Target Identification (BTI)](https://developer.arm.com/documentation/102433/latest/)
- [CVE-2021-4154: Kernel Type Confusion Local Privilege Escalation (NIST NVD)](https://nvd.nist.gov/vuln/detail/CVE-2021-4154)
- [Clang/LLVM Documentation - Kernel Control Flow Integrity](https://clang.llvm.org/docs/ControlFlowIntegrity.html)
