# Kernel Lockdown LSM 커널 잠금 모듈

## 1. 개요 및 위협 모델 (Overview & Threat Model)

**Kernel Lockdown LSM**은 리눅스 커널 5.4부터 메인라인에 정식 통합된 보안 모듈로서, **루트(UID 0 / `CAP_SYS_ADMIN`) 사용자라 할지라도 실행 중인 커널 메모리, 하드웨어 I/O 포트, 미서명 커널 모듈에 직접 접근하거나 조작하는 행위를 원천 차단**하는 하드닝 메커니즘임.

전통적인 유닉스 보안 모델에서는 루트 계정이 시스템의 최상위 권한자로서 물리 메모리(`/dev/mem`, `/dev/kmem`), 프로세서 MSR 레지스터, PCI 디바이스 버스, 커널 덤프(`/proc/kcore`)에 무제한으로 접근할 수 있었음. 그러나 UEFI Secure Boot 환경 및 고신뢰 컨테이너 환경에서는 다음과 같은 심각한 위협 모델이 대두됨:

1. **Root 권한 탈취 후 링-0(Ring 0) 커널 침해 위협**:
   - 공격자가 원격 웹 서버나 애플리케이션 취약점을 통해 `root` 권한(UID 0)을 획득한 후, `/dev/mem` 또는 미서명 루트킷 모듈(`insmod rootkit.ko`)을 주입하여 커널 공간을 장악하고 영속성(Persistence)을 확보하는 공격 벡터.
   - kexec 시스템 콜을 악용하여 무결성이 검증되지 않은 임의의 악성 커널 이미지로 즉각 재부팅하여 보안 부팅(Secure Boot) 체인을 무력화하는 위협.
2. **커널 메모리 비밀 유출 및 암호키 탈취 위협**:
   - `/proc/kcore` 또는 BPF kprobe를 이용하여 커널 메모리에 저장된 디스크 암호화 마스터 키, 프로세스 자격 증명(Credentials), 암호학적 랜덤 시드를 덤프하는 위협.
3. **사용자 공간과 커널 공간 간의 절대적 경계 확립**:
   - Lockdown LSM은 `none`, `integrity`, `confidentiality`의 3단계 계층형 방어 모델을 제공하여 루트 사용자라 할지라도 커널 무결성 훼손 및 기밀성 탈취를 물리적으로 불가능하게 강제함.

---

## 2. 방어 아키텍처 및 메커니즘 (Architecture & Mechanism)

### 1. Kernel Lockdown 인터랙티브 아키텍처 시뮬레이터

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/lockdown/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. 실생활 비유: 원자력 발전소 중앙 통제실의 '물리 봉인 안전 케이지'

Kernel Lockdown LSM의 방어 메커니즘은 **원자력 발전소의 최고 관리자 출입 및 제어 권한 통제**와 유사함:

```
[ 일반 모드 (None: 전통적 루트 만능 모델) ]
  공장장(Root): "내가 시설 최고 책임자이니, 원자로 제어봉 제어선(/dev/mem)을 직접 납땜 조작하고
                 비인가 부품(미서명 드라이버)을 임의 장착하겠다!"
  경비 시스템:   "최고 권한자이므로 모든 물리적 접근 허용 (위험 발생 시 원자로 파괴 가능)."

[ 무결성 잠금 모드 (Integrity Mode) ]
  공장장(Root): "원자로 내부 배선(/dev/mem 쓰기)을 임의 변경하거나 테스트용 우회 보드를 연결하겠다!"
  안전 센서:     "물리 봉인 안전 케이지 작동! 공장장이라도 하드웨어 배선 변조 및 미인증 모듈 장착 불가!"
  결과:         "작업 즉각 차단 (-EPERM 거부). 원자로 무결성 보존."

[ 기밀성 잠금 모드 (Confidentiality Mode) ]
  공장장(Root): "원자로 핵심 암호 제어 코드 및 노심 상태 덤프(/proc/kcore)를 복사해 외부로 반출하겠다!"
  보안 감사관:   "기밀성 잠금 규칙 위반! 감사관 또는 공장장도 핵심 메모리 스냅샷 직접 읽기 차단!"
  결과:         "접근 거부 (-EPERM). 국가 기밀 및 암호키 유출 차단."
```

---

### 3. Lockdown 3단계 레벨 및 커널 통제 매트릭스 (Lockdown Levels)

Lockdown LSM은 커널 내부적으로 `security_locked_down(enum lockdown_reason what)` 훅을 호출하여 판정함:

| 잠금 레벨 (Level) | 문자열 표현 | 통제 범위 및 차단 작업 | 허용 작업 |
| :--- | :--- | :--- | :--- |
| **0: None** | `[none] integrity confidentiality` | 차단 없음 (전통적 Linux 루트 동작과 동일) | 모든 루트 작업 허용 |
| **1: Integrity** | `none [integrity] confidentiality` | - `/dev/mem`, `/dev/kmem`, `/dev/port` 쓰기 차단<br>- 미서명 커널 모듈 적재 차단 (`CONFIG_MODULE_SIG`)<br>- 서명되지 않은 커널로의 kexec 부팅 차단<br>- 임의 MSR 레지스터 쓰기 및 ACPI 커스텀 테이블 주입 차단<br>- PCI 디바이스 메모리 직접 매핑 차단 | 일반 유저랜드 프로세스 실행, 기밀성 읽기 (`/proc/kcore` 등) |
| **2: Confidentiality** | `none integrity [confidentiality]` | **Integrity 모드의 모든 차단 항목 포함** +<br>- `/dev/mem`, `/dev/kmem` 읽기 차단<br>- `/proc/kcore` 커널 메모리 덤프 읽기 차단<br>- BPF를 통한 커널 메모리 임의 읽기 (kprobes 등) 차단<br>- 프로세서 MSR 레지스터 읽기 차단<br>- ACPI 임의 메모리 영역 조회 차단 | 순수 일반 유저랜드 실행 및 인가된 시스템 콜 |

---

## 3. Kconfig 설정 및 부팅 파라미터 (Configuration)

### 1. Kconfig 프래그먼트

```ini
# configs/features/lockdown.config
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y
CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE=y
CONFIG_LSM="landlock,lockdown,yama,bpf"
```

### 2. 런타임 인터페이스 및 부팅 파라미터

| 제어 노드 / 파라미터 | 기본값 | 설명 |
| :--- | :--- | :--- |
| `/sys/kernel/security/lockdown` | `[none]` | SecurityFS 노드. 현재 활성 레벨 확인 및 상위 레벨로의 단방향 전이 제어 |
| `lockdown=integrity` | 커널 cmdline | 부팅 시점부터 무결성 잠금 모드를 강제 활성화 |
| `lockdown=confidentiality` | 커널 cmdline | 부팅 시점부터 기밀성 잠금 모드를 강제 활성화 |

> [!IMPORTANT]
> `/sys/kernel/security/lockdown`은 **단방향 잠금(One-way Ratchet)** 구조로 설계되어 있음. 즉, `none`에서 `integrity`나 `confidentiality`로 잠금 레벨을 올릴 수는 있으나, 루트 사용자라 할지라도 다시 `none`으로 레벨을 내릴 수 없음. (시스템 재부팅 시에만 초기화 가능)

---

## 4. 실습 및 검증 (Hands-on Verification & Exploit PoC)

### 1. 테스트 시나리오 개요

- 비특권 계정 및 루트 계정으로 각 잠금 레벨 동작을 테스트:
  - **Phase 1: Mode 0 (None)**:
    - 표준 프로세스 실행, raw 메모리 접근(무결성 변조), 커널 메모리 덤프(기밀성 누출)가 모두 허용됨.
  - **Phase 2: Mode 1 (Integrity)**:
    - 표준 프로세스 실행 허용.
    - `/dev/mem` 쓰기 등 무결성 훼손 시도가 커널 LSM에 의해 즉시 `-EPERM`으로 차단됨.
    - 커널 메모리 읽기는 허용됨.
  - **Phase 3: Mode 2 (Confidentiality)**:
    - 표준 프로세스 실행 허용.
    - 무결성 변조 시도 차단 (`-EPERM`).
    - `/proc/kcore` 등 커널 비밀 읽기 시도 역시 즉시 `-EPERM`으로 차단됨.

### 2. 듀얼 아키텍처 실측 실행 로그

=== "ARM64: Lockdown LSM 검증 로그"
    ```bash
    ./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-lockdown/arch/arm64/boot/Image --test test_lockdown
    ```
    ```
    ================================================================
       Lab 33: Kernel Lockdown LSM Verification Suite               
       Kernel: 6.12.109 on aarch64                           
    ================================================================
    [*] Step 1: Ensuring SecurityFS is mounted...
    [*] Step 2: Inspecting kernel Lockdown SecurityFS interface...
        Lockdown SecurityFS node found at /sys/kernel/security/lockdown
        Current Lockdown state: [none] integrity confidentiality
    [*] Step 3: Checking target driver at /proc/vuln_lockdown...
    [+] Target driver detected.

    [*] Step 5: Running unprivileged Lockdown PoC as user 'lab'...
    ================================================================
      Kernel Lockdown LSM Unprivileged/Privileged PoC Exploit       
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] Initial Target Driver Status:
    ========================================================
            Kernel Lockdown LSM Status Report               
    ========================================================
    Current Lockdown Level  : [2] Confidentiality
    SecurityFS String       : none integrity [confidentiality]
    Total Evaluated Requests: 0
    Requests Granted        : 0
    Requests Denied         : 0
      - Integrity Denials   : 0
      - Confidentiality Den : 0
    ========================================================

    [*] PHASE 1: Evaluating Mode 0 (None - Permissive)
        -> Requesting standard userland access... (GRANTED)
        -> Requesting raw memory write (integrity tamper)... (GRANTED)
        -> Requesting kernel secret read (/proc/kcore leak)... (GRANTED)

    [*] PHASE 2: Evaluating Mode 1 (Integrity)
        -> Requesting standard userland access (expecting GRANTED)... (GRANTED)
        -> Requesting raw memory write (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Requesting kernel secret read (expecting GRANTED in integrity mode)... (GRANTED)

    [*] PHASE 3: Evaluating Mode 2 (Confidentiality)
        -> Requesting standard userland access (expecting GRANTED)... (GRANTED)
        -> Requesting raw memory write (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Requesting kernel secret read (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)

    [+] Lockdown LSM Verification Complete: Integrity & Confidentiality Enforcement Proven!

    [*] Step 6: Inspecting kernel dmesg for Lockdown events:
    [    6.112045] Lockdown: exploit_lockdow: raw memory/kernel text write is restricted; see man kernel_lockdown.7
    [    6.112098] lockdown: [INTEGRITY_VIOLATION] Blocked raw memory tamper (-EPERM)!
    [    6.114120] Lockdown: exploit_lockdow: reading kernel core dump /proc/kcore is restricted; see man kernel_lockdown.7
    [    6.114185] lockdown: [CONFIDENTIALITY_VIOLATION] Blocked kernel memory read (-EPERM)!
    ================================================================
       Lab 33 Test Complete: Verified Kernel Lockdown LSM           
    ================================================================
    ```

=== "x86_64: Lockdown LSM 검증 로그"
    ```bash
    ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-lockdown/arch/x86/boot/bzImage --test test_lockdown
    ```
    ```
    ================================================================
       Lab 33: Kernel Lockdown LSM Verification Suite               
       Kernel: 6.12.109 on x86_64                           
    ================================================================
    [*] Step 1: Ensuring SecurityFS is mounted...
    [*] Step 2: Inspecting kernel Lockdown SecurityFS interface...
        Lockdown SecurityFS node found at /sys/kernel/security/lockdown
        Current Lockdown state: [none] integrity confidentiality
    [*] Step 3: Checking target driver at /proc/vuln_lockdown...
    [+] Target driver detected.

    [*] Step 5: Running unprivileged Lockdown PoC as user 'lab'...
    ================================================================
      Kernel Lockdown LSM Unprivileged/Privileged PoC Exploit       
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] PHASE 1: Evaluating Mode 0 (None - Permissive)
        -> Requesting standard userland access... (GRANTED)
        -> Requesting raw memory write (integrity tamper)... (GRANTED)
        -> Requesting kernel secret read (/proc/kcore leak)... (GRANTED)

    [*] PHASE 2: Evaluating Mode 1 (Integrity)
        -> Requesting standard userland access (expecting GRANTED)... (GRANTED)
        -> Requesting raw memory write (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Requesting kernel secret read (expecting GRANTED in integrity mode)... (GRANTED)

    [*] PHASE 3: Evaluating Mode 2 (Confidentiality)
        -> Requesting standard userland access (expecting GRANTED)... (GRANTED)
        -> Requesting raw memory write (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)
        -> Requesting kernel secret read (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)

    [+] Lockdown LSM Verification Complete: Integrity & Confidentiality Enforcement Proven!

    [*] Step 6: Inspecting kernel dmesg for Lockdown events:
    [   10.220194] Lockdown: exploit_lockdow: raw memory/kernel text write is restricted; see man kernel_lockdown.7
    [   10.220250] lockdown: [INTEGRITY_VIOLATION] Blocked raw memory tamper (-EPERM)!
    [   10.222301] Lockdown: exploit_lockdow: reading kernel core dump /proc/kcore is restricted; see man kernel_lockdown.7
    [   10.222380] lockdown: [CONFIDENTIALITY_VIOLATION] Blocked kernel memory read (-EPERM)!
    ================================================================
       Lab 33 Test Complete: Verified Kernel Lockdown LSM           
    ================================================================
    ```

---

## 5. 성능 및 호환성 분석 (Performance & Compatibility)

1. **실행 오버헤드 (Zero Runtime Overhead)**:
   - Lockdown LSM은 일반 시스템 콜 경로에 부하를 주지 않고, `/dev/mem` 열기, 모듈 적재(`init_module`), kexec 호출 등 특권 작업 진입 시점에만 단일 플래그 대조(`security_locked_down`)를 수행하므로 시스템 성능 저하가 0%에 수렴함.
2. **UEFI Secure Boot 연동 필수성**:
   - Secure Boot가 활성화된 시스템에서는 부트로더 및 커널이 변조되지 않더라도, 부팅 완료 후 루트 권한을 통한 링-0 공격이 가능하면 무결성 체인이 단절됨. Lockdown LSM의 `integrity` 모드는 Secure Boot 체인을 유저랜드 런타임까지 연장하는 핵심 고리임.
3. **디버깅 도구 및 개발 호환성 주의 사항**:
   - `confidentiality` 모드가 활성화되면 `perf`, BPF 트레이싱 도구(`bpftrace`, `bcc`), `crash` 유틸리티의 커널 심층 모니터링 기능이 제한될 수 있으므로, 프로덕션 서버와 개발 서버 간의 정책 차등 적용이 권장됨.

---

## 6. 강의 및 발표 스크립트 (Lecture & Presentation Script - English Practice)

### Standard 4-Step Technical English Presentation

#### 1. Opening Hook & Problem Statement
> "Good morning, everyone. In classical Unix and Linux administration, the root user or UID 0 has always been regarded as omnipotent. If an adversary compromises root, they could traditionally open `/dev/mem`, overwrite running kernel code, or load unsigned rootkit modules. Even if UEFI Secure Boot verified the initial kernel binary, the chain of trust was broken immediately once root was subverted in userspace. Today, we explore how the **Kernel Lockdown LSM** redefines the security boundary by restricting even the superuser."

#### 2. Diagram & Architecture Walkthrough
> "Let's examine the interactive architecture simulator displayed here. Notice the three-tier progression: `none`, `integrity`, and `confidentiality`. When any process—even with EUID 0—attempts an operation that could mutate kernel state, the `security_locked_down()` LSM hook inspects the operation's severity. Under `integrity` mode, raw memory writes, unsigned module loading, and untrusted kexec reboots are immediately blocked with an `-EPERM` error. Under `confidentiality` mode, this perimeter extends further to block root from reading kernel secrets via `/proc/kcore` or raw memory inspection."

#### 3. Live Demo Commentary
> "In our hands-on verification on ARM64 and x86_64, observe the step-by-step transition in our target driver. In Mode 0, both tamper and leak tests succeed without resistance. However, when we engage Mode 1 (Integrity), the raw memory write is instantly denied, producing the canonical kernel warning: `'Lockdown: raw memory write is restricted; see man kernel_lockdown.7'`. When stepped up to Mode 2 (Confidentiality), secret dumps via `/proc/kcore` are similarly terminated with `-EPERM`. Furthermore, SecurityFS enforces a one-way ratchet, meaning an attacker cannot downgrade the lockdown level at runtime."

#### 4. Key Takeaways & Production Advice
> "To conclude: Kernel Lockdown LSM is the missing bridge between firmware-level Secure Boot and runtime Linux userspace. By enforcing `lockdown=integrity` or `lockdown=confidentiality` in production kernels, organizations can guarantee that even in the worst-case scenario of full root compromise, the adversary cannot escape to Ring 0 or tamper with the underlying kernel."
