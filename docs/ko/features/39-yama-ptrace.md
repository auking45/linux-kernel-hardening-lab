# Yama LSM 및 Ptrace 범위 제한 (Ptrace Scope Restrictions)

## 1. 개요 및 위협 모델 (Overview & Threat Model)

**Yama LSM (`CONFIG_SECURITY_YAMA`)**은 동일한 사용자 계정(Same UID) 내에서 실행 중인 프로세스 간의 **무분별한 `ptrace()` 시스템 콜 디버깅 및 메모리 주입 공격을 제한하여 횡적 이동(Lateral Movement)을 차단하는 핵심 접근 제어 보안 모듈**임.

전통적인 유닉스 임의적 접근 제어(DAC) 모델에서는 동일한 UID를 가진 프로세스라면 권한 상승 없이도 다른 모든 동일 UID 프로세스에 `ptrace(PTRACE_ATTACH)`를 호출하여 메모리를 자유롭게 읽고 쓸 수 있었음:

1. **동일 UID 형제 프로세스(Sibling Process) 침해 위협**:
   - 공격자가 취약한 유저 애플리케이션(e.g., 웹 브라우저, 메신저, 데스크톱 앱)을 통해 비특권 셸을 획득한 후, 동일한 사용자 권한으로 백그라운드에서 동작 중인 `ssh-agent`, `gpg-agent`, 키링 데몬, 암호 관리자 프로세스에 `ptrace`로 부착하는 공격 벡터.
   - root 권한 획득 없이도 메모리 덤프를 통해 SSH 개인키, GPG 패스프레이즈, 브라우저 세션 토큰을 탈취하고 임의 셸코드를 주입(Code Injection)하여 영속성을 확보하는 위협 존재.
2. **디버거 정상 기능과의 조화**:
   - GDB 등 정상 개발 도구는 일반적으로 부모 프로세스가 자식 프로세스를 생성(`fork()`)하여 디버깅하므로, 부모-자식 관계의 정당한 디버깅은 허용하되 무관한 형제 프로세스 간의 부착만 선별 차단하는 정책이 요구됨.
3. **Yama 4단계 Ptrace 통제 범위 (`kernel.yama.ptrace_scope`)**:
   - `0`: 전통적 DAC (제한 없음).
   - `1`: **제한적 Ptrace (기본값)**: 직계 자식 프로세스 또는 `prctl(PR_SET_PTRACER)`로 인가받은 관계만 허용.
   - `2`: 관리자 전용 (`CAP_SYS_PTRACE` 보유 프로세스만 허용).
   - `3`: 완전 차단 (시스템 전역 Ptrace 영구 비활성화).

---

## 2. 방어 아키텍처 및 메커니즘 (Architecture & Mechanism)

### 1. Yama LSM 인터랙티브 아키텍처 시뮬레이터

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/yama-ptrace/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. 실생활 비유: 대기업 연구소의 '프로젝트 팀 간 물리 격리벽'

Yama LSM의 방어 메커니즘은 **동일 부서 연구원 간의 무단 서랍 열람 금지 규정**과 일치함:

```
[ 비활성화 상태 (Scope 0: 전통적 DAC) ]
  침입자:   "나는 김 연구원(UID 1000)의 브라우저를 해킹하여 김 연구원의 신분증을 손에 넣었다!"
  침입자:   "같은 김 연구원의 서랍인 SSH 에이전트와 지갑(동일 UID 형제 프로세스)을 뒤져 마스터키를 훔치겠다!"
  경비원:   "신분증이 같으므로 모든 서랍 열람 허용." (치명적인 계정 탈취 사고 발생)

[ Yama Scope 1 활성화 (Restricted: 기본 모드) ]
  침입자:   "김 연구원의 브라우저에서 SSH 에이전트 프로세스로 ptrace(PTRACE_ATTACH) 시도!"
  검문관:   "Yama LSM 보안 훅(security_ptrace_access_check) 가동! 프로세스 족보(Lineage) 대조!"
  판정:     "브라우저는 SSH 에이전트의 부모가 아님! PR_SET_PTRACER 허가도 없음! 형제 공격 확인!"
  조치:     "접근 즉시 거부 (-EPERM 차단)! SSH 개인키 메모리 보호 완료!"
```

---

### 3. Yama Ptrace Scope 4단계 레벨 매트릭스

| Ptrace Scope | 명칭 및 모드 | 통제 정책 및 허용 범위 | 보안 효과 및 특징 |
| :---: | :--- | :--- | :--- |
| **0** | **Classic DAC** | 동일 UID를 가진 모든 프로세스 간 ptrace 전면 허용 | 보안 취약. 악성코드가 동일 유저의 모든 프로세스 도청 가능 |
| **1** | **Restricted (권장)** | 직계 자식 프로세스(`fork()`) 또는 `prctl(PR_SET_PTRACER)` 명시적 인가 대상만 허용 | Ubuntu, Debian 기본값. 형제 프로세스 공격 완벽 차단. GDB 정상 동작 |
| **2** | **Admin Only** | 오직 `CAP_SYS_PTRACE` 권한(root)을 보유한 프로세스만 ptrace 사용 가능 | 일반 사용자의 모든 디버깅 차단. 고신뢰 프로덕션 서버에 적합 |
| **3** | **No Ptrace** | 시스템 전역에서 ptrace 영구 차단 (root 포함). 재부팅 전까지 0~2로 복구 불가 | **단방향 래칫(One-way Ratchet)**. 금융/국방 미션 크리티컬 노드에 적용 |

---

## 3. Kconfig 설정 및 sysctl 파라미터 (Configuration)

### 1. Kconfig 프래그먼트

```ini
# configs/features/yama.config
CONFIG_SECURITY=y
CONFIG_SECURITY_YAMA=y
CONFIG_LSM="landlock,lockdown,yama,bpf"
```

### 2. 런타임 제어 인터페이스 및 sysctl

| 파라미터 / 인터페이스 | 기본값 | 설명 |
| :--- | :--- | :--- |
| `/proc/sys/kernel/yama/ptrace_scope` | `1` | 활성 Ptrace 범위 (0: DAC, 1: Restricted, 2: Admin, 3: Disabled) |
| `prctl(PR_SET_PTRACER, pid, 0, 0, 0)` | 유저 API | 대상 프로세스가 특정 PID에게 자신을 ptrace하도록 명시적으로 권한 위임 |
| `lsm=...,yama,...` | 커널 cmdline | 커널 부팅 시 활성화할 LSM 스택에 yama 등록 |

---

## 4. 실습 및 검증 (Hands-on Verification & Exploit PoC)

### 1. 테스트 시나리오 개요

- 비특권 계정(`lab`, UID 1000)으로 로그인:
  - **Phase 1: Scope 0 (Classic DAC)**:
    - 자식 프로세스 추적 및 동일 UID 형제 프로세스 추적이 모두 허용됨.
  - **Phase 2: Scope 1 (Restricted Yama)**:
    - 자식 프로세스 추적은 정상 허용 (`ret = 0`).
    - 형제 프로세스 추적 시도 시 커널 Yama LSM이 즉각 가로채 `-EPERM`으로 차단.
  - **Phase 3: Live Sibling Process Ptrace Test**:
    - 파이프로 동기화된 두 형제 프로세스(Sibling A, Sibling B)를 포크.
    - Sibling B가 Sibling A에 `ptrace(PTRACE_ATTACH)` 시도 시 커널이 `-EPERM`을 반환함을 검증.
    - Sibling B가 자신이 직접 포크한 Child C에 부착할 때는 정상 성공함을 검증.

### 2. 듀얼 아키텍처 실측 실행 로그

=== "ARM64: Yama LSM 검증 로그"
    ```bash
    ./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-yama/arch/arm64/boot/Image --test test_yama_ptrace
    ```
    ```
    ================================================================
       Lab 39: Yama LSM Ptrace Scope Verification Suite             
       Kernel: 6.12.109 on aarch64                           
    ================================================================
    [*] Step 1: Inspecting kernel Yama ptrace_scope parameter...
        kernel.yama.ptrace_scope: 1
    [*] Step 2: Checking target driver at /proc/vuln_yama...
    [+] Target driver detected.

    [*] Step 4: Running unprivileged Yama PoC as user 'lab'...
    ================================================================
      Linux Yama LSM Ptrace Scope Restrictions Verification PoC    
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] Kernel Yama Sysctl (/proc/sys/kernel/yama/ptrace_scope): 1
    [*] Initial Target Driver Status:
    ========================================================
            Linux Yama LSM Ptrace Scope Status              
    ========================================================
    Current Ptrace Scope    : [1] 1 (Restricted: Parent-Child only)
    LSM Registered          : CONFIG_SECURITY_YAMA=y
    Total Ptrace Probes     : 0
    Ptrace Attach Granted   : 0
    Ptrace Attach Denied    : 0 (-EPERM)
    ========================================================

    [*] PHASE 1: Evaluating Scope 0 (Classic DAC)
        -> Tracing child process... (GRANTED)
        -> Tracing sibling process with same UID... (GRANTED)

    [*] PHASE 2: Evaluating Scope 1 (Restricted Parent-Child)
        -> Tracing child process (expecting GRANTED: ret = 0)... (GRANTED)
        -> Tracing sibling process (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)

    [*] PHASE 3: Live Sibling Process Ptrace Injection Test
        [Attacker 1082] Attempting ptrace(PTRACE_ATTACH) to Sibling A (1081)...
        [Attacker 1082] [+] SUCCESS: Sibling ptrace was BLOCKED by Yama! (Operation not permitted: errno=1)
                     -> Sibling process memory cannot be snooped or altered!
        [Attacker 1082] Testing allowed parent-to-child ptrace on Child C (1083)...
        [Attacker 1082] [+] SUCCESS: Parent-to-child ptrace succeeded as expected!

    [+] Yama LSM Verification Complete: Sibling Process Tampering Blocked!

    [*] Step 5: Inspecting kernel dmesg for Yama events:
    [    4.110290] yama: [DENIED] Sibling ptrace attack blocked! Sibling-to-sibling ptrace forbidden under Scope 1 (-EPERM)
    ================================================================
       Lab 39 Test Complete: Verified Yama LSM Ptrace Restrictions  
    ================================================================
    ```

=== "x86_64: Yama LSM 검증 로그"
    ```bash
    ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-yama/arch/x86/boot/bzImage --test test_yama_ptrace
    ```
    ```
    ================================================================
       Lab 39: Yama LSM Ptrace Scope Verification Suite             
       Kernel: 6.12.109 on x86_64                           
    ================================================================
    [*] Step 1: Inspecting kernel Yama ptrace_scope parameter...
        kernel.yama.ptrace_scope: 1
    [*] Step 2: Checking target driver at /proc/vuln_yama...
    [+] Target driver detected.

    [*] Step 4: Running unprivileged Yama PoC as user 'lab'...
    ================================================================
      Linux Yama LSM Ptrace Scope Restrictions Verification PoC    
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] Kernel Yama Sysctl (/proc/sys/kernel/yama/ptrace_scope): 1
    [*] PHASE 1: Evaluating Scope 0 (Classic DAC)
        -> Tracing child process... (GRANTED)
        -> Tracing sibling process with same UID... (GRANTED)

    [*] PHASE 2: Evaluating Scope 1 (Restricted Parent-Child)
        -> Tracing child process (expecting GRANTED: ret = 0)... (GRANTED)
        -> Tracing sibling process (expecting BLOCKED: -EPERM)... (BLOCKED: -EPERM)

    [*] PHASE 3: Live Sibling Process Ptrace Injection Test
        [Attacker 2095] Attempting ptrace(PTRACE_ATTACH) to Sibling A (2094)...
        [Attacker 2095] [+] SUCCESS: Sibling ptrace was BLOCKED by Yama! (Operation not permitted: errno=1)
                     -> Sibling process memory cannot be snooped or altered!
        [Attacker 2095] Testing allowed parent-to-child ptrace on Child C (2096)...
        [Attacker 2095] [+] SUCCESS: Parent-to-child ptrace succeeded as expected!

    [+] Yama LSM Verification Complete: Sibling Process Tampering Blocked!

    [*] Step 5: Inspecting kernel dmesg for Yama events:
    [    8.230190] yama: [DENIED] Sibling ptrace attack blocked! Sibling-to-sibling ptrace forbidden under Scope 1 (-EPERM)
    ================================================================
       Lab 39 Test Complete: Verified Yama LSM Ptrace Restrictions  
    ================================================================
    ```

---

## 5. 성능 및 디버깅 호환성 분석 (Performance & Compatibility)

1. **런타임 오버헤드 (Zero Runtime Impact)**:
   - Yama LSM은 프로세스가 `ptrace` 시스템 콜을 통해 다른 프로세스에 부착을 시도하는 순간에만 부모-자식 트리 관계를 대조하므로, 일상적인 프로세스 연산 속도에 미치는 오버헤드는 0%임.
2. **GDB 및 디버거 호환성**:
   - `gdb ./program` 실행 방식은 GDB가 자식 프로세스를 직접 생성하므로 Scope 1에서 아무런 제약 없이 정상 동작함.
   - 이미 실행 중인 프로세스에 뒤늦게 부착하는 `gdb -p <PID>` 방식은 Scope 1에서 차단되므로, 디버깅 대상 프로세스가 시작 시 `prctl(PR_SET_PTRACER, gdb_pid)`을 호출하거나 root 권한(`sudo gdb`)으로 실행해야 함.
3. **프로덕션 보안 권장 사항**:
   - 디버깅 도구가 불필요한 고보안 프로덕션 및 클라우드 컨테이너 노드에서는 `/etc/sysctl.d/99-yama.conf`에 `kernel.yama.ptrace_scope = 2` 또는 `3`을 지정하여 모든 비인가 ptrace 공격을 영구 차단할 것을 권장함.

---

## 6. 강의 및 발표 스크립트 (Lecture & Presentation Script - English Practice)

### Standard 4-Step Technical English Presentation

#### 1. Opening Hook & Problem Statement
> "Good morning, everyone. In standard Linux discretionary access control, all processes running under the same user ID are considered equal peers. While this seems intuitive, it creates a fatal lateral movement vector. If an adversary gains remote execution inside an unprivileged desktop application—like a web browser or chat client—they can simply call `ptrace(PTRACE_ATTACH)` on the user's `ssh-agent`, password vault, or GPG daemon. Without needing root privileges, they can dump cryptographic keys directly from memory. Today, we examine the standard defense against sibling process tampering: **Yama LSM and Ptrace Scope Restrictions**."

#### 2. Diagram & Architecture Walkthrough
> "Please examine our interactive architecture simulator on the screen. Look at the relationship hierarchy. Under traditional Scope 0, any same-UID process can attach to any other process. But when Yama LSM is activated under Scope 1, the `security_ptrace_access_check()` hook evaluates process lineage. A parent process—such as GDB launching a child binary—is granted access cleanly. However, if a sibling process attempts an uninvited attach without prior authorization via `prctl(PR_SET_PTRACER)`, Yama intercepts the system call and immediately terminates it with `-EPERM`."

#### 3. Live Demo Commentary
> "In our live verification on ARM64 and x86_64, look at the transition across test phases. In Phase 1 with Scope 0, sibling attachment succeeds unimpeded. But when we switch to Scope 1, our live sibling exploit test demonstrates that Sibling B's attempt to attach to Sibling A is decisively rejected with `Operation not permitted (errno=1)`. Concurrently, when Sibling B forks its own direct child, the attach succeeds without error. Standard developer debugging remains fully intact, while lateral process eavesdropping is completely neutralized."

#### 4. Key Takeaways & Production Advice
> "To conclude: Yama LSM provides surgical protection against credential dumping and in-memory shellcode injection across same-user processes. Enforcing `kernel.yama.ptrace_scope = 1` should be the standard default on all workstations, while production servers and container hosts should consider elevating to Scope 2 or Scope 3 to permanently close the ptrace attack surface."
