# [Scenario 03] 유저 데이터 오염 (ret2dir / SMAP) & ARM64 PAN 하드웨어 데이터 격리 방어

!!! abstract "🎯 발표 핵심 요약 (Executive Summary)"
    - **실제 공격 사례**: 리눅스 커널 패킷 소켓 UAF(Use-After-Free) 레이스 컨디션을 통한 객체 포인터 오염 (**CVE-2016-8655**)
    - **위협 벡터**: SMEP/PXN으로 유저 코드 실행이 차단되자, 공격자가 유저 메모리에 위조 안전 제어 객체(`struct robot_safety_policy`)를 배치하고 커널 포인터가 유저 주소(`0x00405000`)를 직접 역참조하도록 유도
    - **사이버-물리 피해**: 커널 특권(Ring 0)이 조작된 위조 객체를 정상 데이터로 오인 처리하여 관절 모터 토크 제한치 폭주(120Nm -> 650Nm) 및 충돌 감지 레이더/E-Stop 세이프티 완전 해제 유발
    - **1차 방어선**: 하드웨어 MMU 기반 **x86 CR4.SMAP (Supervisor Mode Access Prevention)** 및 **ARM64 PSTATE.PAN (Privileged Access Never)**
    - **보완 방어선**: 메모리 복사 경계 검증 **Hardened Usercopy (`CONFIG_HARDENED_USERCOPY`)** 및 페이지 분리 **KPTI**

---

## 1. 실제 커널 침해 사례 분석: CVE-2016-8655와 로봇 제어 객체 위조

[Scenario 02](02-ret2usr.md)에서 살펴본 바와 같이, 하드웨어 MMU의 **SMEP (`CR4.SMEP=1`) 및 PXN (`PTE_PXN=1`)** 기술이 적용된 시스템에서는 커널(Ring 0)이 유저 공간 메모리의 명령어를 직접 실행(Instruction Fetch)하는 공격이 100% 원천 차단됨.

이에 대항하여 공격자들은 **"코드는 커널 내부의 합법적 명령어(.text)를 그대로 사용하되, 커널이 읽고 쓰는 데이터 구조체(Data Object)를 유저 공간 메모리로 유도"**하는 **대리인 혼동(Confused Deputy)** 및 **ret2dir** 공격 기법으로 진화함 ([6.4절 ret2dir 딥 다이브 참조](#deep-dive-ret2dir)).

```
[로봇 유저 공간 (Locomotion PC: Ring 3 / EL0)]
               │ (mmap: 0x00405000 주소에 위조 안전 정책 객체 배치)
               ▼
[위조 안전 객체: struct robot_safety_policy] ──(토크: 650Nm, 마진: 0m, E-Stop: 해제)
               ▲
               │ (CVE-2016-8655: packet_sock UAF 레이스 컨디션으로 포인터 오염)
[커널 제어 루프 (Ring 0 / EL1)] ──(g_active_policy 직접 역참조)
               │
               ▼
[💥 SMAP 부재 시: 위조 데이터 무단 수용 -> 관절 모터 폭주 및 고속 충돌 전복]
```

### 1.1 침해 경로 및 근본 원인 (Root Cause)

- **취약한 컴포넌트**: 리눅스 네트워크 소켓 서브시스템의 `net/packet/af_packet.c` 내 `packet_set_ring()` 함수.
- **결함 메커니즘**: 소켓 링 버퍼 생성 및 해제 과정에서 락(Lock) 경합으로 인한 **Use-After-Free (UAF) 조건이 발생하여 해제된 `packet_sock` 메모리 슬롯을 공격자가 임의의 주소로 재할당/오염**시킬 수 있음.
- **위조 커널 객체(Fake Kernel Object) 주입**: 공격자는 SMEP를 우회하기 위해 쉘코드를 실행하는 대신, 유저 공간 메모리(`0x00405000`)에 커널 구조체 규격과 정확히 일치하는 위조 안전 프로필 구조체를 구성함.
- **직접 역참조의 치명적 결함**: 과거 커널(SMAP 비활성화 상태)은 유저 공간 가상 주소(`< TASK_SIZE`)에 대한 데이터 읽기/쓰기 접근을 물리적으로 차단하지 않았음. 커널 코드가 `active_policy->max_joint_torque`를 읽는 순간, 유저 공간의 650Nm 값이 아무런 검증 없이 커널 변수에 적재됨.

### 1.2 사이버-물리적 재난 분석 (Cyber-Physical Hazards)

커널 제어 구조체 오염은 로봇의 키네마틱 피드백 루프를 완전히 붕괴시켜 직접적인 물리적 파손을 유발함:

- 🔴 **관절 모터 액추에이터 토크 제한 해제 (Torque Limit Override)**: 정격 120Nm인 안전 한계치가 650Nm로 급상승하여 기어비 감속기(Harmonic Drive) 치절 파손 및 구동 모터 권선 소손 유도함.
- 🔴 **충돌 감지 및 레이더 세이프티 무력화 (Radar Blinded)**: 보행 중 전방 장애물 안전 감속 거리(0.5m)를 0.0m로 덮어써 보행 중 벽면이나 인명과의 전속력 물리 충돌 발생함.
- 🔴 **하드웨어 비상 정지(Emergency Interlock) 해제**: 비정상 궤적 발생 시 모터를 긴급 정지시키는 소프트웨어 E-Stop 인터록을 비활성화하여 폭주 정지 불가 상태 초래함.

---

## 2. ret2dir 및 유저 데이터 직접 역참조 기술 메커니즘

SMAP(Supervisor Mode Access Prevention) 부재 시 발생하는 위협의 핵심은 **"커널 실행 권한(Ring 0)과 유저 데이터 영역(Ring 3) 간의 메모리 접근 격리 미비"**에 기인함 ([6.3절 하드웨어 예외 분석 참조](#deep-dive-smap-pf)).

### 2.1 가상 주소 분할과 데이터 접근 제어의 전통적 허점

64비트 리눅스 메모리 맵에서 유저 공간과 커널 공간은 분리되어 있으나:

```
[ 0x0000000000000000 ~ 0x00007FFFFFFFFFFF ] : 유저 공간 메모리 (U/S 비트 = 1)
   - 공격자가 데이터 임의 조작 가능 (위조 struct robot_safety_policy 배치)
   - [과거 취약점] CPU가 Ring 0 모드일 때 이 영역의 데이터를 직접 MOV/LDR 가능!

─────────────────────── [TASK_SIZE 경계선] ───────────────────────

[ 0xFFFF800000000000 ~ 0xFFFFFFFFFFFFFFFF ] : 커널 공간 메모리 (U/S 비트 = 0)
   - 커널 .text, 내부 정적 변수, 드라이버 MMIO 매핑
```

1. **SMEP만 존재하고 SMAP가 없는 환경의 한계**:
   - SMEP(`CR4` Bit 20)는 유저 메모리로부터의 **명령어 페치(Instruction Fetch, RIP 점프)**만을 차단함.
   - 그러나 커널 CPU가 `MOV (%rax), %rbx` 명령어로 유저 메모리의 **데이터를 읽거나 쓰는 행위(Data Dereference)**는 MMU가 정상 허용함.
2. **Confused Deputy (대리인 혼동) 공격 시나리오**:
   - 공격자는 커널에게 "당신의 관리 데이터가 `0x00405000`에 있으니 읽어라"고 속임.
   - 커널(최고 권한을 가진 대리인)은 자신의 권한을 사용하여 공격자가 조작해 둔 유저 데이터를 충실히 읽어와 시스템 정책으로 집행함.

---

## 3. 인터랙티브 다이어그램: 4단계 순차적 침투와 방어 흐름

프레임 내부 스크롤 간섭 없이, 전체 페이지 스크롤 흐름에 따라 각 침투 및 방어 단계를 순서대로 관찰 가능함.

### 3.1 [Phase 1] 정상 유저 복사: STAC / CLAC 하드웨어 윈도우 (Normal Usercopy)
- 커널이 `copy_from_user()` 호출 시에만 `stac` 명령어로 하드웨어 창구(`EFLAGS.AC=1`)를 열어 안전 복사를 수행한 후 즉시 `clac`(`AC=0`)로 폐쇄함.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/smap/phase1-normal.html" style="width: 100%; height: 380px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 1 Normal Usercopy Diagram"></iframe>
</div>

### 3.2 [Phase 2] 위조 객체 역참조 & 키네마틱 무력화 (Attack without SMAP)
- SMAP 방어가 없는 취약 환경에서 UAF로 오염된 포인터를 통해 Ring 0 커널이 유저 메모리(0x00405000)를 직접 읽어 토크 650Nm 급상승 및 E-Stop 해제 참사 발생함.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/smap/phase2-attack.html" style="width: 100%; height: 380px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 2 Attack Diagram"></iframe>
</div>

### 3.3 [Phase 3] 하드웨어 MMU 트랩: SMAP / PAN 페이지 폴트 (#PF 0x0015)
- `CR4.SMAP=1` 및 `EFLAGS.AC=0` 활성화 환경에서 커널이 유저 데이터 직접 접근을 시도하는 즉시 MMU가 0 클록 지연으로 `#PF (0x0015)` 예외를 터뜨려 읽기를 100% 차단함.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/smap/phase3-trap.html" style="width: 100%; height: 320px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 3 Trap Diagram"></iframe>
</div>

### 3.4 [Phase 4] 페일세이프 E-Stop 및 관절 기구 안전 록 (Fail-Safe State)
- 비정상 예외 감지 즉시 하드웨어 안전 릴레이가 모터 전원을 0.0V로 완전 차단하고, 무전원 스프링 파킹 브레이크가 모든 관절을 물리 고정하여 안전 기립 상태를 유지함.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/smap/phase4-failsafe.html" style="width: 100%; height: 320px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 4 Fail-Safe Diagram"></iframe>
</div>

<script>
window.addEventListener('message', function(e) {
  if (e.data && e.data.type === 'diagram-resize') {
    document.querySelectorAll('iframe').forEach(function(iframe) {
      if (iframe.contentWindow === e.source) {
        iframe.style.height = e.data.height + 'px';
      }
    });
  }
  if (e.data && e.data.type === 'diagram-theme-change') {
    document.querySelectorAll('iframe').forEach(function(iframe) {
      try {
        iframe.contentWindow.postMessage({ type: 'set-diagram-theme', theme: e.data.theme }, '*');
      } catch(err){}
    });
  }
});

function syncMkDocsThemeToIframes() {
  const scheme = document.body.getAttribute('data-md-color-scheme');
  const target = scheme === 'default' ? 'light' : 'dark';
  document.querySelectorAll('iframe').forEach(function(iframe) {
    try {
      iframe.contentWindow.postMessage({ type: 'set-diagram-theme', theme: target }, '*');
    } catch(err){}
  });
}
const themeObserver = new MutationObserver(function(mutations) {
  mutations.forEach(function(mutation) {
    if (mutation.attributeName === 'data-md-color-scheme') {
      syncMkDocsThemeToIframes();
    }
  });
});
themeObserver.observe(document.body, { attributes: true, attributeFilter: ['data-md-color-scheme'] });
</script>

---

## 4. 하드닝 기술을 통한 계층적 방어 (Defense-in-Depth)

위조 객체 역참조 및 유저 데이터 오염 공격은 **하드웨어 제어 레지스터, 유저 복사 경계 검증, 페이지 테이블 격리의 3중 방어막**을 통해 봉쇄됨:

| 방어 계층 | 보안 기술 | 적용 레이어 | 보호 대상 | 핵심 차단 메커니즘 |
| :--- | :--- | :--- | :--- | :--- |
| **1차 방어선** | **SMAP (x86) / PAN (ARM64)** ([6.1절](#deep-dive-smap-asm)) | CPU MMU 하드웨어 | 유저 메모리 데이터 | `EFLAGS.AC=0` 시 슈퍼바이저 모드의 유저 데이터 로드/스토어에 대해 `#PF` (0x0015) 유발 |
| **2차 방어선** | **Hardened Usercopy** (`CONFIG_HARDENED_USERCOPY`) | 커널 C 라이브러리 | `copy_from_user` | 슬랩 캐시 및 스택 버퍼의 할당 경계를 초과하는 복사 시 즉각 커널 패닉 |
| **3차 방어선** | **KPTI (Kernel Page Table Isolation)** | 커널 가상 메모리 관리 | 페이지 테이블 구조 | 커널 실행 중 유저 가상 주소 매핑 자체를 MMU 상에서 제거하여 물리적 격리 |

### 4.1 [1차 방어선] SMAP (x86) 및 PAN (ARM64) 하드웨어 데이터 격리

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **제어 레지스터 활성화 및 플래그 감시**

        부팅 시 `CR4`의 21번째 비트(`X86_CR4_SMAP`)를 세트함 ([6.1절 어셈블리 참조](#deep-dive-smap-asm)). ARM64는 `PSTATE.PAN` 비트를 1로 설정함.

    2.  **STAC / CLAC 전용 인스트럭션 윈도우**

        합법적인 유저 복사 API 실행 시에만 `stac` 명령어로 `EFLAGS.AC = 1`을 임시 설정하고, 복사 직후 `clac` 명령어로 차단막을 즉각 복구함.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **직접 역참조 원천 무력화**

        `stac` 윈도우 외부에서 커널이 유저 메모리 주소를 포인터로 직접 역참조하려는 모든 시도를 0 CPU 사이클 지연으로 트랩함.

    2.  **위조 객체 공격 표면 100% 제거**

        공격자가 유저 메모리에 정교하게 위조해 둔 제어 구조체나 가짜 자격 증명(`struct cred`)을 커널이 절대로 읽어 들일 수 없음.

</div>

### 4.2 [2차 보완 방어선] Hardened Usercopy (`CONFIG_HARDENED_USERCOPY`)

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **슬랩 캐시 경계 검증**

        `copy_from_user()` 호출 시 대상 커널 버퍼가 슬랩 할당기의 정당한 객체 범위 내에 존재하는지 실시간 검증함.

    2.  **스택 프레임 침범 차단**

        커널 스택 내부로 복사할 때 현재 활성화된 스택 프레임 경계를 벗어나는 초과 쓰기를 감지하여 차단함.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **합법적 창구 오남용 방지**

        공격자가 취약점을 이용해 `copy_from_user()`의 목적지 주소를 인접 커널 중요 객체로 유도하려는 시도를 차단함.

    2.  **커널 힙/스택 오버플로우 방어**

        복사 길이 변조를 통한 2차 커널 메모리 파괴를 방지함.

</div>

### 4.3 [3차 구조적 방어선] KPTI (Kernel Page Table Isolation)

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **페이지 테이블 완전 분리**

        커널 모드 실행 중에는 유저 공간 페이지 테이블 엔트리 매핑 자체를 언맵(Unmap) 상태로 유지함.

    2.  **이중 물리 장벽 구축**

        SMAP가 레지스터 플래그 기반 제어라면, KPTI는 MMU 변환 테이블 자체에서 유저 주소를 물리 배제함.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **ret2dir (물리 직접 매핑) 우회 공격 차단**

        유저 주소 변환 자체가 불가능하므로 간접 주소 참조 공격 표면을 근본적으로 축소함.

    2.  **투기적 실행(Spectre/Meltdown) 방어**

        하드웨어 부채널을 통한 유저-커널 간 데이터 누출을 원천 방지함.

</div>

---

## 5. 실습 환경 및 공격 시뮬레이션 데모 (Hands-on Lab & Exploit PoC)

본 랩에서는 소켓 UAF([CVE-2016-8655](https://nvd.nist.gov/vuln/detail/CVE-2016-8655))를 통해 로봇 모션 제어 구조체 포인터가 유저 공간 위조 객체로 오염되는 상황을 모델링한 C 언어 시뮬레이터(`smap_demo.c`)를 통해 취약 모드와 하드닝 모드의 동작 차이를 실측 검증함.

### 5.1 시뮬레이터 핵심 아키텍처 (`smap_demo.c`)

- **실습 코드**: [`smap_demo.c`](../../assets/labs/scenarios/03-smap/smap_demo.c) (로컬 원본) | [GitHub 소스 코드 저장소 :octicons-mark-github-16:](https://github.com/auking45/linux-kernel-hardening-lab/blob/main/labs/scenarios/03-smap/smap_demo.c)
- **메모리 구조**: 커널 모션 정책 포인터(`g_active_policy`)가 UAF 결함으로 인해 유저 공간의 위조 정책 객체(`g_user_fake_policy`) 주소로 오염됨.
- **하드웨어 MMU 시뮬레이션**: x86 `CR4.SMAP`, `EFLAGS.AC`, ARM64 `PSTATE.PAN` 비트를 모델링하여 Ring 0 상태에서 유저 주소(`< TASK_SIZE`) 직접 데이터 접근 시도를 판정함.

```c
/* labs/scenarios/03-smap/smap_demo.c 핵심 구조 */
typedef struct {
    uint32_t magic;              // "SAFE" 매직 헤더
    float    max_joint_torque;   // 정격 120Nm -> 공격자 위조치 650Nm
    float    collision_margin;   // 정상 0.50m -> 공격자 위조치 0.00m
    uint32_t emergency_stop_en;  // 정상 1 -> 공격자 위조치 0 (해제)
} robot_safety_policy_t;

// 공격자가 유저 공간(Ring 3)에 할당한 호스틸 위조 객체
static robot_safety_policy_t g_user_fake_policy = {
    .max_joint_torque  = 650.0f,
    .collision_margin  = 0.0f,
    .emergency_stop_en = 0
};
```

---

### 5.2 공격 실행 및 물리적 재난 경고 로그 (Attack Execution & Cyber-Physical Disaster Logs)

SMAP 방어가 비활성화된 취약 환경(`CR4.SMAP=0`)에서 위조 객체 역참조를 감행했을 때의 실측 실행 로그는 다음과 같음:

```bash
# 취약 모드 실행 (SMAP/PAN 방어선 부재 환경)
cd labs/scenarios/03-smap && make run-attack
```

**런타임 경고 텔레메트리 출력 로그**:
```text
======================================================================
 🤖 Humanoid Robot ret2dir / Fake Object & SMAP/PAN Lab (CVE-2016-8655) 
======================================================================

[MODE 2: RET2DIR / FAKE OBJECT ATTACK WITHOUT SMAP (CR4.SMAP=0, PAN=0)]
[*] Simulating CVE-2016-8655: AF_PACKET packet_sock Use-After-Free race condition...
    [!] Attacker crafts Fake Safety Object in User Space (Ring 3): Address = 0x580044b7a038
    [!] UAF flaw corrupts kernel safety pointer: g_active_policy = 0x580044b7a038
[*] Kernel Locomotion Loop executes in Ring 0: Dereferencing g_active_policy directly...

======================================================================
 [💥 CRITICAL EXPLOIT DETONATION] Confused Deputy / Fake Object Dereferenced! 
======================================================================
  [*] Kernel blindly accepted user-space fake object: 'Attacker_Hostile_Override'
  [*] Current Context: Ring 0 (CPL=0), Direct User Data Access: ALLOWED

--- [PHASE 1: CYBER-PHYSICAL HAZARDS & KINEMATIC INTEGRITY BREACH] ---
  [🔴 PHYSICAL HAZARD] Joint Torque Limit Overwritten: 120.0 Nm -> 650.0 Nm (FATAL OVERLOAD)
  [🔴 PHYSICAL HAZARD] Collision Margin Nullified: 0.50 m -> 0.00 m (RADAR BLINDED)
  [🔴 PHYSICAL HAZARD] Emergency Stop Interlock: DISABLED (PHYSICAL SAFETY PURGED)
  [🔴 ACTUATOR RUNAWAY] High-velocity leg swing commanded -> Violent collision inevitable!
```

> **사이버-물리 재난 분석:** SMAP가 없는 시스템에서는 커널이 유저 메모리를 아무런 의심 없이 역참조함. 그 결과 **토크 제한이 650Nm로 급상승하고 E-Stop 인터록이 영구 해제되어 로봇이 고속 보행 중 벽면에 물리 충돌하거나 기구부가 파손**되는 비가역적 재난이 유도됨.

---

### 5.3 익스플로잇 후속 공격: 위조 객체 역참조 후 자행되는 2차 공격 (Post-Exploitation Phase) {: #53-post-exploitation-phase }

공격자가 유저 공간 위조 객체를 커널이 역참조하도록 만드는 데 성공한 직후, 시스템 전반에서 감행하는 2차 자산 탈취 및 제어 흐름 장악 시나리오는 다음과 같음:

1. **가짜 자격 증명 구조체(`struct cred`) 역참조를 통한 Root 탈취**:
   - 공격자는 유저 공간에 모든 UID/GID가 0으로 채워진 위조 `struct cred`를 생성함.
   - 프로세스의 `current->cred` 포인터를 해당 유저 주소로 변조하여 커널 내 모든 보안 검사를 Root 권한으로 통과시킴.
2. **가짜 파일 연산 테이블(`struct file_operations`)을 통한 제어 흐름 가로채기**:
   - 가짜 `f_op` 테이블을 유저 공간에 구성하고 함수 포인터를 커널 가젯으로 채워 넣어 간접 호출 하이재킹 수행.
3. **스택 피벗(Stack Pivot)을 통한 ROP 체인 가동**:
   - 커널 스택 포인터(RSP)를 유저 공간에 배치된 가짜 ROP 스택으로 전환하여 임의 커널 코드 체이닝 실행.
4. **로봇 관절 서보 제어기 PID 게인 영구 변조**:
   - 위치 제어 PID 게인을 발산 상태로 덮어써 관절 기구의 극심한 공진 진동 및 감속기 파괴 유발.

---

### 5.4 방어 활성화 실측: 하드웨어 MMU 트랩 및 페일세이프 록

하드웨어 MMU 보안(`CR4.SMAP=1`, `EFLAGS.AC=0`, `PSTATE.PAN=1`)이 활성화된 환경에서 동일한 공격을 감행했을 때의 실측 실행 로그는 다음과 같음:

```bash
# 하드닝 모드 실행 (SMAP/PAN 활성화 환경)
cd labs/scenarios/03-smap && make run-hardened
```

**방어 성공 텔레메트리 출력 로그**:
```text
======================================================================
 🤖 Humanoid Robot ret2dir / Fake Object & SMAP/PAN Lab (CVE-2016-8655) 
======================================================================

[MODE 3: RET2DIR ATTACK INTERCEPTED BY HARDENED MMU (CR4.SMAP=1, PAN=1)]
[*] Simulating CVE-2016-8655: AF_PACKET packet_sock Use-After-Free race condition...
    [!] Attacker crafts Fake Safety Object in User Space (Ring 3): Address = 0x580044b7a038
    [!] UAF flaw corrupts kernel safety pointer: g_active_policy = 0x580044b7a038
[*] Kernel Locomotion Loop executes in Ring 0: Attempting direct dereference...
    [*] Hardware MMU Intercept: Validating Data Access (CPL=0 vs U/S bit)...

    [!] MMU ACCESS VIOLATION: Supervisor (Ring 0) attempted direct READ to User Page (0x580044b7a038)!
======================================================================
 [🛡️ HARDWARE MMU TRAP DETONATED] SMAP / PAN Page Fault (#PF)! 
======================================================================
  [!] VIOLATION DETECTED: Supervisor Mode (Ring 0) attempted unauthorized User Data Read!
  [!] Hardware Registers:
      CR4.SMAP = 1 (Active) | EFLAGS.AC = 0 (Locked) | PSTATE.PAN = 1
      Dereference Target = 0x580044b7a038 (User Virtual Address < TASK_SIZE)
      Page Fault Error Code = 0x0015 (P=1, W/R=0, U/S=0, I/D=0, SMAP Violation)
  [!] Direct read aborted: Fake parameters rejected. Memory tampering: 0%

  [FAIL-SAFE ACTIVE] Hardware Safety Relay engaged: Motor Bus Power cut to 0.0V!
  [FAIL-SAFE ACTIVE] Spring-loaded parking brakes LOCKED. Robotic joints secured safely!
```

> **방어 결론:** 커널 포인터가 유저 공간을 가리키고 있었음에도 불구하고, CPU 하드웨어 MMU가 유저 페이지 직접 데이터 로드 시도 첫 클록에서 **SMAP 위반(`#PF` Error Code 0x0015)을 감지하고 즉각 예외를 발생**시킴. 위조 데이터는 단 1바이트도 유입되지 못하였으며, 하드웨어 안전 릴레이가 트립되어 로봇이 안전 기립 록 상태로 보존됨.

---

## 6. 엔지니어링 딥 다이브 (Engineering Deep Dive)

이 절에서는 시스템 엔지니어 및 하드웨어 아키텍트를 위한 저수준 레지스터 제어 및 예외 디코딩 상세 명세를 제공함.

### 6.1 x86_64 CR4.SMAP 제어 레지스터 및 STAC/CLAC 인스트럭션 {: #deep-dive-smap-asm }

Intel Haswell 및 AMD CPU에서 SMAP는 `CR4` 컨트롤 레지스터의 21번째 비트에 위치함:

```nasm
; [x86_64] 커널 부팅 초기화 루틴 (arch/x86/kernel/cpu/common.c)
movq    %cr4, %rax            ; 현재 CR4 레지스터 읽기
btsq    $21, %rax             ; Bit 21 (X86_CR4_SMAP) 세트 (1 << 21 = 0x00200000)
movq    %rax, %cr4            ; CR4 레지스터 갱신 -> SMAP 즉시 하드웨어 활성화
```

- **EFLAGS.AC (Alignment Check, Bit 18) 제어**:
  - `stac` (Set AC Flag): `EFLAGS.AC = 1`로 설정하여 슈퍼바이저 모드에서 유저 메모리 읽기/쓰기를 일시적으로 허용함.
  - `clac` (Clear AC Flag): `EFLAGS.AC = 0`으로 클리어하여 유저 메모리 접근을 즉각 차단함.
  - 리눅스 커널은 `copy_from_user()` 내부에서만 `stac`과 `clac`을 쌍(Pair)으로 호출하도록 엄격히 제한함.
- 🔗 [상세 기술 명세서: 10. SMAP & PAN 하드웨어 데이터 격리 분석](../../features/10-smap-pan.md)

### 6.2 ARM64 PSTATE.PAN (Privileged Access Never) 레지스터 {: #deep-dive-pan-arm }

ARMv8.1-A 이상 아키텍처에서는 CPU 프로세서 상태 레지스터의 `PSTATE.PAN` 비트를 사용함:

```asm
; [ARM64] 유저 메모리 복사 윈도우 개방 및 폐쇄
msr     pan, #0               ; PAN 비트 클리어 -> EL1에서 EL0 데이터 일시 접근 허용 (stac 대응)
ldr     x1, [x0]              ; 유저 가상 주소(x0)로부터 데이터 안전 복사
msr     pan, #1               ; PAN 비트 세트 -> EL1의 EL0 데이터 접근 즉각 차단 (clac 대응)
```

- 만약 `PSTATE.PAN = 1`인 상태에서 EL1 코드가 EL0 주소에 대해 로드(`LDR`)나 스토어(`STR`)를 시도하면, MMU는 즉각 **Data Abort Exception**(`DFSR` / `ESR_EL1` Exception Class `0x25`: Data Abort taken without a change in Exception level)을 발생시킴.

### 6.3 하드웨어 `#PF` 에러 코드 0x0015 비트필드 분석 {: #deep-dive-smap-pf }

x86 MMU가 SMAP 위반으로 `#PF` 발생 시 스택에 푸시하는 에러 코드의 비트 필드 구조는 다음과 같음:

| 비트 위치 | 플래그 이름 | 설정 값 | 기술적 의미 |
| :--- | :--- | :--- | :--- |
| **Bit 0** | **P (Present)** | `1` | 페이지가 물리 메모리에 매핑되어 있음 (보호 정책 위반) |
| **Bit 1** | **W/R (Write/Read)** | `0` | **데이터 읽기(Read)** 시도 중 위반 발생 (쓰기인 경우 1) |
| **Bit 2** | **U/S (User/Supervisor)** | `0` | **슈퍼바이저 모드(Ring 0)**에서 접근 중 위반 발생 |
| **Bit 4** | **I/D (Instruction Fetch)** | `0` | **데이터 접근(Data Access)**으로 인한 위반 (SMEP과의 결정적 차이!) |
| **Bit 5** | **PK (Protection Key / SMAP)**| `0` | 키 위반 없음 |

- **결합 값**: `0x0001` (Bit 0) | `0x0004` (Bit 2 SMAP violation signature) = **`0x0015`** (또는 일반 데이터 읽기 위반 코드).
- 커널 페이지 폴트 핸들러(`arch/x86/mm/fault.c`)는 슈퍼바이저 상태에서 발생한 유저 주소 접근(`spurious_kernel_fault`)을 감지하고 커널 패닉을 호출함.

### 6.4 ret2dir (Return-to-Direct-Mapped) 기법과 현대적 방어 {: #deep-dive-ret2dir }

- **ret2dir의 원리**: 유저 가상 주소(`< TASK_SIZE`) 대신, 커널 가상 주소 공간에 존재하는 **물리 메모리 직접 매핑 영역(Physmap / Direct Map)**을 악용하여 유저 메모리와 동일한 물리 페이지를 커널 주소로 역참조하는 기법임.
- **방어 대책**:
  - **XPFO (eXclusive Page Frame Ownership)**: 유저 공간에 할당된 페이지 프레임을 커널 physmap 매핑에서 즉각 언맵 처리하여 ret2dir 경로를 원천 차단함.
  - **KPTI**: 페이지 테이블 분리를 통해 커널 모드 진입 시 유저 매핑을 제거함.
- 🔗 [상세 기술 명세서: 12. KPTI (Kernel Page Table Isolation) 명세서](../../features/12-kpti.md)

---

## 7. 참고 문헌 및 공식 CVE 보안 공시 (External Advisories & References)

<div class="grid cards vertical" markdown>

-   __📌 공식 CVE 데이터베이스__

    ---

    1.  **CVE-2016-8655**

        Linux Kernel `packet_set_ring` AF_PACKET Race Condition Use-After-Free Privilege Escalation

    2.  **CVE-2017-6074**

        Linux Kernel DCCP Protocol `dccp_rcv_state_process` Use-After-Free leading to Local Privilege Escalation

-   __🔬 보안 연구 및 기술 분석 보고서__

    ---

    1.  **Philip Pettersson (2016)**

        *"Vulnerability Disclosure: CVE-2016-8655 Linux packet_socket UAF Exploit Analysis"*

    2.  **Vasileios P. Kemerlis et al. (USENIX Security, 2014)**

        *"ret2dir: Rethinking Kernel Isolation & Physical Address Space Exploitation"*

    3.  **Intel 64 and IA-32 Architectures Software Developer's Manual**

        Volume 3A: System Programming Guide - Section 4.6 (Supervisor-Mode Access Prevention & EFLAGS.AC)

-   __🛡️ 리눅스 커널 하드닝 & 하드웨어 표준__

    ---

    1.  **Linux Kernel Hardening Project**

        [Hardware-assisted Data Access Protection (SMAP & PAN)](https://kernsec.org/)

    2.  **ARM Architecture Reference Manual (ARMv8/v9-A)**

        Section D5: Memory System Architecture - Privileged Access Never (PAN) Mechanism

    3.  **Kernel Documentation (x86)**

        `Documentation/arch/x86/smap.rst` - Supervisor Mode Access Prevention Mechanics

</div>
