# [Scenario 01] 휴머노이드 무선 통신 데몬의 버퍼 오버플로우와 스택 카나리 방어

!!! abstract "🎯 발표 핵심 요약 (Executive Summary)"
    - **실제 공격 사례**: Unitree G1 EDU 휴머노이드 로봇의 BLE 데몬 버퍼 오버플로우 (**CVE-2026-76640**)
    - **위협 벡터**: 페어링 없는 BLE GATT 쓰기를 통해 500바이트 버퍼에 1,050바이트 초과 입력 주입
    - **사이버-물리 피해**: 보행 제어 컴퓨터(Locomotion PC)의 `root` 권한 탈취 및 충돌 감지(Collision Detection) 세이프티 무력화
    - **1차 방어선**: 컴파일러 기반 **스택 카나리 (Stack Protector: `CONFIG_STACKPROTECTOR_STRONG`)**
    - **보완 방어선**: **Fortify Source (`_FORTIFY_SOURCE=3`)** 및 **Seccomp / Least Privilege 격리**

---

## 1. 실제 휴머노이드 로봇 침해 사례 분석: Unitree G1 EDU (CVE-2026-76640)

2026년 8월, 보안 연구원 Olivier Laflamme에 의해 공개된 **Unitree G1 EDU 휴머노이드 로봇의 원격 코드 실행(RCE) 취약점**은 임베디드 사이버-물리 시스템(CPS)에서 메모리 오염 취약점이 물리적 파손을 유발하는 대표적인 실전 사례임 ([6.1절 딥 다이브 참조](#deep-dive-bss-stack)).

```
[근거리 공격자 (BLE 반경 10m)]
               │ (페어링 없는 GATT 쓰기: 0xFFE2)
               ▼
[휴머노이드 통신 데몬: btgatt-server] ──(1,050B 초과 복사)──> [500B wifi_ssid 버퍼 오버플로우]
                                                                     │ (이벤트 루프 포인터 오염)
                                                                     ▼
                                                   [Locomotion PC Root 코드 실행 (system())]
                                                                     │
                                                                     ▼
                                                   [💥 충돌 감지 무력화 & 로봇 물리 제어권 탈취]
```

### 1.1 침해 경로 및 근본 원인 (Root Cause)

- **취약한 컴포넌트**: 로봇의 무선 프로비저닝을 담당하는 백그라운드 데몬인 `btgatt-server`.
- **결함 메커니즘**: 블루투스 저전력(BLE) 인터페이스를 통해 Wi-Fi 접속 정보를 수신할 때, **500바이트 크기의 `wifi_ssid` 버퍼에 길이 검증(Bounds Check) 없이 1,050바이트의 데이터를 기록**하는 전형적인 버퍼 오버플로우(Buffer Overflow) 발생함.
- **권한 상승 및 장악**: 오버플로우된 데이터가 인접한 메모리 구조체와 이벤트 루프 제어 흐름을 변조하여, 최종적으로 보행 제어 컴퓨터(Locomotion PC)에서 `system()` 명령을 `root` 권한으로 실행하게 됨.

### 1.2 사이버-물리적 위협 분석 (Cyber-Physical Hazards)

일반 서버 환경의 침해 사고와 달리, 휴머노이드 로봇에서의 Root 쉘 획득은 다음과 같은 직접적인 물리적 재난으로 직결됨:

- 🔴 **충돌 감지 및 비상 정지(Safety Interlock) 소프트웨어 무력화**: 로봇이 사람이나 장애물을 인지하고 감속/정지하는 센서-액추에이터 피드백 루프를 소프트웨어 레벨에서 해제 가능함.
- 🔴 **보행 제어 궤적 변조**: 다리 관절 액추에이터의 토크 제한치(Torque Limit)를 변조하여 고속 보행 중 전복을 유도하거나 기구부 모터 과열 파손 유발함.
- 🔴 **로봇 봇넷(Physical Botnet) 전파**: 침해된 G1 로봇이 자체 BLE 송신기를 통해 주변 반경 내의 다른 G1 로봇을 연쇄적으로 무선 감염시키는 물리 봇넷 구성 가능함.

---

## 2. 버퍼 오버플로우 기술 메커니즘 및 메모리 오염 원리

버퍼 오버플로우는 프로그램이 할당된 메모리 버퍼의 물리적 경계를 검사하지 않고 데이터를 초과 복사(`memcpy`, `strcpy`, 잘못된 포인터 연산)할 때 발생함 ([6.2절 어셈블리 검증 참조](#deep-dive-assembly)).

### 2.1 스택 프레임의 침식 과정

함수가 호출될 때 스택 메모리는 다음과 같은 순서로 배치됨:

```
[ 낮은 주소 (Low Memory) ]
▲  [ 로컬 변수 및 버퍼: char cmd_buf[64] ] ── (정상 쓰기 방향: ────────────────▶ )
│  -------------------------------------------------- [경계선]
│  [ 스택 카나리 (Stack Canary: 난수) ]      <--- 오버플로우 시 1차 오염 대상!
│  [ 저장된 프레임 포인터 (Saved FP / RBP) ]  <--- 2차 오염 대상
│  [ 함수 리턴 주소 (Return Address / RIP) ]  <--- 3차 오염 대상 (공격자의 최종 목표)
[ 높은 주소 (High Memory) ]
```

1. **정상 동작**: 로컬 버퍼 크기(예: 64B 또는 500B) 내에서만 데이터가 기록되며, 카나리와 리턴 주소는 안전하게 보존됨.
2. **오버플로우 발생**: 입력 데이터가 버퍼 크기를 초과하면 인접한 메모리로 덮어쓰기(Overflow)가 시작됨.
3. **제어 흐름 탈취 시도**: 방어 기능이 없다면 공격자가 리턴 주소(RIP/LR)를 악성 쉘코드나 가젯 주소로 덮어써서, 함수가 반환되는 순간 CPU 실행 흐름을 완전히 장악함.

---

## 3. 인터랙티브 다이어그램: 4단계 순차적 침투와 방어 흐름

프레임 내부 스크롤 간섭 없이, 전체 페이지 스크롤 흐름에 따라 각 침투 및 방어 단계를 순서대로 관찰 가능함.

### 3.1 [Phase 1] 정상 무선 텔레메트리 및 안전한 스택 메모리 (Normal State)
- 관제 콘솔에서 유효한 규격(32B)의 정상 BLE 패킷 수신 및 스택 카나리 무결성(VALID) 유지 상태임.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/humanoid-bof/phase1-normal.html" style="width: 100%; height: 380px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 1 Normal State Diagram"></iframe>
</div>

### 3.2 [Phase 2] 초과 페이로드 주입과 메모리 침범 (Buffer Overflow Injection)
- 페어링 없는 BLE GATT 인터페이스를 통해 500B 버퍼에 1,050B 악성 입력을 주입하여 카나리 슬롯(`0x4141...`)을 덮어씀.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/humanoid-bof/phase2-attack.html" style="width: 100%; height: 380px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 2 Attack Diagram"></iframe>
</div>

### 3.3 [Phase 3] 스택 카나리 방어선 작동 및 실행 차단 (Canary Trap & Intercept)
- 함수 에필로그에서 마스터 가드와 스택 카나리의 불일치 감지 즉시 `__stack_chk_fail()` 핸들러 호출하여 리턴 주소 분기를 100% 원천 차단함.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/humanoid-bof/phase3-trap.html" style="width: 100%; height: 320px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 3 Trap Diagram"></iframe>
</div>

### 3.4 [Phase 4] 페일세이프 E-Stop 및 로봇 안전 정지 (Fail-Safe State)
- 비정상 종료 감지 즉시 하드웨어 세이프티 릴레이가 관절 모터 드라이버 전원을 물리 차단(0V)하여 로봇을 기립 록 상태로 안전 정지시킴.

<div style="margin: 1rem 0; overflow: hidden; border-radius: 8px;">
  <iframe src="../../assets/diagrams/humanoid-bof/phase4-failsafe.html" style="width: 100%; height: 320px; border: none; display: block; overflow: hidden;" scrolling="no" onload="try { if(this.contentWindow.document.querySelector('.card')) { this.style.height = (this.contentWindow.document.querySelector('.card').offsetHeight + 16) + 'px'; } } catch(e){}" title="Phase 4 Fail-Safe Diagram"></iframe>
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
});
</script>


---

## 4. 하드닝 기술을 통한 계층적 방어 (Defense-in-Depth)

Unitree G1 사례와 같은 메모리 오염 기반 RCE는 단일 보안 패치가 아닌 **컴파일러, 커널, 샌드박싱의 다층 하드닝(Defense-in-Depth)**을 통해 원천 무력화 가능함:

| 방어 계층 | 보안 기술 | 적용 레이어 | 보호 대상 | 핵심 차단 메커니즘 |
| :--- | :--- | :--- | :--- | :--- |
| **1차 방어선** | **Stack Protector** (`CONFIG_STACKPROTECTOR_STRONG`) ([6.3절](#deep-dive-compiler-flags)) | 컴파일러 / 함수 스택 | 리턴 주소 (RIP/LR) | 에필로그 XOR 검증 불일치 시 `__stack_chk_fail()` 패닉 유도 (0% 저지) |
| **2차 방어선** | **Fortify Source** (`_FORTIFY_SOURCE=3`) ([6.4절](#deep-dive-fortify)) | 컴파일러 / C 라이브러리 | 메모리 복사 함수 | 런타임 버퍼 오버플로우(1,050B > 500B) 복사 전 감지 즉시 `SIGABRT` |
| **3차 방어선** | **Least Privilege & Seccomp** | 시스템 / 커널 LSM | 권한 및 시스템 콜 | 비특권 UID 격리 및 `execve` 차단으로 Root 쉘 획득 원천 무력화 |

### 4.1 [1차 방어선] 스택 카나리 (Stack Protector: `CONFIG_STACKPROTECTOR_STRONG`)

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **프롤로그 난수 삽입**

        컴파일러(GCC/Clang)는 함수 진입 시 리턴 주소 바로 앞 스택 슬롯에 프로세스별 무작위 64비트 난수(Canary)를 삽입함 ([6.3절 플래그 기준 참조](#deep-dive-compiler-flags)).

    2.  **에필로그 XOR 무결성 검증**

        함수 복귀(ret) 직전, 스택에 보존된 카나리 값을 마스터 레지스터 참조값(x86: `%gs:40`, ARM64: `__stack_chk_guard`)과 XOR 연산으로 대조함.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **선행 덮어쓰기 강제**

        버퍼 오버플로우 페이로드가 리턴 주소에 도달하려면 반드시 그 사이에 위치한 카나리 슬롯을 먼저 덮어쓸 수밖에 없음.

    2.  **실행 흐름 탈취 원천 차단**

        카나리 변조 확인 즉시 `ret` 명령어를 실행하지 않고 `__stack_chk_fail()` 핸들러를 호출하여 프로세스를 패닉/종료시킴으로써 임의 코드 실행 성공률을 0%로 차단함.

</div>

### 4.2 [2차 보완 방어선] Fortify Source (`_FORTIFY_SOURCE=3`)

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **안전 래퍼 함수 자동 치환**

        컴파일러가 위험 메모리 함수(`memcpy`, `strcpy`, `snprintf`)의 목적지 버퍼 크기를 인지할 수 있는 경우(예: `sizeof(wifi_ssid) == 500`), 빌드 타임에 안전 래퍼 함수(`__memcpy_chk`)로 자동 교체함 ([6.4절 메커니즘 참조](#deep-dive-fortify)).

    2.  **런타임 크기 사전 계산**

        Clang/GCC의 `__builtin_dynamic_object_size`를 활용하여 복사 실행 직전 소스 크기와 타깃 버퍼 크기를 동적으로 비교 검증함.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **메모리 오염 전 선제적 차단**

        런타임에 복사 데이터 길이(1,050B)가 버퍼 크기(500B)를 초과함을 복사 시작 전에 감지하고 즉시 프로세스를 강제 중단(`SIGABRT`)함.

    2.  **제로데이 익스플로잇 방어**

        스택뿐만 아니라 힙(Heap) 및 BSS 전역 변수 영역의 버퍼 오버플로우까지 광범위하게 보호함.

</div>

### 4.3 [3차 권한 격리] 최소 권한 및 Seccomp 시스템 콜 필터링

<div class="grid cards vertical" markdown>

-   __⚙️ 작동 원리 (Mechanism)__

    ---

    1.  **비특권 전용 계정 격리**

        블루투스 통신 데몬(`btgatt-server`)을 시스템 최고 권한인 `root`가 아닌 전용 비특권 계정(`bluetooth` / `daemon`)으로 강제 강등하여 실행함.

    2.  **Seccomp-BPF 시스템 콜 화이트리스트**

        통신 데몬에 BPF 필터를 적용하여 네트워크 통신 및 이벤트 처리에 필요한 시스템 콜만 허용하고, 위험 시스템 콜을 원천 차단함.

-   __🛡️ 방어 효과 (Defense Impact)__

    ---

    1.  **RCE 발생 시 피해 반경 최소화**

        취약점으로 인해 데몬의 제어권이 탈취되더라도, 공격자가 획득하는 권한은 비특권 권한에 불과하여 보행 제어 하드웨어 직접 접근이 불가능함.

    2.  **쉘 획득 및 프로세스 생성 차단**

        공격자의 쉘 획득 시도(`execve`, `fork`, `system`)가 Seccomp 계층에서 즉각 `SIGSYS` 또는 `EPERM`으로 차단됨.

</div>

---

## 5. 실습 환경 및 공격 시뮬레이션 데모 (Hands-on Lab & Exploit PoC)

본 랩에서는 실제 Unitree G1 휴머노이드 로봇의 무선 프로비저닝 데몬 결함([CVE-2026-76640](https://nvd.nist.gov/vuln/detail/CVE-2026-76640))을 재현한 C 언어 시뮬레이터(`humanoid_bof_demo.c`)를 통해, 취약한 환경과 스택 카나리가 적용된 환경의 동작 차이를 실측 검증함.

### 5.1 취약 데몬 시뮬레이터 구현 (`humanoid_bof_demo.c`)

- 실습 코드 위치: [`labs/scenarios/01-humanoid-bof/humanoid_bof_demo.c`](file:///home/auking45/repos/linux-kernel-hardening-lab/labs/scenarios/01-humanoid-bof/humanoid_bof_demo.c)
- **메모리 구조**: 500바이트 크기의 스택 버퍼(`ssid`) 뒤에 스택 카나리 및 이벤트 콜백 함수 포인터가 인접 배치됨.
- **취약점 트리거**: 길이 검증 없이 1,050바이트의 악성 BLE 패킷을 복사하여 스택 슬롯을 파괴함.

```c
/* labs/scenarios/01-humanoid-bof/humanoid_bof_demo.c 핵심 구조 */
typedef struct {
    char ssid[500];             // 500바이트 로컬 스택 버퍼
    uint64_t simulated_canary;  // 스택 카나리 난수 슬롯 (%gs:40 / __stack_chk_guard)
    void (*event_callback)(void); // 함수 복귀 주소 및 이벤트 콜백
} daemon_context_t;
```

---

### 5.2 공격 실행 및 물리적 재난 경고 로그 (Attack Execution & Cyber-Physical Disaster Logs)

컴파일 시 스택 보호를 비활성화(`-fno-stack-protector`)한 취약 데몬에 1,050바이트 공격 페이로드를 주입했을 때의 실측 실행 로그는 다음과 같음:

```bash
# 취약 모드 실행 (방어선 부재 환경)
cd labs/scenarios/01-humanoid-bof && make run-attack
```

**런타임 경고 텔레메트리 출력 로그**:
```text
======================================================================
 🤖 Humanoid Robot BLE Daemon BOF & Hardening Laboratory (CVE-2026-76640) 
======================================================================

[MODE 2: ATTACK INJECTION WITHOUT STACK CANARY (EXPLOIT SUCCEEDS)]
[*] Processing incoming BLE GATT packet (Length: 1050 bytes, Buffer capacity: 500 bytes)...
    [!] BUFFER OVERFLOW TRIGGERED: copying 1050 bytes into 500-byte stack buffer!

======================================================================
 [💥 CRITICAL EXPLOIT DETONATION] Locomotion PC Hijacked! 
======================================================================
  [*] Attacker control flow reached: __builtin_return_address(0) hijacked!
  [*] Current Context: UID = 0, EUID = 0 (root / Locomotion Daemon)

--- [PHASE 1: CYBER-PHYSICAL HAZARDS & SAFETY OVERRIDE] ---
  [🔴 PHYSICAL HAZARD] Collision Avoidance Safety Interlock (Radar Loop): DEACTIVATED
  [🔴 PHYSICAL HAZARD] Actuator Torque Limit modified: 120.0 Nm -> 350.0 Nm (OVERLOAD)
  [🔴 PHYSICAL HAZARD] Gait Trajectory: High-speed instability injected -> Risk of Violent Tip-over
  [🔴 BOTNET BEACON] BLE Transmitter reconfigured: Broadcasting worm beacon on GATT 0xFFE2
```

> **사이버-물리 재난 분석:** 버퍼 오버플로우로 인해 제어 흐름이 탈취되는 순간, 일반 IT 시스템의 데이터 유출 단계를 넘어 **하드웨어 인터록 해제 및 모터 토크 과열 파손**이라는 비가역적 물리 재난이 즉각 유도됨.

---

### 5.3 익스플로잇 후속 공격: 로컬 민감 정보 및 제어 소켓 탈취 (Post-Exploitation Phase)

공격자가 데몬을 통해 `root` 쉘(UID 0)을 획득한 직후, 로봇 로컬 시스템에서 자행하는 2차 자산 탈취 시나리오는 다음과 같음:

```text
--- [PHASE 2: LOCAL SENSITIVE ASSET EXFILTRATION] ---
  [🔓 ASSET DUMP] /etc/unitree/wpa_supplicant.conf -> PSK: "Corp_Secret_Robotics_2026!"
  [🔓 ASSET DUMP] /opt/unitree/calibration.json    -> Joint Zero-Offsets & Kinematic Matrix exfiltrated
  [🔓 ASSET DUMP] /var/run/unitree/locomotion.sock  -> Direct IPC socket connection established
```

1. **사내 Wi-Fi 마스터 키 탈취**: 로봇에 저장된 기업 무선망 접속 패스프레이즈를 탈취하여 인접 내부망으로 침투 반경 확장.
2. **기구학 캘리브레이션 덤프**: 관절 모터의 영점 오프셋 및 PID 게인 값을 유출하여 하드웨어 파라미터 교란.
3. **보행 제어 IPC 소켓 연결**: `/var/run/unitree/locomotion.sock` 도메인 소켓에 악성 관절 궤적 패킷을 직접 주입하여 보행 전복 유도.

---

### 5.4 아키텍처 핵심 분석: Rooting (UID 0 / Ring 3) vs Kernel Space (Ring 0)의 결정적 차이

많은 시스템 관리자와 개발자가 *"루팅(UID 0)을 당하면 공격자가 OS 전체와 하드웨어를 무제한 장악한다"*고 오해함. 그러나 리눅스 아키텍처 관점에서 **루팅과 커널 제어권 장악은 완전히 다른 차원의 보안 경계(Security Boundary)**임:

!!! tip "🛡️ 전사적 보안 아키텍처 심층 분석 (Overview Deep Dive)"
    유저 공간 신원(UID 0)과 CPU 특권 링(Ring 0)의 2중 격리 모델, 커널 하드닝 차단 4대 메커니즘, 그리고 전체 시나리오를 관통하는 공격 체인 피벗(Pivot) 다이어그램의 포괄적 분석은 **[시나리오 로드맵 & 아키텍처 개요: Rooting vs Kernel Space 본질적 차이](index.md#security-boundary-root-vs-kernel)**에서 확인할 수 있음.

```text
+-------------------------------------------------------------------------------+
| [USER SPACE (Ring 3 / EL0)]                                                   |
|   - 일반 사용자 (UID 1000)                                                     |
|   - 루트 관리자 (UID 0)  <--- BLE 데몬 장악 시 공격자가 도달하는 위치!           |
|     * 파일 시스템(/etc/shadow, 설정 파일) 및 일반 네트워크 제어 가능               |
|     * [하드웨어 격리] CPU 특권 명령어(CR0/CR4, 페이지 테이블) 직접 실행 불가!     |
+-------------------------------------------------------------------------------+
       │
       │ === [System Call & Hardware Privilege Boundary] ===
       │ (커널 하드닝 방어선: Lockdown LSM, Module Signing, Strict Devmem)
       ▼
+-------------------------------------------------------------------------------+
| [KERNEL SPACE (Ring 0 / EL1)]                                                 |
|   - MMU 페이지 테이블 매핑, 물리 메모리 직접 접근, 인터럽트 디스크립터(IDT)      |
|   - 하드웨어 완전 제어권 (커널 하드닝 무력화 및 영구 루트킷 상주 가능)           |
+-------------------------------------------------------------------------------+
```

#### (1) 루트(UID 0) 상태에서도 커널 하드닝에 의해 차단되는 작업들

데몬이 UID 0 권한으로 실행 중이더라도, 현대적인 리눅스 커널 하드닝이 활성화된 시스템에서는 다음 작업들이 유저 공간(Ring 3)에서 원천 차단됨:

1. **물리 메모리 및 커널 코드 직접 변조 차단 (`CONFIG_STRICT_DEVMEM` / Lockdown LSM)**:
   - 루트 권한으로 `/dev/mem` 또는 `/dev/kmem`을 열어 커널 코드 영역을 덮어쓰려 시도해도, 커널이 파일 오픈을 거부(`EPERM`)함.
2. **미서명 악성 커널 모듈 로드 차단 (`CONFIG_MODULE_SIG_FORCE`)**:
   - 루트가 임의의 커널 루트킷(`.ko`)을 빌드하여 `init_module()` 시스템 콜을 호출해도, 개인키 서명이 없으면 커널이 모듈 로드를 거부함.
3. **CPU 특권 제어 레지스터 변조 불가 (Hardware Ring 3 Trap)**:
   - 유저 공간에서는 `mov %rax, %cr4`나 `MSR` 쓰기 같은 CPU 하드웨어 명령어를 실행할 수 없으며, 실행 시 즉각 불법 명령어(`SIGILL`) 트랩 발생함.
4. **시스템 핵심 바이너리 위변조 차단 (IMA / EVM)**:
   - 루트 권한으로 시스템 바이너리를 변조하더라도, 디지털 서명이 일치하지 않으면 실행 단계에서 차단됨.

#### (2) 공격자의 다음 단계 (Next Attack Pivot)와 Scenario 02 연결

- 따라서 공격자가 유저 공간 루트(UID 0)를 획득한 후 시스템을 영구 장악(Persistence)하거나 하드웨어 MMU를 마음대로 조작하려면, **반드시 유저 공간(Ring 3)에서 커널 공간(Ring 0)으로 침투하는 2차 커널 취약점(Privilege Escalation)**을 익스플로잇해야 함.
- 공격자가 유저 모드에서 커널 모드로 점프하여 임의 코드를 실행하려는 대표적인 기법이 바로 **ret2usr (Return-to-User)**이며, 이를 하드웨어 MMU 레벨에서 봉쇄하는 기술이 바로 다음 **[Scenario 02. ret2usr & SMEP/PXN 하드웨어 실행 방어]**임.

---

### 5.5 방어 활성화 실측: 스택 카나리 감지 및 페일세이프 록

컴파일러 스택 보호(`CONFIG_STACKPROTECTOR_STRONG`)가 활성화된 바이너리에서 동일한 1,050바이트 공격 페이로드를 주입했을 때의 실측 실행 로그는 다음과 같음:

```bash
# 하드닝 모드 실행 (스택 카나리 활성화 환경)
cd labs/scenarios/01-humanoid-bof && make run-canary
```

**방어 성공 텔레메트리 출력 로그**:
```text
======================================================================
 🤖 Humanoid Robot BLE Daemon BOF & Hardening Laboratory (CVE-2026-76640) 
======================================================================

[MODE 3: ATTACK INJECTION WITH STACK CANARY ACTIVE (ATTACK INTERCEPTED)]
[*] Processing incoming BLE GATT packet (Length: 1050 bytes, Buffer capacity: 500 bytes)...
    [!] BUFFER OVERFLOW TRIGGERED: copying 1050 bytes into 500-byte stack buffer!
[*] Function Epilogue: Validating Stack Canary (XOR with master guard)...

======================================================================
 [🛡️ STACK PROTECTOR TRAP DETONATED] __stack_chk_fail() invoked! 
======================================================================
  [!] Canary Mismatch Detected: Expected 0xDEADC0DEBEEFCAFE, Found 0x4141414141414141
  [!] Execution aborted: ret instruction withheld. Arbitrary code execution: 0%
  [FAIL-SAFE ACTIVE] Motor driver power cut (0V) -> Robotic joints locked safely!
```

> **방어 결론:** 오버플로우가 발생했음에도 불구하고, 함수 에필로그 검증에서 카나리 변조가 100% 감지되어 CPU가 `ret` 명령어를 실행하지 않고 프로세스를 즉각 중단함. 이로써 루트 쉘 획득 및 2차 물리 재난이 **사전에 원천 차단**됨.

---

## 6. 엔지니어링 딥 다이브 (Engineering Deep Dive)

이 절에서는 시스템 엔지니어 및 보안 연구원을 위한 하드웨어 아키텍처 및 어셈블리 레벨의 상세 구현 명세를 제공함.

### 6.1 BSS vs Stack 오버플로우 익스플로잇 메커니즘 {: #deep-dive-bss-stack }

- `btgatt-server` 결함은 BSS 세그먼트에 정적으로 할당된 전역 버퍼(`wifi_ssid`)에서 발생하여 인접한 이벤트 루프 콜백 포인터(함수 포인터)를 변조함.
- 만약 버퍼가 로컬 함수 스택에 할당되어 있었다면 스택 프레임의 리턴 주소(RIP/LR)를 덮어쓰는 전형적인 Stack Buffer Overflow가 되며, 이 경우 **스택 카나리(Stack Protector)**가 1차 감지선이 됨.
- 반면 BSS나 힙 세그먼트 오염의 경우에는 **Clang kCFI (Control Flow Integrity)**나 **Fortify Source**가 핵심 방어선으로 동작함.
- 🔗 [커널 제어 흐름 무결성 상세: 13. Clang kCFI 명세서](../../features/13-kcfi.md)

### 6.2 x86_64 vs ARM64 스택 프레임 및 에필로그 검증 어셈블리 {: #deep-dive-assembly }

함수 에필로그 단계에서 컴파일러가 삽입한 무결성 검증 루틴의 아키텍처별 실제 어셈블리 구현은 다음과 같음:

=== "x86_64"

    ```nasm
    ; [프롤로그] 카나리 삽입
    movq    %gs:40, %rax          ; Per-CPU 스토리지에서 카나리 로드
    movq    %rax, -8(%rbp)        ; 리턴 주소 직전에 카나리 저장

    ; [에필로그] 카나리 검증
    movq    -8(%rbp), %rax
    xorq    %gs:40, %rax          ; XOR 비교
    jne     __stack_chk_fail      ; 불일치 시 패닉 분기
    leave
    ret
    ```

=== "ARM64 (AArch64)"

    ```asm
    ; [프롤로그] 카나리 삽입
    adrp    x8, __stack_chk_guard ; 전역 가드 주소 로드
    ldr     x9, [x8, :lo12:__stack_chk_guard]
    str     x9, [sp, #8]          ; 스택 프레임에 카나리 저장

    ; [에필로그] 카나리 검증
    ldr     x10, [sp, #8]
    cmp     x9, x10               ; 레지스터 비교
    b.ne    __stack_chk_fail      ; 불일치 시 트랩 분기
    ret
    ```

### 6.3 컴파일러 플래그별 카나리 삽입 기준 및 커널 권고안 {: #deep-dive-compiler-flags }

- `-fstack-protector`: 8바이트 이상의 `char` 배열을 포함하는 함수에만 카나리 삽입.
- `-fstack-protector-strong`: 로컬 배열(타입 무관), 가변 길이 배열(VLA), 스택 주소 참조(`&local_var`)가 발생하는 모든 함수로 보호 범위 대폭 확장.
- 리눅스 커널은 기본적으로 `CONFIG_STACKPROTECTOR_STRONG`을 강력 권고함.
- 🔗 [상세 기술 명세서: 01. Stack Protector 커널 구현 분석](../../features/01-stack-protector.md)

### 6.4 Fortify Source 메커니즘과 경계 검사 최적화 (`_FORTIFY_SOURCE=3`) {: #deep-dive-fortify }

- `_FORTIFY_SOURCE=3`은 GCC 12+ 및 Clang 12+에서 도입된 최고 수준의 버퍼 검증 레벨로, 정적 크기뿐 아니라 동적으로 크기가 결정되는 버퍼(`__builtin_dynamic_object_size`)까지 추적하여 초과 복사를 원천 차단함.
- 🔗 [상세 기술 명세서: 02. Fortify Source 메모리 보호 분석](../../features/02-fortify-source.md)

---

## 7. 참고 문헌 및 공식 CVE 보안 공시 (External Advisories & References)

<div class="grid cards vertical" markdown>

-   __📌 공식 CVE 데이터베이스__

    ---

    1.  **CVE-2026-76640**

        Unitree G1 EDU Humanoid Robot BLE `btgatt-server` Buffer Overflow leading to Root RCE

    2.  **CVE-2026-76639**

        Unitree G1 EDU `chat_go` / `bashrunner` Path Traversal RCE

-   __🔬 보안 연구 및 기술 분석 보고서__

    ---

    1.  **Olivier Laflamme (The Hacker News, Aug 2026)**

        *"Two Unitree G1 EDU Humanoid Robot Flaws Enable Root RCE, One Starts Over Bluetooth"*

    2.  **Boschko Research (Aug 2026)**

        *"Deep Dive: G1 BLE RCE Chain Technical Disclosure & Physical Safety Risks"*

    3.  **Trend Micro & PoliMi (CPS Security Analysis)**

        *"Rogue Robots: Testing the Limits of an Industrial Robot’s Security"*

-   __🛡️ 리눅스 커널 하드닝 & 임베디드 표준__

    ---

    1.  **Linux Kernel Hardening Project**

        [Compiler-based Stack Protection Mechanics](https://kernsec.org/)

    2.  **NIST SP 800-82 Rev. 3**

        Guide to Operational Technology (OT) Security

    3.  **CIS Linux Benchmark**

        Section 1.5 - Memory Protection & Compiler Flags

</div>

