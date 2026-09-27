# MDS 및 TAA 완화: 마이크로아키텍처 버퍼 소거 (VERW / MD_CLEAR)

## 1. 개요 및 배경

현대 프로세서는 메모리 계층 간의 데이터 전송 지연을 최소화하기 위해 CPU 코어 내부에 **마이크로아키텍처 내부 버퍼(Internal Hardware Buffers)**를 광범위하게 운용함. 이러한 버퍼에는 캐시 라인 채우기 및 축출을 담당하는 **Line Fill Buffer(LFB)**, 스토어-투-로드 포워딩을 위한 **Store Buffer(SB)**, 로드 파이프라인 인터페이스인 **Load Ports(LP)**가 포함됨.

2019년 공개된 **MDS (Microarchitectural Data Sampling)** 및 **TAA (TSX Asynchronous Abort)**는 CPU의 비순차적 실행(Out-of-Order Execution) 엔진이 예외 처리(Fault)나 트랜잭션 중단(Abort) 중 파이프라인 정지를 피하려는 과정에서 내부 버퍼의 잔여 데이터를 무분별하게 참조하는 치명적인 하드웨어 취약점군임:
1. **폴팅 로드와 마이크로아키텍처 데이터 투기적 전달**:
   - 유저 공간 프로그램이 접근 권한이 없는 커널 메모리 주소를 읽거나 매핑되지 않은 주소를 읽으면 페이지 폴트(Page Fault, `#PF`) 또는 TSX 비동기 중단이 유발됨.
   - CPU 실행 엔진은 MMU(메모리 관리 장치)가 페이지 테이블을 순회하여 폴트를 확정하기 전까지 파이프라인이 멈추는 것을 방지하기 위해, 직전에 실행되었던 다른 스레드나 커널이 남겨둔 **LFB/SB/LP 내부 버퍼의 잔여 데이터(Residual Data)**를 Load 명령어의 결과값으로 투기적으로 전달함.
2. **사이드 채널 캐시 인코딩 및 기밀 복원**:
   - 공격자의 투기적 가젯은 전달받은 미세구조 버퍼 바이트를 인덱스로 삼아 유저 제어 프로브 배열(`probe_array[sampled_byte * 512]`)의 캐시 라인을 워밍업함.
   - 이후 폴트가 확정되어 아키텍처 레지스터가 롤백되고 시그널 핸들러(`SIGSEGV`)가 실행되더라도, **L1D 캐시에 적재된 태그 상태는 영구 보존**됨.
   - 공격자는 **Flush+Reload** 시간차 측정을 통해 커널 암호화 키, `/etc/shadow` 해시, 타 프로세스의 기밀 메모리를 초당 수십~수백 킬로바이트 속도로 무차별 추출함.

리눅스 커널은 Intel 마이크로코드 업데이트와 결합하여, 유저 공간 복귀(`sysret`, `iret`) 및 가상머신 전환 시 **`VERW` 명령어를 실행하여 CPU 내부 버퍼 전체를 0으로 강제 소거(MD_CLEAR)**함으로써 공격을 완벽히 차단함.

---

## 2. 실세계 비유: 은행 창구의 미처리 전표와 영구 파쇄기(VERW)

`MDS` 취약점과 `VERW` 버퍼 소거의 메커니즘은 **은행 창구의 미처리 전표 방치와 영구 파쇄기 도입**에 비유할 수 있음:

```
[ 취약한 방식 (Baseline: 마이크로아키텍처 버퍼 소거 미적용) ]
  VIP 고객(커널): "창구(CPU 코어)에서 비밀 계좌 이체(시스템 콜) 완료 후 퇴장!"
  은행원(CPU):   "전표 처리 완료! 하지만 창구 옆 임시 바구니(Line Fill Buffer)에 이전 고객의 전표(0x46)를 그대로 둠."
  불량 고객(공격자): "창구에 가서 존재하지 않는 가짜 계좌 번호(Faulting Load)를 제시!"
  은행원(CPU):   "계좌 조회 지연 중... 심심하니 바구니에 있던 이전 VIP 고객 전표(0x46)를 꺼내 힐끗 보여줌 (투기적 샘플링)!"
  불량 고객:     "창구 거절(SIGSEGV)당하기 직전, 전표 번호(0x46)를 메모해 두고 나중에 확인하여 VIP 기밀 완벽 탈취!"

[ 하드닝 방식 (Hardened: VERW 명령어를 통한 MD_CLEAR 소거) ]
  VIP 고객(커널): "비밀 계좌 이체 완료 후 퇴장!"
  보안 수칙(VERW): "고객이 창구를 떠나기 전(커널-유저 전환), 반드시 영구 파쇄기(VERW)를 돌려 모든 바구니를 백지로 채워라!"
  은행원(CPU):   (VERW 마이크로코드 실행 ──► LFB, Store Buffer, Load Port의 모든 전표를 0x00 백지로 즉각 분쇄/덮어쓰기)
  불량 고객:     "가짜 계좌 번호 제시!"
  은행원(CPU):   "바구니에는 오직 깨끗한 백지(0x00)뿐. 아무런 비밀도 보이지 않음."
  불량 고객:     "얻은 데이터는 오직 0뿐 (비밀 유출 0바이트 실패)!"
```

1. **전통적 커널 (버퍼 잔여물 방치)**:
   - 시스템 콜 처리 완료 후 유저 공간으로 복귀할 때 CPU 내부 임시 큐(LFB)를 정리하지 않고 방치함.
   - 비특권 공격자가 고의적 폴트(Invalid Memory Read)를 일으켜 버퍼 잔여물을 무단 샘플링함.
2. **VERW 하드닝 커널 (즉시 일괄 파쇄)**:
   - 커널 모드에서 유저 모드로 문맥이 전환되는 모든 관문에서 `VERW` 명령어를 강제 실행함.
   - CPU 하드웨어 마이크로코드가 작동하여 LFB, Store Buffer, Load Port를 0으로 완벽히 소거하여 어떤 투기적 로드도 기밀 잔여물을 읽지 못함.

---

## 3. 핵심 아키텍처 및 방어 메커니즘

### 3.1 MDS 취약점 4대 변종과 대상 하드웨어 버퍼

| 취약점 명칭 | CVE 식별자 | 공격 대상 CPU 마이크로아키텍처 버퍼 | 공격 양상 |
| :--- | :--- | :--- | :--- |
| **MFBDS (ZombieLoad v1)** | CVE-2018-12130 | **Line Fill Buffer (LFB)**<br>(L1D 캐시 미스 시 L2/L3 및 메모리로부터 캐시 라인을 채워오는 12개 비순차적 버퍼) | 비정상적 로드 시 LFB에 대기 중인 모든 코어/하이퍼스레드의 데이터가 누출됨 |
| **MSBDS (Fallout)** | CVE-2018-12126 | **Store Buffer (SB)**<br>(CPU 스토어 명령어가 메모리로 커밋되기 전 대기하는 56개 엔트리) | 선행 Store의 주소 해결 지연 시 스토어 버퍼 잔여 데이터가 후행 비인가 로드로 유출됨 |
| **MLPDS (RIDL)** | CVE-2018-12127 | **Load Ports (LP)**<br>(메모리 로드 명령어를 실행하는 실행 포트 2/3의 임시 레지스터) | 로드 포트를 통과하는 타 스레드/커널의 직전 읽기 데이터가 샘플링됨 |
| **MDSUM (RIDL Variant)** | CVE-2019-11091 | **Uncacheable Memory (UC)** 버퍼 | 캐시 불가능 메모리(MMIO, 디바이스 메모리) 접근 버퍼 잔여물이 샘플링됨 |
| **TAA (ZombieLoad v2)** | CVE-2019-11135 | **TSX Transactional Abort** LFB 버퍼 | TSX 트랜잭션 영역 내 비동기 중단 발생 시 LFB 데이터가 투기적으로 로드로 포워딩됨 |

---

### 3.2 x86_64 VERW 명령어 기반 마이크로코드 버퍼 소거 (`MD_CLEAR`)

Intel은 마이크로코드 업데이트를 통해 x86 세그먼트 레지스터 유효성 검사 명령어인 **`VERW` (Verify a Segment for Writing)**에 CPU 버퍼 일괄 소거 기능을 추가함:

```x86asm
/* Linux Kernel x86_64 CPU Buffer Clearing Entry */
.macro CLEAR_CPU_BUFFERS
    /* X86_FEATURE_MD_CLEAR 기능 플래그 확인 시 VERW 명령어 실행 */
    ALTERNATIVE "", "verw x86_verw_sel(%rip)", X86_FEATURE_MD_CLEAR
.endm
```

```c
/* <asm/nospec-branch.h> 커널 내부 C 구현체 */
static __always_inline void x86_clear_cpu_buffers(void)
{
    static const u16 ds = __KERNEL_DS;
    /*
     * 반드시 메모리 오퍼랜드 형태(verw %[ds])로 호출해야 마이크로코드의 버퍼 플러시 동작이 보장됨.
     * 레지스터 오퍼랜드 형태(verw %ax)는 버퍼 플러시를 유발하지 않음.
     * VERW는 ZF 플래그를 수정하므로 "cc" 클로버가 필수적임.
     */
    asm volatile("verw %[ds]" : : [ds] "m" (ds) : "cc");
}
```

- **실행 위치**:
  - `syscall` / `sysret` 및 `iret` 유저 공간 복귀 경로.
  - 게스트 가상머신(KVM) 진입(`VM-Entry`) 및 종료(`VM-Exit`) 경로.
  - 프로세스 문맥 교환(Context Switch) 및 유휴(Idle) 진입 경로.

---

### 3.3 SMT (Simultaneous Multi-Threading) 및 교차 스레드 공격

MDS 취약점은 하나의 물리 코어를 공유하는 두 개의 논리 스레드(Hyper-Threading) 간에 LFB와 Store Buffer가 하드웨어적으로 공유된다는 점에서 기인함:

- **문제점**: 스레드 A(커널 또는 타 프로세스)가 메모리를 읽는 동시에, 스레드 B(공격자)가 폴팅 로드를 반복하면 스레드 A의 유효 데이터가 스레드 B로 실시간 유출됨.
- **완전 완화 전략**:
  - `VERW` 버퍼 소거는 문맥 전환 시점의 잔여물을 지우지만, 동일 물리 코어에서 동시 실행 중인 형제 스레드 간의 실시간 스누핑을 막기 위해서는 **SMT 비활성화(`nosmt` 또는 `mds=full,nosmt`)**가 권장됨.

---

### 3.4 ARM64 아키텍처 상태

ARM 아키텍처(Cortex-A, Neoverse 등)는 내부 마이크로아키텍처 설계 상:
- 예외를 발생시키는 비인가 로드 명령어에 대해 uncommitted Line Fill Buffer의 데이터를 투기적으로 포워딩하는 구조를 채택하지 않음.
- 따라서 ARM64 전 프로세서는 **MDS 및 TAA 취약점에 하드웨어적으로 영향을 받지 않음 (`Not affected`)**.

---

### 3.5 리눅스 커널 통제 및 sysfs 인터페이스

- **sysfs 진단 경로**:
  - `/sys/devices/system/cpu/vulnerabilities/mds`
  - `/sys/devices/system/cpu/vulnerabilities/tsx_async_abort`
  - `/sys/devices/system/cpu/vulnerabilities/mmio_stale_data`
- **대표적 sysfs 상태**:
  - `Mitigation: Clear CPU buffers; SMT disabled`: 버퍼 소거 및 SMT 비활성화로 완전 방어.
  - `Mitigation: Clear CPU buffers; SMT vulnerable`: 버퍼 소거 적용 중이나 SMT 활성화 상태.
  - `Not affected`: 하드웨어 면역 프로세서 (ARM64 또는 최신 Intel 코어).
- **부팅 커맨드라인**:
  - `mds=full`: VERW 버퍼 소거 상시 활성화.
  - `mds=full,nosmt`: VERW 활성화 및 형제 하이퍼스레드 완전 오프라인.
  - `mds=off`: 완화 비활성화.
  - `tsx_async_abort=full`: TAA 방어 활성화.

---

## 4. 인터랙티브 아키텍처 시뮬레이터

MDS/TAA 투기적 데이터 샘플링 공격과 VERW 명령어를 통한 마이크로아키텍처 버퍼 소거 메커니즘을 시각화한 대화형 다이어그램임:

<iframe src="../../assets/diagrams/mds/architecture.html" width="100%" height="700px" style="border: 1px solid var(--card-border); border-radius: 8px; margin: 16px 0; background: #0b132b;"></iframe>

---

## 5. 실습 환경 및 검증 시나리오

본 실습 모듈(`labs/25-mds`)은 커널 드라이버와 비특권 PoC 익스플로잇을 통해 MDS 버퍼 잔여물 샘플링 취약성과 VERW 버퍼 소거 방어를 검증함.

### 5.1 타깃 드라이버 (`/proc/vuln_mds`)

- **파일 위치**: `labs/25-mds/vuln_mds.c`
- **인터페이스**:
  - `echo 'mode baseline' > /proc/vuln_mds`: Mode 0 (버퍼 소거 비활성화 / 취약 모드) 전환.
  - `echo 'mode hardened' > /proc/vuln_mds`: Mode 1 (VERW 버퍼 소거 활성화 / 방어 모드) 전환.
  - `echo 'sample <offset>' > /proc/vuln_mds`: 특정 기밀 오프셋에 대해 샘플링 사이클 실행.
  - `echo 'verw' > /proc/vuln_mds`: `VERW` 명령어를 즉각 발행하여 CPU 버퍼 소거.
  - `echo 'run_bench' > /proc/vuln_mds`: 인커널 자체 벤치마크 루틴 수행.
  - `mmap()`: 128KB 2차 프로브 배열을 유저 공간에 매핑하여 Flush+Reload 캐시 관측 허용.

### 5.2 비특권 익스플로잇 PoC (`labs/25-mds/exploit.c`)

비특권 계정 `lab` (UID 1000)에서 실행되며, 두 단계에 걸쳐 방어 유효성을 검증함:

```bash
# QEMU 가상머신 내 자동화 검증 스크립트 실행
/bin/test_mds
```

1. **Phase 1: Baseline 모드 (Mode 0 - 버퍼 소거 미적용)**:
   - 커널 내부 LFB 슬롯에 기밀 데이터(`FLAG{...}`) 잔여물이 남아있는 상태에서 유저 공간 복귀.
   - 폴팅 로드를 통해 LFB 잔여 바이트를 투기 샘플링하여 캐시 프로브 라인 가열.
   - `[FAIL/VULNERABLE] In Baseline mode, MDS sampled stale microarchitectural buffer data!` 판정.
2. **Phase 2: Hardened 모드 (Mode 1 - VERW 버퍼 소거 활성화)**:
   - 유저 공간 복귀 전 `VERW` 명령어가 실행되어 LFB 슬롯이 0x00으로 소거됨.
   - 샘플링 로드는 오직 0x00만 획득하며 기밀 바이트는 단 1바이트도 캐시에 남지 않음.
   - `[PASS/PROTECTED] Microarchitectural buffer clearing (VERW) prevented data sampling!` 판정.

---

## 6. 취약점 변종 및 방어 비교 매트릭스

| 변종 명칭 | 대상 버퍼 | 하드웨어 취약 아키텍처 | 리눅스 커널 방어 기법 | SMT 영향 |
| :--- | :--- | :--- | :--- | :--- |
| **MFBDS (ZombieLoad)** | Line Fill Buffer | Intel Sandy Bridge ~ Coffee Lake | 유저 공간 복귀 시 VERW 실행 | SMT 간 공격 가능 (nosmt 권장) |
| **MSBDS (Fallout)** | Store Buffer | Intel Haswell ~ Cascade Lake | VERW 실행 (`mds=full`) | 동일 물리 코어 스택 공유 |
| **MLPDS (RIDL)** | Load Ports | Intel Nehalem ~ Whiskey Lake | VERW 실행 (`mds=full`) | 스레드 간 로드 포트 공유 |
| **TAA (ZombieLoad v2)** | TSX LFB Abort | Intel Skylake, Cascade Lake | `tsx_async_abort=full` + VERW | SMT 간 TSX 어보트 스누핑 |
| **ARM64 Architecture** | N/A (면역) | ARMv8 / ARMv9 전 기종 | 하드웨어 면역 (`Not affected`) | 영향 없음 |

---

## 7. 참고 문헌

- [Kernel Documentation: Microarchitectural Data Sampling (MDS)](https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/mds.html)
- [Kernel Documentation: TSX Asynchronous Abort (TAA)](https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/tsx_async_abort.html)
- [Intel Security Advisory: Microarchitectural Data Sampling (INTEL-SA-00233)](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00233.html)
- [ZombieLoad Attack Whitepaper (Schwarz et al., 2019)](https://zombieloadattack.com/)
- [RIDL: Rogue In-Flight Data Load (van Schaik et al., S&P 2019)](https://mdsattacks.com/)
