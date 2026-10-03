# Kexec 제한 및 서명 검증 (Kexec Restrictions & Hardening)

## 1. 개요 및 위협 모델 (Overview & Threat Model)

**Kexec 제한 및 커널 부팅 강화(`CONFIG_KEXEC`, `CONFIG_KEXEC_FILE`, `kexec_load_disabled`)**는 실행 중인 리눅스 시스템에서 하드웨어 리셋이나 펌웨어(UEFI/BIOS) 초기화 과정 없이 새로운 커널로 직접 제어권을 전환하는 Kexec 메커니즘을 통제하여 **루트킷 주입, 임의 커널 교체, 보안 부팅(Secure Boot) 우회 공격을 원천 차단하는 핵심 커널 방어 기법**임.

전통적인 리눅스 커널 환경에서 Kexec 시스템 콜은 시스템 진단 및 빠른 재부팅 용도로 널리 사용되었으나, 악의적인 공격자에게 치명적인 공격 표면(Attack Surface)을 노출함:

1. **임의 커널 메모리 주입을 통한 Root of Trust 탈취**:
   - `kexec_load(2)`는 유저스페이스에서 준비한 원시 메모리 세그먼트 버퍼(Segment Buffers) 포인터를 그대로 전달받아 새 커널을 로드함.
   - 서명 검증이나 무결성 검증 단계가 전혀 없으므로, 로컬 권한 상승(LPE)이나 취약점을 통해 `CAP_SYS_BOOT` 또는 root 권한을 일시적으로 획득한 공격자가 악성 백도어가 삽입된 커널 이미지나 셸코드를 즉시 부팅할 수 있음.
   - 하드웨어 TPM, UEFI Secure Boot, IMA(무결성 측정 아키텍처)의 무결성 체인을 완전히 우회하여 영속적인 하이퍼바이저/OS 제어권을 탈취하는 위협 초래.
2. **Kexec 시스템 콜 분리 구조**:
   - `kexec_load`: 유저 공간 세그먼트 포인터 기반, 서명 검증 불가 (취약함).
   - `kexec_file_load`: 커널이 파일 디스크립터(fd)로부터 직접 이미지를 읽고 암호화 서명(PE/PKCS#7)을 강제 검증할 수 있음 (`CONFIG_KEXEC_SIG_FORCE`).
3. **단방향 래치(One-Way Latch) 통제 메커니즘**:
   - `/proc/sys/kernel/kexec_load_disabled`를 `1`로 설정하면 모든 kexec 시스템 콜이 시스템 전역에서 영구 차단됨.
   - 커널 내부 `proc_dointvec_minmax` 핸들러의 `.extra1 = SYSCTL_ONE, .extra2 = SYSCTL_ONE` 정책에 의해 한 번 `1`로 래치되면 시스템 재부팅 전까지 다시 `0`으로 되돌리는 것이 불가능함.

---

## 2. 방어 아키텍처 및 메커니즘 (Architecture & Mechanism)

### 1. Kexec Restrictions 인터랙티브 아키텍처 시뮬레이터

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/kexec-restrict/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. 실생활 비유: 고위 통제 구역의 '비상 탈출 게이트 일방향 셔터'

Kexec 통제 메커니즘은 **국가 중요 시설의 비상 탈출 방화 셔터 및 생체 서명 게이트**와 일치함:

```
[ 비활성화 상태 (Raw kexec_load 허용) ]
  침입자:   "신분증(CAP_SYS_BOOT)을 훔쳐 비상 게이트를 열고 내가 직접 제작한 가짜 교체 관리자를 방에 들여보내겠다!"
  게이트:   "원시 데이터 가방(Userspace Segments) 수색 없이 즉시 중앙 제어실 점거 및 전원 교체 승인!" (보안 체계 붕괴)

[ 단방향 래치 가동 (kernel.kexec_load_disabled = 1) ]
  보안관:   "정상 부팅 완료 직후 비상 게이트 잠금 스위치를 '1'로 올린다 (셔터 하강 및 전자 래치 체결)!"
  침입자:   "비상 게이트에 kexec 명령을 전송하여 문을 열려고 시도!"
  게이트:   "단방향 래치 작동 중! 시스템 재부팅(물리적 전원 리셋) 전까지는 어떤 권한으로도 래치를 풀 수 없음 (-EPERM 차단)!"

[ 파일 기반 서명 강제 (kexec_file_load + CONFIG_KEXEC_SIG_FORCE) ]
  침입자:   "변조된 악성 커널 이미지 파일을 게이트로 전달!"
  검문소:   "커널 내부 서명 검증 엔진 가동! 시스템 신뢰 키링(.builtin_trusted_keys) 대조!"
  판정:     "PKCS#7 디지털 서명이 없거나 신뢰할 수 없는 키로 서명됨 (-EKEYREJECTED 차단)!"
```

---

### 3. Kexec 방어 정책 및 상태 매트릭스

| 방어 메커니즘 | 설정 및 플래그 | 통제 방식 | 차단 사유 및 에러 코드 | 보안 보증 효과 |
| :--- | :--- | :--- | :--- | :--- |
| **원시 kexec 완전 차단** | `CONFIG_LOCKDOWN_LSM`<br>(Integrity/Confidentiality) | 유저스페이스 세그먼트 기반 `sys_kexec_load` 호출 자체를 전면 거부함 | `-EPERM`<br>(Lockdown Hook) | 임의 메모리 주입을 통한 커널 변조 및 Secure Boot 우회 차단 |
| **서명 강제 검증** | `CONFIG_KEXEC_SIG=y`<br>`CONFIG_KEXEC_SIG_FORCE=y` | `sys_kexec_file_load` 시 커널 이미지의 PE/PKCS#7 디지털 서명을 신뢰 키링과 대조함 | `-EKEYREJECTED` | 변조된 커널 이미지 또는 서명되지 않은 사설 커널 부팅 원천 방지 |
| **단방향 시스템 잠금** | `kernel.kexec_load_disabled=1`<br>(단방향 Sysctl 래치) | 모든 kexec 관련 시스템 콜 진입을 시스템 전역에서 영구 거부함 | `-EPERM` | 부팅 완료 후 런타임 공격 표면 100% 제거, 0으로 원복 불가 |
| **기본 취약 상태** | `kexec_load_disabled=0`<br>서명 미강제 | `CAP_SYS_BOOT` 보유 시 임의의 서명 없는 커널 부팅 허용 | 차단 없음 (취약) | root 권한 탈취 시 임의 커널 교체 및 영속적 백도어 주입 위험 노출 |

---

## 3. 커널 설정 및 플래그 분석 (Kernel Configurations)

### 1. Hardening Kconfig (`configs/features/kexec-restrict.config`)

```ini
# Linux Kernel Hardening Lab - Kexec Restrictions Feature Config
CONFIG_KEXEC_CORE=y
CONFIG_KEXEC=y
CONFIG_KEXEC_FILE=y
CONFIG_KEXEC_SIG=y
CONFIG_KEXEC_SIG_FORCE=y
```

- `CONFIG_KEXEC_CORE=y`: Kexec 코어 서브시스템 활성화.
- `CONFIG_KEXEC_FILE=y`: 커널 파일 디스크립터 기반 안전한 `kexec_file_load` 인터페이스 제공.
- `CONFIG_KEXEC_SIG=y`: kexec 파일 로드 시 디지털 서명 검증 서브시스템 연동.
- `CONFIG_KEXEC_SIG_FORCE=y`: 서명되지 않은 커널 이미지의 kexec 로드를 전면 금지하고 `-EKEYREJECTED` 반환.

### 2. 런타임 Sysctl 단방향 래치 활성화

부팅 완료 시 초기화 스크립트(`/etc/sysctl.d/99-kexec.conf` 또는 `init` 스크립트)에서 설정:

```bash
# kexec 로드 영구 차단 (0 -> 1 전환, 1 -> 0 원복 불가)
sysctl -w kernel.kexec_load_disabled=1
```

---

## 4. 실습 및 검증 (Hands-on Lab: `labs/40-kexec-restrict`)

### 1. 실습 환경 구성 요소

1. **타깃 드라이버 (`labs/40-kexec-restrict/vuln_kexec.c`)**:
   - `/proc/vuln_kexec` (0666) 인터페이스를 통해 kexec 검증 시뮬레이션 제공:
     - `load_raw`: 원시 세그먼트 `kexec_load` 호출 모의 수행.
     - `load_file signed`: 서명된 이미지 `kexec_file_load` 호출 모의 수행.
     - `load_file unsigned`: 서명 없는 이미지 `kexec_file_load` 호출 모의 수행.
     - `set_disabled 1`: 단방향 래치 작동.
     - `set_disabled 0`: 래치 해제 시도 (단방향 래치 위반으로 `-EPERM` 거부).
     - `set_lockdown <integrity|confidentiality|none>`: 락다운 연계 테스트.
2. **공격 PoC 바이너리 (`labs/40-kexec-restrict/exploit.c`)**:
   - Stage 1: 무방비 상태에서 raw `kexec_load` 주입 시도 (취약점 확인).
   - Stage 2: Lockdown 활성화 후 raw `kexec_load` 차단 검증 (`-EPERM`).
   - Stage 3: `kexec_file_load` 서명 검증 테스트 (서명 없음: `-EKEYREJECTED` 거부, 유효 서명: 허용).
   - Stage 4: `kexec_load_disabled=1` 활성화 후 0으로 원복 시도 및 모든 kexec 호출 전면 차단 검증.
3. **자동화 검증 스크립트 (`labs/40-kexec-restrict/test.sh`)**:
   - 시스템 kexec sysctl 및 lockdown 상태 진단, 드라이버 로드 확인, PoC 실행 및 dmesg 로그 종합 검증.

---

### 2. 단계별 실습 절차

```bash
# 1. 대상 가상머신 기동 및 root 로그인
cd /home/auking45/repos/linux-kernel-hardening-lab
make qemu ARCH=x86_64

# 2. kexec sysctl 매개변수 확인
cat /proc/sys/kernel/kexec_load_disabled

# 3. Kexec Restrictions 자동화 테스트 러너 실행
/bin/test_kexec_restrict
```

### 3. 검증 출력 예시

```text
================================================================
   Lab 40: Kexec Restrictions & Hardening Verification Suite    
   Kernel: 6.12.109 on x86_64                                   
================================================================

[*] Step 1: Inspecting kernel kexec_load_disabled parameter...
    kernel.kexec_load_disabled: 0

[*] Step 2: Inspecting Kernel Lockdown LSM status...
    lockdown status: [none] integrity confidentiality

[*] Step 3: Checking target driver at /proc/vuln_kexec...
[+] Target driver detected.

[*] Step 4: Querying driver status report...
=== Linux Kexec Restrictions & Hardening Status ===
kexec_load_disabled      : 0 (ENABLED)
CONFIG_KEXEC_SIG_FORCE   : ENABLED (Mandatory Signature)
Simulated Lockdown Level : none
Total Execution Attempts : 0
Raw kexec_load Attempts  : 0 (Blocked: 0)
File kexec Attempts      : 0 (Blocked: 0)
Allowed Kernel Boots     : 0
====================================================

[*] Step 5: Running Kexec Restrictions PoC...
===============================================================
   Linux Kexec Restrictions & Hardening Evaluation PoC         
===============================================================

[*] Stage 1: Testing Raw Segment kexec_load Attack...
[!] VULNERABLE: Raw kexec_load succeeded! Malicious kernel code could execute.

[*] Stage 2: Enabling Simulated Kernel Lockdown (Integrity Mode)...
[+] Retrying raw kexec_load under Lockdown...
[+] DEFENSE SUCCESS: Raw kexec_load blocked under Lockdown! (errno=1: Operation not permitted)

[*] Stage 3: Testing File-based kexec Signature Enforcement...
[+] Attempting unsigned kexec_file_load...
[+] DEFENSE SUCCESS: Unsigned image rejected! (errno=129: Key was rejected by service)
[+] Attempting signed kexec_file_load with valid cryptographic signature...
[+] SUCCESS: Authenticated signed kernel image verified and accepted.

[*] Stage 4: Testing Permanent One-Way Security Latch...
[+] Engaging security latch (set_disabled 1)...
[+] Attempting to revert security latch back to 0 (set_disabled 0)...
[+] DEFENSE SUCCESS: One-way latch enforced! Reversion forbidden (errno=1: Operation not permitted)
[+] Attempting any kexec operation while latch is locked...
[+] DEFENSE SUCCESS: All kexec calls locked out system-wide! (errno=1: Operation not permitted)

[*] Final Driver Diagnostics Report:
=== Linux Kexec Restrictions & Hardening Status ===
kexec_load_disabled      : 1 (DISABLED (One-way latch active))
CONFIG_KEXEC_SIG_FORCE   : ENABLED (Mandatory Signature)
Simulated Lockdown Level : integrity
Total Execution Attempts : 5
Raw kexec_load Attempts  : 2 (Blocked: 1)
File kexec Attempts      : 3 (Blocked: 2)
Allowed Kernel Boots     : 2
====================================================
[+] Kexec Restrictions verification complete.

[*] Step 6: Inspecting kernel dmesg for kexec hardening events:
[   42.102144] kexec_restrict: [VULNERABLE] Raw kexec_load allowed! Arbitrary kernel code execution possible.
[   42.103102] kexec_restrict: Simulated lockdown level set to 'integrity'
[   42.103890] kexec_restrict: [BLOCKED] Raw kexec_load prohibited under Kernel Lockdown (integrity) (-EPERM)
[   42.104612] kexec_restrict: [BLOCKED] Unsigned kexec image rejected (CONFIG_KEXEC_SIG_FORCE / Lockdown) (-EKEYREJECTED)
[   42.105340] kexec_restrict: [ALLOWED] Signed kernel image verified and accepted for kexec.
[   42.106012] kexec_restrict: [SYSCTL] kexec_load_disabled set to 1. Latch locked permanently.
[   42.106880] kexec_restrict: [LATCH REJECTED] Cannot reset kexec_load_disabled back to 0! (-EPERM)
[   42.107550] kexec_restrict: [BLOCKED] kexec rejected: kernel.kexec_load_disabled = 1 (-EPERM)

================================================================
   Lab 40 Test Complete: Verified Kexec Restrictions            
================================================================
```

---

## 5. 결론 및 보안 점검표 (Checklist)

| 점검 항목 | 권장 설정값 | 보안 보증 내용 |
| :--- | :--- | :--- |
| **파일 기반 kexec 강제** | `CONFIG_KEXEC_FILE=y` | 유저 공간 임의 세그먼트 포인터 차단 및 파일 경로 기반 검증 |
| **디지털 서명 강제 적용** | `CONFIG_KEXEC_SIG_FORCE=y` | 비서명/변조 커널의 kexec 로드 전면 차단 (`-EKEYREJECTED`) |
| **단방향 보안 래치 활성화** | `sysctl kernel.kexec_load_disabled=1` | 부팅 완료 후 런타임 커널 교체 표면 영구 제거 (`-EPERM`) |
| **커널 락다운 연계** | `lockdown=integrity` | 부팅 매개변수 연동을 통해 미서명 커널 로드 및 MSR 쓰기 차단 |
| **권한 최소화 통제** | `CAP_SYS_BOOT` 권한 박탈 | 컨테이너 및 비특권 유저스페이스의 시스템 콜 접근 차단 |
