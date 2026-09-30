# IMA (Integrity Measurement Architecture) 파일 무결성 측정 및 감정

## 1. 개요 및 배경

**IMA (Integrity Measurement Architecture)**는 리눅스 커널 2.6.30에 처음 도입된 하위 보안 서브시스템으로, 파일이 실행되거나 메모리에 매핑되기 전에 **파일의 암호학적 해시를 측정(Measurement)하고, 기준 해시와 대조하여 무결성을 감정(Appraisal)하며, 변조가 감지될 경우 실행을 차단**하는 강력한 무결성 보장 메커니즘임.

기존의 접근 제어 메커니즘(DAC, MAC)은 프로세스의 권한 범위는 제한할 수 있으나, 시스템 내부 실행 바이너리나 설정 파일 자체가 오프라인 공격, 부트로더 감염, 악성코드 주입 등으로 변조된 상황을 직접 탐지하지 못함:
1. **신뢰 기반 측정 (Cryptographic Measurement)**:
   - 실행 파일(`execve`), 커널 모듈, 펌웨어 등이 로드될 때 커널 암호화 프레임워크를 통해 SHA-256 해시를 계산하고 런타임 측정 목록에 누적 기록함.
2. **하드웨어 신뢰점 연동 (TPM PCR 10 Extension)**:
   - 측정된 해시는 물리적 또는 가상 TPM(Trusted Platform Module)의 **PCR 10(Platform Configuration Register)**에 암호학적으로 확장($\text{Extend}$)되어 원격 검증(Remote Attestation)의 신뢰 기반(Root of Trust)을 제공함:
   $$\text{PCR}_{10}^{\text{new}} = \text{SHA256}(\text{PCR}_{10}^{\text{old}} \parallel \text{File\_Hash})$$
3. **런타임 감정 및 위반 차단 (Appraisal & Fail-Closed)**:
   - 파일의 확장 속성(`security.ima` xattr)에 저장된 기준 해시 또는 디지털 서명과 계산된 해시를 비교함. 불일치 발생 시 커널은 즉시 `-EACCES`를 반환하여 손상된 바이너리의 실행을 원천 차단함.
4. **유연한 정책 프레임워크 (IMA Policy)**:
   - 측정 대상 파일 유형(바이너리, 라이브러리, 펌웨어), 감사 규칙, 감정 모드(`log` vs `enforce`)를 런타임 정책 파일(`/sys/kernel/security/ima/policy`)을 통해 세부 제어함.

---

## 2. 실세계 비유: 은행 금고 이송 차량의 디지털 봉인 바코드

`IMA`의 동작 원리는 **고액 현금 수송 차량의 위변조 방지 디지털 봉인 씰과 중앙 관제 검수 체계**에 비유할 수 있음:

```
[ 일반 DAC/MAC 환경 (봉인 미검증: 외형상 차량 번호판만 확인 후 통과) ]
  수송원(시스템 프로세스): "은행 중앙 금고에서 현금 상자(/bin/trusted_app)를 운반해왔습니다!"
  경비원(커널 DAC):       "운반자가 정규 수송원(UID 0/Root)이 맞으니 금고 진입을 허용합니다."
  결과:                   이송 도중 공격자가 몰래 상자 내용을 가짜 지폐(악성코드)로 바꿔치기했으나,
                          내용물 검증 없이 통과되어 은행 전체가 오염됨!

[ IMA Measurement & Appraisal 환경 (출입 전 디지털 암호화 지문 대조) ]
  수송원(시스템 프로세스): "현금 상자(/bin/trusted_app)를 금고실에 투입하겠습니다!"
  IMA 검사관(커널 후크):  "잠깐! 투입 전 현금 상자의 고유 지문(SHA-256 해시)을 즉시 측정합니다.
                          1. 측정 결과: [sha256:e3b0c442...]
                          2. 중앙 블랙박스(TPM PCR 10)에 이 측정값을 영구 봉인 기록함.
                          3. 상자 표면에 인쇄된 공인 봉인표(security.ima xattr)와 1:1 대조 시작!"

  [상황 A: 정품 상자]
  IMA 검사관:             "봉인표의 기준 해시와 방금 측정한 해시가 100% 일치함! 투입 승인 (ret = 0)."

  [상황 B: 1바이트 변조된 악성 상자]
  IMA 검사관:             "경보! 상자 내용물 해시 불일치 (Tamper Detected)!
                          1. 무결성 훼손 감사 로그(type=1800 audit: invalid-hash) 발송!
                          2. ima_appraise=enforce 모드이므로 금고 투입 즉시 거부 (-EACCES: 차단)!"

  최종 결과: 공격자가 파일 1바이트를 변조하더라도 암호학적 해시 불일치로 커널 진입이 완벽히 차단됨!
```

---

## 3. 핵심 아키텍처 및 내부 메커니즘

### 3.1 SecurityFS 인터페이스 및 런타임 구조

IMA는 `/sys/kernel/security/ima/` 노드를 통해 유저스페이스 및 감사 데몬과 통신함:

```bash
/sys/kernel/security/ima/
├── ascii_runtime_measurements    # 부팅 후 측정된 모든 파일의 PCR, 템플릿 해시, 파일 경로 목록
├── runtime_measurements_count    # 현재까지 누적 기록된 무결성 측정 총 횟수
├── violations                    # 무결성 위반(예: 실행 중인 파일의 쓰기 시도 등) 누적 카운트
└── policy                        # 런타임 측정 및 감정 규칙을 등록하는 엔드포인트
```

- **`ascii_runtime_measurements` 포맷**:
  ```text
  10 <template-hash> ima-ng sha256:<file-hash> <file-path>
  ```
  - `10`: 대상 TPM PCR 인덱스 번호.
  - `ima-ng`: 확장 템플릿 형식 (암호화 알고리즘 + 다이제스트 + 파일명).

---

### 3.2 런타임 감정(Appraisal) 모드 및 정책 제어

IMA 감정 엔진은 부팅 명령줄 파라미터(`ima_appraise=...`)로 동작 모드를 결정함:

1. **`ima_appraise=off`**:
   - 감정 기능을 완전히 비활성화함 (측정만 수행하거나 비활성).
2. **`ima_appraise=log` (Baseline)**:
   - 해시 불일치 또는 미서명 파일 실행 시 커널 감사 로그(`auditd`)에 위반 경고(`cause=invalid-hash`)를 남기되, 파일 실행은 허용함(`return 0`).
3. **`ima_appraise=enforce` (Hardened)**:
   - 해시가 일치하지 않거나 유효한 전자서명이 결여된 파일의 실행/오픈 요청을 커널 레벨에서 즉각 거절(`-EACCES`)함.
4. **`ima_appraise=fix`**:
   - 파일 쓰기 후 닫힐 때 새로운 해시를 `security.ima` 확장 속성에 자동 갱신(골든 이미지 생성 시 활용).

---

### 3.3 커널 후크 진입 파이프라인

커널 시스템 콜 진입 시 IMA는 다음과 같은 후크를 통해 VFS 레벨에서 가로챔:

```c
/* kernel source: security/integrity/ima/ima_main.c */
int ima_bprm_check(struct linux_binprm *bprm)
{
    int ret;
    u32 secid;

    /* 1. 활성 정책에 따라 측정/감정 대상 여부 판정 */
    ret = ima_must_measure(bprm->file, MAY_EXEC, BPRM_CHECK);
    if (ret < 0)
        return 0;

    /* 2. SHA-256 해시 계산 및 TPM PCR 10 확장 */
    ima_store_measurement(iint, bprm->file, ...);

    /* 3. security.ima xattr 대조 및 감정 판정 */
    return ima_appraise_measurement(iint, bprm->file, ...);
}
```

- **BPRM_CHECK**: 바이너리 실행 파일(`execve`) 검사.
- **FILE_CHECK**: 일반 파일 오픈(`sys_open`, `sys_openat`) 검사.
- **MMAP_CHECK**: 공유 라이브러리(`mmap` with `PROT_EXEC`) 매핑 검사.

---

## 4. 대화형 아키텍처 시뮬레이터

아래 시뮬레이터를 통해 정상 바이너리와 1바이트 변조 바이너리의 SHA-256 암호화 해시 계산 과정, TPM PCR 10 확장 흐름, 그리고 Log vs Enforce 모드에 따른 차단 동작을 대화형으로 체험할 수 있음:

<iframe src="../../assets/diagrams/ima/architecture.html" width="100%" height="780" frameborder="0" style="border-radius: 8px; border: 1px solid var(--md-default-fg-color--lightest); margin: 20px 0;"></iframe>

---

## 5. 공격 벡터 및 실습 랩 구조

### 5.1 타깃 드라이버 (`/proc/vuln_ima`)

- **파일 위치**: `labs/30-ima/vuln_ima.c`
- **노출 노드**: `/proc/vuln_ima` (권한 `0666`)
- **지원 제어 명령**:
  - `echo 'mode log' > /proc/vuln_ima`: Mode 0 설정 (Log 모드: 해시 불일치 시 감사 로그 생성 후 실행 허용)
  - `echo 'mode enforce' > /proc/vuln_ima`: Mode 1 설정 (Enforce 모드: 해시 불일치 시 커널 레벨에서 즉각 `-EACCES` 차단)
  - `echo 'test valid' > /proc/vuln_ima`: 정상 바이너리(기준 골든 해시 일치) 실행/검증 테스트
  - `echo 'test tampered' > /proc/vuln_ima`: 변조된 바이너리(해시 불일치) 실행 시도
  - `echo 'run_bench' > /proc/vuln_ima`: 인커널 자체 종합 IMA 감정 검증 루틴 실행

---

### 5.2 유저랜드 PoC 익스플로잇 (`exploit_ima`)

- **파일 위치**: `labs/30-ima/exploit.c`
- **동작 시나리오**:
  1. **환경 진단**: `/sys/kernel/security/ima/runtime_measurements_count` 및 `violations` 노드 확인.
  2. **Phase 1 (Log 모드 검증)**:
     - 변조된 바이너리 실행 요청 시 위반 로그가 남지만 실행이 허용(ALLOWED)됨을 확인.
  3. **Phase 2 (Enforce 모드 검증)**:
     - 정상 바이너리는 승인(GRANTED)되고, 변조된 바이너리는 `-EACCES`로 즉시 차단됨을 확인.

---

### 5.3 인게스트 검증 스크립트 (`test_ima`)

- **파일 위치**: `labs/30-ima/test.sh` (루트fs 내 `/bin/test_ima` 설치)
- **주요 검증 단계**:
  1. `securityfs` 마운트 및 `/sys/kernel/security/ima` 노드 확인.
  2. `/proc/vuln_ima` 타깃 노드 존재 및 상태 확인.
  3. 비특권 일반 계정 `lab` (UID 1000) 권한으로 `/bin/exploit_ima` 실행.
  4. 커널 `dmesg`에서 표준 IMA 감사 레코드(`type=1800 audit(ima): action=appraise_data cause=invalid-hash`) 검증.

---

## 6. Kconfig 설정 비교

### 6.1 방어 활성화 (`configs/features/ima.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_INTEGRITY=y
CONFIG_IMA=y
CONFIG_IMA_MEASURE_PCR_IDX=10
CONFIG_IMA_LSM_RULES=y
CONFIG_IMA_APPRAISE=y
CONFIG_IMA_APPRAISE_BOOTPARAM=y
CONFIG_IMA_DEFAULT_HASH_SHA256=y
CONFIG_IMA_WRITE_POLICY=y
CONFIG_IMA_READ_POLICY=y
CONFIG_LSM="landlock,lockdown,yama,bpf"
```

> [!NOTE]
> IMA는 `CONFIG_INTEGRITY=y`를 기반으로 동작하며, 측정 해시 무결성을 위해 기본 해시 알고리즘으로 SHA-256을 사용함.

### 6.2 방어 비활성화 (`configs/features/ima-disabled.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_INTEGRITY=n
CONFIG_IMA=n
CONFIG_LSM="capability"
```

---

## 7. 검증 및 QEMU 실행 방법

### 7.1 루트 파일시스템 빌드
```bash
./scripts/build_rootfs.sh --arch arm64 --force
./scripts/build_rootfs.sh --arch x86_64 --force
```

### 7.2 커널 빌드
```bash
# ARM64 커널 빌드
./scripts/build_kernel.sh --arch arm64 --feature ima

# x86_64 커널 빌드
./scripts/build_kernel.sh --arch x86_64 --feature ima
```

### 7.3 QEMU 자동 검증 실행
```bash
# ARM64 검증
./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-ima/arch/arm64/boot/Image --test test_ima --timeout 60

# x86_64 검증
./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-ima/arch/x86/boot/bzImage --test test_ima --timeout 60
```
