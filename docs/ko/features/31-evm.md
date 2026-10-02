# EVM (Extended Verification Module) 파일 메타데이터 및 xattr 무결성 보호

## 1. 개요 및 배경

**EVM (Extended Verification Module)**은 리눅스 커널 3.2에 병합된 무결성 하위 시스템으로, 파일의 확장 보안 속성(Extended Attributes, xattr) 및 핵심 inode 메타데이터에 대한 **오프라인 위변조 및 비인가 수정을 방어하기 위해 암호학적 HMAC 또는 전자서명을 강제**하는 보안 기술임.

IMA(Integrity Measurement Architecture)가 파일 본문 내용의 해시(`security.ima`)를 검증하여 바이너리 변조를 막는다면, EVM은 이와 상호 보완적으로 동작하여 **메타데이터 수준의 공격 표면**을 완벽히 차단함:
1. **메타데이터 위조를 통한 권한 상승 방어**:
   - 공격자가 파일 내용은 건드리지 않고 오프라인 디스크 조작이나 취약점을 통해 비특권 바이너리에 `security.capability` 속성(예: `CAP_SETUID`)을 몰래 추가하거나 파일 소유자(`i_uid`)를 root(0)로 변경하는 권한 상승 공격을 차단함.
2. **보안 속성 간 암호학적 결합 (HMAC-SHA256)**:
   - 커널 신뢰 키링(`keyring`)에 보관된 대칭키 또는 비대칭키를 사용하여 `security.ima`, `security.selinux`, `security.apparmor`, `security.capability` 속성과 `inode` 메타데이터(UID, GID, Mode, Inode 번호)를 단일 HMAC 다이제스트로 결합하고 이를 `security.evm` 속성에 저장함.
3. **Fail-Closed 런타임 강제**:
   - 보호 대상 xattr이나 파일 소유권이 단 1비트라도 승인 없이 변경되면 커널은 HMAC 불일치를 감지하고 해당 파일에 대한 접근이나 실행을 즉시 거부(`-EPERM` 또는 `-EACCES`)함.

---

## 2. 실세계 비유: 공증 계약서의 위변조 방지 압인 인장과 서명 결합

`EVM`의 동작 구조는 **공증 문서의 본문과 서명란, 날짜 도장을 하나로 묶는 위변조 방지 특수 압인 인장**에 비유할 수 있음:

```
[ IMA 단독 적용 환경 (본문만 검증: 서명 위조에 취약) ]
  공격자:         "계약서 본문(파일 내용)은 한 글자도 바꾸지 않았다!"
  공격자 조작:    "대신 문서 하단에 '모든 재산 처분 권한(security.capability: CAP_SETUID)' 도장을 몰래 찍는다."
  결과:           IMA 검사관은 본문 내용만 대조하므로 도장이 조작된 사실을 인지하지 못하고,
                  공격자가 손쉽게 최고 관리자 권한을 획득함!

[ IMA + EVM 통합 환경 (본문 해시 + 도장 + 서류 정보를 특수 봉인 씰로 결합) ]
  공격자:         "일반 도구(/bin/lab_tool)에 몰래 CAP_SETUID 도장(xattr)을 부여하겠다!"
  EVM 검사관:     "잠깐! 이 문서의 xattr과 소유자 정보가 변경되었다.
                  1. 현재 메타데이터: [security.ima + security.capability + UID 1000]
                  2. 커널 마스터키로 재계산한 HMAC: [ffffffff...]
                  3. 문서 표면의 공인 봉인 씰(security.evm): [a1b2c3d4...]
                  4. HMAC 불일치 감지! 불법 위변조 시도로 판정!"
  EVM 검사관:     "접근 및 실행 즉각 거절 (-EPERM: Operation not permitted)!"

  최종 결과: 파일 본문뿐만 아니라 파일에 부여된 모든 보안 권한과 소유권이 완전하게 보호됨!
```

---

## 3. 핵심 아키텍처 및 내부 메커니즘

### 3.1 EVM 보호 대상 메타데이터 구성

EVM은 다음과 같은 복합 속성 튜플을 결합하여 HMAC을 계산함:

$$\text{HMAC} = \text{HMAC-SHA256}(K_{\text{evm}}, \text{XATTRs} \parallel \text{Inode\_Metadata})$$

| 범주 | 보호 항목 | 보안 의미 |
| :--- | :--- | :--- |
| **보안 확장 속성** | `security.ima` | IMA 파일 본문 무결성 해시 |
| | `security.selinux` | SELinux 프로세스/객체 보안 라벨 |
| | `security.apparmor` | AppArmor 프로파일 바인딩 |
| | `security.smack` | SMAP 접근 제어 레이블 |
| | `security.capability` | POSIX 파일 기능(Capabilities: `CAP_SETUID` 등) |
| **inode 메타데이터** | `i_uid` | 파일 소유자 사용자 ID |
| | `i_gid` | 파일 소유 그룹 ID |
| | `i_mode` | 파일 권한 비트 및 파일 형식 |
| | `i_ino` | 파일 시스템 내부 고유 inode 번호 |
| | `i_generation` | inode 재생성 카운터 (재사용 공격 방어) |

---

### 3.2 SecurityFS 인터페이스 및 초기화

EVM은 `/sys/kernel/security/evm` 엔드포인트를 통해 상태를 노출하고 마스터키를 활성화함:

```bash
/sys/kernel/security/evm
# 값 비트마스크:
# 1 = EVM_INIT_HMAC (HMAC 대칭키 활성화 완료)
# 2 = EVM_INIT_X509 (X.509 비대칭 디지털 서명 활성화 완료)
```

- 부팅 시 유저스페이스 키링 유틸리티(`keyctl`)가 암호화된 `evm-key`를 커널 루트 키링에 주입하고 `echo 1 > /sys/kernel/security/evm`을 기록하여 EVM 엔진을 봉인 활성화함.

---

### 3.3 VFS 후크 감시 파이프라인

파일 수정이나 속성 변경 시스템 콜 발생 시 EVM은 다음과 같이 개입함:

```c
/* kernel source: security/integrity/evm/evm_main.c */
int evm_inode_setxattr(struct dentry *dentry, const char *xattr_name,
                       const void *xattr_value, size_t xattr_value_len)
{
    /* 1. 수정하려는 xattr이 EVM 보호 대상인지 판정 */
    if (!evm_protected_xattr(xattr_name))
        return 0;

    /* 2. 현재 파일의 기존 security.evm 무결성 사전 검증 */
    if (evm_verify_current_integrity(dentry) != 0)
        return -EPERM; /* 이전 서명이 깨져 있으면 수정 거부 */

    return 0;
}

void evm_inode_post_setxattr(struct dentry *dentry, ...)
{
    /* 3. 변경 완료 후 새로운 HMAC-SHA256을 계산하여 security.evm 원자적 갱신 */
    evm_update_evmxattr(dentry, ...);
}
```

---

## 4. 대화형 아키텍처 시뮬레이터

아래 시뮬레이터를 통해 Inode 메타데이터와 xattr의 암호학적 결합 과정, 커널 키링 기반 HMAC-SHA256 계산, 정상 검증 vs Capability 주입 공격 차단 동작을 대화형으로 확인할 수 있음:

<iframe src="../../assets/diagrams/evm/architecture.html" width="100%" height="780" frameborder="0" style="border-radius: 8px; border: 1px solid var(--md-default-fg-color--lightest); margin: 20px 0;"></iframe>

---

## 5. 공격 벡터 및 실습 랩 구조

### 5.1 타깃 드라이버 (`/proc/vuln_evm`)

- **파일 위치**: `labs/31-evm/vuln_evm.c`
- **노출 노드**: `/proc/vuln_evm` (권한 `0666`)
- **지원 제어 명령**:
  - `echo 'mode permissive' > /proc/vuln_evm`: Mode 0 설정 (Permissive 모드: 메타데이터 위변조 감사 로그 생성 후 허용)
  - `echo 'mode enforce' > /proc/vuln_evm`: Mode 1 설정 (Enforce 모드: HMAC 불일치 시 즉각 `-EPERM` 차단)
  - `echo 'test valid' > /proc/vuln_evm`: 정상 메타데이터 및 유효한 `security.evm` HMAC 검증
  - `echo 'test tampered_cap' > /proc/vuln_evm`: 미인가 `security.capability` (CAP_SETUID) 주입 시도
  - `echo 'test tampered_uid' > /proc/vuln_evm`: inode UID를 root(0)로 불법 변조 시도
  - `echo 'run_bench' > /proc/vuln_evm`: 인커널 자체 종합 EVM 무결성 검증 루틴 실행

---

### 5.2 유저랜드 PoC 익스플로잇 (`exploit_evm`)

- **파일 위치**: `labs/31-evm/exploit.c`
- **동작 시나리오**:
  1. **환경 점검**: `/sys/kernel/security/evm` 및 활성 LSM 스택 점검.
  2. **Phase 1 (Permissive 검증)**:
     - Capability 및 UID 위변조 요청이 허용되며 감사 로그만 남는 상태 확인.
  3. **Phase 2 (Enforce 검증)**:
     - 정상 파일 메타데이터 검증은 승인(GRANTED)됨을 확인.
     - `security.capability` 주입 및 소유자 변경 시도가 `-EPERM`으로 완벽히 차단됨을 확인.

---

### 5.3 인게스트 검증 스크립트 (`test_evm`)

- **파일 위치**: `labs/31-evm/test.sh` (루트fs 내 `/bin/test_evm` 설치)
- **주요 검증 단계**:
  1. `securityfs` 마운트 및 `/sys/kernel/security/evm` 노드 확인.
  2. `/proc/vuln_evm` 타깃 노드 존재 및 상태 확인.
  3. 비특권 계정 `lab` (UID 1000)으로 `/bin/exploit_evm` 실행.
  4. 커널 `dmesg`에서 표준 EVM 감사 레코드(`type=1800 audit(evm): action=appraise_metadata cause=invalid-HMAC`) 검증.

---

## 6. Kconfig 설정 비교

### 6.1 방어 활성화 (`configs/features/evm.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_INTEGRITY=y
CONFIG_IMA=y
CONFIG_EVM=y
CONFIG_EVM_ATTR_FSUUID=y
CONFIG_EVM_ADD_XATTRS=y
CONFIG_LSM="landlock,lockdown,yama,bpf"
```

### 6.2 방어 비활성화 (`configs/features/evm-disabled.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_INTEGRITY=n
CONFIG_EVM=n
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
./scripts/build_kernel.sh --arch arm64 --feature evm

# x86_64 커널 빌드
./scripts/build_kernel.sh --arch x86_64 --feature evm
```

### 7.3 QEMU 자동 검증 실행
```bash
# ARM64 검증
./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-evm/arch/arm64/boot/Image --test test_evm --timeout 60

# x86_64 검증
./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-evm/arch/x86/boot/bzImage --test test_evm --timeout 60
```
