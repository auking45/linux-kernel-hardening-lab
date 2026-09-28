# AppArmor 프로파일 기반 프로세스 격리 및 경로 강제 접근 제어 (Path MAC)

## 1. 개요 및 배경

**AppArmor (Application Armor)**는 파일 시스템의 **전체 파일 경로(Pathname)**를 기반으로 애플리케이션의 동작 권한을 제한하는 대표적인 리눅스 보안 모듈(LSM)임. inode 기반의 레이블(Security Context)을 파일 시스템 확장 속성(xattr)에 저장해야 하는 SELinux와 달리, AppArmor는 사람이 직관적으로 읽고 작성할 수 있는 파일 경로 규칙을 사용하므로 설정과 배포가 신속하고 직관적임.

현대 리눅스 배포판(Ubuntu, Debian, SUSE) 및 컨테이너 런타임(Docker, Kubernetes, containerd)에서는 다음과 같은 이유로 AppArmor를 기본 보안 계층으로 채택함:
1. **파일 시스템 비종속적 경로 제어**:
   - 파일 시스템 포맷(ext4, xfs, tmpfs, nfs 등)이나 xattr 지원 여부와 무관하게 모든 파일 경로에 대해 균일한 접근 제어 규칙을 적용할 수 있음.
2. **최소 권한 원칙(Principle of Least Privilege)의 강제**:
   - 취약점이 발생하더라도 프로세스가 접근할 수 있는 디렉터리, 파일, 네트워크 소켓, IPC, `ptrace` 기능을 사전에 정의된 프로파일 범위로 엄격히 제한함.
3. **점진적 배포 모델 (Complain vs Enforce)**:
   - 프로파일을 학습 및 감사 목적으로 운용하는 **Complain (불평/학습) 모드**와 위반 행위를 커널 레벨에서 즉각 차단하는 **Enforce (강제) 모드**를 지원하여 서비스 중단 위험 없이 단계적으로 정책을 강화할 수 있음.

---

## 2. 실세계 비유: 은행 지점의 직원 업무 구역 출입증과 보안 수칙서

`AppArmor`의 동작 메커니즘은 **은행 지점의 물리적 출입 통제 및 업무 매뉴얼**에 비유할 수 있음:

```
[ 일반 DAC 환경 (자유 출입 모드: 신분증만 있으면 은행 내 모든 방 열람 가능) ]
  직원(프로세스: lab): "은행 금고실(/tmp/secret_token) 문을 열겠습니다!"
  경비원(커널 DAC):   "당신은 은행 소속 직원이군요(UID 1000). 키가 맞으니 문을 열어드립니다."
  결과:               내부 직원이나 탈취당한 계정이 중요 금고와 전산망에 무제한 접근하여 횡령/유출 발생!

[ AppArmor Complain 모드 (학습/감시 모드: 모든 행동을 기록하되 차단하지 않음) ]
  직원(프로세스: lab): "금고실(/tmp/secret_token)을 열고, 외부 전화망(Raw Socket)을 연결합니다!"
  보안요원(AppArmor): "수칙 위반 감지! 하지만 현재는 수습/학습 모드이므로 접근을 허용하고
                       감사 로그(auditd/dmesg)에 경고를 기록합니다."
  결과:               차단은 발생하지 않으나 위반 행위 패턴이 로그로 수집되어 프로파일 튜닝에 활용됨.

[ AppArmor Enforce 모드 (엄격 강제 모드: 인가된 장부 외 접근 시 즉각 구속) ]
  직원(프로세스: lab): "금고실(/tmp/secret_token) 문을 열겠습니다!"
  보안요원(AppArmor): "당신의 업무 프로파일에는 '창구 업무 장부(/tmp/allowed_file)'만 허용되어 있습니다!
                       금고실 접근 요청을 즉시 기각합니다 (-EACCES)!"
  직원(프로세스: lab): "그럼 외부 도청기(Raw Socket)나 동료 컴퓨터 원격제어(ptrace)를 시도합니다!"
  보안요원(AppArmor): "네트워크 및 ptrace 권한 미보유! 즉각 거부 (-EPERM)!"

  최종 결과: 공격자가 프로세스 실행 권한을 장악하더라도 허가되지 않은 파일 및 시스템 호출이 완벽히 차단됨!
```

---

## 3. 핵심 아키텍처 및 내부 메커니즘

### 3.1 경로 매칭 엔진 (Pathname Resolution)

전통적인 파일 접근 시 커널은 `dentry` 및 `inode`를 조회하지만, AppArmor의 `apparmor_file_open` 및 `apparmor_inode_permission` 후크는 해당 파일의 전체 가상 파일 시스템(VFS) 절대 경로를 계산하여 프로파일 규칙과 대조함:

```c
/* kernel source: security/apparmor/lsm.c & file.c */
static int apparmor_file_open(struct file *file)
{
    struct aa_profile *profile = aa_current_profile();
    struct path_cond cond = {
        .uid = file_inode(file)->i_uid,
        .mode = file_inode(file)->i_mode,
    };
    struct aa_perms perms;

    if (unconfined(profile))
        return 0;

    /* dentry/vfsmount로부터 정규화된 절대 경로 계산 */
    aa_path_perm(OP_OPEN, profile, &file->f_path, 0,
                 MAY_READ | MAY_WRITE, &cond, &perms);

    return aa_check_perms(profile, &perms, ...);
}
```

- **경로 정규화**: 심볼릭 링크 및 마운트 네임스페이스를 고려하여 VFS 루트 기준 정규 경로(`d_path()`)를 추출함.
- **결정적 유한 오토마타 (DFA)**: 컴파일된 바이너리 프로파일은 최적화된 DFA 상태 머신으로 커널에 로드되어 $O(1)$에 근접한 초고속 경로 매칭을 수행함.

---

### 3.2 프로파일 상태 머신 및 모드 전이

AppArmor 프로파일은 프로세스별로 다음과 같은 상태를 가짐:

1. **Unconfined (비격리)**:
   - 프로파일이 적용되지 않은 일반 상태로, 표준 리눅스 DAC(권한 비트, POSIX ACL)만 적용됨.
2. **Complain (불평/감사 모드)**:
   - 프로파일 규칙을 위반하는 접근이 발생해도 요청을 거부하지 않고(`return 0`), 커널 감사 로그(`auditd`, `dmesg`)에 위반 내역(`apparmor="ALLOWED"`)을 기록함.
3. **Enforce (강제 격리 모드)**:
   - 프로파일에 명시적으로 허용(`allow`)되지 않은 모든 접근 시도를 거부(`-EACCES` 또는 `-EPERM`)하고 차단 이벤트(`apparmor="DENIED"`)를 기록함.
4. **Kill (즉각 종료)**:
   - 특정 치명적 위반 발생 시 해당 프로세스에 `SIGKILL`을 전송하여 즉각 사살함.

---

### 3.3 SecurityFS 인터페이스 및 프로파일 동적 관리

AppArmor는 `/sys/kernel/security/apparmor/` 디렉터리를 통해 유저스페이스 도구(`apparmor_parser`, `aa-status`, `aa-enforce`)와 통신함:

```bash
/sys/kernel/security/apparmor/
├── profiles              # 현재 로드된 모든 프로파일과 적용 모드 목록
├── .load                 # 새 바이너리 프로파일을 커널에 주입하는 엔드포인트
├── .replace              # 기존 프로파일을 중단 없이 원자적으로 교체하는 엔드포인트
└── .remove               # 등록된 프로파일을 해제하는 엔드포인트
```

- **`/proc/[pid]/attr/apparmor/current`**: 특정 프로세스에 바인딩된 현재 프로파일 및 실행 모드를 확인하거나 `aa_change_hat` / `aa_change_profile`을 통해 동적 하위 도메인 전환을 수행함.

---

## 4. 대화형 아키텍처 시뮬레이터

아래 시뮬레이터를 통해 AppArmor의 경로 해석 파이프라인, Complain vs Enforce 모드 차이, DFA 경로 매칭 엔진, 그리고 SecurityFS 프로파일 관리 인터페이스를 대화형으로 체험할 수 있음:

<iframe src="../../assets/diagrams/apparmor/architecture.html" width="100%" height="780" frameborder="0" style="border-radius: 8px; border: 1px solid var(--md-default-fg-color--lightest); margin: 20px 0;"></iframe>

---

## 5. 공격 벡터 및 실습 랩 구조

### 5.1 타깃 드라이버 (`/proc/vuln_apparmor`)

- **파일 위치**: `labs/27-apparmor/vuln_apparmor.c`
- **노출 노드**: `/proc/vuln_apparmor` (권한 `0666`)
- **지원 제어 명령**:
  - `echo 'mode complain' > /proc/vuln_apparmor`: Mode 0 설정 (Complain 모드: 위반 사항 허용 및 감사 로그 생성)
  - `echo 'mode enforce' > /proc/vuln_apparmor`: Mode 1 설정 (Enforce 모드: 경로, 네트워크, ptrace 위반 즉각 차단)
  - `echo 'test normal' > /proc/vuln_apparmor`: 인가된 정상 경로(`/tmp/allowed_file`) 접근 테스트
  - `echo 'test file' > /proc/vuln_apparmor`: 미인가 비인가 파일(`/tmp/secret_token`) 접근 시도
  - `echo 'test network' > /proc/vuln_apparmor`: 비인가 저수준 소켓(`AF_PACKET` raw socket) 생성 시도
  - `echo 'test ptrace' > /proc/vuln_apparmor`: 타 프로세스 메모리 검사(`PTRACE_ATTACH`) 시도
  - `echo 'run_bench' > /proc/vuln_apparmor`: 인커널 자체 종합 성능 및 접근 제어 검증 실행

---

### 5.2 유저랜드 PoC 익스플로잇 (`exploit_apparmor`)

- **파일 위치**: `labs/27-apparmor/exploit.c`
- **검증 시나리오**:
  1. **사전 진단**: `/sys/kernel/security/lsm`, `/proc/self/attr/apparmor/current`, `/sys/kernel/security/apparmor/profiles`를 질의하여 커널 내 AppArmor 활성화 상태 확인.
  2. **Phase 1 (Complain 모드 검증)**:
     - 비인가 파일, 네트워크 소켓, ptrace 요청이 모두 성공(ALLOWED)하며 차단되지 않는 상태 확인.
  3. **Phase 2 (Enforce 모드 검증)**:
     - 정상 인가 파일 접근은 정상 성공(GRANTED)함을 확인.
     - 비인가 파일 접근은 `-EACCES`로 즉시 차단됨을 확인.
     - 원시 소켓 생성 및 ptrace 요청은 `-EPERM`으로 즉시 차단됨을 확인.

---

### 5.3 인게스트 검증 스크립트 (`test_apparmor`)

- **파일 위치**: `labs/27-apparmor/test.sh` (루트fs 내 `/bin/test_apparmor` 설치)
- **주요 검증 단계**:
  1. `securityfs` 마운트 및 `/sys/kernel/security/apparmor` 노드 존재 여부 확인.
  2. `/proc/vuln_apparmor` 타깃 드라이버 존재 확인.
  3. 비특권 사용자 `lab` (UID 1000)으로 `/bin/exploit_apparmor` 실행 및 결과 검증.
  4. 커널 `dmesg`에서 AppArmor 감사 로그(`apparmor="ALLOWED"`, `apparmor="DENIED"`) 확인.

---

## 6. Kconfig 설정 비교

### 6.1 방어 활성화 (`configs/features/apparmor.config`)
```ini
CONFIG_NET=y
CONFIG_INET=y
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_PATH=y
CONFIG_SECURITY_APPARMOR=y
CONFIG_SECURITY_APPARMOR_HASH=y
CONFIG_SECURITY_APPARMOR_HASH_DEFAULT=y
CONFIG_DEFAULT_SECURITY_APPARMOR=y
CONFIG_LSM="landlock,lockdown,yama,apparmor,bpf"
```

> [!NOTE]
> AppArmor는 네트워크 접근 제어와 소켓 후크를 지원하므로 반드시 `CONFIG_NET=y` 및 `CONFIG_INET=y`가 함께 활성화되어야 함.

### 6.2 방어 비활성화 (`configs/features/apparmor-disabled.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
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
./scripts/build_kernel.sh --arch arm64 --feature apparmor

# x86_64 커널 빌드
./scripts/build_kernel.sh --arch x86_64 --feature apparmor
```

### 7.3 QEMU 자동 검증 실행
```bash
# ARM64 검증
./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-apparmor/arch/arm64/boot/Image --test test_apparmor --timeout 60

# x86_64 검증
./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-apparmor/arch/x86/boot/bzImage --test test_apparmor --timeout 60
```
