# Landlock 비특권 애플리케이션 자체 샌드박싱 (Unprivileged Sandboxing)

## 1. 개요 및 배경

**Landlock**은 리눅스 커널 5.13에 처음 병합된 보안 모듈(LSM)로, 루트(Root/`CAP_SYS_ADMIN`) 권한이 없는 **일반 비특권 사용자 프로세스가 스스로 자신의 시스템 자원 접근 범위를 안전하게 격리(Sandboxing)**할 수 있도록 설계된 차세대 보안 메커니즘임.

전통적인 강제적 접근 제어(MAC: SELinux, AppArmor)는 시스템 전역 정책을 작성하고 로드하기 위해 반드시 루트 관리자 권한이 요구되며 복잡한 정책 언어를 학습해야 하는 진입 장벽이 존재했음. 반면 현대 소프트웨어 환경(웹 브라우저 렌더러, 마이크로서비스, 언트러스티드 플러그인, LLM 에이전트 등)은 비특권 상태에서도 격리가 필수적임:
1. **비특권 자체 제한 (Self-Confinement without Root)**:
   - 프로세스는 어떠한 특권도 요구하지 않고 표준 UAPI 시스템 콜(`landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`)만을 사용하여 스스로 샌드박스를 구축함.
2. **권한 확대 방지 및 불가역적 격리 (`PR_SET_NO_NEW_PRIVS`)**:
   - 샌드박스 활성화 전 `prctl(PR_SET_NO_NEW_PRIVS, 1)` 설정을 강제함으로써 `setuid` 실행 파일을 통한 권한 상승을 원천 차단함.
3. **계층적 규칙 중첩 (Stacking Rulesets & Fail-Closed)**:
   - 프로세스가 자식 프로세스를 생성하거나 추가적인 샌드박스 규칙을 적용할 때, 권한은 오직 축소(교집합)될 뿐 절대로 다시 확장될 수 없음.
4. **미세 파일시스템 및 네트워크 제어**:
   - 파일 읽기/쓰기/실행/디렉터리 탐색뿐만 아니라 리눅스 6.7+부터 TCP 포트 바인딩/연결(`LANDLOCK_ACCESS_NET_*`)까지 비특권 격리 가능함.

---

## 2. 실세계 비유: 연구원의 자발적 클린룸 자가 격리와 열쇠 폐기

`Landlock`의 동작 원리는 **국가 연구소 연구원의 자발적 클린룸 자가 격리와 외부 마스터키 자진 파기**에 비유할 수 있음:

```
[ 일반 비특권 환경 (무제한 출입 모드: 신분증으로 열 수 있는 모든 연구실 방문 가능) ]
  연구원(프로세스: lab): "외부에서 다운로드한 미검증 분석 스크립트를 실행하겠습니다!"
  결과:                 스크립트에 악성 코드가 포함되어 있을 경우, 연구원의 홈 디렉터리,
                        공용 임시 폴더(/tmp/host_secret), SSH 키가 모두 탈취됨!

[ Landlock 적용 환경 (자발적 보안 클린룸 진입 및 마스터키 파기) ]
  연구원(프로세스: lab): "지금부터 위험한 실험을 수행하므로 내 출입 권한을 스스로 축소합니다!
                         1. 오직 '실험실 구역(/tmp/sandbox/)'의 파일만 읽고 쓰겠습니다.
                         2. 다른 방의 열쇠는 완전히 버립니다(PR_SET_NO_NEW_PRIVS).
                         3. 출입문을 잠그고 자물쇠를 안쪽에서 용접합니다(landlock_restrict_self)!"
  
  [실험 진행 중 악성코드 발동]
  악성코드:              "호스트 비밀 문서(/tmp/host_secret)를 읽어 탈취하겠다!"
  커널 Landlock 검문관:  "이 프로세스의 규칙셋에는 '/tmp/sandbox/' 하위 경로만 허용되어 있음!
                         외부 파일 접근 요청 즉시 거절 (-EACCES: Permission denied)!"
  악성코드:              "루트 권한을 획득하기 위해 setuid 도구를 실행하겠다!"
  커널 검문관:           "NO_NEW_PRIVS가 고정되어 있어 어떠한 권한 상승도 불가능함!"

  최종 결과: 공격자가 애플리케이션 코드를 완전히 장악하더라도 사전에 정의된 격리 구역 외부로 유출 불가!
```

---

## 3. 핵심 아키텍처 및 내부 메커니즘

### 3.1 Landlock UAPI 시스템 콜 3단계

Landlock 샌드박싱은 표준 C 라이브러리 및 UAPI 시스템 콜을 통해 3단계로 이루어짐:

```c
/* 1단계: 규칙셋 생성 (규칙이 통제할 대상 권한 플래그 선언) */
struct landlock_ruleset_attr ruleset_attr = {
    .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                         LANDLOCK_ACCESS_FS_WRITE_FILE |
                         LANDLOCK_ACCESS_FS_READ_DIR,
};
int ruleset_fd = syscall(444 /* __NR_landlock_create_ruleset */,
                         &ruleset_attr, sizeof(ruleset_attr), 0);

/* 2단계: 허용 경로 규칙 추가 (PATH_BENEATH: 특정 디렉터리 하위 트리 인가) */
int dir_fd = open("/tmp/sandbox", O_PATH | O_DIRECTORY);
struct landlock_path_beneath_attr path_attr = {
    .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
                      LANDLOCK_ACCESS_FS_WRITE_FILE |
                      LANDLOCK_ACCESS_FS_READ_DIR,
    .parent_fd = dir_fd,
};
syscall(445 /* __NR_landlock_add_rule */, ruleset_fd,
        LANDLOCK_RULE_PATH_BENEATH, &path_attr, 0);

/* 3단계: 권한 상승 잠금 및 샌드박스 영구 강제 */
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
syscall(446 /* __NR_landlock_restrict_self */, ruleset_fd, 0);
```

---

### 3.2 접근 권한 비트마스크 (Access Rights Bitmask)

Landlock은 파일시스템 동작을 세분화하여 제어함:

| 비트마스크 플래그 | 설명 |
| :--- | :--- |
| `LANDLOCK_ACCESS_FS_EXECUTE` | 실행 파일(`execve`) 실행 허용 |
| `LANDLOCK_ACCESS_FS_WRITE_FILE` | 파일 내용 쓰기 허용 |
| `LANDLOCK_ACCESS_FS_READ_FILE` | 파일 내용 읽기 허용 |
| `LANDLOCK_ACCESS_FS_READ_DIR` | 디렉터리 항목 목록 조회(`getdents64`) 허용 |
| `LANDLOCK_ACCESS_FS_REMOVE_DIR` | 빈 디렉터리 삭제(`rmdir`) 허용 |
| `LANDLOCK_ACCESS_FS_REMOVE_FILE` | 일반 파일 삭제(`unlink`) 허용 |
| `LANDLOCK_ACCESS_FS_MAKE_REG` | 일반 정규 파일 생성(`creat`, `mknod`) 허용 |
| `LANDLOCK_ACCESS_FS_MAKE_DIR` | 새 디렉터리 생성(`mkdir`) 허용 |

- **Default Deny 원칙**: `handled_access_fs`에 포함된 동작 중, `landlock_add_rule`로 인가되지 않은 모든 경로는 커널에서 즉시 `-EACCES`로 거부됨.

---

### 3.3 계층적 중첩 (Stacking Rulesets) 및 상속 모델

Landlock 규칙셋은 `struct cred` 내의 `security` 블롭에 연결 리스트 형태로 상속됨:

```
[ 부모 프로세스 ] ── (규칙셋 A: /usr, /tmp 허용)
        │ fork() / execve()
        ▼
[ 자식 프로세스 ] ── (부모의 규칙셋 A 상속)
        │ landlock_restrict_self(규칙셋 B: /tmp/sandbox 만 허용)
        ▼
[ 제한된 자식 ]   ── (규칙셋 A ∩ 규칙셋 B = /tmp/sandbox 만 접근 가능!)
```

- 하위 프로세스는 부모의 제약을 완화할 수 없으며 오직 추가 제한만 가능함.
- 부모와 자식 간 권한 격리가 완벽히 보장됨.

---

## 4. 대화형 아키텍처 시뮬레이터

아래 시뮬레이터를 통해 비특권 프로세스의 Landlock 시스템 콜 흐름, VFS 후크 순회 검증, 허용된 샌드박스 내부 접근 vs 차단되는 외부 호스트 파일 탈출 시도를 대화형으로 확인할 수 있음:

<iframe src="../../assets/diagrams/landlock/architecture.html" width="100%" height="780" frameborder="0" style="border-radius: 8px; border: 1px solid var(--md-default-fg-color--lightest); margin: 20px 0;"></iframe>

---

## 5. 공격 벡터 및 실습 랩 구조

### 5.1 타깃 드라이버 (`/proc/vuln_landlock`)

- **파일 위치**: `labs/29-landlock/vuln_landlock.c`
- **노출 노드**: `/proc/vuln_landlock` (권한 `0666`)
- **지원 제어 명령**:
  - `echo 'mode baseline' > /proc/vuln_landlock`: Mode 0 설정 (일반 DAC 모드: 샌드박스 외부 호스트 파일 접근 허용)
  - `echo 'mode hardened' > /proc/vuln_landlock`: Mode 1 설정 (Landlock 샌드박스 모드: 외부 탈출 시도 즉각 `-EACCES` 차단)
  - `echo 'test sandbox' > /proc/vuln_landlock`: 인가된 샌드박스 내부 파일(`/tmp/sandbox/allowed_file.txt`) 읽기/쓰기 테스트
  - `echo 'test escape' > /proc/vuln_landlock`: 샌드박스 외부 기밀 파일(`/tmp/host_secret`) 접근 시도
  - `echo 'test write' > /proc/vuln_landlock`: 시스템 파일 임의 쓰기 시도
  - `echo 'run_bench' > /proc/vuln_landlock`: 인커널 자체 종합 샌드박스 검증 루틴 실행

---

### 5.2 유저랜드 PoC 익스플로잇 (`exploit_landlock`)

- **파일 위치**: `labs/29-landlock/exploit.c`
- **동작 시나리오**:
  1. **네이티브 Landlock ABI 진단**: 시스템 콜 444를 호출하여 커널의 Landlock 지원 버전 조회.
  2. **Phase 1 (Baseline 검증)**:
     - 샌드박스 외부 파일(`/tmp/host_secret`) 읽기가 성공함을 확인 (미보호 상태).
  3. **Phase 2 (Hardened 검증)**:
     - 인가된 샌드박스 내부 파일 접근은 정상 성공(GRANTED)함을 확인.
     - 샌드박스 외부 파일 접근 및 시스템 쓰기는 `-EACCES`로 완벽히 차단됨을 확인.

---

### 5.3 인게스트 검증 스크립트 (`test_landlock`)

- **파일 위치**: `labs/29-landlock/test.sh` (루트fs 내 `/bin/test_landlock` 설치)
- **주요 검증 단계**:
  1. `securityfs` 마운트 및 `/sys/kernel/security/lsm` 내 `landlock` 활성화 확인.
  2. 테스트 격리 디렉터리(`/tmp/sandbox`) 및 외부 기밀 파일(`/tmp/host_secret`) 생성.
  3. 비특권 일반 사용자 `lab` (UID 1000) 권한으로 `/bin/exploit_landlock` 실행.
  4. 커널 `dmesg`에서 Landlock 차단 이벤트 로그 검증.

---

## 6. Kconfig 설정 비교

### 6.1 방어 활성화 (`configs/features/landlock.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_LANDLOCK=y
CONFIG_LSM="landlock,lockdown,yama,bpf"
```

> [!TIP]
> Landlock은 현대 리눅스 배포판에서 기본 스택 LSM 최우선 순위로 배치되어 비특권 샌드박스를 처리함.

### 6.2 방어 비활성화 (`configs/features/landlock-disabled.config`)
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
./scripts/build_kernel.sh --arch arm64 --feature landlock

# x86_64 커널 빌드
./scripts/build_kernel.sh --arch x86_64 --feature landlock
```

### 7.3 QEMU 자동 검증 실행
```bash
# ARM64 검증
./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-landlock/arch/arm64/boot/Image --test test_landlock --timeout 60

# x86_64 검증
./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-landlock/arch/x86/boot/bzImage --test test_landlock --timeout 60
```
