# Stackable LSM 아키텍처 및 복수 LSM 활성화 (lsm=...)

## 1. 개요 및 배경

리눅스 커널 2.6에 처음 도입된 **LSM (Linux Security Modules)** 프레임워크는 커널의 DAC(임의적 접근 제어) 검사 이후에 동작하는 표준 강제적 접근 제어(MAC) 인터페이스임. 초기 LSM은 전역 함수 포인터 테이블(`security_ops`)을 기반으로 설계되어 단 하나의 "주요(Major)" 보안 모듈(SELinux, AppArmor, Smack, TOMOYO 중 택일)만 등록할 수 있었음.

그러나 현대 엔터프라이즈 및 클라우드 네이티브 환경에서는 다양한 보안 모듈의 동시 운용이 필수적임:
1. **모듈별 특화 보안 영역의 분리**:
   - 시스템 전역 강제적 접근 제어(MAC): AppArmor, SELinux
   - 프로세스 메모리 보호 및 디버깅 격리: Yama
   - 비특권 애플리케이션 파일/네트워크 샌드박싱: Landlock
   - 펌웨어 및 커널 이미지 공급망 고정: LoadPin
   - 커널 런타임 변조 및 하드웨어 직접 접근 방지: Lockdown
   - 동적 런타임 프로그래머블 정책: BPF LSM
2. **단일 독점 모델의 한계 극복**:
   - 리눅스 5.1(2019년)을 기점으로 커널은 단일 함수 포인터를 버리고 **스택 가능한 연결 리스트 체인(`hlist_head`)**과 **복합 보안 블롭(Composite Security Blobs)** 아키텍처로 완전히 전환함.
   - 이를 통해 여러 개의 보안 모듈이 충돌 없이 공존하며, 시스템 콜 진입 시 체인에 등록된 모든 LSM의 후크 함수를 순차적으로 실행할 수 있게 됨.

---

## 2. 실세계 비유: 국제공항의 다중 보안 검색대와 복합 보안 패스

`Stackable LSM`의 동작 원리는 **국제공항의 다단계 보안 검색대와 통합 보안 패스**에 완벽히 비유할 수 있음:

```
[ 전통적 단일 LSM 모델 (Legacy Single LSM: 공항에 단 하나의 검색대만 존재) ]
  승객(시스템 콜): "비행기(커널 자원)에 탑승하겠습니다!"
  공항 관리소:     "우리 공항은 오직 신분증 검사대(SELinux) 또는 가방 스캐너(AppArmor) 중
                   단 하나만 설치할 수 있습니다!"
  결과:            신분증 검사대를 선택하면 가방 속 흉기를 잡지 못하고,
                   가방 스캐너를 선택하면 위조 신분증을 잡지 못하는 상호 배타적 보안 공백 발생!

[ 현대 스택형 LSM 모델 (Stackable LSM: 직렬 연계 다중 검색대 & 통합 배지) ]
  승객(시스템 콜): "비행기(커널 자원)에 탑승하겠습니다!"
  통합 보안 패스: [ 신분증 태그 | 액체류 스티커 | 위험물 표식 | 세관 도장 ] (단일 통합 배지)
  
  [1번 검색대: 신분 확인 (Capability/DAC)] ──► 통과 (ret = 0)
  [2번 검색대: 격리 구역 확인 (Landlock)] ──► 통과 (ret = 0)
  [3번 검색대: 위험물 반입 차단 (Lockdown)] ──► "인가되지 않은 위험물 감지!" (ret = -EPERM)
  [4번 검색대: 신체 수색 (Yama)]            ──► (3번에서 거절당했으므로 즉시 퇴장, 평가 중단!)

  최종 결과: 단 하나의 검색대라도 통과하지 못하면 즉시 탑승 거절(Fail-Closed)!
```

1. **단일 독점 방식 (Legacy)**:
   - 객체마다 하나의 보안 포인터만 제공되어 여러 모듈이 포인터를 독점하려 다툼.
2. **스택형 다중 체인 (Stackable LSM)**:
   - 승객(프로세스/파일)에 부여된 보안 배지(Blob) 안에 각 검색대(LSM) 전용 주머니를 연속으로 배치함.
   - 순차적으로 모든 검색대를 통과해야 하며, 단 한 곳이라도 불합격을 내리면 즉각 퇴장(Fail-Closed) 조치함.

---

## 3. 핵심 아키텍처 및 내부 메커니즘

### 3.1 후크 체인 관리와 Fail-Closed 평가 루프

모든 커널 보안 이벤트(예: 프로세스 생성, 소켓 연결, 파일 오픈)는 `security_hook_heads` 구조체 내의 이중 연결 리스트 헤드로 표현됨:

```c
/* include/linux/lsm_hook_defs.h & security/security.c */
struct security_hook_heads {
    struct hlist_head bprm_check_security;
    struct hlist_head file_open;
    struct hlist_head inode_permission;
    struct hlist_head ptrace_access_check;
    /* ... 200여 개 이상의 세부 보안 후크 헤드 ... */
};

/* 후크 호출 매크로 */
#define call_int_hook(FUNC, IRC, ...) ({       \
    int RC = IRC;                              \
    struct security_hook_list *P;              \
    hlist_for_each_entry(P, &security_hook_heads.FUNC, list) { \
        RC = P->hook.FUNC(__VA_ARGS__);        \
        if (RC != 0)                           \
            break; /* 어느 모듈이든 에러 반환 시 즉각 중단 */ \
    }                                          \
    RC;                                        \
})
```

- **Fail-Closed 결정론**:
  - 체인에 등록된 모듈들이 순차적으로 호출됨.
  - 모든 모듈이 `0`을 반환해야만 요청이 승인됨.
  - 임의의 모듈이 `-EACCES` 또는 `-EPERM` 등의 음수 에러 코드를 반환하면 루프는 즉시 `break`되어 후속 모듈을 평가하지 않고 시스템 콜을 거부함.

---

### 3.2 복합 보안 블롭 (Shared Security Blobs)

과거 모듈 간 공존을 가로막았던 `void *security` 독점 문제는 **단일 연속 메모리 슬랩과 오프셋 분할 기법**으로 해결됨:

```c
/* include/linux/lsm_hooks.h */
struct lsm_blob_sizes {
    int lbs_cred;   /* struct cred 확장 크기 */
    int lbs_file;   /* struct file 확장 크기 */
    int lbs_inode;  /* struct inode 확장 크기 */
    int lbs_ipc;    /* struct kern_ipc_perm 확장 크기 */
    int lbs_msg;    /* struct msg_msg 확장 크기 */
    int lbs_task;   /* struct task_struct 확장 크기 */
    int lbs_xattr;  /* struct xattr 확장 크기 */
};
```

1. **부팅 시 크기 합산**:
   - 커널 초기화 시 활성화된 모든 LSM의 `lsm_blob_sizes`를 집계하여 총합 바이트 수를 계산함.
2. **단일 할당 및 오프셋 지정**:
   - 객체(`struct cred`, `struct inode` 등) 생성 시 단 한 번의 `kmalloc`으로 연속 버퍼를 할당함.
   - 각 LSM은 할당된 버퍼 내 자신의 상대 오프셋(예: Landlock은 `+16`, SafeSetID는 `+24`)을 부여받아 자신의 사설 구조체로 형변환하여 사용함.

---

### 3.3 부팅 파라미터 제어 (`lsm=...`) 및 SecurityFS

커널 빌드 시 기본 순서는 `CONFIG_LSM`으로 정의되지만, 부팅 시 부트로더(GRUB/QEMU) 명령줄 파라미터로 동적 오버라이드가 가능함:

```bash
# 기본 활성화 설정 예시
CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,bpf"

# 부팅 명령줄 파라미터를 통한 런타임 제어
lsm=landlock,lockdown,yama,bpf lsm.debug
```

- **`lsm=...`**: 활성화할 LSM의 목록과 평가 순서를 명시적으로 정의함. 나열되지 않은 모듈은 비활성화됨 (단, `capability`는 필수 모듈로서 암묵적으로 항상 최우선 배치됨).
- **`lsm.debug`**: 부팅 시 각 모듈의 등록 순서, 할당된 블롭 크기 및 오프셋 정보를 커널 로그(`dmesg`)에 상세히 출력함.
- **`/sys/kernel/security/lsm`**: `securityfs`를 통해 현재 활성화된 LSM 스택 목록을 쉼표 구분 문자열로 노출함.
- **`lsm_list_modules` (Syscall 461)**: 리눅스 6.8+에서 도입된 UAPI 시스템 콜로, 유저 공간에서 정수형 LSM ID 배열을 안전하게 조회할 수 있음.

---

## 4. 대화형 아키텍처 시뮬레이터

아래 시뮬레이터를 통해 순차적 후크 체인 파이프라인, 모듈별 판정, 복합 보안 블롭 메모리 레이아웃 및 부팅 파라미터 적용 결과를 대화형으로 확인할 수 있음:

<iframe src="../../assets/diagrams/lsm-stacking/architecture.html" width="100%" height="780" frameborder="0" style="border-radius: 8px; border: 1px solid var(--md-default-fg-color--lightest); margin: 20px 0;"></iframe>

---

## 5. 공격 벡터 및 실습 랩 구조

### 5.1 타깃 드라이버 (`/proc/vuln_lsm`)

- **파일 위치**: `labs/26-lsm-stacking/vuln_lsm_stacking.c`
- **노출 노드**: `/proc/vuln_lsm` (권한 `0666`)
- **주요 제어 명령**:
  - `echo 'mode baseline' > /proc/vuln_lsm`: Mode 0 (단일 DAC/Capability 모드 전환, 고급 스택 LSM 우회)
  - `echo 'mode hardened' > /proc/vuln_lsm`: Mode 1 (스택형 다중 LSM 체인 활성화, Fail-Closed 강제 적용)
  - `echo 'test_access normal' > /proc/vuln_lsm`: 일반 접근 요청 평가
  - `echo 'test_access yama' > /proc/vuln_lsm`: 인가되지 않은 ptrace 접근 검사 (Yama 차단 대상)
  - `echo 'test_access landlock' > /proc/vuln_lsm`: 샌드박스 외부 경로 접근 검사 (Landlock 차단 대상)
  - `echo 'test_access lockdown' > /proc/vuln_lsm`: 커널 메모리 직접 수정 시도 검사 (Lockdown 차단 대상)
  - `echo 'run_bench' > /proc/vuln_lsm`: 인커널 자체 종합 벤치마크 및 검증 루틴 실행

---

### 5.2 유저랜드 PoC 익스플로잇 (`exploit_lsm_stacking`)

- **파일 위치**: `labs/26-lsm-stacking/exploit.c`
- **동작 단계**:
  1. `/sys/kernel/security/lsm` 및 시스템 콜 461(`__NR_lsm_list_modules`)을 통해 활성 LSM 스택 조회.
  2. Baseline 모드에서 정책 위반 요청(Yama, Landlock, Lockdown)들이 차단되지 않고 통과되는 보안 공백 확인.
  3. Hardened 모드로 전환 후 동일 요청들이 각각 해당 모듈에 의해 즉각 거부(`DENIED`)되며 체인이 단절됨을 확인.

---

### 5.3 인게스트 검증 스크립트 (`test_lsm_stacking`)

- **파일 위치**: `labs/26-lsm-stacking/test.sh` (루트fs 내 `/bin/test_lsm_stacking` 배치)
- **동작 내용**:
  1. `securityfs` 마운트 상태 확인 및 `/sys/kernel/security/lsm` 조회.
  2. `/proc/vuln_lsm` 드라이버 존재 확인.
  3. 비특권 유저 `lab` 권한으로 `/bin/exploit_lsm_stacking` 실행.
  4. 커널 `dmesg` 로그에서 LSM 후크 차단 이벤트 검증.

---

## 6. Kconfig 설정 비교

### 6.1 방어 활성화 (`configs/features/lsm-stacking.config`)
```ini
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_PATH=y
CONFIG_SECURITY_YAMA=y
CONFIG_SECURITY_LANDLOCK=y
CONFIG_SECURITY_LOADPIN=y
CONFIG_SECURITY_SAFESETID=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,bpf"
```

### 6.2 기본/비활성화 (`configs/features/lsm-stacking-disabled.config`)
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
./scripts/build_kernel.sh --arch arm64 --feature lsm-stacking

# x86_64 커널 빌드
./scripts/build_kernel.sh --arch x86_64 --feature lsm-stacking
```

### 7.3 QEMU 자동 검증 실행
```bash
# ARM64 검증
./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-lsm-stacking/arch/arm64/boot/Image --test test_lsm_stacking --timeout 30

# x86_64 검증
./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-lsm-stacking/arch/x86/boot/bzImage --test test_lsm_stacking --timeout 30
```
