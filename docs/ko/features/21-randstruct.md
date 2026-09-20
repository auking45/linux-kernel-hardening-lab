# RANDSTRUCT: 커널 핵심 구조체 멤버 오프셋 랜덤화

## 1. 개요 및 배경

C 언어로 작성된 전통적인 운영체제 커널에서 구조체(Structure)의 멤버 변수들은 소스코드에 선언된 순서대로 메모리에 순차 배치됨. 이러한 결정론적(Deterministic) 메모리 레이아웃은 컴파일러와 하드웨어의 접근 효율성을 높이지만, 커널 보안 측면에서 매우 취약한 공격 표면을 제공함.

공격자는 다음과 같은 고정 오프셋(Fixed Offset) 기법을 악용하여 커널을 공격함:
1. **권한 상승(Privilege Escalation)을 위한 고정 오프셋 덮어쓰기**:
   - 프로세스의 보안 자격 증명을 담고 있는 `struct cred`는 모든 프로세스의 `task_struct->cred`에 연결되어 있음.
   - 표준 빌드에서 `struct cred`의 `uid`, `gid`, `euid` 필드는 시작 오프셋으로부터 고정된 위치(예: Offset 8, 12, 24)에 존재함.
   - 임의 메모리 쓰기(Arbitrary Write) 취약점을 확보한 공격자는 타깃 오프셋에 0(`0x00000000`)을 기록하는 것만으로 손쉽게 root 권한을 탈취함.
2. **함수 포인터 하이재킹(Function Pointer Hijacking)**:
   - `struct file_operations`나 네트워크 소켓, 드라이버 디스패치 테이블 등 함수 포인터로만 구성된 구조체에서 특정 오프셋(예: `write`, `ioctl`)의 함수 포인터를 공격자의 ROP 가젯이나 쉘코드로 덮어써 제어 흐름을 장악함.

이러한 고정 오프셋 공격은 KASLR(커널 주소 공간 배치 난수화)이 활성화되어 있더라도 무력화되지 않음. KASLR은 구조체 자체의 기저 주소(Base Address)를 무작위화하지만, **구조체 내부 멤버 간의 상대적 거리(Relative Offset)는 변하지 않기 때문**임.

리눅스 커널은 과거 PaX/Grsecurity의 **`CONFIG_GCC_PLUGIN_RANDSTRUCT`**를 도입하였으며, 현대 커널(6.x LTS) 및 최신 Clang 컴파일러(Clang 16+)에서는 네이티브 플래그 **`-frandomize-layout-seed-file` (`CONFIG_RANDSTRUCT_FULL=y`)**를 표준으로 지원하여, 컴파일 시점마다 256비트 난수 시드를 기반으로 구조체 멤버 배치를 무작위 재배열함.

---

## 2. 실세계 비유: 은행 대여금고 번호판 무작위 셔플링

`CONFIG_RANDSTRUCT`의 동작 원리는 **은행 비밀 대여금고실의 번호판 재배치**에 비유할 수 있음:

```
[ 취약한 방식 (Baseline: CONFIG_RANDSTRUCT_NONE) ]
  설계도에 적힌 고정 순서대로 금고 배치
  ┌────────────────────────────────────────────────────────┐
  │ [1번: 기본서류] │ [2번: 지점장 인증키] │ [3번: 금괴/현금]│
  └────────────────────────────────────────────────────────┘
                           ▲
             공격자: "설계도대로 3번 금고만 드릴로 뚫는다!" ──► 성공!

[ 하드닝 방식 (Hardened: CONFIG_RANDSTRUCT) ]
  금고실 개장 시마다 관리자가 내부 배치 번호를 무작위로 셔플
  ┌────────────────────────────────────────────────────────┐
  │ [3번: 폐휴지함] │ [1번: 비상벨 스위치] │ [2번: 지점장 키]│
  └────────────────────────────────────────────────────────┘
                           ▲
             공격자: "설계도대로 3번 위치를 뚫는다!" ──► 비상벨 작동 & 체포!
```

1. **전통적 커널 (고정 번호 금고실)**:
   - 공개된 건물 청사진(커널 소스코드 및 심볼)에 금괴가 항상 입구로부터 3번째 칸(Offset 16)에 있다고 적혀 있음.
   - 공격자는 불을 끄고 어둠 속(KASLR 환경)에서도 입구로부터 정확히 3번째 칸만 더듬어 뚫으면 100% 금괴(root 권한)를 탈취할 수 있음.
2. **RANDSTRUCT 활성화 커널 (무작위 셔플 금고실)**:
   - 건물을 지을 때마다(커널 빌드 시마다) 암호학적 주사위를 굴려 금고 칸의 순서를 뒤섞음.
   - 공격자가 기존 청사진을 믿고 3번째 칸을 뚫으면, 그곳에는 금괴 대신 폐휴지(비밀 토큰)나 비상벨 스위치(커널 패닉 트랩)가 놓여 있어 공격이 완전히 실패하고 침입 사실이 즉각 발각됨.

---

## 3. 핵심 아키텍처 및 동작 원리

### 3.1 무작위화 대상 구조체 (Target Selection)

리눅스 커널에서 `CONFIG_RANDSTRUCT`가 활성화되면 다음 두 가지 범주의 구조체가 자동으로 무작위화 대상에 포함됨 (`security/Kconfig.hardening`):

1. **`__randomize_layout` 명시적 선언 구조체**:
   - 커널 보안 및 권한 관리에 직결된 핵심 구조체:
     - `struct cred` (`include/linux/cred.h`): `uid`, `gid`, `suid`, `sgid`, `euid`, `egid`, `cap_effective` 등.
     - `struct file` (`include/linux/fs.h`): 파일 디스크립터 포인터 및 권한.
     - `struct inode` (`include/linux/fs.h`): 파일시스템 아이노드 메타데이터.
     - `struct task_struct` 내의 다수 서브 구조체.
2. **함수 포인터 전용 구조체 (Pure Function Pointer Structs)**:
   - 구조체 내부의 모든 멤버가 함수 포인터로만 구성된 경우 (예: `struct file_operations`, `struct inode_operations`, `struct proto_ops` 등).
   - 수동으로 `__no_randomize_layout` 어노테이션이 붙지 않은 한 자동으로 멤버 순서가 뒤섞임.

### 3.2 컴파일 시점 256비트 난수 시드 생성 메커니즘

커널 빌드 과정(`scripts/basic/Makefile`)에서 `scripts/gen-randstruct-seed.sh` 스크립트가 실행됨:
```bash
# scripts/gen-randstruct-seed.sh
SEED=$(od -A n -t x8 -N 32 /dev/urandom | tr -d ' \n')
echo "$SEED" > "$1"
HASH=$(echo -n "$SEED" | sha256sum | cut -d" " -f1)
echo "#define RANDSTRUCT_HASHED_SEED \"$HASH\"" > "$2"
```
1. `/dev/urandom`으로부터 32바이트(256비트)의 고엔트로피 암호학적 난수를 추출하여 `scripts/basic/randstruct.seed` 파일에 저장함.
2. 컴파일러에 해당 시드 파일을 전달함:
   - **Clang (LLVM=1)**: `-frandomize-layout-seed-file=$(objtree)/scripts/basic/randstruct.seed`
   - **GCC Plugin**: `-fplugin=randomize_layout_plugin.so`
3. 컴파일러는 각 구조체 타입의 고유 해시와 시드를 결합하여 의사 난수 생성기(PRNG)를 초기화하고, 멤버 선언 목록을 Fisher-Yates 알고리즘으로 무작위 셔플함.
4. 빌드 결과물마다 완전히 다른 오프셋이 생성되므로, 빌드 트리를 공유하지 않는 외부 공격자는 오프셋을 역산할 수 없음.

### 3.3 GCC 플러그인 vs Clang 16+ 네이티브 구현 비교

| 항목 | GCC 플러그인 (`GCC_PLUGIN_RANDSTRUCT`) | Clang 네이티브 (`CC_HAS_RANDSTRUCT`) |
| :--- | :--- | :--- |
| **구현 방식** | 호스트 GCC C++ 플러그인 모듈 (`.so`) | 컴파일러 프론트엔드 네이티브 옵션 |
| **비트필드 처리** | 비트필드를 개별 변수로 분리 (패딩 증가) | 인접 비트필드를 묶고 비트 순서만 셔플 (패딩 최소화) |
| **성능 최적화 모드** | `RANDSTRUCT_PERFORMANCE` 지원 (캐시라인 경계 제한) | `RANDSTRUCT_FULL` 완전 랜덤화 기본 적용 |
| **호스트 의존성** | 호스트의 타깃별 `gcc-plugin-dev` 패키지 필수 | Clang 16+ 바이너리 자체로 크로스 빌드 완결 |

---

## 4. 인터랙티브 아키텍처 다이어그램

공격자의 고정 오프셋 임의 쓰기 시도와 RANDSTRUCT 활성화 시 멤버 재배치로 인한 방어 메커니즘을 시뮬레이션한 대화형 다이어그램임:

<iframe src="../../assets/diagrams/randstruct/architecture.html" width="100%" height="680" frameborder="0" style="border-radius: 8px; border: 1px solid #3a506b; margin: 16px 0;"></iframe>

---

## 5. 실습 및 공격/방어 시연

### 5.1 취약점 실습 드라이버 (`vuln_randstruct.c`)

`/proc/vuln_randstruct` (모드 0666) 인터페이스를 통해 다음 기능을 제공함:
- **오프셋 덤프 (`cat /proc/vuln_randstruct`)**:
  - `struct victim_struct`의 멤버별 오프셋 출력.
  - 실제 커널 핵심 구조체 `struct cred`의 `uid`, `gid`, `euid` 오프셋 출력.
- **고정 오프셋 임의 쓰기 시뮬레이션 (`echo exploit_fixed_uid > /proc/vuln_randstruct`)**:
  - 공격자가 표준 베이스라인 오프셋 16을 타깃으로 `0x00000000` 쓰기 시도.
  - 베이스라인에서는 `uid`가 정확히 0으로 변조되어 권한 상승 발생.
  - 하드닝 커널에서는 `uid`가 오프셋 36 등으로 이동하여, 오프셋 16 쓰기는 무관한 필드에 떨어지고 `uid`는 1000으로 안전하게 유지됨.
- **함수 포인터 하이재킹 시뮬레이션 (`echo exploit_fixed_callback > /proc/vuln_randstruct`)**:
  - 베이스라인 오프셋 40에 악성 함수 포인터 주입 시도.
  - 하드닝 커널에서는 포인터 하이재킹 차단 확인.

### 5.2 비특권 사용자 익스플로잇 PoC (`exploit.c`)

비특권 계정 `lab` (UID 1000)에서 실행되어 공격 성공/차단 여부를 정밀 판정함:
```bash
/bin/exploit_randstruct
```
- **베이스라인 (Vulnerable)**:
  - 고정 오프셋 16 쓰기 후 `g_victim.uid = 0` (root 권한 탈취 성공).
  - 고정 오프셋 40 쓰기 후 콜백 하이재킹 성공.
  - 종료 코드: `42` (취약점 확인).
- **하드닝 (Protected)**:
  - 고정 오프셋 16 쓰기 후 `g_victim.uid = 1000` (권한 상승 실패).
  - 오프셋 40 쓰기 후 콜백 변조 차단.
  - 종료 코드: `0` (보안 무결성 통과).

---

## 6. 듀얼 아키텍처 검증 매트릭스

| 아키텍처 | 커널 설정 | victim->uid 오프셋 | cred->uid 오프셋 | 고정 오프셋 공격 결과 | 판정 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ARM64** | `CONFIG_RANDSTRUCT_FULL=y` | 🛡️ **무작위 재배치 (≠16)** | 🛡️ **무작위 재배치 (≠8)** | 🛡️ **공격 실패 (UID=1000 유지)** | ✅ **PASS** |
| **ARM64** | `CONFIG_RANDSTRUCT_NONE=y` | ❌ **16 (고정 오프셋)** | ❌ **8 (고정 오프셋)** | ❌ **공격 성공 (UID=0 탈취)** | ⚠️ **FAIL** |
| **x86_64** | `CONFIG_RANDSTRUCT_FULL=y` | 🛡️ **무작위 재배치 (≠16)** | 🛡️ **무작위 재배치 (≠8)** | 🛡️ **공격 실패 (UID=1000 유지)** | ✅ **PASS** |
| **x86_64** | `CONFIG_RANDSTRUCT_NONE=y` | ❌ **16 (고정 오프셋)** | ❌ **8 (고정 오프셋)** | ❌ **공격 성공 (UID=0 탈취)** | ⚠️ **FAIL** |

---

## 7. 프로덕션 보안 가이드라인 및 트레이드오프

1. **성능 오버헤드**:
   - 구조체 멤버가 무작위로 배치됨에 따라 캐시라인 적중률(Cache Locality)이 다소 저하되어 약 **0.5% ~ 1.5% 수준의 미세한 CPU 오버헤드**가 발생할 수 있음.
   - 캐시 민감도가 매우 높은 시스템에서는 `CONFIG_RANDSTRUCT_PERFORMANCE`를 고려할 수 있으나, 현대 서버/모바일 환경에서는 `CONFIG_RANDSTRUCT_FULL` 적용이 권장됨.
2. **외부 커널 모듈과의 바이너리 호환성**:
   - 구조체 오프셋이 커널 빌드 시마다 변경되므로, 사외 OOT(Out-of-Tree) 커널 모듈을 빌드할 때 반드시 해당 커널의 `randstruct.seed` 파일이 보존되어 있어야 함 (`make mrproper` 시 삭제됨).
3. **포렌식 도구의 제약**:
   - Volatility 등 메모리 덤프 포렌식 도구가 표준 커널 프로파일로 분석할 수 없게 되므로, 사내 포렌식을 위해서는 해당 빌드의 `vmlinux` 디버그 심볼을 아카이빙해야 함.

