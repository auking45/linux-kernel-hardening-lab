# CONFIG_RANDOMIZE_BASE: KASLR 및 nokaslr 부팅 파라미터 비교 실습

<div style="margin: 1.5rem 0; border: 1px solid var(--md-default-fg-color--lightest); border-radius: 8px; overflow: hidden;">
  <iframe src="../../assets/diagrams/kaslr/architecture.html" style="width: 100%; height: 600px; border: none; display: block;" title="KASLR Architecture Diagram"></iframe>
</div>

---

## 1. 개요 및 위협 모델 (Overview & Threat Model)

### 1.1 해결하고자 하는 위협: 결정론적 커널 메모리 배치와 정적 ROP 가젯 공격

- **정적 주소 공간의 취약성**:
  - KASLR이 적용되지 않은 커널(`nokaslr` 또는 `CONFIG_RANDOMIZE_BASE=n`)은 커널 코드의 시작 주소(`_text`)가 빌드 타임에 결정된 고정 가상 주소(x86_64: `0xffffffff81000000`, ARM64: 고정 base)에 항상 정적으로 매핑됨.
  - 공격자는 사전에 빌드된 `vmlinux` 바이너리나 배포판의 심볼 테이블(`System.map`)만 오프라인으로 분석하면, 임의의 제어 흐름 가로채기(ROP)에 필요한 모든 명령어 조각(Gadget)과 핵심 특권 함수(`commit_creds`, `init_cred`)의 절대 주소를 확정할 수 있음.
  - 이로 인해 단 한 번의 스택 버퍼 오버플로우나 함수 포인터 변조 취약점만으로도 100% 성공하는 원클릭 권한 상승 익스플로잇이 가능해짐.
- **KASLR(Kernel Address Space Layout Randomization)의 방어 철학**:
  - 부팅 초기(Early Boot / Decompressor) 시점에 하드웨어 난수 기반으로 임의의 **KASLR Slide(오프셋)**를 추출하여 커널 코드 및 정적 데이터 배치를 가상 메모리 공간 내 수백~수천 개의 슬롯 중 하나로 무작위화함.
  - 공격자가 커널 내부 메모리 주소를 사전에 훔쳐보는 정보 유출(Infoleak) 취약점을 동반하지 않는 한, 기존의 하드코딩된 주소로 분기하면 매핑되지 않은 메모리 영역(Unmapped Hole)에 접근하여 즉각적인 Page Fault 패닉을 유발하고 공격을 원천 무력화함.

### 1.2 직관적 실전 비유: 이사 다니는 비밀 요새 (The Moving Safehouse Metaphor)

- **비유 설명**:
  - 커널 텍스트와 핵심 함수들은 국가의 전략 사령부인 **비밀 요새**에 해당함.
  - **하드닝 이전 (Base Kernel / `nokaslr`)**: 비밀 요새의 위치(지도상의 좌표)가 항상 동일한 장소(`0xffffffff81000000`)에 고정되어 있음. 적군(공격자)은 정찰할 필요도 없이 사전에 기록된 좌표로 장거리 대포(정적 ROP 페이로드)를 발사하여 요새를 단번에 파괴함.
  - **KASLR 하드닝 적용**: 요새는 매일 밤(부팅할 때마다) 수백 개의 위장 후보지 중 임의의 좌표(`Slide`)로 위치를 조용히 이동함. 적군이 어제의 좌표로 대포를 쏘면 포탄은 허공(Unmapped Page)에 떨어지고 공격은 실패함. 적군이 요새를 타격하려면 반드시 내부 첩자(메모리 정보 유출 취약점)를 매수하여 오늘의 새로운 좌표를 먼저 알아내야만 함.

---

## 2. 커널 내부 구현 원리 (Kernel Internal Architecture)

### 2.1 초기 압축 해제기(Early Decompressor) 단계의 슬라이드 결정

- **부팅 시점의 무작위 위치 선정**:
  - 커널이 실제로 압축을 해제하고 페이징을 활성화하기 직전, 초기 부트스트랩 코드(`arch/x86/boot/compressed/kaslr.c`, `arch/arm64/kernel/kaslr.c`)가 실행됨.
  - CPU 하드웨어 난수 명령어(`RDRAND`), 타임스탬프 카운터(`RDTSC`), 펌웨어 인터페이스(UEFI RNG 프로토콜), 또는 가상화 하이퍼바이저가 제공하는 엔트로피(`virtio-rng`)를 결합하여 시드(Seed)를 생성함.
- **슬롯 분할 및 정렬 (x86_64 vs ARM64)**:
  - **x86_64**: `__START_KERNEL_map` (`0xffffffff80000000`)부터 1GB 영역 내에서 2MB 단위(PMD 크기)로 정렬된 슬롯 중 하나를 무작위 선택함 (최대 512~1024개 슬롯, 약 9~10비트 엔트로피 제공).
  - **ARM64**: 모듈 영역 및 vmalloc 영역과의 충돌을 피하며 2MB(또는 64KB 페이지 구성에 따른 크기) 단위로 커널 가상 주소(`_text`)를 무작위화함.

### 2.2 부팅 커맨드라인 파라미터 제어 (`nokaslr`)

- 커널 초기 압축 해제 코드는 커맨드라인에서 `nokaslr` 문자열을 조기에 직접 탐색함:
  ```c
  /* arch/x86/boot/compressed/kaslr.c */
  if (cmdline_find_option_bool("nokaslr")) {
      warn("KASLR disabled: 'nokaslr' on cmdline.");
      return;
  }
  ```
- 커맨드라인에 `nokaslr`가 명시된 경우 난수 슬라이드 생성을 전면 건너뛰고 기본 컴파일 베이스(`STATIC_TEXT_BASE`)에 커널을 적재함. 디버깅(GDB 커널 분석, KGDB, 트레이싱) 시 심볼 주소 일관성을 위해 널리 활용됨.

---

## 3. 실습 환경 및 Exploit PoC (Hands-on Lab & Exploit PoC)

### 3.1 취약 타깃 드라이버 (`vuln_kaslr.c`)

- `/proc/vuln_kaslr` (mode 0666) 인터페이스 구현:
  - **텔레메트리 판독 (Read)**: 현재 커널 텍스트의 실제 위치(`_text`), 컴파일 시점의 정적 기준 주소, 실시간 KASLR 슬라이드 오프셋, 무작위화 활성화 상태를 보고함.
  - **임의 주소 함수 디스패치 시뮬레이션 (Write)**: 유저가 전달한 절대 주소를 타깃 함수(`kaslr_target_function`)와 비교하여, 하드코딩된 정적 주소 공격의 성공/실패 여부를 안전하게 검증함.

### 3.2 Dual-Arch QEMU 실측 결과 대조

```bash
# 1. Base 커널 (nokaslr 취약 환경) 실행
./scripts/run_lab.sh --arch x86_64 --feature kaslr-disabled --test test_kaslr

# 2. Hardened 커널 (KASLR 활성화 환경) 실행
./scripts/run_lab.sh --arch x86_64 --feature kaslr --test test_kaslr
```

=== "Base Kernel (Vulnerable: nokaslr 정적 공격 성공)"

    ```text
    =========================================================
      Linux Kernel Hardening Lab - KASLR Exploit PoC
      Architecture: x86_64
      Current User: UID = 1000 (non-root 'lab' user)
    =========================================================
    [*] Kernel Memory Layout Telemetry:
        Current Text Base:   0xffffffff81000000
        Static Default Base: 0xffffffff81000000
        Target Function:     0xffffffff8143f210
        KASLR Slide:         0x0000000000000000
        KASLR Status:        DISABLED (Deterministic)

    =========================================================
    [*] Stage 1: Blind Attack (Without Kernel Infoleak)
        Attempting call to precomputed static address: 0xffffffff8143f210
    =========================================================
    [!] VULNERABILITY CONFIRMED: KASLR IS DISABLED (nokaslr)
    [!] Static gadget address 0xffffffff8143f210 matched target perfectly!
    [!] Attackers can execute arbitrary ROP chains with 100% certainty.
    ```
    > **분석:** KASLR이 비활성화된 환경에서는 커널 텍스트 베이스가 항상 `0xffffffff81000000`으로 고정되며 슬라이드가 `0x0`임. 사전에 컴파일된 정적 함수 주소로 공격했을 때 즉시 표적에 적중함.

=== "Hardened Kernel (Mitigated: KASLR 슬라이드 방어 성공)"

    ```text
    =========================================================
      Linux Kernel Hardening Lab - KASLR Exploit PoC
      Architecture: x86_64
      Current User: UID = 1000 (non-root 'lab' user)
    =========================================================
    [*] Kernel Memory Layout Telemetry:
        Current Text Base:   0xffffffff9bc00000
        Static Default Base: 0xffffffff81000000
        Target Function:     0xffffffff9c03f210
        KASLR Slide:         0x000000001ac00000
        KASLR Status:        ENABLED

    =========================================================
    [*] Stage 1: Blind Attack (Without Kernel Infoleak)
        Attempting call to precomputed static address: 0xffffffff8143f210
    =========================================================
    [+] DEFENSE ACTIVE: KASLR RANDOMIZATION VERIFIED!
    [+] Blind static address missed the target by 0x1ac00000 bytes.
    [+] Execution hijacked to invalid/unmapped memory is foiled!

    =========================================================
    [*] Stage 2: Infoleak-Assisted Attack (Simulated Infoleak)
        Applying known KASLR slide 0x1ac00000 -> Adjusted Address: 0xffffffff9c03f210
    =========================================================
    [*] Infoleak-adjusted dispatch completed.
    [*] Key Takeaway: KASLR forces attackers to find an infoleak first,
        proving why Category 1 defenses (e.g. STACKLEAK) are vital!
    ```
    > **분석:** KASLR이 활성화된 커널은 부팅 시 `0x1ac00000` 바이트의 무작위 슬라이드를 적용함. 정보 유출 없는 블라인드 공격은 400MB 이상의 오차가 발생하여 차단되며, 오직 인포릭 취약점을 통해서만 주소 계산이 가능함을 증명함.

---

## 4. 운영 및 모니터링 인터페이스 (Runtime Administration)

### 4.1 `/proc/cmdline` 부팅 플래그

- 시스템 부팅 파라미터에서 `nokaslr` 존재 여부를 검사하여 KASLR 활성화 상태를 확인함:
  ```bash
  cat /proc/cmdline | grep -o "nokaslr" || echo "KASLR is ACTIVE"
  ```

### 4.2 `/proc/kallsyms` 및 `kptr_restrict` 연계

- KASLR의 효용성을 유지하기 위해 비특권 유저가 `/proc/kallsyms`나 `/sys/kernel/debug`를 통해 런타임 커널 주소를 읽지 못하도록 `kptr_restrict` sysctl을 반드시 연계 적용해야 함:
  ```bash
  # 비특권 유저 대상 커널 포인터 마스킹 (0으로 치환)
  sysctl -w kernel.kptr_restrict=1
  ```

---

## 5. 성능 및 오버헤드 분석 (Performance & Overhead)

- **CPU 런타임 연산 오버헤드: 0.0%**:
  - KASLR의 주소 무작위화는 부팅 시 페이지 테이블을 초기 구축할 때 단 한 번 적용됨.
  - 일단 부팅이 완료되면 MMU 하드웨어가 페이지 테이블을 통해 가상 주소를 물리 주소로 직결 변환하므로, 시스템 콜 및 커널 코드 실행 시 발생하는 런타임 오버헤드는 **완전한 0% (Zero Overhead)**임.
- **부팅 시간 오버헤드**:
  - 엔트로피 추출 및 페이지 테이블 오프셋 계산에 소요되는 시간은 수 밀리초(ms) 미만으로 측정되어 전체 부팅 시간에 영향이 없음.

---

## 6. 발표 대본 및 핵심 표현 (Presentation Script & Vocabulary)

### 6.1 프레젠테이션 발표 대본 (Korean & English)

```text
[1단계: Hook - 고정된 좌표의 치명적 위험]
"도둑이 우리 집 주소를 정확히 알고 있고 문 앞 비밀번호까지 이미 적어두었다면,
 집을 아무리 튼튼하게 지어도 언젠가 털릴 수밖에 없습니다.
 KASLR이 꺼진 커널이 그렇습니다. 커널 코드의 주소가 0xffffffff81000000으로 고정되어 있으면
 공격자는 단 한 번의 취약점으로 사전에 준비한 ROP 체인을 100% 성공시킵니다."

"If a burglar possesses your exact home address and pre-written lock combinations,
 no matter how fortified your door is, a single break-in guarantees complete disaster.
 This is precisely the vulnerability of an unrandomized kernel.
 With fixed addresses at 0xffffffff81000000, attackers execute pre-computed ROP chains with 100% certainty."

[2단계: Metaphor & Architecture - 이사 다니는 요새]
"KASLR은 이 집을 매일 밤 임의의 새 주소로 조용히 이사시키는 '비밀 요새'입니다.
 부팅할 때마다 하드웨어 난수를 뽑아 0x1ac00000 같은 고유한 KASLR Slide를 부여합니다.
 공격자가 어제의 고정 주소로 대포를 쏘면 허공에 빗맞아 공격이 즉시 실패합니다.
 결국 공격자는 집 주소를 알아내기 위해 '메모리 정보 유출'이라는 별도의 스파이를 고용해야만 합니다."

"KASLR transforms the kernel into a moving safehouse that quietly shifts coordinates upon every boot.
 Using hardware entropy, it generates a unique KASLR Slide—such as 0x1ac00000—offsetting all text and symbols.
 Any blind attack targeted at static addresses strikes unmapped space and collapses.
 This compels attackers to find a secondary infoleak vulnerability just to calculate the shift."

[3단계: Demo & Proof - 다중 방어 계층의 필연성]
"실제 QEMU 실측에서 보았듯이, nokaslr 커널은 정적 주소 공격에 완벽히 무너졌으나,
 KASLR 활성화 커널은 400MB 이상의 오차를 발생시키며 블라인드 공격을 완벽히 차단했습니다.
 그리고 이것이 바로 앞서 우리가 구현한 STACKLEAK이 왜 KASLR과 함께 반드시 존재해야 하는지,
 즉 다층 방어(Defense in Depth)의 진정한 이유를 명쾌하게 증명합니다."

"As verified live in our QEMU environment, the nokaslr kernel succumbed instantly to static payloads,
 whereas the KASLR-enabled kernel deflected blind attacks by a wide margin.
 This conclusively demonstrates why Category 1 defenses like STACKLEAK are indispensable:
 KASLR and stack poisoning work hand-in-glove to deliver true Defense-in-Depth."
```

### 6.2 핵심 프레젠테이션 영어 표현 (Key Presentation Phrases)

| 한국어 표현                            | 권장 영어 스피킹 표현                                   | 용례 및 발화 팁                              |
| :------------------------------------- | :------------------------------------------------------ | :------------------------------------------- |
| **"부팅 시 가상 주소 무작위화"**       | _"randomize the kernel image base at early boot"_       | KASLR의 핵심 정의 및 시점 설명 시            |
| **"정적 공격을 원천 무력화하다"**      | _"render hardcoded ROP gadgets utterly obsolete"_       | 공격자의 정적 무기 무력화 효과 강조 시       |
| **"무작위 오프셋 슬라이드"**           | _"apply a dynamic KASLR slide across the text segment"_ | 슬라이드 메커니즘을 기술적으로 설명할 때     |
| **"선행 정보 유출 취약점을 강제하다"** | _"compel adversaries to chain a prerequisite infoleak"_ | 공격 난이도 증가 및 다층 방어 필요성 설명 시 |
| **"런타임 오버헤드 전무"**             | _"imposes zero runtime performance penalty"_            | 성능 영향도(0%)를 확신 있게 강조할 때        |
