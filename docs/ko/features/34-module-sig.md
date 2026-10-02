# Module Signature Verification 커널 모듈 전자서명 검증

## 1. 개요 및 위협 모델 (Overview & Threat Model)

**커널 모듈 전자서명 검증(Module Signature Verification)**은 리눅스 커널에 적재되는 동적 커널 모듈(`.ko`, LKM)의 **암호학적 무결성과 출처 진위성(Authenticity)을 커널 신뢰 키링(Trusted Keyring) 기반으로 검증하는 핵심 보호 기술**임.

리눅스 커널 모듈은 링-0(Ring 0) 최고 권한에서 실행되므로, 단 하나의 악성 모듈만 적재되어도 시스템 보안 체계 전체(LSM, Seccomp, 페이지 테이블 분리 등)가 일순간에 무력화됨:

1. **LKM 루트킷(Rootkit) 주입 위협**:
   - 공격자가 유저 공간에서 root 권한을 탈취하거나 공급망 공격(Supply Chain Attack)을 통해 `/lib/modules/` 디렉터리에 악의적인 LKM 바이너리를 드롭하고 `insmod` / `modprobe`로 적재하는 공격 벡터.
   - 프로세스 은닉, 시스템 콜 테이블 후킹, 네트워크 패킷 스니핑, 감사 로그 조작을 수행하는 커널 레벨 악성코드 유포 위협 존재.
2. **변조된 드라이버(Tampered Driver) 공격**:
   - 정상 서명된 하드웨어 드라이버 바이너리의 내부 바이트 일부를 패치하여 악성 페이로드를 삽입하고 재적재하는 공격 벡터.
3. **서명 강제(CONFIG_MODULE_SIG_FORCE)를 통한 무결성 확립**:
   - 커널 내부 신뢰 키링(`.builtin_trusted_keys`)에 등록된 X.509 인증서의 공개키로 검증되지 않은 모듈 적재 시도를 즉시 거부(`-ENOKEY`, `-EKEYREJECTED`)하여 링-0 침투를 원천 차단함.

---

## 2. 방어 아키텍처 및 메커니즘 (Architecture & Mechanism)

### 1. 모듈 전자서명 인터랙티브 아키텍처 시뮬레이터

<div class="archify-container" style="margin: 20px 0; border: 1px solid var(--border-color, #334155); border-radius: 8px; overflow: hidden;">
  <iframe
    src="../../assets/diagrams/module-sig/architecture.html"
    width="100%"
    height="500px"
    style="border: none; display: block;"
    loading="lazy"
  ></iframe>
</div>

---

### 2. 실생활 비유: 공항 보안 구역의 '위조 방지 홀로그램 출입 비표'

커널 모듈 전자서명 검증의 동작 메커니즘은 **국제공항 활주로 및 관제탑의 최상위 보안 비표 검사**와 동일함:

```
[ 비강제 모드 (Permissive: sig_enforce=0) ]
  침입자:   "신분증에 정부 인장이 없지만(미서명 루트킷), 일단 관제탑(Ring 0)으로 들어가겠다!"
  경비원:   "인증되지 않은 방문자 경고 도장(TAINT_UNSIGNED_MODULE)만 찍어두고 출입 허용." (심각한 보안 사고 유발)

[ 강제 모드 (Enforce: CONFIG_MODULE_SIG_FORCE=y / sig_enforce=1) ]
  침입자:   "미서명 모듈이나 임의 서명 모듈로 관제탑 출입 시도!"
  검문소:   "국가 보안 인증 키링(.builtin_trusted_keys) 대조 검사 실시!"
  판정 1:   "서명 블록 누락 확인 -> -ENOKEY 거부! 모듈 즉각 파기!"
  판정 2:   "서명은 있으나 바이너리 해시 불일치 -> -EKEYREJECTED 거부! 모듈 즉각 파기!"
  결과:     "인가된 국가 공인 비표(공식 빌드 서명) 소지자만 Ring 0 진입 허용."
```

---

### 3. 모듈 서명 포맷 및 커널 검증 흐름 (Module Format & Validation Flow)

모듈 빌드 시 커널 빌드 시스템은 모듈 ELF 바이너리의 끝부분에 암호학적 서명 트레일러(Trailer)를 부착함:

```
+-------------------------------------------------------+
|                ELF Module Binary Body                 |
|             (.text, .data, .rodata, etc.)             |
+-------------------------------------------------------+
|            PKCS#7 / CMS Cryptographic Signature       |
|          (Signed SHA-256 Digest via X.509 Key)        |
+-------------------------------------------------------+
|  struct module_signature {                            |
|      u8 algo;    /* Hash algo: SHA-256 */             |
|      u8 hash;    /* Public key algo: RSA/ECDSA */     |
|      u8 id_type; /* PKEY_ID_PKCS7 */                  |
|      __be32 sig_len; /* Length of PKCS#7 block */     |
|  }                                                    |
+-------------------------------------------------------+
|  Magic String: "~Module signature append~" (28 bytes) |
+-------------------------------------------------------+
```

1. **매직 스트링 검사 (`module_sig_check`)**:
   - `init_module()` 또는 `finit_module()` 호출 시 커널은 파일의 마지막 28바이트가 `~Module signature append~`와 일치하는지 확인함.
2. **서명 분리 및 ELF 복원**:
   - 매직 스트링과 `struct module_signature` 및 PKCS#7 데이터를 분리하여 순수 ELF 본문과 서명 블록으로 분리함.
3. **키링 대조 및 해시 검증 (`verify_pkcs7_signature`)**:
   - 커널 내부 신뢰 키링(`.builtin_trusted_keys` 또는 세컨더리 키링)에 등록된 X.509 공개키를 조회함.
   - ELF 본문의 SHA-256 다이제스트를 계산하여 PKCS#7 서명과 일치하는지 암호학적으로 검증함.
4. **결과 처리**:
   - 정상 서명: 모듈을 커널 메모리에 매핑하고 초기화 함수(`init()`) 실행.
   - 미서명/변조(`sig_enforce=1`): 모듈 메모리를 즉시 해제하고 `-ENOKEY` 또는 `-EKEYREJECTED` 반환.

---

## 3. Kconfig 설정 및 부팅 파라미터 (Configuration)

### 1. Kconfig 프래그먼트

```ini
# configs/features/module-sig.config
CONFIG_MODULES=y
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_FORCE=y
CONFIG_MODULE_SIG_ALL=y
CONFIG_MODULE_SIG_SHA256=y
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_KEYS=y
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS7_MESSAGE_PARSER=y
```

### 2. 런타임 제어 인터페이스 및 부팅 파라미터

| 파라미터 / 인터페이스 | 기본값 | 설명 |
| :--- | :--- | :--- |
| `module.sig_enforce=1` | 커널 cmdline | 부팅 시 미서명 모듈 적재 차단을 강제 활성화 (`CONFIG_MODULE_SIG_FORCE=y`와 동일) |
| `/sys/module/module/parameters/sig_enforce` | `Y` 또는 `N` | 현재 커널 모듈 서명 강제 상태 조회 노드 |
| `/proc/keys` | R-only | 커널 신뢰 키링(`.builtin_trusted_keys`)에 적재된 X.509 인증서 조회 |
| `/proc/sys/kernel/tainted` | 정수 플래그 | 미서명 모듈 적재 시 `TAINT_UNSIGNED_MODULE` (비트 13, 8192) 활성화 |

---

## 4. 실습 및 검증 (Hands-on Verification & Exploit PoC)

### 1. 테스트 시나리오 개요

- 비특권 계정(`lab`, UID 1000) 및 루트 계정으로 각 모듈 적재 시나리오를 검증:
  - **Phase 1: Baseline (Permissive Mode - sig_enforce=0)**:
    - 정상 서명 모듈: 정상 적재 (`ret = 0`).
    - 미서명 모듈: 적재 허용되나 커널 오염 플래그(`TAINT_UNSIGNED_MODULE`) 기록.
    - 변조된 모듈: 적재 허용되나 경고 메시지 출력.
  - **Phase 2: Hardened (Enforced Mode - CONFIG_MODULE_SIG_FORCE=y)**:
    - 정상 서명 모듈: 정상 적재 허용 (`ret = 0`).
    - 미서명 모듈: 커널이 즉시 거부 및 차단 (`-ENOKEY`).
    - 변조된 모듈: 암호학적 해시 불일치로 즉시 거부 및 차단 (`-EKEYREJECTED`).

### 2. 듀얼 아키텍처 실측 실행 로그

=== "ARM64: Module Signature Verification 검증 로그"
    ```bash
    ./scripts/run_qemu.sh --arch arm64 --kernel build_dir/arm64-modsig/arch/arm64/boot/Image --test test_module_sig
    ```
    ```
    ================================================================
       Lab 34: Module Signature Verification Suite                  
       Kernel: 6.12.109 on aarch64                           
    ================================================================
    [*] Step 1: Inspecting kernel module signature status...
        Module sig_enforce status: Y
    [*] Step 2: Inspecting kernel trusted keyrings (/proc/keys)...
        00000002 I--Q---     1 perm 1f3f0000     0     0 keyring   .builtin_trusted_keys: 1
        071d2ea4 I--Q---     1 perm 1f010000     0     0 asymmetric Kernel Build Signing Key: X.509
    [*] Step 3: Checking target driver at /proc/vuln_module_sig...
    [+] Target driver detected.

    [*] Step 5: Running unprivileged Module Sig PoC as user 'lab'...
    ================================================================
      Module Signature Verification (CONFIG_MODULE_SIG_FORCE) PoC  
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] Initial Target Driver Status:
    ========================================================
       Kernel Module Signature Verification Status Report   
    ========================================================
    Signature Enforcement   : ENFORCED (Strict: -ENOKEY / -EKEYREJECTED) (sig_enforce=1)
    Trusted Keyring Support : CONFIG_SYSTEM_TRUSTED_KEYRING=y
    Signature Hash Algorithm: SHA-256 (PKCS#7 / CMS format)
    Total Load Requests     : 0
    Modules Loaded (Granted): 0
    Modules Denied          : 0
      - Unsigned Denials    : 0 (-ENOKEY)
      - Tampered Denials    : 0 (-EKEYREJECTED)
    ========================================================

    [*] PHASE 1: Evaluating Baseline (Mode: Permissive - sig_enforce=0)
        -> Loading validly signed module (PKCS#7 X.509)... (GRANTED)
        -> Loading unsigned module (rootkit / untrusted .ko)... (GRANTED)
        -> Loading tampered module (corrupted cryptographic signature)... (GRANTED)

    [*] PHASE 2: Evaluating Hardened (Mode: Enforce - CONFIG_MODULE_SIG_FORCE=y)
        -> Loading validly signed module (expecting GRANTED: ret = 0)... (GRANTED)
        -> Loading unsigned module (expecting BLOCKED: -ENOKEY)... (BLOCKED: -ENOKEY)
        -> Loading tampered module (expecting BLOCKED: -EKEYREJECTED)... (BLOCKED: -EKEYREJECTED)

    [+] Module Signature Verification Complete: Unsigned Rootkits Prevented!

    [*] Step 6: Inspecting kernel dmesg for Module Signature events:
    [    5.120401] module_sig: [VERIFIED] Valid PKCS#7 signature verified against .builtin_trusted_keys (ret = 0)
    [    5.120580] module_sig: [REJECTED] Loading of unsigned module is rejected: -ENOKEY
    [    5.120610] PKCS#7 signature missing or not found in kernel trusted keyring
    [    5.121890] module_sig: [REJECTED] Module signature verification failed: -EKEYREJECTED (hash mismatch / key invalid)
    [    5.121920] PKCS#7 signature digest does not match module payload
    ================================================================
       Lab 34 Test Complete: Verified Module Signature Verification 
    ================================================================
    ```

=== "x86_64: Module Signature Verification 검증 로그"
    ```bash
    ./scripts/run_qemu.sh --arch x86_64 --kernel build_dir/x86_64-modsig/arch/x86/boot/bzImage --test test_module_sig
    ```
    ```
    ================================================================
       Lab 34: Module Signature Verification Suite                  
       Kernel: 6.12.109 on x86_64                           
    ================================================================
    [*] Step 1: Inspecting kernel module signature status...
        Module sig_enforce status: Y
    [*] Step 2: Inspecting kernel trusted keyrings (/proc/keys)...
        00000002 I--Q---     1 perm 1f3f0000     0     0 keyring   .builtin_trusted_keys: 1
        182b8ea0 I--Q---     1 perm 1f010000     0     0 asymmetric Kernel Build Signing Key: X.509
    [*] Step 3: Checking target driver at /proc/vuln_module_sig...
    [+] Target driver detected.

    [*] Step 5: Running unprivileged Module Sig PoC as user 'lab'...
    ================================================================
      Module Signature Verification (CONFIG_MODULE_SIG_FORCE) PoC  
      UID: 1000, GID: 1000                                          
    ================================================================
    [*] PHASE 1: Evaluating Baseline (Mode: Permissive - sig_enforce=0)
        -> Loading validly signed module (PKCS#7 X.509)... (GRANTED)
        -> Loading unsigned module (rootkit / untrusted .ko)... (GRANTED)
        -> Loading tampered module (corrupted cryptographic signature)... (GRANTED)

    [*] PHASE 2: Evaluating Hardened (Mode: Enforce - CONFIG_MODULE_SIG_FORCE=y)
        -> Loading validly signed module (expecting GRANTED: ret = 0)... (GRANTED)
        -> Loading unsigned module (expecting BLOCKED: -ENOKEY)... (BLOCKED: -ENOKEY)
        -> Loading tampered module (expecting BLOCKED: -EKEYREJECTED)... (BLOCKED: -EKEYREJECTED)

    [+] Module Signature Verification Complete: Unsigned Rootkits Prevented!

    [*] Step 6: Inspecting kernel dmesg for Module Signature events:
    [    9.340112] module_sig: [VERIFIED] Valid PKCS#7 signature verified against .builtin_trusted_keys (ret = 0)
    [    9.340280] module_sig: [REJECTED] Loading of unsigned module is rejected: -ENOKEY
    [    9.340310] PKCS#7 signature missing or not found in kernel trusted keyring
    [    9.341490] module_sig: [REJECTED] Module signature verification failed: -EKEYREJECTED (hash mismatch / key invalid)
    [    9.341520] PKCS#7 signature digest does not match module payload
    ================================================================
       Lab 34 Test Complete: Verified Module Signature Verification 
    ================================================================
    ```

---

## 5. 성능 및 호환성 분석 (Performance & Compatibility)

1. **런타임 오버헤드 (One-time Verification Cost)**:
   - 모듈 서명 검증은 부팅 시점 또는 드라이버 로드 시점(`modprobe`)에 단 한 번만 수행됨.
   - 드라이버 실행 루틴에는 추가 오버헤드가 전혀 발생하지 않음 (0% Runtime Overhead).
2. **서드파티 및 DKMS 드라이버 호환성 이슈**:
   - NVIDIA 그래픽 드라이버, ZFS 파일시스템, VirtualBox 게스트 확장 등 외부 서드파티 모듈을 DKMS로 자체 빌드하는 경우, 서명 강제 상태에서는 적재가 차단됨.
   - 프로덕션 배포 시 MOK(Machine Owner Key)를 등록하거나 기업 자체 내부 인증 기관(Internal CA) 키를 커널 신뢰 키링에 사전에 주입해야 함.
3. **개인키(Private Key) 보호 수칙**:
   - 모듈 서명에 사용되는 RSA/ECDSA 개인키(`certs/signing_key.pem`)가 유출될 경우 공격자가 임의의 악성 모듈을 서명할 수 있으므로, CI/CD 파이프라인에서 빌드 완료 후 개인키를 즉시 파기하거나 하드웨어 보안 모듈(HSM)을 통해 서명해야 함.

---

## 6. 강의 및 발표 스크립트 (Lecture & Presentation Script - English Practice)

### Standard 4-Step Technical English Presentation

#### 1. Opening Hook & Problem Statement
> "Good morning, everyone. In modern Linux infrastructure, loadable kernel modules represent both incredible architectural flexibility and an existential security threat. Because kernel modules execute in Ring 0 with unrestricted system privileges, an attacker who obtains root access or local write permissions could inject an unsigned LKM rootkit. This rootkit can hook system calls, hide processes, and disable security subsystems without leaving traces. Today, we delve into **Kernel Module Signature Verification**."

#### 2. Diagram & Architecture Walkthrough
> "Please examine our interactive architecture simulator on the screen. Look at the structure of a signed kernel module: it contains the compiled ELF binary, followed by a PKCS#7 cryptographic signature, a module signature metadata header, and the magic trailer `~Module signature append~`. When `init_module()` or `finit_module()` is invoked, the kernel extracts the signature and recalculates the SHA-256 digest over the ELF sections. This digest is cryptographically compared against the trusted X.509 certificates stored in `.builtin_trusted_keys`. When `CONFIG_MODULE_SIG_FORCE=y` is enforced, any unsigned or tampered module is rejected before a single instruction can execute in kernel space."

#### 3. Live Demo Commentary
> "In our live verification on ARM64 and x86_64, look at the difference between Permissive and Enforced modes. In Permissive mode, unsigned modules are allowed to load, but the kernel sets the `TAINT_UNSIGNED_MODULE` flag. However, when we switch to Enforced mode, the unsigned rootkit attempt is instantaneously terminated with `-ENOKEY`, and our tampered module test fails with `-EKEYREJECTED`. The kernel log explicitly notes that the cryptographic signature failed to validate against the trusted keyring. The unauthorized Ring 0 execution attempt is completely thwarted."

#### 4. Key Takeaways & Production Advice
> "To summarize: Enabling `CONFIG_MODULE_SIG_FORCE=y` ensures that only authorized, cryptographically signed drivers can enter the kernel perimeter. In mission-critical enterprise environments, combining module signature enforcement with UEFI Secure Boot and lockdown policies establishes a complete, unbreakable chain of trust from firmware up to running kernel drivers."
