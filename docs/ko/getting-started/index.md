# 빠른 시작 가이드 (Quick Start Guide)

리눅스 커널 하드닝 랩 실습을 위한 호스트 패키지 의존성 설치, 커널 소스 코드 준비 및 QEMU 가상머신 환경 구성 절차 안내.

---

## 1. 사전 요구 패키지 설치

호스트 환경(Ubuntu 22.04 / 24.04 LTS 기준)에서 x86_64 및 arm64 교차 빌드 툴체인 및 QEMU 에뮬레이터 설치 수행:

```bash
sudo apt-get update && sudo apt-get install -y \
    build-essential \
    flex \
    bison \
    libncurses-dev \
    libssl-dev \
    libelf-dev \
    bc \
    qemu-system-x86 \
    qemu-system-arm \
    gcc-x86-64-linux-gnu \
    gcc-aarch64-linux-gnu \
    busybox-static \
    cpio \
    python3-venv \
    git
```

---

## 2. 문서 뷰어 로컬 실행

Python 가상환경 생성 및 MkDocs 의존성 패키지 설치:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
mkdocs serve
```

웹 브라우저로 `http://127.0.0.1:8000` 접속 후 상단 언어 선택기를 통해 한국어 및 영어 실시간 전환 확인 가능함.

---

## 3. 원클릭 커널 빌드 및 QEMU 가상머신 부팅

소스 다운로드부터 rootfs 생성, 커널 빌드 및 QEMU 부팅까지 단 한 번의 명령으로 자동 수행 지원:

```bash
# [방법 A] Makefile 활용 (권장)
make run            # x86_64 베이스 커널 원클릭 빌드 & 부팅
make run-arm64      # ARM64 베이스 커널 원클릭 빌드 & 부팅

# [방법 B] run_lab.sh 오케스트레이터 직접 실행
./scripts/run_lab.sh                                    # x86_64 실행
./scripts/run_lab.sh --arch arm64                       # ARM64 실행
./scripts/run_lab.sh --feature stack-protector          # 하드닝 피처 적용 빌드 & 실행
```
