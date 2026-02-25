# STM8S207RBT6 Firmware Flasher

STM8S207RBT6 마이크로컨트롤러용 펌웨어 업데이트 GUI 도구입니다.
PySide6 기반 GUI로 시리얼 통신을 통해 S19 파일을 STM8 부트로더로 플래싱합니다.
시리얼 통신을 이용하여 바로 bootloading가능합니다. (하드웨어 설정 필요 없음)

---

## 주요 기능

- COM 포트 자동 탐색 및 선택
- S19 (Motorola S-Record) 파일 로드 및 플래싱
- STM8 UART 부트로더 프로토콜 구현 (UM0560 기반)
- 부트로더 다운로드
- 실시간 진행 상태 및 로그 출력
- PyInstaller 단일 실행 파일 빌드 지원

---

## 요구사항

- Python 3.7+
- PySide6
- pyserial
- bincopy

```bash
pip install PySide6 pyserial bincopy
```

---

## 사용법

### 실행

```bash
python flash_stm8_gui.py
```

### 플래싱 절차

1. COM 포트 선택 후 **연결** 클릭
2. **파일 선택** 버튼으로 S19 파일 지정
3. **펌웨어 업데이트 시작** 클릭
4. 진행 상태 및 로그 확인

---

## 워크플로우

```
부트로더 진입 (9600 baud, No Parity)
       ↓
부트로더 초기화 (57600 baud, Even Parity)
       ↓
부트로더 버전 확인 (STBL_GET)
       ↓
EW Routines 다운로드 → RAM (0x00A0)
       ↓
플래시 전체 삭제 (ERASE, 타임아웃 30초)
       ↓
펌웨어 쓰기 (128바이트 청크)
       ↓
MCU 리셋 (GO 명령, 0x008000)
```

---

## 통신 프로토콜

| 단계 | Baudrate | Parity | 용도 |
|------|----------|--------|------|
| 애플리케이션 모드 | 9600 | None | 부트로더 진입 명령 전송 |
| 부트로더 모드 | 57600 | Even | 펌웨어 플래싱 |
| 완료 후 | 9600 | None | 정상 동작 모드 복귀 |

### 부트로더 진입 시퀀스

애플리케이션 펌웨어가 실행 중인 상태에서 아래 시퀀스로 부트로더 모드로 전환합니다.

**1단계 — 진입 명령 전송** (9600 baud, No Parity)

```
PC  → MCU : $LICMD,C*20\r\n
            (HEX: 24 4C 49 43 4D 44 2C 43 2A 32 30 0D 0A)
MCU → PC  : Process FW Update...
```

**2단계 — 부트로더 동기화** (57600 baud, Even Parity로 전환 후)

```
PC  → MCU : 0x7F
MCU → PC  : 0x79  (ACK)
```

> MCU가 `Process FW Update...` 응답을 보내면 즉시 57600 baud Even Parity로 전환하고,
> 0x7F 동기화 바이트를 전송합니다. ACK(0x79)를 수신하면 부트로더 진입 완료.

---

### 부트로더 명령어

| 명령 | 코드 | 설명 |
|------|------|------|
| GET | `0x00 0xFF` | 버전 및 지원 명령 확인 |
| WRITE | `0x31 0xCE` | 메모리 쓰기 |
| ERASE | `0x43 0xBC` | 플래시 전체 삭제 |
| GO | `0x21 0xDE` | 지정 주소에서 실행 |
| READ | `0x11 0xEE` | 메모리 읽기 (검증용) |

---

## STM8 부트로더 프로토콜 특이사항

STM8은 STM32와 동일한 UART 부트로더 프로토콜을 사용하지만, 아래 차이점이 있습니다.

| 항목 | STM32 | STM8S207RBT6 |
|------|-------|--------------|
| 주소 형식 | 4바이트 | 4바이트 (동일) |
| 패킷 크기 | 256바이트 | **128바이트** |
| EW Routines | 불필요 | **필수** |
| 부트로더 속도 | 115200 baud | **57600 baud** |

### EW Routines

STM8은 플래시 삭제/쓰기 전에 RAM(0x00A0)에 실행 루틴을 다운로드해야 합니다.
부트로더 버전에 따라 자동으로 적절한 파일을 선택합니다.

```
E_W_ROUTINEs_128K_ver_2.2.s19  ← 버전 2.2용 (352바이트)
```

---

## 파일 구조

```
python_fw_flash/
├── flash_stm8_gui.py              # 메인 프로그램
├── E_W_ROUTINEs_128K_ver_2.2.s19 # EW Routines (부트로더 v2.2)
└── README.md
```

---

## 타겟 MCU

| 항목 | 값 |
|------|----|
| MCU | STM8S207RBT6 |
| 아키텍처 | STM8 (8비트) |
| Flash | 128KB (0x008000 - 0x027FFF) |
| RAM | 6KB (0x000000 - 0x0017FF) |
| EEPROM | 2KB (0x004000 - 0x0047FF) |

---

## PyInstaller 빌드

```bash
pyinstaller --onefile --windowed --add-data "E_W_ROUTINEs_128K_ver_2.2.s19;." flash_stm8_gui.py
```

빌드된 실행 파일은 `dist/flash_stm8_gui.exe`에 생성됩니다.

---

## 참고 문서

- **UM0560**: STM8 bootloader user manual (STMicroelectronics)
- **AN2659**: STM8 bootloader application note
