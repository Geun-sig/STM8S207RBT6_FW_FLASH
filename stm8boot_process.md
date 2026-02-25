# STM8 부트로더 프로세스 분석 (Sources 디렉토리 기반)

## 개요

STM Flash Loader 공식 소스 코드(Sources 디렉토리)를 분석하여 **0x7F 동기화 바이트 전송 후 0x79 ACK 수신 이후의 순차적인 처리 과정**을 정리한 문서입니다.

**분석 대상**:
- `Sources/STUARTBLLIB/STUARTBLLIB.cpp` - UART 부트로더 프로토콜 구현
- `Sources/STMFlashLoader/STMFlashLoader.cpp` - 메인 플래싱 로직
- `Sources/STBLLIB/STBLLIB.cpp` - 공통 부트로더 API
- `Sources/BIN/Map/STM8_128K.STmap` - STM8 메모리 맵 설정

**타겟 MCU**: STM8S207RBT6 (128KB Flash)

---

## 1. 부트로더 초기화 (`STBL_Init_BL`)

**위치**: `STUARTBLLIB.cpp:725-775`

### 프로토콜

```
1. PC → MCU: 0x7F (동기화 바이트)
2. MCU → PC: 0x79 (ACK) 또는 0x75 (STR750)
```

### 코드 구현

```cpp
LPBYTE RQ_Buffer = (LPBYTE) malloc(1);

// 1. 동기화 바이트 전송
RQ_Buffer[0] = INIT_CON;  // 0x7F
if (Cur_COM.sendData(1, RQ_Buffer) != 1)
    return SEND_FAIL;

// 2. ACK 수신
if (Cur_COM.receiveData(1, RQ_Buffer) != 1)
    return READ_FAIL;

// 3. Work-Around: 일부 디바이스는 리셋 후 0x00 전송
if(RQ_Buffer[0] == 0x00)
    if (Cur_COM.receiveData(1, RQ_Buffer) != 1)
        return READ_FAIL;

// 4. ACK 값에 따른 타겟 구분
switch (RQ_Buffer[0])
{
  case 0x75: { // STR750
      ACK_VALUE = ST75;
      ACK  = 0x75;
      NACK = 0x3F;
  }break;

  case 0x79: { // STM32, STR911, STM8
      ACK_VALUE = ST79;
      ACK  = 0x79;
      NACK = 0x1F;
  }break;

  default: { // 인식 불가 디바이스
      ACK_VALUE = UNDEFINED;
      return UNREOGNIZED_DEVICE;
  }break;
}
```

### 결과

- **성공**: `ACK_VALUE = ST79` 설정, `SUCCESS` 반환
- **실패**: `UNREOGNIZED_DEVICE` 또는 `READ_FAIL`

---

## 2. 부트로더 정보 확인 (`STBL_GET`)

**위치**: `STUARTBLLIB.cpp:779-851`, `STMFlashLoader.cpp:982`

### 목적

- 부트로더 버전 확인
- 지원 명령 목록 파싱

### 프로토콜

```
1. PC → MCU: 0x00 0xFF (GET 명령 + XOR)
2. MCU → PC: 0x79 (ACK)
3. MCU → PC: N (바이트 수)
4. MCU → PC: Version (1바이트)
5. MCU → PC: Commands (N바이트)
6. MCU → PC: 0x79 (ACK)
```

### 지원 명령 파싱

**명령 코드** (`STUARTBLLIB.cpp:228-258`):

| 코드 | 명령 | 설명 |
|------|------|------|
| `0x00` | GET_CMD | 부트로더 정보 조회 |
| `0x01` | GET_VER_ROPS_CMD | 버전 및 보호 상태 |
| `0x02` | GET_ID_CMD | 칩 ID 조회 |
| `0x11` | READ_CMD | 메모리 읽기 (최대 256바이트) |
| `0x21` | GO_CMD | 주소 실행 |
| **`0x31`** | **WRITE_CMD** | **메모리 쓰기** |
| **`0x43`** | **ERASE_CMD** | **플래시 삭제** |
| `0x44` | ERASE_EXT_CMD | 확장 삭제 |
| `0x63` | WRITE_PROTECT_CMD | 쓰기 보호 활성화 |
| `0x73` | WRITE_TEMP_UNPROTECT_CMD | 임시 쓰기 보호 해제 |
| `0x74` | WRITE_PERM_UNPROTECT_CMD | 영구 쓰기 보호 해제 |
| `0x82` | READOUT_PROTECT_CMD | 읽기 보호 활성화 |
| `0x92` | READOUT_PERM_UNPROTECT_CMD | 영구 읽기 보호 해제 |

### 부트로더 버전 변환

```cpp
BYTE Version;
Commands pCmds;
STBL_GET(&Version, &pCmds);

// 버전을 "2.2" 형식으로 변환
CString m_Version;
m_Version.Format("%x.%x", Version/16, Version & 0x0F);
// 예: Version = 0x22 → "2.2"
```

---

## 3. EW Routines 다운로드 (STM8 전용)

**위치**: `STMFlashLoader.cpp:591-694` (Erase 전), `1156-1264` (Download 전)

### 3.1 개요

STM8 부트로더는 **플래시 삭제 및 쓰기 전에 RAM에 실행 루틴을 다운로드**해야 합니다.

### 3.2 STmap 파일에서 EW Routines 파일명 조회

**STM8_128K.STmap** (26-29라인):

```ini
[Product]
Name=STM8_128K
PacketSize=80       # 128바이트 (0x80)
ACKVAL=79          # ACK = 0x79
family = 3         # STM8 family

;; 부트로더 버전별 EW Routines
2.0 = E_W_ROUTINEs_128K_ver_2.0.s19
2.1 = E_W_ROUTINEs_128K_ver_2.1.s19
2.2 = E_W_ROUTINEs_128K_ver_2.2.s19
```

**코드 구현**:

```cpp
CIni Ini((LPCSTR)MapFile);  // STM8_128K.STmap 로드

// 부트로더 버전에 맞는 EW Routines 파일명 조회
if(Ini.IsKeyExist((LPCTSTR)"Product", (LPCTSTR)m_Version))
{
    // 예: m_Version = "2.2" → "E_W_ROUTINEs_128K_ver_2.2.s19"
    CString E_W_ROUTINEs = Ini.GetString((LPCTSTR)"Product", (LPCTSTR)m_Version, "");

    // 파일 경로 구성
    ToFind.Format("%s%s%s", Path, "STM8_Routines\\", E_W_ROUTINEs);
}
```

### 3.3 EW Routines 메모리 맵

| 파일 | 주소 범위 | 크기 |
|------|-----------|------|
| `E_W_ROUTINEs_128K_ver_2.0.s19` | 0x00A0 - 0x01A7 | 264 bytes |
| `E_W_ROUTINEs_128K_ver_2.1.s19` | 0x00A0 - 0x0200 | 353 bytes |
| `E_W_ROUTINEs_128K_ver_2.2.s19` | 0x00A0 - 0x0200 | 353 bytes |
| `E_W_ROUTINEs_128K_ver_2.4.s19` | 0x00A0 - 0x0200 | 353 bytes |

**RAM 영역**: STM8S207RBT6의 RAM은 **0x000000 - 0x0017FF (6KB)**

### 3.4 S19 파일을 RAM에 다운로드

```cpp
HANDLE Image;
if (FILES_ImageFromFile((LPSTR)(LPCSTR)ToFind, &Image, 1) == FILES_NOERROR)
{
    DWORD NbElements;
    FILES_GetImageNbElement(Image, &NbElements);

    // 각 Element를 순차적으로 RAM에 다운로드
    for (int el=0; el < (int)NbElements; el++)
    {
        IMAGEELEMENT Element={0};
        FILES_GetImageElement(Image, el, &Element);
        Element.Data = new BYTE[Element.dwDataLength];
        FILES_GetImageElement(Image, el, &Element);

        // RAM 주소 0x00A0에 EW Routines 다운로드
        if (STBL_DNLOAD(Element.dwAddress,     // 0x00A0
                        Element.Data,
                        Element.dwDataLength,  // ~353바이트
                        FALSE) != SUCCESS)
        {
            // 다운로드 실패
        }
    }

    // 다운로드한 데이터 검증
    for (int el=0; el < (int)NbElements; el++)
    {
        IMAGEELEMENT Element={0};
        FILES_GetImageElement(Image, el, &Element);
        Element.Data = new BYTE[Element.dwDataLength];
        FILES_GetImageElement(Image, el, &Element);

        if (STBL_VERIFY(Element.dwAddress,
                        Element.Data,
                        Element.dwDataLength,
                        FALSE) != SUCCESS)
        {
            // 검증 실패
            char str[255];
            sprintf(str, "Data not matching at address :0x%X. \n"
                         "The page may be write protected.",
                    Element.dwAddress);
            AfxMessageBox(str, MB_OK|MB_ICONEXCLAMATION);
            return 3;
        }
    }
}
```

### 3.5 EW Routines 없을 경우 경고

```cpp
int family = Ini.GetInt((LPCTSTR)"Product", (LPCTSTR)"family", 0);
if(family == 3)  // STM8
{
    printf("\n!WARNING: The erase or download operation may fail \n"
           " EW routines file is missing\n");
}
```

---

## 4. 플래시 삭제 (`STBL_ERASE`)

**위치**: `STUARTBLLIB.cpp:984-1193`, `STMFlashLoader.cpp:704`

### 프로토콜 - 전체 삭제

```
1. PC → MCU: 0x43 0xBC (ERASE 명령 + XOR)
2. MCU → PC: 0x79 (ACK)
3. PC → MCU: 0xFF 0x00 (전체 삭제 + XOR)
4. MCU → PC: 0x79 (ACK) - 타임아웃 30초
```

### 코드 구현

```cpp
// 전체 플래시 삭제
STBL_ERASE(0xFFFF, NULL);
```

**내부 처리** (`STUARTBLLIB.cpp:1002-1011`):

```cpp
if (NbSectors == 0xFFFF)
{
    pRQ->_nbSectors = 0xFF;
    pRQ->_length = 0;

    BYTE Result = Send_RQ(pRQ);
    if (Result != SUCCESS) return Result;

    Progress = 0xFF / 10;
}
```

**Send_RQ 프로토콜** (`STUARTBLLIB.cpp:564-617`):

```cpp
case ERASE_CMD:
{
    // 0xFF = 전체 삭제
    if (pRQ->_nbSectors == 0xFF)
    {
        RQ_Buffer = (LPBYTE) malloc(2);
        RQ_Buffer[0] = pRQ->_nbSectors;  // 0xFF
        RQ_Buffer[1] = ~pRQ->_nbSectors; // 0x00
    }

    DataSize = 2;
    if (Cur_COM.sendData(pRQ->_length + DataSize, RQ_Buffer) != pRQ->_length + DataSize)
        return SEND_FAIL;

    // ACK 수신 (타임아웃 30초)
    if (Cur_COM.receiveData(1, RQ_Buffer) != 1)
        return READ_FAIL;

    if (RQ_Buffer[0] != ACK)
        return CMD_FAIL;
}
```

### 타임아웃

**플래시 삭제는 오랜 시간이 걸리므로 타임아웃 30초 설정 필요**

---

## 5. 펌웨어 다운로드

**위치**: `STMFlashLoader.cpp:1266-1383`, `STUARTBLLIB.cpp:1454-1539`

### 5.1 S19 파일 로드

```cpp
HANDLE Handle;
if (FILES_ImageFromFile((LPSTR)(LPCSTR)filename, &Handle, 1) == FILES_NOERROR)
{
    FILES_SetImageName(Handle, (LPSTR)(LPCSTR)filename);

    DWORD NbElements = 0;
    FILES_GetImageNbElement(Handle, &NbElements);
}
```

### 5.2 각 Element 다운로드

```cpp
for (int el=0; el < (int)NbElements; el++)
{
    IMAGEELEMENT Element={0};
    FILES_GetImageElement(Handle, el, &Element);
    Element.Data = (LPBYTE)malloc(Element.dwDataLength);
    FILES_GetImageElement(Handle, el, &Element);

    // 플래시에 데이터 쓰기
    if (STBL_DNLOAD(Element.dwAddress,   // 0x008000~
                    Element.Data,
                    Element.dwDataLength,
                    optimize) != SUCCESS)
    {
        write_debug_info("downloading", el, Element.dwAddress,
                        (float)Element.dwDataLength/(float)1024, KO);
        return 3;
    }

    write_debug_info("downloading", el, Element.dwAddress,
                    (float)Element.dwDataLength/(float)1024, OK);
}
```

### 5.3 STBL_DNLOAD 내부 처리

**위치**: `STUARTBLLIB.cpp:1454-1539`

```cpp
STBLLIB_API BYTE STBL_DNLOAD(DWORD Address, LPBYTE pData, DWORD Length,
                              BOOL bTruncateLeadFFForDnLoad)
{
    LPBYTE Holder = pData;
    BYTE Result = SUCCESS;
    LPBYTE buffer = (LPBYTE) malloc(MAX_DATA_SIZE);  // 256바이트

    DWORD nbuffer = (DWORD)(Length / MAX_DATA_SIZE);
    DWORD ramain  = (DWORD)(Length % MAX_DATA_SIZE);

    LPBYTE Empty = new BYTE[MAX_DATA_SIZE];
    memset(Empty, 0xFF, MAX_DATA_SIZE);

    // 256바이트 청크 단위로 분할
    if (nbuffer > 0)
    {
        for(int i=1; i <= nbuffer; i++)
        {
            memset(buffer, 0xFF, MAX_DATA_SIZE);
            memcpy(buffer, pData, MAX_DATA_SIZE);

            // 0xFF로만 구성된 청크 건너뛰기 (optimize)
            BOOL AllFFs = FALSE;
            if((memcmp(Empty, buffer, MAX_DATA_SIZE) == 0) && bTruncateLeadFFForDnLoad)
            {
                AllFFs = TRUE;
            }

            if(!AllFFs)
            {
                // STBL_WRITE 호출
                Result = STBL_WRITE(Address, MAX_DATA_SIZE, buffer);
                if (Result != SUCCESS) return Result;
            }

            pData += MAX_DATA_SIZE;
            Address += MAX_DATA_SIZE;
            Progress++;
        }
    }

    // 남은 데이터 처리
    if (ramain > 0)
    {
        memset(buffer, 0xFF, MAX_DATA_SIZE);

        // Work-around: 4바이트 정렬 (v2.8.0에서 제거됨)
        Result = STBL_READ(Address, Newramain, buffer);
        if (Result != SUCCESS) return Result;

        memcpy(buffer, pData, ramain);

        BOOL AllFFs = FALSE;
        if((memcmp(Empty, buffer, ramain) == 0) && bTruncateLeadFFForDnLoad)
            AllFFs = TRUE;

        if(!AllFFs)
        {
            Result = STBL_WRITE(Address, Newramain, buffer);
            if (Result != SUCCESS) return Result;
        }

        Progress++;
    }

    free(buffer);
    pData = Holder;
    return Result;
}
```

---

## 6. Write Memory 프로토콜 (`STBL_WRITE`)

**위치**: `STUARTBLLIB.cpp:420-494`

### 프로토콜

```
1. PC → MCU: 0x31 0xCE (WRITE 명령 + XOR)
2. MCU → PC: 0x79 (ACK)
3. PC → MCU: Address (4바이트) + Checksum
4. MCU → PC: 0x79 (ACK)
5. PC → MCU: N (바이트 수 - 1) + Data + Checksum
6. MCU → PC: 0x79 (ACK)
```

### 코드 구현

```cpp
case WRITE_CMD:
{
    // 1. Write 명령 전송
    RQ_Buffer[0] = pRQ->_cmd;     // 0x31
    RQ_Buffer[1] = ~pRQ->_cmd;    // 0xCE
    if (Cur_COM.sendData(2, RQ_Buffer) != 2)
        return SEND_FAIL;

    // 2. ACK 수신
    if (Cur_COM.receiveData(1, RQ_Buffer) != 1)
        return READ_FAIL;
    if (RQ_Buffer[0] != ACK)
        return CMD_FAIL;

    // 3. 주소 전송 (4바이트 + 체크섬)
    BYTE Checksum = 0x00;
    RQ_Buffer[0] = (pRQ->_address >> 24) & 0xFF;
    Checksum = Checksum ^ RQ_Buffer[0];
    RQ_Buffer[1] = (pRQ->_address >> 16) & 0xFF;
    Checksum = Checksum ^ RQ_Buffer[1];
    RQ_Buffer[2] = (pRQ->_address >> 8) & 0xFF;
    Checksum = Checksum ^ RQ_Buffer[2];
    RQ_Buffer[3] = (pRQ->_address) & 0xFF;
    Checksum = Checksum ^ RQ_Buffer[3];
    RQ_Buffer[4] = Checksum;

    if (Cur_COM.sendData(5, RQ_Buffer) != 5)
        return SEND_FAIL;

    // 4. ACK 수신
    if (Cur_COM.receiveData(1, RQ_Buffer) != 1)
        return READ_FAIL;
    if (RQ_Buffer[0] != ACK)
        return CMD_FAIL;

    // 5. 데이터 전송
    BYTE checksum = 0x00;
    RQ_Buffer[0] = pRQ->_length - 1;  // N (실제 바이트 수 - 1)
    checksum = RQ_Buffer[0];

    if (Cur_COM.sendData(1, RQ_Buffer) != 1)
        return SEND_FAIL;

    // 데이터 체크섬 계산
    for (int i = 0; i < pRQ->_length; i++)
        checksum = checksum ^ pRQ->_data[i];

    // 데이터 전송
    if (Cur_COM.sendData(pRQ->_length, pRQ->_data) != pRQ->_length)
        return SEND_FAIL;

    // 체크섬 전송
    RQ_Buffer[0] = checksum;
    if (Cur_COM.sendData(1, RQ_Buffer) != 1)
        return SEND_FAIL;

    // 6. 최종 ACK 수신
    if (Cur_COM.receiveData(1, RQ_Buffer) != 1)
        return READ_FAIL;
    if (RQ_Buffer[0] != ACK)
        return CMD_FAIL;
}
```

### 주소 형식 (STM32 vs STM8)

| MCU | 주소 예시 | 4바이트 표현 |
|-----|-----------|-------------|
| STM32F103 | 0x08000000 | `0x08, 0x00, 0x00, 0x00` |
| STM8S207 | 0x008000 | `0x00, 0x00, 0x80, 0x00` |

**프로토콜은 항상 4바이트 주소를 사용하지만, 상위 바이트는 0x00으로 채워짐**

---

## 7. 검증 (옵션)

**위치**: `STMFlashLoader.cpp:1347-1381`

### 프로토콜

```cpp
for (int el=0; el < (int)NbElements; el++)
{
    IMAGEELEMENT Element={0};
    FILES_GetImageElement(Handle, el, &Element);
    Element.Data = (LPBYTE)malloc(Element.dwDataLength);
    FILES_GetImageElement(Handle, el, &Element);

    if (STBL_VERIFY(Element.dwAddress,
                    Element.Data,
                    Element.dwDataLength,
                    optimize) != SUCCESS)
    {
        VerifySuccess = false;
        write_debug_info("verifying", el, Element.dwAddress,
                        (float)Element.dwDataLength/(float)1024, KO);
        return 3;
    }

    write_debug_info("verifying", el, Element.dwAddress,
                    (float)Element.dwDataLength/(float)1024, OK);
}
```

### STBL_VERIFY 내부

**위치**: `STUARTBLLIB.cpp:1383-1448`

```cpp
// 플래시에서 데이터 읽기
Result = STBL_READ(Address, MAX_DATA_SIZE, buffer);
if (Result != SUCCESS) return Result;

// 원본 데이터와 비교
if (memcmp(pData, buffer, MAX_DATA_SIZE) != 0)
{
    return CMD_NOT_ALLOWED;  // 검증 실패
}
```

---

## 8. MCU 리셋 (`STBL_GO`)

**위치**: `STUARTBLLIB.cpp:389-419`, `STMFlashLoader.cpp:1833`

### 프로토콜

```
1. PC → MCU: 0x21 0xDE (GO 명령 + XOR)
2. MCU → PC: 0x79 (ACK)
3. PC → MCU: Address (4바이트) + Checksum
4. MCU → PC: 0x79 (ACK) - MCU 리셋되므로 응답 없을 수 있음
```

### 코드 구현

```cpp
case GO_CMD:
{
    // 1. GO 명령 전송
    RQ_Buffer[0] = pRQ->_cmd;     // 0x21
    RQ_Buffer[1] = ~pRQ->_cmd;    // 0xDE
    if (Cur_COM.sendData(2, RQ_Buffer) != 2)
        return SEND_FAIL;

    // 2. ACK 수신
    if (Cur_COM.receiveData(1, RQ_Buffer) != 1)
        return READ_FAIL;
    if (RQ_Buffer[0] != ACK)
        return CMD_FAIL;

    // 3. 주소 전송
    BYTE Checksum = 0x00;
    RQ_Buffer[0] = (pRQ->_address >> 24) & 0xFF;
    Checksum = Checksum ^ RQ_Buffer[0];
    RQ_Buffer[1] = (pRQ->_address >> 16) & 0xFF;
    Checksum = Checksum ^ RQ_Buffer[1];
    RQ_Buffer[2] = (pRQ->_address >> 8) & 0xFF;
    Checksum = Checksum ^ RQ_Buffer[2];
    RQ_Buffer[3] = (pRQ->_address) & 0xFF;
    Checksum = Checksum ^ RQ_Buffer[3];
    RQ_Buffer[4] = Checksum;

    if (Cur_COM.sendData(5, RQ_Buffer) != 5)
        return SEND_FAIL;

    // 4. ACK 수신 (리셋되면 응답 없을 수 있음)
    if (Cur_COM.receiveData(1, RQ_Buffer) != 1)
        return READ_FAIL;

    // 주석 처리: GO 명령 실행 후 ACK 반환 보장 안 됨
    // if (RQ_Buffer[0] != ACK)
    //     return CMD_FAIL;
}
```

### 주소

| MCU | 플래시 시작 주소 | 4바이트 표현 |
|-----|------------------|-------------|
| STM32F103 | 0x08000000 | `0x08, 0x00, 0x00, 0x00` |
| STM8S207 | 0x008000 | `0x00, 0x00, 0x80, 0x00` |

---

## 전체 워크플로우 요약

### STM8 부트로더 플래싱 순서

```
┌─────────────────────────────────────────────────────────────┐
│ 1. 초기화                                                    │
│    0x7F 전송 → 0x79 ACK 수신                                │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. 부트로더 정보 확인 (STBL_GET)                            │
│    명령: 0x00 0xFF                                          │
│    수신: 버전 + 지원 명령 목록                               │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. 부트로더 버전 변환                                        │
│    예: 0x22 → "2.2"                                         │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. EW Routines 다운로드 (STM8만 해당)                       │
│    - STmap 파일에서 버전별 EW Routines 파일명 조회          │
│      예: "2.2" → "E_W_ROUTINEs_128K_ver_2.2.s19"           │
│    - S19 파일을 RAM(0x00A0)에 STBL_DNLOAD                  │
│    - STBL_VERIFY로 검증                                     │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. 플래시 삭제 (STBL_ERASE)                                 │
│    명령: 0x43 0xBC                                          │
│    데이터: 0xFF 0x00 (전체 삭제)                            │
│    타임아웃: 30초                                            │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│ 6. 펌웨어 다운로드                                           │
│    - S19 파일을 256바이트 청크로 분할                        │
│    - 각 청크를 STBL_WRITE (0x31)로 플래시에 쓰기           │
│      주소: 0x008000~                                        │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│ 7. 검증 (옵션)                                               │
│    - STBL_READ로 플래시 읽기                                │
│    - 원본 데이터와 memcmp                                    │
└────────────────────┬────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────────────────────┐
│ 8. MCU 리셋 (STBL_GO)                                       │
│    명령: 0x21 0xDE                                          │
│    주소: 0x008000                                           │
└─────────────────────────────────────────────────────────────┘
```

---

## STM32 vs STM8 주요 차이점

| 항목 | STM32F103 | STM8S207RBT6 |
|------|-----------|--------------|
| **아키텍처** | ARM Cortex-M3 (32비트) | STM8 (8비트) |
| **플래시 시작** | 0x08000000 | 0x008000 |
| **주소 길이** | 4바이트 | 4바이트 (프로토콜은 동일, 상위 바이트 0x00) |
| **EW Routines** | ❌ 불필요 | ✅ **필수** (RAM 다운로드) |
| **EW Routines 주소** | - | 0x00A0 - 0x0200 (RAM) |
| **Erase 타임아웃** | 짧음 (~수초) | **길음 (30초)** |
| **파일 형식** | Intel HEX | Motorola S19 |
| **패킷 크기** | 256바이트 | 128바이트 (0x80) |
| **Family** | 0 (STM32F1) | 3 (STM8) |
| **ACK** | 0x79 | 0x79 (동일) |

---

## 현재 문제점 분석

### Python 코드에서 발생한 문제

**증상**:
- 부트로더 진입: ✅ 성공
- 부트로더 초기화 (0x7F → 0x79): ✅ 성공
- EW Routines 다운로드: ❌ 실패
  - Write Memory 명령 (0x31 0xCE): ✅ ACK 수신
  - 주소 전송 (0x00, 0x00, 0xA0, 0xA0): ❌ **무응답**

**분석**:
1. **주소 형식은 정확함**
   - 주소: 0x0000A0 (3바이트 big-endian) → `0x00, 0x00, 0xA0`
   - 체크섬: `0x00 ^ 0x00 ^ 0xA0 = 0xA0`
   - 전송: `0x00, 0x00, 0xA0, 0xA0` ✅

2. **가능한 원인**
   - **부트로더가 0x00A0 영역 사용 중** - 낮은 RAM 주소를 부트로더 스택/변수로 사용
   - **주소 길이 문제** - STM8은 실제 2바이트 주소 사용 가능성
   - **Write 명령 전 준비 작업 필요** - Write Unprotect 등
   - **부트로더 버전 불일치** - 다른 EW Routines 버전 필요

3. **Sources 코드와의 일치성**
   - Python 코드는 Sources 코드와 **동일한 워크플로우** 사용
   - 공식 STM Flash Loader도 동일한 프로토콜 구현

---

## 다음 조사 방향

### 우선순위 1: 부트로더 버전 확인

```python
def get_bootloader_version(self):
    """STBL_GET 명령으로 부트로더 정보 확인"""
    # 1. GET 명령 전송
    self.serial.write(bytes([0x00, 0xFF]))
    ack = self.serial.read(1)

    if ack != b'\x79':
        return None

    # 2. 바이트 수 수신
    n = self.serial.read(1)[0]

    # 3. 버전 수신
    version = self.serial.read(1)[0]

    # 4. 명령 목록 수신
    commands = self.serial.read(n)

    # 5. ACK 수신
    ack = self.serial.read(1)

    # 6. 버전 변환 (0x22 → "2.2")
    ver_str = f"{version >> 4}.{version & 0x0F}"

    return ver_str, commands
```

### 우선순위 2: 다른 EW Routines 버전 시도

- `E_W_ROUTINEs_128K_ver_2.0.s19` (264 bytes, 0x00A0 - 0x01A7)
- `E_W_ROUTINEs_128K_ver_2.1.s19` (353 bytes, 0x00A0 - 0x0200)

### 우선순위 3: EW Routines 없이 플래시 삭제 시도

일부 STM8 부트로더는 자체적으로 플래시 삭제를 지원할 수 있음.

```python
def erase_flash_without_ew_routines(self):
    """EW Routines 없이 플래시 삭제 시도"""
    # STBL_ERASE 명령 직접 호출
    self.serial.write(bytes([0x43, 0xBC]))
    # ...
```

### 우선순위 4: STM8 주소 길이 확인

STM8은 16비트 주소 공간을 사용하므로, **2바이트 주소**를 시도해볼 수 있음.

```python
# 4바이트 주소 (현재)
addr_bytes = [
    (addr >> 24) & 0xFF,
    (addr >> 16) & 0xFF,
    (addr >> 8) & 0xFF,
    addr & 0xFF
]

# 2바이트 주소 (시도)
addr_bytes = [
    (addr >> 8) & 0xFF,
    addr & 0xFF
]
```

---

## 참고 문서

- **UM0560**: STM8 bootloader user manual
- **AN2659**: STM8 bootloader application note
- **Sources/STMFlashLoader/**: STM Flash Loader 소스 코드
- **Sources/STUARTBLLIB/**: UART 부트로더 프로토콜 구현
- **Sources/BIN/Map/**: 디바이스별 메모리 맵 파일

---

## 파일 현황

**현재 라인 수**: 890 라인 (download_ew_routines 포함)

**주요 함수**:
- `enter_bootloader()` (100-151) - 부트로더 진입 ✅ 동작
- `bl_init()` (153-191) - 부트로더 초기화 ✅ 동작
- `download_ew_routines()` (199-255) - EW Routines 다운로드 ❌ 실패
- `erase_flash()` (257-291) - 플래시 삭제 (테스트 안 됨)
- `write_memory()` (293-336) - 메모리 쓰기 (부분 성공: 명령만 ACK)
- `program_firmware()` (338-399) - 펌웨어 프로그래밍 (테스트 안 됨)
- `reset_mcu()` (401-434) - MCU 리셋 (테스트 안 됨)

---

**작성일**: 2026-01-05
**작성자**: Claude (Sources 디렉토리 분석 기반)
