from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QLabel, QPushButton, QComboBox,
                               QLineEdit, QProgressBar, QTextEdit, QGroupBox,
                               QFileDialog, QMessageBox)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from PySide6.QtGui import QFont, QTextCursor, QPixmap
import serial
import serial.tools.list_ports
import time
import os
import bincopy
import sys


class FlashWorker(QThread):
    """펌웨어 플래싱 작업을 수행하는 워커 스레드"""
    progress_updated = Signal(str, float)  # status, percentage
    log_message = Signal(str)  # message
    finished = Signal(bool)  # success

    def __init__(self, port, s19_file):
        super().__init__()
        self.port = port
        self.s19_file = s19_file
        self.ser = None
        self.is_running = True

    def run(self):
        """펌웨어 플래싱 메인 함수"""
        try:
            # 1. 부트로더 진입
            if not self.enter_bootloader():
                self.progress_updated.emit("실패: 부트로더 진입 실패", 0)
                self.finished.emit(False)
                return

            # MCU 부트로더 준비 대기 (600ms)
            time.sleep(0.6)

            # 2. 부트로더 초기화
            if not self.bl_init():
                self.progress_updated.emit("실패: 부트로더 초기화 실패", 0)
                self.finished.emit(False)
                return

            # 3. 부트로더 정보 확인
            bl_info = self.get_bootloader_info()
            if bl_info:
                self.log_message.emit(f"✓ 부트로더 버전: {bl_info['version_str']}")
                self.log_message.emit(f"✓ 지원 명령 수: {len(bl_info['commands'])}개")
            else:
                self.log_message.emit("경고: 부트로더 정보를 확인할 수 없습니다")

            # 4. EW Routines 다운로드
            if not self.download_ew_routines(bl_info):
                self.progress_updated.emit("실패: EW Routines 다운로드 실패", 0)
                self.finished.emit(False)
                return

            # 5. 플래시 삭제
            if not self.erase_flash():
                self.progress_updated.emit("실패: 플래시 삭제 실패", 0)
                self.finished.emit(False)
                return

            # 6. 펌웨어 프로그래밍
            if not self.program_firmware():
                self.progress_updated.emit("실패: 펌웨어 쓰기 실패", 0)
                self.finished.emit(False)
                return

            # 7. MCU 리셋
            if self.reset_mcu():
                self.progress_updated.emit("완료: 펌웨어 업데이트 성공!", 100)
                self.log_message.emit("펌웨어 업데이트가 성공적으로 완료되었습니다!")
                self.finished.emit(True)
            else:
                self.progress_updated.emit("경고: 리셋 실패", 95)
                self.finished.emit(True)

        except Exception as e:
            self.log_message.emit(f"치명적 오류: {str(e)}")
            self.progress_updated.emit("실패: 치명적 오류 발생", 0)
            self.finished.emit(False)

        finally:
            if self.ser and self.ser.is_open:
                self.ser.close()

    def stop(self):
        """작업 중지"""
        self.is_running = False

    def init_serial(self, baudrate, parity=serial.PARITY_NONE):
        """시리얼 포트 초기화"""
        if self.ser and self.ser.is_open:
            self.ser.close()

        time.sleep(0.1)

        self.ser = serial.Serial(
            port=self.port,
            baudrate=baudrate,
            bytesize=serial.EIGHTBITS,
            parity=parity,
            stopbits=serial.STOPBITS_ONE,
            timeout=1
        )

        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()
        time.sleep(0.05)

    def enter_bootloader(self):
        """부트로더 진입"""
        if not self.is_running:
            return False

        self.log_message.emit("애플리케이션 통신 초기화 중...")
        self.progress_updated.emit("부트로더 진입 중...", 5)

        try:
            self.init_serial(9600, serial.PARITY_NONE)

            self.log_message.emit("부트로더 명령 전송 중...")
            boot_cmd = b"$LICMD,C*20\r\n"
            self.ser.write(boot_cmd)
            self.ser.flush()

            self.log_message.emit("MCU 응답 대기 중...")
            start_time = time.time()
            all_received = bytearray()

            while self.is_running:
                if self.ser.in_waiting > 0:
                    data = self.ser.read(self.ser.in_waiting)
                    all_received.extend(data)
                    self.log_message.emit(f"수신 RAW ({len(data)}바이트): {data.hex()}")
                    try:
                        text = data.decode('utf-8', errors='ignore')
                        self.log_message.emit(f"수신 TEXT: {repr(text)}")
                        if "Process FW Update" in text:
                            self.log_message.emit("MCU가 펌웨어 업데이트 준비 완료")
                            break
                    except:
                        pass

                if time.time() - start_time > 10:
                    self.log_message.emit(f"총 수신 데이터: {all_received.hex() if all_received else '없음'}")
                    raise Exception("MCU 응답 타임아웃")

                time.sleep(0.05)

            if not self.is_running:
                return False

            self.log_message.emit("부트로더 통신 모드로 전환 중...")
            self.init_serial(57600, serial.PARITY_EVEN)
            self.progress_updated.emit("부트로더 동기화 중...", 10)

            return True

        except Exception as e:
            self.log_message.emit(f"부트로더 진입 오류: {str(e)}")
            return False

    def bl_init(self):
        """부트로더 초기화"""
        if not self.is_running:
            return False

        ACK = b'\x79'
        max_attempts = 5

        for attempt in range(max_attempts):
            if not self.is_running:
                return False

            try:
                self.log_message.emit(f"부트로더 동기화 시도 {attempt + 1}/{max_attempts}")

                self.ser.reset_input_buffer()
                self.ser.reset_output_buffer()
                self.ser.write(b'\x7F')
                self.ser.flush()

                # ACK 응답 대기 (최대 50ms)
                start_time = time.time()
                while time.time() - start_time < 0.05:
                    if not self.is_running:
                        return False

                    if self.ser.in_waiting > 0:
                        ack = self.ser.read(1)
                        if ack == ACK:
                            self.log_message.emit("부트로더 ACK 수신됨")
                            return True
                    time.sleep(0.001)

            except Exception as e:
                self.log_message.emit(f"동기화 오류: {str(e)}")

        self.log_message.emit("부트로더 응답 없음")
        return False

    def get_bootloader_info(self):
        """부트로더 버전 및 지원 명령 목록 확인 (STBL_GET)"""
        if not self.is_running:
            return None

        ACK = b'\x79'

        try:
            self.log_message.emit("부트로더 정보 확인 중...")

            # 1. GET 명령 전송 (0x00 0xFF)
            self.ser.reset_input_buffer()
            self.ser.write(bytes([0x00, 0xFF]))
            self.ser.flush()

            # 2. ACK 수신
            ack = self.ser.read(1)
            if ack != ACK:
                self.log_message.emit(f"GET 명령 ACK 실패: {ack.hex() if ack else '없음'}")
                return None

            # 3. 바이트 수 수신 (N)
            n_bytes = self.ser.read(1)
            if not n_bytes:
                self.log_message.emit("바이트 수 수신 실패")
                return None

            n = n_bytes[0]
            self.log_message.emit(f"명령 개수: {n}개")

            # 4. 부트로더 버전 수신
            version_bytes = self.ser.read(1)
            if not version_bytes:
                self.log_message.emit("버전 정보 수신 실패")
                return None

            version = version_bytes[0]
            version_str = f"{version >> 4}.{version & 0x0F}"
            self.log_message.emit(f"부트로더 버전: {version_str} (0x{version:02X})")

            # 5. 지원 명령 목록 수신
            commands_bytes = self.ser.read(n)
            if len(commands_bytes) != n:
                self.log_message.emit(f"명령 목록 수신 실패: {len(commands_bytes)}/{n}")
                return None

            # 6. 최종 ACK 수신
            final_ack = self.ser.read(1)
            if final_ack != ACK:
                self.log_message.emit(f"최종 ACK 실패: {final_ack.hex() if final_ack else '없음'}")
                return None

            # 명령 목록 파싱
            command_names = {
                0x00: "GET",
                0x01: "GET_VER_ROPS",
                0x02: "GET_ID",
                0x11: "READ",
                0x21: "GO",
                0x31: "WRITE",
                0x43: "ERASE",
                0x44: "ERASE_EXT",
                0x63: "WRITE_PROTECT",
                0x73: "WRITE_TEMP_UNPROTECT",
                0x74: "WRITE_PERM_UNPROTECT",
                0x82: "READOUT_PROTECT",
                0x92: "READOUT_PERM_UNPROTECT"
            }

            supported_commands = []
            for cmd in commands_bytes:
                cmd_name = command_names.get(cmd, f"UNKNOWN(0x{cmd:02X})")
                supported_commands.append(cmd_name)

            self.log_message.emit(f"지원 명령: {', '.join(supported_commands)}")

            # WRITE와 ERASE 명령 지원 확인
            has_write = 0x31 in commands_bytes
            has_erase = 0x43 in commands_bytes or 0x44 in commands_bytes

            if not has_write:
                self.log_message.emit("경고: WRITE 명령이 지원되지 않습니다!")
            if not has_erase:
                self.log_message.emit("경고: ERASE 명령이 지원되지 않습니다!")

            return {
                'version': version,
                'version_str': version_str,
                'commands': list(commands_bytes),
                'supported_commands': supported_commands,
                'has_write': has_write,
                'has_erase': has_erase
            }

        except Exception as e:
            self.log_message.emit(f"부트로더 정보 확인 오류: {str(e)}")
            return None

    def download_ew_routines(self, bl_info=None):
        """STM8 Erase/Write Routines를 RAM에 다운로드

        Args:
            bl_info: get_bootloader_info()에서 반환된 부트로더 정보 딕셔너리
        """
        if not self.is_running:
            return False

        try:
            self.log_message.emit("EW Routines 다운로드 중...")
            self.progress_updated.emit("EW Routines 다운로드 중...", 12)

            # EW Routines 파일 경로
            if getattr(sys, 'frozen', False):
                # PyInstaller로 빌드된 실행 파일
                application_path = sys._MEIPASS
            else:
                # 일반 Python 스크립트
                application_path = os.path.dirname(os.path.abspath(__file__))

            # 부트로더 버전에 맞는 EW Routines 파일 선택
            if bl_info and bl_info.get('version_str'):
                version_str = bl_info['version_str']
                # 예: "2.2" → "E_W_ROUTINEs_128K_ver_2.2.s19"
                ew_filename = f"E_W_ROUTINEs_128K_ver_{version_str}.s19"
                self.log_message.emit(f"부트로더 버전 {version_str}에 맞는 EW Routines 선택")
            else:
                # 기본값: 2.2 버전
                ew_filename = "E_W_ROUTINEs_128K_ver_2.2.s19"
                self.log_message.emit("기본 EW Routines 사용 (ver 2.2)")

            ew_file = os.path.join(application_path, ew_filename)

            # 파일이 없으면 다른 버전 시도
            if not os.path.exists(ew_file):
                self.log_message.emit(f"파일을 찾을 수 없음: {ew_filename}")
                fallback_versions = ["2.4", "2.2", "2.1", "2.0"]

                for ver in fallback_versions:
                    ew_filename = f"E_W_ROUTINEs_128K_ver_{ver}.s19"
                    ew_file = os.path.join(application_path, ew_filename)
                    if os.path.exists(ew_file):
                        self.log_message.emit(f"대체 파일 사용: {ew_filename}")
                        break
                else:
                    raise Exception(f"EW Routines 파일을 찾을 수 없습니다: {ew_file}")

            # S19 파일 로드
            bf = bincopy.BinFile(ew_file)

            if not bf.segments:
                raise Exception("EW Routines 파일에 데이터가 없습니다")

            # Segments 정보 확인
            self.log_message.emit(f"S19 파일 세그먼트 수: {len(bf.segments)}")
            for idx, segment in enumerate(bf.segments):
                seg_start = segment.minimum_address
                seg_end = segment.maximum_address
                seg_size = seg_end - seg_start + 1
                self.log_message.emit(f"  세그먼트 {idx}: 0x{seg_start:04X} - 0x{seg_end:04X} ({seg_size} 바이트)")

            start_addr = bf.minimum_address
            end_addr = bf.maximum_address

            # 바이너리 데이터 추출
            ew_data = bytearray(bf.as_binary(minimum_address=start_addr, maximum_address=end_addr))

            # 데이터 검증: 처음 16바이트와 마지막 16바이트 출력
            first_16 = ' '.join([f'{b:02X}' for b in ew_data[:16]])
            last_16 = ' '.join([f'{b:02X}' for b in ew_data[-16:]])
            self.log_message.emit(f"EW Routines 로드됨: 0x{start_addr:04X} - 0x{end_addr:04X} ({len(ew_data)} 바이트)")
            self.log_message.emit(f"처음 16바이트: {first_16}")
            self.log_message.emit(f"마지막 16바이트: {last_16}")

            # RAM에 쓰기 (STM8은 128바이트 청크)
            chunk_size = 128
            addr = start_addr

            chunk_count = (len(ew_data) + chunk_size - 1) // chunk_size
            self.log_message.emit(f"EW Routines를 {chunk_count}개 청크로 전송 중...")

            for i in range(0, len(ew_data), chunk_size):
                if not self.is_running:
                    return False

                chunk = ew_data[i:i+chunk_size]

                # 청크의 처음 8바이트 출력
                chunk_preview = ' '.join([f'{b:02X}' for b in chunk[:8]])
                self.log_message.emit(f"청크 {i//chunk_size + 1}/{chunk_count}: 0x{addr:04X} ({len(chunk)} 바이트) [{chunk_preview}...]")

                if not self.write_memory(addr, chunk):
                    raise Exception(f"EW Routines 쓰기 실패: 0x{addr:04X}")

                addr += len(chunk)

            self.log_message.emit("EW Routines 다운로드 완료")
            self.progress_updated.emit("플래시 삭제 준비 중...", 15)
            return True

        except Exception as e:
            self.log_message.emit(f"EW Routines 다운로드 오류: {str(e)}")
            return False

    def erase_flash(self):
        """플래시 삭제"""
        if not self.is_running:
            return False

        ACK = b'\x79'

        try:
            self.log_message.emit("플래시 삭제 시작...")

            self.ser.write(b'\x43\xBC')
            self.ser.flush()

            ack = self.ser.read(1)
            if ack != ACK:
                raise Exception(f"삭제 명령 NACK: {ack.hex() if ack else 'None'}")

            self.ser.write(b'\xFF\x00')
            self.ser.flush()

            old_timeout = self.ser.timeout
            self.ser.timeout = 30

            ack = self.ser.read(1)
            self.ser.timeout = old_timeout

            if ack != ACK:
                raise Exception(f"플래시 삭제 실패: {ack.hex() if ack else 'None'}")

            self.log_message.emit("플래시 삭제 완료")
            self.progress_updated.emit("펌웨어 쓰기 준비 중...", 18)
            return True

        except Exception as e:
            self.log_message.emit(f"플래시 삭제 오류: {str(e)}")
            return False

    def read_memory(self, address, length):
        """메모리 읽기"""
        if not self.is_running:
            return None

        ACK = b'\x79'

        # STM8은 최대 128바이트 읽기 지원
        if length > 128:
            raise Exception("읽기 크기가 너무 큼 (최대 128바이트)")

        try:
            # 1. READ 명령 전송 (0x11 0xEE)
            self.ser.write(b'\x11\xEE')
            self.ser.flush()

            ack = self.ser.read(1)
            if ack != ACK:
                raise Exception(f"읽기 명령 NACK: {ack.hex() if ack else 'None'}")

            # 2. 주소 전송 (4바이트)
            addr_bytes = address.to_bytes(4, 'big')
            checksum = addr_bytes[0] ^ addr_bytes[1] ^ addr_bytes[2] ^ addr_bytes[3]
            self.ser.write(addr_bytes + bytes([checksum]))
            self.ser.flush()

            ack = self.ser.read(1)
            if ack != ACK:
                raise Exception(f"주소 NACK: {ack.hex() if ack else 'None'}")

            # 3. 읽기 크기 전송 (N = length - 1)
            length_byte = length - 1
            self.ser.write(bytes([length_byte, ~length_byte & 0xFF]))
            self.ser.flush()

            ack = self.ser.read(1)
            if ack != ACK:
                raise Exception(f"크기 NACK: {ack.hex() if ack else 'None'}")

            # 4. 데이터 수신
            data = self.ser.read(length)
            if len(data) != length:
                raise Exception(f"데이터 수신 불완전: {len(data)}/{length} 바이트")

            return bytearray(data)

        except Exception as e:
            self.log_message.emit(f"메모리 읽기 오류: {str(e)}")
            return None

    def write_memory(self, address, data):
        """메모리 쓰기"""
        if not self.is_running:
            return False

        ACK = b'\x79'

        # STM8은 최대 128바이트 패킷 지원
        if len(data) > 128:
            raise Exception("데이터 청크가 너무 큼 (최대 128바이트)")

        try:
            self.ser.write(b'\x31\xCE')
            self.ser.flush()

            ack = self.ser.read(1)
            if ack != ACK:
                raise Exception(f"쓰기 명령 NACK: {ack.hex() if ack else 'None'}")

            # STM8도 4바이트 주소 사용 (프로토콜은 STM32와 동일)
            # 주소 0x00A0 → [0x00, 0x00, 0x00, 0xA0]
            addr_bytes = address.to_bytes(4, 'big')
            checksum = addr_bytes[0] ^ addr_bytes[1] ^ addr_bytes[2] ^ addr_bytes[3]

            # 디버깅: 전송할 주소와 체크섬 출력
            addr_hex = ' '.join([f'{b:02X}' for b in addr_bytes])
            self.log_message.emit(f"주소 전송: [{addr_hex}] 체크섬: 0x{checksum:02X}")

            self.ser.write(addr_bytes + bytes([checksum]))
            self.ser.flush()

            ack = self.ser.read(1)
            if ack != ACK:
                raise Exception(f"주소 NACK: {ack.hex() if ack else 'None'}")

            length_byte = len(data) - 1
            chksum = length_byte
            for b in data:
                chksum ^= b

            # 디버깅: 데이터 길이와 체크섬 출력
            self.log_message.emit(f"데이터 전송: {len(data)} 바이트 (N={length_byte}, 체크섬=0x{chksum:02X})")

            self.ser.write(bytes([length_byte]) + data + bytes([chksum]))
            self.ser.flush()

            ack = self.ser.read(1)
            if ack != ACK:
                raise Exception(f"데이터 NACK: {ack.hex() if ack else 'None'}")

            return True

        except Exception as e:
            self.log_message.emit(f"메모리 쓰기 오류: {str(e)}")
            return False

    def program_firmware(self):
        """펌웨어 프로그래밍"""
        if not self.is_running:
            return False

        try:
            # S19 파일 로드
            bf = bincopy.BinFile(self.s19_file)

            # 주소 범위 확인
            if not bf.segments:
                raise Exception("파일에 데이터가 없습니다")

            start_addr = bf.minimum_address
            end_addr = bf.maximum_address

            # STM8S207RBT6 메모리 범위 검증
            STM8_FLASH_START = 0x008000
            STM8_FLASH_END = 0x027FFF  # 128KB
            STM8_MAX_ADDRESS = 0xFFFFFF  # 3바이트 최대값

            if start_addr < STM8_FLASH_START or end_addr > STM8_FLASH_END:
                raise Exception(
                    f"주소 범위 오류: S19 파일 주소(0x{start_addr:06X}-0x{end_addr:06X})가 "
                    f"STM8 플래시 범위(0x{STM8_FLASH_START:06X}-0x{STM8_FLASH_END:06X})를 벗어남"
                )

            if end_addr > STM8_MAX_ADDRESS:
                raise Exception(f"주소가 3바이트 범위를 초과합니다: 0x{end_addr:08X}")

            # Segments 정보 확인
            self.log_message.emit(f"펌웨어 S19 파일 세그먼트 수: {len(bf.segments)}")
            for idx, segment in enumerate(bf.segments):
                seg_start = segment.minimum_address
                seg_end = segment.maximum_address
                seg_size = seg_end - seg_start + 1
                self.log_message.emit(f"  세그먼트 {idx}: 0x{seg_start:06X} - 0x{seg_end:06X} ({seg_size} 바이트)")

            # 바이너리 데이터 추출
            bin_data = bytearray(bf.as_binary(minimum_address=start_addr, maximum_address=end_addr))

            # 데이터 검증: 처음 16바이트와 마지막 16바이트 출력
            first_16 = ' '.join([f'{b:02X}' for b in bin_data[:16]])
            last_16 = ' '.join([f'{b:02X}' for b in bin_data[-16:]])
            self.log_message.emit(f"펌웨어 로드됨: 0x{start_addr:06X} - 0x{end_addr:06X} ({len(bin_data)} 바이트)")
            self.log_message.emit(f"처음 16바이트: {first_16}")
            self.log_message.emit(f"마지막 16바이트: {last_16}")

            chunk_size = 128
            addr = start_addr
            last_progress_reported = -1

            # 총 청크 수와 예상 전송량 계산
            chunk_count = (len(bin_data) + chunk_size - 1) // chunk_size
            total_bytes = chunk_count * (2 + 5 + 1 + 1) + len(bin_data)  # 명령+주소+N+체크섬+데이터
            self.log_message.emit(f"총 {chunk_count}개 청크로 전송 예정 (약 {total_bytes} 바이트)")

            for i in range(0, len(bin_data), chunk_size):
                if not self.is_running:
                    return False

                chunk = bin_data[i:i+chunk_size]

                # 10% 단위로만 청크 미리보기 출력 (로그 과다 방지)
                current_progress = int(((i + len(chunk)) / len(bin_data)) * 100)
                if current_progress % 10 == 0 and i < chunk_size * 3:  # 처음 3개 청크만
                    chunk_preview = ' '.join([f'{b:02X}' for b in chunk[:8]])
                    self.log_message.emit(f"청크 {i//chunk_size + 1}: 0x{addr:06X} ({len(chunk)}B) [{chunk_preview}...]")

                if not self.write_memory(addr, chunk):
                    return False

                addr += len(chunk)

                # 진행률 계산 (10%부터 90%까지)
                progress = ((i + len(chunk)) / len(bin_data)) * 70 + 20
                progress_10 = int(progress / 10) * 10

                if progress_10 != last_progress_reported and progress_10 % 10 == 0:
                    self.progress_updated.emit(f"펌웨어 쓰기 중... ({progress_10}%)", progress_10)
                    self.log_message.emit(f"진행률: {progress_10}% ({i + len(chunk)} / {len(bin_data)} 바이트)")
                    last_progress_reported = progress_10

            self.log_message.emit("프로그래밍 완료")
            self.progress_updated.emit("MCU 리셋 중...", 95)
            return True

        except Exception as e:
            self.log_message.emit(f"프로그래밍 오류: {str(e)}")
            return False

    def reset_mcu(self):
        """MCU 리셋"""
        if not self.is_running:
            return False

        ACK = b'\x79'

        try:
            self.log_message.emit("MCU 리셋 중...")

            self.ser.write(b'\x21\xDE')
            self.ser.flush()

            ack = self.ser.read(1)
            if ack != ACK:
                raise Exception(f"GO 명령 NACK: {ack.hex() if ack else 'None'}")

            # STM8도 4바이트 주소 사용 (프로토콜은 STM32와 동일)
            # 주소 0x008000 → [0x00, 0x00, 0x80, 0x00]
            addr_bytes = (0x008000).to_bytes(4, 'big')
            checksum = addr_bytes[0] ^ addr_bytes[1] ^ addr_bytes[2] ^ addr_bytes[3]
            self.ser.write(addr_bytes + bytes([checksum]))
            self.ser.flush()

            ack = self.ser.read(1)
            if ack != ACK:
                self.log_message.emit("리셋 명령 완료 (응답 없음 - 정상)")
            else:
                self.log_message.emit("MCU 리셋 완료")

            return True

        except Exception as e:
            self.log_message.emit(f"리셋 오류: {str(e)}")
            self.log_message.emit("수동으로 MCU를 리셋해주세요.")
            return False


class STM32FlasherGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("(주)마린테크")
        self.setFixedSize(600, 650)  # 가로 80% (750 * 0.8 = 600)

        # 변수 초기화
        self.ser = None
        self.is_flashing = False
        self.flash_worker = None
        self.is_connected = False

        # GUI 생성
        self.init_ui()

        # COM 포트 목록 새로고침
        self.refresh_com_ports()

    def init_ui(self):
        """GUI 초기화"""
        # 중앙 위젯
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 메인 레이아웃
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(15, 15, 15, 15)

        # 제목 영역 (로고 + 텍스트)
        title_layout = QHBoxLayout()
        title_layout.setAlignment(Qt.AlignCenter)

        # 로고 이미지
        logo_label = QLabel()

        # PyInstaller 실행 파일과 일반 실행 모두 지원
        if getattr(sys, 'frozen', False):
            # PyInstaller로 빌드된 실행 파일
            application_path = sys._MEIPASS
        else:
            # 일반 Python 스크립트
            application_path = os.path.dirname(os.path.abspath(__file__))

        logo_path = os.path.join(application_path, "marine_logo.png")

        if os.path.exists(logo_path):
            pixmap = QPixmap(logo_path)
            # 로고 크기 조정 (높이 50px)
            scaled_pixmap = pixmap.scaledToHeight(50, Qt.SmoothTransformation)
            logo_label.setPixmap(scaled_pixmap)
        else:
            # 이미지가 없으면 빈 공간
            logo_label.setText("")
            logo_label.setFixedSize(50, 50)

        title_layout.addWidget(logo_label)

        # 제목 텍스트
        title_label = QLabel("마린테크 해상용 충방전기 FW Upgrade")
        title_font = QFont("Arial", 18, QFont.Bold)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: navy; padding: 10px;")
        title_layout.addWidget(title_label)

        main_layout.addLayout(title_layout)

        # COM 포트 설정 그룹
        port_group = QGroupBox("COM 포트 설정")
        port_layout = QVBoxLayout()

        port_select_layout = QHBoxLayout()
        port_select_layout.addWidget(QLabel("COM 포트:"))

        self.port_combo = QComboBox()
        self.port_combo.setMinimumWidth(120)
        port_select_layout.addWidget(self.port_combo)

        self.connect_button = QPushButton("연결")
        self.connect_button.clicked.connect(self.toggle_connection)
        port_select_layout.addWidget(self.connect_button)

        port_select_layout.addStretch()
        port_layout.addLayout(port_select_layout)

        self.connection_status_label = QLabel("연결 안됨")
        self.connection_status_label.setStyleSheet("color: red;")
        port_layout.addWidget(self.connection_status_label)

        port_group.setLayout(port_layout)
        main_layout.addWidget(port_group)

        # 펌웨어 파일 그룹
        file_group = QGroupBox("펌웨어 파일")
        file_layout = QHBoxLayout()

        file_layout.addWidget(QLabel("S19 파일:"))

        self.file_entry = QLineEdit()
        self.file_entry.setMinimumWidth(280)
        self.file_entry.textChanged.connect(self.on_file_changed)
        file_layout.addWidget(self.file_entry)

        browse_button = QPushButton("찾아보기")
        browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(browse_button)

        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)

        # 진행 상태 그룹
        progress_group = QGroupBox("진행 상태")
        progress_layout = QVBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(self.progress_bar)

        status_layout = QHBoxLayout()
        self.status_label = QLabel("준비")
        status_font = QFont("Arial", 10)
        self.status_label.setFont(status_font)
        status_layout.addWidget(self.status_label)

        status_layout.addStretch()

        self.percentage_label = QLabel("0%")
        self.percentage_label.setFont(status_font)
        status_layout.addWidget(self.percentage_label)

        progress_layout.addLayout(status_layout)
        progress_group.setLayout(progress_layout)
        main_layout.addWidget(progress_group)

        # 컨트롤 버튼
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        self.flash_button = QPushButton("업데이트 시작")
        self.flash_button.setEnabled(False)
        self.flash_button.setMinimumWidth(150)
        self.flash_button.clicked.connect(self.start_flashing)
        button_layout.addWidget(self.flash_button)

        button_layout.addStretch()
        main_layout.addLayout(button_layout)

        # 로그 창 그룹
        log_group = QGroupBox("로그표시")
        log_layout = QVBoxLayout()
        log_layout.setContentsMargins(8, 8, 8, 12)  # 하단 마진 증가

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMinimumHeight(250)

        # 로그 폰트 설정 (크기 증가)
        log_font = QFont("Consolas", 10)  # 고정폭 폰트, 크기 10
        self.log_text.setFont(log_font)

        # 라인 간격 및 여백 조정
        self.log_text.setStyleSheet("""
            QTextEdit {
                line-height: 1.4;
                padding: 8px;
                padding-bottom: 15px;
            }
        """)

        # 텍스트 마진 설정으로 하단 공간 확보
        doc = self.log_text.document()
        doc.setDocumentMargin(10)

        log_layout.addWidget(self.log_text)

        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)

    def log_message(self, message):
        """로그 메시지 출력"""
        timestamp = time.strftime('%H:%M:%S')

        # 중요 메시지는 굵게 표시
        if any(keyword in message for keyword in ['완료', '성공', '실패', '오류', '에러', 'ACK', 'MCU']):
            # HTML 형식으로 강조
            formatted_message = f"<b>{timestamp} - {message}</b>"
        else:
            formatted_message = f"{timestamp} - {message}"

        self.log_text.append(formatted_message)

        # 자동 스크롤 - 항상 최신 로그가 보이도록
        cursor = self.log_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.log_text.setTextCursor(cursor)
        self.log_text.ensureCursorVisible()

        # 스크롤바를 맨 아래로 (추가 여유 공간 확보)
        scrollbar = self.log_text.verticalScrollBar()
        QTimer.singleShot(10, lambda: scrollbar.setValue(scrollbar.maximum()))

    def update_status(self, status, percentage=None):
        """상태 업데이트"""
        self.status_label.setText(status)
        if percentage is not None:
            self.progress_bar.setValue(int(percentage))
            self.percentage_label.setText(f"{int(percentage)}%")

    def refresh_com_ports(self):
        """COM 포트 목록 새로고침"""
        ports = []
        for port in serial.tools.list_ports.comports():
            ports.append(port.device)

        self.port_combo.clear()
        self.port_combo.addItems(ports)

        self.log_message(f"COM 포트 검색 완료: {len(ports)}개 포트 발견")

    def toggle_connection(self):
        """COM 포트 연결/해제"""
        if self.is_connected:
            self.disconnect_port()
        else:
            self.connect_port()

    def connect_port(self):
        """COM 포트 연결"""
        if not self.port_combo.currentText():
            QMessageBox.critical(self, "오류", "COM 포트를 선택해주세요.")
            return

        try:
            # 시리얼 포트 열기 (애플리케이션 통신 설정)
            self.ser = serial.Serial(
                port=self.port_combo.currentText(),
                baudrate=9600,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=1
            )

            self.is_connected = True
            self.connect_button.setText("연결 해제")
            self.connection_status_label.setText(f"연결됨: {self.port_combo.currentText()}")
            self.connection_status_label.setStyleSheet("color: green;")
            self.port_combo.setEnabled(False)
            self.log_message(f"{self.port_combo.currentText()} 포트에 연결되었습니다")

            # 업데이트 시작 버튼 상태 갱신
            self.update_flash_button_state()

        except serial.SerialException as e:
            QMessageBox.critical(self, "연결 오류", f"COM 포트 연결에 실패했습니다:\n{str(e)}")
            self.log_message(f"연결 오류: {str(e)}")

    def disconnect_port(self):
        """COM 포트 연결 해제"""
        if self.ser and self.ser.is_open:
            self.ser.close()

        self.is_connected = False
        self.connect_button.setText("연결")
        self.connection_status_label.setText("연결 안됨")
        self.connection_status_label.setStyleSheet("color: red;")
        self.port_combo.setEnabled(True)
        self.log_message("포트 연결이 해제되었습니다")

        # 업데이트 시작 버튼 상태 갱신
        self.update_flash_button_state()

    def update_flash_button_state(self):
        """업데이트 시작 버튼 활성화/비활성화 상태 업데이트"""
        # COM 포트가 연결되고 S19 파일이 선택되어 있으면 활성화
        file_path = self.file_entry.text()
        if (self.is_connected and
            file_path and
            os.path.exists(file_path) and
            file_path.lower().endswith('.s19')):
            self.flash_button.setEnabled(True)
        else:
            self.flash_button.setEnabled(False)

    def browse_file(self):
        """S19 파일 선택"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "S19 파일 선택",
            "",
            "S19 files (*.s19)"
        )
        if file_path:
            # 파일 확장자 검증
            if not file_path.lower().endswith('.s19'):
                QMessageBox.critical(
                    self,
                    "파일 형식 오류",
                    "S19 파일만 선택할 수 있습니다.\n확장자가 .s19인 파일을 선택해주세요."
                )
                self.log_message(f"파일 선택 실패: S19 파일이 아닙니다 - {os.path.basename(file_path)}")
                return

            self.file_entry.setText(file_path)
            self.log_message(f"파일 선택됨: {os.path.basename(file_path)}")

            # 업데이트 시작 버튼 상태 갱신
            self.update_flash_button_state()

    def on_file_changed(self):
        """파일 경로 변경 시"""
        self.update_flash_button_state()

    def validate_inputs(self):
        """입력값 검증"""
        if not self.is_connected:
            QMessageBox.critical(self, "오류", "COM 포트에 먼저 연결해주세요.")
            return False

        if not self.port_combo.currentText():
            QMessageBox.critical(self, "오류", "COM 포트를 선택해주세요.")
            return False

        file_path = self.file_entry.text()
        if not file_path:
            QMessageBox.critical(self, "오류", "S19 파일을 선택해주세요.")
            return False

        if not os.path.exists(file_path):
            QMessageBox.critical(self, "오류", "선택된 파일이 존재하지 않습니다.")
            return False

        # S19 파일 확장자 검증
        if not file_path.lower().endswith('.s19'):
            QMessageBox.critical(self, "오류", "S19 파일만 업데이트할 수 있습니다.\n확장자가 .s19인 파일을 선택해주세요.")
            return False

        return True

    def start_flashing(self):
        """펌웨어 업데이트 시작"""
        if not self.validate_inputs():
            return

        self.is_flashing = True
        self.flash_button.setEnabled(False)
        self.connect_button.setEnabled(False)

        # 로그 초기화
        self.log_text.clear()
        self.update_status("초기화 중...", 0)

        # 기존 시리얼 포트 닫기 (FlashWorker가 새로 열 수 있도록)
        if self.ser and self.ser.is_open:
            self.ser.close()
            self.log_message("기존 연결 닫는 중...")

        # 워커 스레드 생성 및 시작
        self.flash_worker = FlashWorker(
            self.port_combo.currentText(),
            self.file_entry.text()
        )
        self.flash_worker.progress_updated.connect(self.on_progress_updated)
        self.flash_worker.log_message.connect(self.log_message)
        self.flash_worker.finished.connect(self.on_flashing_finished)
        self.flash_worker.start()

    def on_progress_updated(self, status, percentage):
        """진행률 업데이트 슬롯"""
        self.update_status(status, percentage)

    def on_flashing_finished(self, success):
        """플래싱 완료 슬롯"""
        self.is_flashing = False
        self.connect_button.setEnabled(True)

        # 애플리케이션 통신용으로 다시 연결
        if success:
            # 잠시 대기 (MCU 리셋 시간)
            QTimer.singleShot(1000, self.reconnect_after_flash)
        else:
            # 실패 시 연결 상태 초기화
            self.is_connected = False
            self.connect_button.setText("연결")
            self.connection_status_label.setText("연결 안됨")
            self.connection_status_label.setStyleSheet("color: red;")
            self.port_combo.setEnabled(True)
            self.update_flash_button_state()

        # 워커 정리
        if self.flash_worker:
            self.flash_worker.wait()
            self.flash_worker = None

    def reconnect_after_flash(self):
        """플래싱 완료 후 재연결"""
        try:
            self.ser = serial.Serial(
                port=self.port_combo.currentText(),
                baudrate=9600,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=1
            )
            # 연결 상태 유지
            self.is_connected = True
            self.connect_button.setText("연결 해제")
            self.connection_status_label.setText(f"연결됨: {self.port_combo.currentText()}")
            self.connection_status_label.setStyleSheet("color: green;")
            self.port_combo.setEnabled(False)
            self.log_message("애플리케이션 통신 모드로 재연결되었습니다")
        except Exception as e:
            # 재연결 실패 시 연결 상태 초기화
            self.is_connected = False
            self.connect_button.setText("연결")
            self.connection_status_label.setText("연결 안됨")
            self.connection_status_label.setStyleSheet("color: red;")
            self.port_combo.setEnabled(True)
            self.log_message(f"재연결 실패: {str(e)}")
            self.log_message("수동으로 다시 연결해주세요")

        # 업데이트 시작 버튼 상태 갱신
        self.update_flash_button_state()

    def closeEvent(self, event):
        """프로그램 종료 시 처리"""
        if self.is_flashing:
            QMessageBox.warning(
                self,
                "경고",
                "펌웨어 업데이트가 진행 중입니다.\n업데이트가 완료될 때까지 기다려주세요."
            )
            event.ignore()
            return

        # 연결 해제 및 종료
        if self.is_connected:
            self.disconnect_port()
        if self.ser and self.ser.is_open:
            self.ser.close()

        event.accept()


def main():
    app = QApplication(sys.argv)
    window = STM32FlasherGUI()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
