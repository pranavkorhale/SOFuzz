"""
SOFuzz - Architecture Detector
Detects architecture of .so files
"""

import struct
import platform
from typing import Optional, Tuple
from dataclasses import dataclass

from ..utils.logger import get_logger
from ..utils.file_utils import FileUtils
from ..utils.constants import (
    ELF_MAGIC,
    ELFClass,
    ELFData,
    ELFMachine,
    MACHINE_NAMES
)


@dataclass
class ArchInfo:
    """Architecture information"""
    machine: int
    machine_name: str
    bits: int
    endianness: str
    is_valid: bool = True
    error: Optional[str] = None


class ArchDetector:
    """
    Detects architecture of ELF/SO files
    """
    
    def __init__(self):
        self.logger = get_logger()
    
    def detect(self, file_path: str) -> ArchInfo:
        """Detect architecture of an ELF file"""
        try:
            if not FileUtils.file_exists(file_path):
                return ArchInfo(
                    machine=0,
                    machine_name="Unknown",
                    bits=0,
                    endianness="unknown",
                    is_valid=False,
                    error=f"File not found: {file_path}"
                )
            
            with open(file_path, 'rb') as f:
                header = f.read(20)
                
                if len(header) < 20:
                    return ArchInfo(
                        machine=0,
                        machine_name="Unknown",
                        bits=0,
                        endianness="unknown",
                        is_valid=False,
                        error="File too small"
                    )
                
                if header[:4] != ELF_MAGIC:
                    return ArchInfo(
                        machine=0,
                        machine_name="Unknown",
                        bits=0,
                        endianness="unknown",
                        is_valid=False,
                        error="Not an ELF file"
                    )
                
                ei_class = header[4]
                ei_data = header[5]
                
                if ei_class == ELFClass.ELFCLASS32:
                    bits = 32
                elif ei_class == ELFClass.ELFCLASS64:
                    bits = 64
                else:
                    bits = 0
                
                if ei_data == ELFData.ELFDATA2LSB:
                    endianness = "little"
                    endian_char = '<'
                elif ei_data == ELFData.ELFDATA2MSB:
                    endianness = "big"
                    endian_char = '>'
                else:
                    endianness = "unknown"
                    endian_char = '<'
                
                machine = struct.unpack(f"{endian_char}H", header[18:20])[0]
                machine_name = MACHINE_NAMES.get(machine, f"Unknown ({machine})")
                
                return ArchInfo(
                    machine=machine,
                    machine_name=machine_name,
                    bits=bits,
                    endianness=endianness,
                    is_valid=True
                )
                
        except Exception as e:
            self.logger.error(f"Architecture detection failed: {e}")
            return ArchInfo(
                machine=0,
                machine_name="Unknown",
                bits=0,
                endianness="unknown",
                is_valid=False,
                error=str(e)
            )
    
    def is_compatible(self, file_path: str) -> bool:
        """Check if file is compatible with current system"""
        info = self.detect(file_path)
        
        if not info.is_valid:
            return False
        
        machine = platform.machine().lower()
        
        system_machine_map = {
            'x86_64': ELFMachine.EM_X86_64,
            'amd64': ELFMachine.EM_X86_64,
            'i386': ELFMachine.EM_386,
            'i686': ELFMachine.EM_386,
            'aarch64': ELFMachine.EM_AARCH64,
            'arm64': ELFMachine.EM_AARCH64,
            'armv7l': ELFMachine.EM_ARM,
            'arm': ELFMachine.EM_ARM,
        }
        
        expected_machine = system_machine_map.get(machine)
        
        if expected_machine is None:
            return False
        
        # x86_64 systems can also run x86 binaries
        if expected_machine == ELFMachine.EM_X86_64:
            return info.machine in [ELFMachine.EM_X86_64, ELFMachine.EM_386]
        
        return info.machine == expected_machine
    
    def get_system_arch(self) -> str:
        """Get current system architecture"""
        machine = platform.machine().lower()
        
        arch_map = {
            'x86_64': 'x86_64',
            'amd64': 'x86_64',
            'i386': 'x86',
            'i686': 'x86',
            'aarch64': 'arm64-v8a',
            'arm64': 'arm64-v8a',
            'armv7l': 'armeabi-v7a',
            'arm': 'armeabi-v7a',
        }
        
        return arch_map.get(machine, machine)
    
    def can_emulate(self, file_path: str) -> Tuple[bool, str]:
        """
        Check if file can be emulated using QEMU
        
        Returns:
            Tuple of (can_emulate, emulator_command)
        """
        info = self.detect(file_path)
        
        if not info.is_valid:
            return False, ""
        
        emulators = {
            ELFMachine.EM_ARM: "qemu-arm",
            ELFMachine.EM_AARCH64: "qemu-aarch64",
            ELFMachine.EM_386: "qemu-i386",
            ELFMachine.EM_X86_64: "qemu-x86_64",
        }
        
        emulator = emulators.get(info.machine)
        
        if emulator:
            # Check if emulator is available
            from ..utils.process_utils import ProcessUtils
            if ProcessUtils.check_command_exists(emulator):
                return True, emulator
        
        return False, ""