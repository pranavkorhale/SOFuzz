"""
SOFuzz - ELF Parser
Parses ELF file structure
"""

import struct
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.file_utils import FileUtils
from ..utils.constants import (
    ELF_MAGIC,
    ELFClass,
    ELFData,
    ELFType,
    ELFMachine,
    SectionType,
    MACHINE_NAMES
)


@dataclass
class ELFHeader:
    """ELF file header"""
    ei_class: int = 0
    ei_data: int = 0
    ei_version: int = 0
    ei_osabi: int = 0
    e_type: int = 0
    e_machine: int = 0
    e_version: int = 0
    e_entry: int = 0
    e_phoff: int = 0
    e_shoff: int = 0
    e_flags: int = 0
    e_ehsize: int = 0
    e_phentsize: int = 0
    e_phnum: int = 0
    e_shentsize: int = 0
    e_shnum: int = 0
    e_shstrndx: int = 0
    
    @property
    def is_64bit(self) -> bool:
        return self.ei_class == ELFClass.ELFCLASS64
    
    @property
    def is_little_endian(self) -> bool:
        return self.ei_data == ELFData.ELFDATA2LSB
    
    @property
    def is_shared_object(self) -> bool:
        return self.e_type == ELFType.ET_DYN
    
    @property
    def machine_name(self) -> str:
        return MACHINE_NAMES.get(self.e_machine, f"Unknown ({self.e_machine})")


@dataclass
class SectionHeader:
    """ELF section header"""
    sh_name: int = 0
    sh_type: int = 0
    sh_flags: int = 0
    sh_addr: int = 0
    sh_offset: int = 0
    sh_size: int = 0
    sh_link: int = 0
    sh_info: int = 0
    sh_addralign: int = 0
    sh_entsize: int = 0
    name: str = ""


@dataclass
class ProgramHeader:
    """ELF program header"""
    p_type: int = 0
    p_flags: int = 0
    p_offset: int = 0
    p_vaddr: int = 0
    p_paddr: int = 0
    p_filesz: int = 0
    p_memsz: int = 0
    p_align: int = 0


@dataclass
class ELFInfo:
    """Complete ELF file information"""
    path: str = ""
    size: int = 0
    header: ELFHeader = field(default_factory=ELFHeader)
    sections: List[SectionHeader] = field(default_factory=list)
    programs: List[ProgramHeader] = field(default_factory=list)
    is_valid: bool = False
    error: Optional[str] = None


class ELFParser:
    """
    Parses ELF file structure
    """
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.logger = get_logger()
        self.data: bytes = b''
        self.endian: str = '<'
        self.is_64bit: bool = True
    
    def parse(self) -> ELFInfo:
        """Parse the ELF file"""
        info = ELFInfo(path=self.file_path)
        
        try:
            if not FileUtils.file_exists(self.file_path):
                info.error = f"File not found: {self.file_path}"
                return info
            
            self.data = FileUtils.read_file(self.file_path)
            info.size = len(self.data)
            
            if not self._validate_magic():
                info.error = "Not a valid ELF file"
                return info
            
            info.header = self._parse_header()
            self.is_64bit = info.header.is_64bit
            self.endian = '<' if info.header.is_little_endian else '>'
            
            info.sections = self._parse_sections(info.header)
            self._resolve_section_names(info.sections, info.header)
            info.programs = self._parse_programs(info.header)
            
            info.is_valid = True
            self.logger.debug(f"Parsed ELF: {self.file_path}")
            
        except Exception as e:
            info.error = str(e)
            self.logger.error(f"ELF parsing failed: {e}")
        
        return info
    
    def _validate_magic(self) -> bool:
        """Validate ELF magic bytes"""
        if len(self.data) < 4:
            return False
        return self.data[:4] == ELF_MAGIC
    
    def _parse_header(self) -> ELFHeader:
        """Parse ELF header"""
        header = ELFHeader()
        
        header.ei_class = self.data[4]
        header.ei_data = self.data[5]
        header.ei_version = self.data[6]
        header.ei_osabi = self.data[7]
        
        self.endian = '<' if header.ei_data == ELFData.ELFDATA2LSB else '>'
        self.is_64bit = header.ei_class == ELFClass.ELFCLASS64
        
        if self.is_64bit:
            fmt = f"{self.endian}HHIQQQIHHHHHH"
            offset = 16
            size = 48
            
            values = struct.unpack(fmt, self.data[offset:offset + size])
            
            header.e_type = values[0]
            header.e_machine = values[1]
            header.e_version = values[2]
            header.e_entry = values[3]
            header.e_phoff = values[4]
            header.e_shoff = values[5]
            header.e_flags = values[6]
            header.e_ehsize = values[7]
            header.e_phentsize = values[8]
            header.e_phnum = values[9]
            header.e_shentsize = values[10]
            header.e_shnum = values[11]
            header.e_shstrndx = values[12]
        else:
            fmt = f"{self.endian}HHIIIIIHHHHHH"
            offset = 16
            size = 36
            
            values = struct.unpack(fmt, self.data[offset:offset + size])
            
            header.e_type = values[0]
            header.e_machine = values[1]
            header.e_version = values[2]
            header.e_entry = values[3]
            header.e_phoff = values[4]
            header.e_shoff = values[5]
            header.e_flags = values[6]
            header.e_ehsize = values[7]
            header.e_phentsize = values[8]
            header.e_phnum = values[9]
            header.e_shentsize = values[10]
            header.e_shnum = values[11]
            header.e_shstrndx = values[12]
        
        return header
    
    def _parse_sections(self, header: ELFHeader) -> List[SectionHeader]:
        """Parse section headers"""
        sections = []
        
        if header.e_shoff == 0:
            return sections
        
        for i in range(header.e_shnum):
            offset = header.e_shoff + (i * header.e_shentsize)
            section = self._parse_section_header(offset)
            sections.append(section)
        
        return sections
    
    def _parse_section_header(self, offset: int) -> SectionHeader:
        """Parse a single section header"""
        section = SectionHeader()
        
        if self.is_64bit:
            fmt = f"{self.endian}IIQQQQIIQQ"
            size = 64
            
            values = struct.unpack(fmt, self.data[offset:offset + size])
            
            section.sh_name = values[0]
            section.sh_type = values[1]
            section.sh_flags = values[2]
            section.sh_addr = values[3]
            section.sh_offset = values[4]
            section.sh_size = values[5]
            section.sh_link = values[6]
            section.sh_info = values[7]
            section.sh_addralign = values[8]
            section.sh_entsize = values[9]
        else:
            fmt = f"{self.endian}IIIIIIIIII"
            size = 40
            
            values = struct.unpack(fmt, self.data[offset:offset + size])
            
            section.sh_name = values[0]
            section.sh_type = values[1]
            section.sh_flags = values[2]
            section.sh_addr = values[3]
            section.sh_offset = values[4]
            section.sh_size = values[5]
            section.sh_link = values[6]
            section.sh_info = values[7]
            section.sh_addralign = values[8]
            section.sh_entsize = values[9]
        
        return section
    
    def _resolve_section_names(self, sections: List[SectionHeader], header: ELFHeader) -> None:
        """Resolve section names from string table"""
        if header.e_shstrndx >= len(sections):
            return
        
        strtab_section = sections[header.e_shstrndx]
        strtab_offset = strtab_section.sh_offset
        strtab_size = strtab_section.sh_size
        
        strtab = self.data[strtab_offset:strtab_offset + strtab_size]
        
        for section in sections:
            name_offset = section.sh_name
            if name_offset < len(strtab):
                name_end = strtab.find(b'\x00', name_offset)
                if name_end == -1:
                    name_end = len(strtab)
                section.name = strtab[name_offset:name_end].decode('utf-8', errors='ignore')
    
    def _parse_programs(self, header: ELFHeader) -> List[ProgramHeader]:
        """Parse program headers"""
        programs = []
        
        if header.e_phoff == 0:
            return programs
        
        for i in range(header.e_phnum):
            offset = header.e_phoff + (i * header.e_phentsize)
            program = self._parse_program_header(offset)
            programs.append(program)
        
        return programs
    
    def _parse_program_header(self, offset: int) -> ProgramHeader:
        """Parse a single program header"""
        program = ProgramHeader()
        
        if self.is_64bit:
            fmt = f"{self.endian}IIQQQQQQ"
            size = 56
            
            values = struct.unpack(fmt, self.data[offset:offset + size])
            
            program.p_type = values[0]
            program.p_flags = values[1]
            program.p_offset = values[2]
            program.p_vaddr = values[3]
            program.p_paddr = values[4]
            program.p_filesz = values[5]
            program.p_memsz = values[6]
            program.p_align = values[7]
        else:
            fmt = f"{self.endian}IIIIIIII"
            size = 32
            
            values = struct.unpack(fmt, self.data[offset:offset + size])
            
            program.p_type = values[0]
            program.p_offset = values[1]
            program.p_vaddr = values[2]
            program.p_paddr = values[3]
            program.p_filesz = values[4]
            program.p_memsz = values[5]
            program.p_flags = values[6]
            program.p_align = values[7]
        
        return program
    
    def get_section_by_name(self, name: str) -> Optional[SectionHeader]:
        """Get section by name"""
        info = self.parse()
        for section in info.sections:
            if section.name == name:
                return section
        return None
    
    def get_section_data(self, section: SectionHeader) -> bytes:
        """Get raw data for a section"""
        if not self.data:
            self.data = FileUtils.read_file(self.file_path)
        return self.data[section.sh_offset:section.sh_offset + section.sh_size]
    
    def get_raw_data(self) -> bytes:
        """Get raw file data"""
        if not self.data:
            self.data = FileUtils.read_file(self.file_path)
        return self.data