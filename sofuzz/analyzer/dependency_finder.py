"""
SOFuzz - Dependency Finder
Finds library dependencies in ELF files
"""

import struct
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from ..utils.logger import get_logger
from .elf_parser import ELFParser, ELFInfo, SectionHeader


DT_NULL = 0
DT_NEEDED = 1
DT_STRTAB = 5
DT_STRSZ = 10
DT_SONAME = 14
DT_RPATH = 15
DT_RUNPATH = 29


@dataclass
class DependencyInfo:
    needed_libs: List[str] = field(default_factory=list)
    soname: Optional[str] = None
    rpath: Optional[str] = None
    runpath: Optional[str] = None


class DependencyFinder:
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.logger = get_logger()
        self.parser = ELFParser(file_path)
        self.elf_info: Optional[ELFInfo] = None
        self.data: bytes = b''
        self.endian: str = '<'
        self.is_64bit: bool = True
    
    def find(self) -> DependencyInfo:
        dep_info = DependencyInfo()
        
        try:
            self.elf_info = self.parser.parse()
            
            if not self.elf_info.is_valid:
                self.logger.error(f"Invalid ELF file: {self.elf_info.error}")
                return dep_info
            
            self.data = self.parser.get_raw_data()
            self.endian = '<' if self.elf_info.header.is_little_endian else '>'
            self.is_64bit = self.elf_info.header.is_64bit
            
            dynamic_section = self._get_section_by_name(".dynamic")
            dynstr_section = self._get_section_by_name(".dynstr")
            
            if not dynamic_section or not dynstr_section:
                self.logger.warning("No .dynamic section found")
                return dep_info
            
            dynstr = self.data[dynstr_section.sh_offset:dynstr_section.sh_offset + dynstr_section.sh_size]
            dep_info = self._parse_dynamic_section(dynamic_section, dynstr)
            
            self.logger.info(f"Found {len(dep_info.needed_libs)} dependencies")
            
        except Exception as e:
            self.logger.error(f"Dependency finding failed: {e}")
        
        return dep_info
    
    def _get_section_by_name(self, name: str) -> Optional[SectionHeader]:
        if not self.elf_info:
            return None
        for section in self.elf_info.sections:
            if section.name == name:
                return section
        return None
    
    def _parse_dynamic_section(self, dynamic: SectionHeader, dynstr: bytes) -> DependencyInfo:
        dep_info = DependencyInfo()
        
        if self.is_64bit:
            entry_size = 16
        else:
            entry_size = 8
        
        num_entries = dynamic.sh_size // entry_size
        
        for i in range(num_entries):
            offset = dynamic.sh_offset + (i * entry_size)
            
            if self.is_64bit:
                fmt = f"{self.endian}QQ"
                d_tag, d_val = struct.unpack(fmt, self.data[offset:offset + 16])
            else:
                fmt = f"{self.endian}II"
                d_tag, d_val = struct.unpack(fmt, self.data[offset:offset + 8])
            
            if d_tag == DT_NULL:
                break
            
            if d_tag in [DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH]:
                string_val = self._get_string(dynstr, d_val)
                
                if d_tag == DT_NEEDED:
                    dep_info.needed_libs.append(string_val)
                elif d_tag == DT_SONAME:
                    dep_info.soname = string_val
                elif d_tag == DT_RPATH:
                    dep_info.rpath = string_val
                elif d_tag == DT_RUNPATH:
                    dep_info.runpath = string_val
        
        return dep_info
    
    def _get_string(self, strtab: bytes, offset: int) -> str:
        if offset >= len(strtab):
            return ""
        end = strtab.find(b'\x00', offset)
        if end == -1:
            end = len(strtab)
        return strtab[offset:end].decode('utf-8', errors='ignore')
    
    def get_needed_libs(self) -> List[str]:
        dep_info = self.find()
        return dep_info.needed_libs
    
    def print_dependencies(self) -> None:
        dep_info = self.find()
        
        print(f"\n{'='*50}")
        print(f"Dependencies for {self.file_path}")
        print(f"{'='*50}")
        
        if dep_info.soname:
            print(f"SONAME: {dep_info.soname}")
        
        if dep_info.rpath:
            print(f"RPATH: {dep_info.rpath}")
        
        if dep_info.runpath:
            print(f"RUNPATH: {dep_info.runpath}")
        
        print(f"\nNeeded libraries:")
        for lib in dep_info.needed_libs:
            print(f"  - {lib}")
        
        print(f"\nTotal: {len(dep_info.needed_libs)} dependencies")
