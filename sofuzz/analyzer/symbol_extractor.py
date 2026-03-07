"""
SOFuzz - Symbol Extractor
Extracts symbols from ELF files
"""

import struct
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from ..utils.logger import get_logger
from ..utils.constants import (
    SymbolType,
    SymbolBinding,
    SectionType,
    SKIP_FUNCTION_PREFIXES
)
from .elf_parser import ELFParser, ELFInfo, SectionHeader


@dataclass
class Symbol:
    """Represents an ELF symbol"""
    name: str = ""
    value: int = 0
    size: int = 0
    sym_type: int = 0
    binding: int = 0
    visibility: int = 0
    section_index: int = 0
    
    @property
    def type_name(self) -> str:
        types = {
            0: "NOTYPE",
            1: "OBJECT",
            2: "FUNC",
            3: "SECTION",
            4: "FILE",
            5: "COMMON",
            6: "TLS",
        }
        return types.get(self.sym_type, f"UNKNOWN({self.sym_type})")
    
    @property
    def binding_name(self) -> str:
        bindings = {
            0: "LOCAL",
            1: "GLOBAL",
            2: "WEAK",
        }
        return bindings.get(self.binding, f"UNKNOWN({self.binding})")
    
    @property
    def is_function(self) -> bool:
        return self.sym_type == SymbolType.STT_FUNC
    
    @property
    def is_global(self) -> bool:
        return self.binding == SymbolBinding.STB_GLOBAL
    
    @property
    def is_defined(self) -> bool:
        return self.section_index != 0


@dataclass
class SymbolTable:
    """Collection of symbols"""
    symbols: List[Symbol] = field(default_factory=list)
    functions: List[Symbol] = field(default_factory=list)
    objects: List[Symbol] = field(default_factory=list)
    total_count: int = 0
    function_count: int = 0
    object_count: int = 0


class SymbolExtractor:
    """
    Extracts symbols from ELF files
    
    Usage:
        extractor = SymbolExtractor("libnative.so")
        symbols = extractor.extract()
        
        for func in symbols.functions:
            print(f"Function: {func.name} at 0x{func.value:x}")
    """
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.logger = get_logger()
        self.parser = ELFParser(file_path)
        self.elf_info: Optional[ELFInfo] = None
        self.data: bytes = b''
        self.endian: str = '<'
        self.is_64bit: bool = True
    
    def extract(self) -> SymbolTable:
        """
        Extract all symbols from ELF file
        
        Returns:
            SymbolTable with all symbols
        """
        symbol_table = SymbolTable()
        
        try:
            # Parse ELF file
            self.elf_info = self.parser.parse()
            
            if not self.elf_info.is_valid:
                self.logger.error(f"Invalid ELF file: {self.elf_info.error}")
                return symbol_table
            
            self.data = self.parser.get_raw_data()
            self.endian = '<' if self.elf_info.header.is_little_endian else '>'
            self.is_64bit = self.elf_info.header.is_64bit
            
            # Extract from .dynsym (dynamic symbols - exported)
            dynsym_section = self._get_section_by_name(".dynsym")
            dynstr_section = self._get_section_by_name(".dynstr")
            
            if dynsym_section and dynstr_section:
                symbols = self._extract_symbols(dynsym_section, dynstr_section)
                symbol_table.symbols.extend(symbols)
            
            # Extract from .symtab (all symbols - if available)
            symtab_section = self._get_section_by_name(".symtab")
            strtab_section = self._get_section_by_name(".strtab")
            
            if symtab_section and strtab_section:
                symbols = self._extract_symbols(symtab_section, strtab_section)
                # Avoid duplicates
                existing_names = {s.name for s in symbol_table.symbols}
                for sym in symbols:
                    if sym.name not in existing_names:
                        symbol_table.symbols.append(sym)
            
            # Categorize symbols
            for sym in symbol_table.symbols:
                if sym.is_function:
                    symbol_table.functions.append(sym)
                elif sym.sym_type == SymbolType.STT_OBJECT:
                    symbol_table.objects.append(sym)
            
            symbol_table.total_count = len(symbol_table.symbols)
            symbol_table.function_count = len(symbol_table.functions)
            symbol_table.object_count = len(symbol_table.objects)
            
            self.logger.info(f"Extracted {symbol_table.function_count} functions, {symbol_table.object_count} objects")
            
        except Exception as e:
            self.logger.error(f"Symbol extraction failed: {e}")
        
        return symbol_table
    
    def _get_section_by_name(self, name: str) -> Optional[SectionHeader]:
        """Get section by name"""
        if not self.elf_info:
            return None
        for section in self.elf_info.sections:
            if section.name == name:
                return section
        return None
    
    def _extract_symbols(self, sym_section: SectionHeader, str_section: SectionHeader) -> List[Symbol]:
        """Extract symbols from a symbol table section"""
        symbols = []
        
        # Get string table
        strtab = self.data[str_section.sh_offset:str_section.sh_offset + str_section.sh_size]
        
        # Calculate entry size
        if self.is_64bit:
            entry_size = 24  # sizeof(Elf64_Sym)
        else:
            entry_size = 16  # sizeof(Elf32_Sym)
        
        if sym_section.sh_entsize > 0:
            entry_size = sym_section.sh_entsize
        
        # Calculate number of symbols
        num_symbols = sym_section.sh_size // entry_size
        
        for i in range(num_symbols):
            offset = sym_section.sh_offset + (i * entry_size)
            symbol = self._parse_symbol(offset, strtab)
            if symbol.name:  # Only add symbols with names
                symbols.append(symbol)
        
        return symbols
    
    def _parse_symbol(self, offset: int, strtab: bytes) -> Symbol:
        """Parse a single symbol entry"""
        symbol = Symbol()
        
        if self.is_64bit:
            # Elf64_Sym structure
            fmt = f"{self.endian}IBBHQQ"
            values = struct.unpack(fmt, self.data[offset:offset + 24])
            
            st_name = values[0]
            st_info = values[1]
            st_other = values[2]
            symbol.section_index = values[3]
            symbol.value = values[4]
            symbol.size = values[5]
        else:
            # Elf32_Sym structure
            fmt = f"{self.endian}IIIBBH"
            values = struct.unpack(fmt, self.data[offset:offset + 16])
            
            st_name = values[0]
            symbol.value = values[1]
            symbol.size = values[2]
            st_info = values[3]
            st_other = values[4]
            symbol.section_index = values[5]
        
        # Extract type and binding from st_info
        symbol.sym_type = st_info & 0xf
        symbol.binding = st_info >> 4
        symbol.visibility = st_other & 0x3
        
        # Get symbol name from string table
        if st_name < len(strtab):
            name_end = strtab.find(b'\x00', st_name)
            if name_end == -1:
                name_end = len(strtab)
            symbol.name = strtab[st_name:name_end].decode('utf-8', errors='ignore')
        
        return symbol
    
    def get_exported_functions(self, skip_internal: bool = True) -> List[Symbol]:
        """
        Get only exported (global, defined) functions
        
        Args:
            skip_internal: Skip internal functions (like __cxa_*)
        
        Returns:
            List of exported function symbols
        """
        symbol_table = self.extract()
        exported = []
        
        for func in symbol_table.functions:
            # Must be global or weak and defined
            if not (func.is_global or func.binding == SymbolBinding.STB_WEAK):
                continue
            if not func.is_defined:
                continue
            
            # Skip internal functions
            if skip_internal:
                skip = False
                for prefix in SKIP_FUNCTION_PREFIXES:
                    if func.name.startswith(prefix):
                        skip = True
                        break
                if skip:
                    continue
            
            exported.append(func)
        
        return exported
    
    def get_function_by_name(self, name: str) -> Optional[Symbol]:
        """Get a specific function by name"""
        symbol_table = self.extract()
        
        for func in symbol_table.functions:
            if func.name == name:
                return func
        
        return None
    
    def print_symbols(self) -> None:
        """Print all symbols (for debugging)"""
        symbol_table = self.extract()
        
        print(f"\n{'='*70}")
        print(f"Symbols in {self.file_path}")
        print(f"{'='*70}")
        print(f"{'Name':<40} {'Type':<10} {'Bind':<8} {'Address':<16} {'Size':<8}")
        print(f"{'-'*70}")
        
        for sym in symbol_table.symbols:
            print(f"{sym.name:<40} {sym.type_name:<10} {sym.binding_name:<8} 0x{sym.value:<14x} {sym.size:<8}")
        
        print(f"\nTotal: {symbol_table.total_count} symbols")
        print(f"Functions: {symbol_table.function_count}")
        print(f"Objects: {symbol_table.object_count}")