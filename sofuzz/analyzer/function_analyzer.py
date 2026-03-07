"""
SOFuzz - Function Analyzer
Analyzes functions in ELF files for fuzzing
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

from ..utils.logger import get_logger
from ..utils.file_utils import FileUtils
from ..utils.constants import SKIP_FUNCTION_PREFIXES
from .elf_parser import ELFParser, ELFInfo
from .symbol_extractor import SymbolExtractor, Symbol, SymbolTable
from .dependency_finder import DependencyFinder, DependencyInfo


@dataclass
class FunctionInfo:
    """Detailed function information for fuzzing"""
    name: str
    address: int
    size: int
    binding: str
    is_exported: bool
    is_jni: bool = False
    estimated_params: int = 0
    risk_score: int = 0
    notes: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    """Complete analysis result"""
    file_path: str
    file_size: int
    architecture: str
    is_64bit: bool
    is_valid: bool
    all_functions: List[FunctionInfo] = field(default_factory=list)
    fuzzable_functions: List[FunctionInfo] = field(default_factory=list)
    jni_functions: List[FunctionInfo] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    total_functions: int = 0
    fuzzable_count: int = 0
    jni_count: int = 0
    errors: List[str] = field(default_factory=list)


class FunctionAnalyzer:
    """
    Analyzes functions in ELF files to identify fuzzing targets
    """
    
    INTERESTING_KEYWORDS = [
        'parse', 'read', 'load', 'decode', 'decompress',
        'process', 'handle', 'input', 'data', 'buffer',
        'string', 'copy', 'alloc', 'free', 'memory',
        'encrypt', 'decrypt', 'hash', 'sign', 'verify',
        'network', 'socket', 'connect', 'send', 'recv',
        'file', 'open', 'write', 'image', 'audio', 'video',
        'json', 'xml', 'html', 'url', 'http',
        'deserialize', 'unmarshal', 'convert', 'transform',
    ]
    
    RISKY_KEYWORDS = [
        'unsafe', 'raw', 'native', 'jni', 'c_str',
        'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
        'memcpy', 'memmove', 'alloc', 'realloc',
    ]
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.logger = get_logger()
        self.elf_parser = ELFParser(file_path)
        self.symbol_extractor = SymbolExtractor(file_path)
        self.dependency_finder = DependencyFinder(file_path)
    
    def analyze(self) -> AnalysisResult:
        """Perform complete analysis"""
        result = AnalysisResult(
            file_path=self.file_path,
            file_size=0,
            architecture="",
            is_64bit=False,
            is_valid=False
        )
        
        try:
            if not FileUtils.file_exists(self.file_path):
                result.errors.append(f"File not found: {self.file_path}")
                return result
            
            result.file_size = FileUtils.get_file_size(self.file_path)
            
            elf_info = self.elf_parser.parse()
            
            if not elf_info.is_valid:
                result.errors.append(f"Invalid ELF: {elf_info.error}")
                return result
            
            result.is_valid = True
            result.architecture = elf_info.header.machine_name
            result.is_64bit = elf_info.header.is_64bit
            
            symbol_table = self.symbol_extractor.extract()
            
            for sym in symbol_table.functions:
                func_info = self._analyze_function(sym)
                result.all_functions.append(func_info)
                
                if func_info.is_jni:
                    result.jni_functions.append(func_info)
                
                if self._is_fuzzable(func_info):
                    result.fuzzable_functions.append(func_info)
            
            result.fuzzable_functions.sort(key=lambda f: f.risk_score, reverse=True)
            
            dep_info = self.dependency_finder.find()
            result.dependencies = dep_info.needed_libs
            
            result.total_functions = len(result.all_functions)
            result.fuzzable_count = len(result.fuzzable_functions)
            result.jni_count = len(result.jni_functions)
            
            self.logger.info(f"Analysis complete: {result.fuzzable_count} fuzzable functions")
            
        except Exception as e:
            result.errors.append(str(e))
            self.logger.error(f"Analysis failed: {e}")
        
        return result
    
    def _analyze_function(self, symbol: Symbol) -> FunctionInfo:
        """Analyze a single function"""
        func = FunctionInfo(
            name=symbol.name,
            address=symbol.value,
            size=symbol.size,
            binding=symbol.binding_name,
            is_exported=symbol.is_global and symbol.is_defined
        )
        
        if symbol.name.startswith("Java_"):
            func.is_jni = True
            func.notes.append("JNI function")
            func.risk_score += 20
        
        name_lower = symbol.name.lower()
        
        for keyword in self.INTERESTING_KEYWORDS:
            if keyword in name_lower:
                func.risk_score += 10
                func.notes.append(f"Contains '{keyword}'")
        
        for keyword in self.RISKY_KEYWORDS:
            if keyword in name_lower:
                func.risk_score += 15
                func.notes.append(f"Risky: contains '{keyword}'")
        
        if symbol.size > 500:
            func.risk_score += 5
            func.notes.append("Large function")
        elif symbol.size > 1000:
            func.risk_score += 10
            func.notes.append("Very large function")
        
        if symbol.size > 0:
            func.estimated_params = min(symbol.size // 50, 10)
        
        return func
    
    def _is_fuzzable(self, func: FunctionInfo) -> bool:
        """Check if function should be fuzzed"""
        if not func.is_exported:
            return False
        
        for prefix in SKIP_FUNCTION_PREFIXES:
            if func.name.startswith(prefix):
                return False
        
        if func.size > 0 and func.size < 10:
            return False
        
        return True
    
    def get_top_targets(self, count: int = 10) -> List[FunctionInfo]:
        """Get top fuzzing targets by risk score"""
        result = self.analyze()
        return result.fuzzable_functions[:count]
    
    def get_jni_functions(self) -> List[FunctionInfo]:
        """Get all JNI functions"""
        result = self.analyze()
        return result.jni_functions
    
    def print_analysis(self) -> None:
        """Print analysis results"""
        result = self.analyze()
        
        print(f"\n{'='*70}")
        print(f"Analysis: {result.file_path}")
        print(f"{'='*70}")
        print(f"Architecture: {result.architecture}")
        print(f"64-bit: {result.is_64bit}")
        print(f"File size: {result.file_size} bytes")
        print(f"Total functions: {result.total_functions}")
        print(f"Fuzzable functions: {result.fuzzable_count}")
        print(f"JNI functions: {result.jni_count}")
        
        print(f"\n{'='*70}")
        print("Top Fuzzing Targets (by risk score):")
        print(f"{'='*70}")
        print(f"{'Name':<40} {'Address':<14} {'Size':<8} {'Score':<6}")
        print(f"{'-'*70}")
        
        for func in result.fuzzable_functions[:20]:
            print(f"{func.name:<40} 0x{func.address:<12x} {func.size:<8} {func.risk_score:<6}")
            if func.notes:
                for note in func.notes[:2]:
                    print(f"  └─ {note}")
        
        if result.jni_count > 0:
            print(f"\n{'='*70}")
            print("JNI Functions:")
            print(f"{'='*70}")
            for func in result.jni_functions:
                print(f"  {func.name}")
        
        if result.dependencies:
            print(f"\n{'='*70}")
            print("Dependencies:")
            print(f"{'='*70}")
            for dep in result.dependencies:
                print(f"  - {dep}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert analysis to dictionary (for JSON export)"""
        result = self.analyze()
        
        return {
            'file_path': result.file_path,
            'file_size': result.file_size,
            'architecture': result.architecture,
            'is_64bit': result.is_64bit,
            'is_valid': result.is_valid,
            'total_functions': result.total_functions,
            'fuzzable_count': result.fuzzable_count,
            'jni_count': result.jni_count,
            'dependencies': result.dependencies,
            'fuzzable_functions': [
                {
                    'name': f.name,
                    'address': hex(f.address),
                    'size': f.size,
                    'binding': f.binding,
                    'is_jni': f.is_jni,
                    'risk_score': f.risk_score,
                    'notes': f.notes,
                }
                for f in result.fuzzable_functions
            ],
            'errors': result.errors,
        }