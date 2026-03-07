"""
SOFuzz - Harness Compiler
Compiles generated C harnesses
"""

import os
import subprocess
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field

from ..utils.logger import get_logger
from ..utils.file_utils import FileUtils
from ..utils.process_utils import ProcessUtils


@dataclass
class CompileResult:
    """Result of harness compilation"""
    source_path: str
    binary_path: str
    success: bool
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


class HarnessCompiler:
    """
    Compiles C harnesses for fuzzing
    """
    
    DEFAULT_FLAGS = [
        "-g",
        "-O0",
        "-fno-omit-frame-pointer",
        "-Wall",
    ]
    
    ASAN_FLAGS = [
        "-fsanitize=address",
        "-fsanitize=undefined",
    ]
    
    REQUIRED_LIBS = [
        "-ldl",
        "-lpthread",
    ]
    
    def __init__(
        self,
        compiler: str = "gcc",
        extra_flags: List[str] = None,
        use_sanitizers: bool = False
    ):
        self.compiler = compiler
        self.extra_flags = extra_flags or []
        self.use_sanitizers = use_sanitizers
        self.logger = get_logger()
        
        # Check if compiler exists
        if not ProcessUtils.check_command_exists(compiler):
            self.logger.warning(f"Compiler not found: {compiler}")
    
    def compile(
        self,
        source_path: str,
        output_path: Optional[str] = None,
        extra_flags: List[str] = None
    ) -> CompileResult:
        """
        Compile a harness source file
        
        Args:
            source_path: Path to .c source file
            output_path: Path for output binary (optional)
            extra_flags: Additional compiler flags
        
        Returns:
            CompileResult with compilation status
        """
        # Determine output path
        if output_path is None:
            output_path = source_path.replace(".c", "")
        
        result = CompileResult(
            source_path=source_path,
            binary_path=output_path,
            success=False
        )
        
        try:
            # Check source exists
            if not FileUtils.file_exists(source_path):
                result.error = f"Source file not found: {source_path}"
                return result
            
            # Build command
            cmd = [self.compiler]
            
            # Add flags
            cmd.extend(self.DEFAULT_FLAGS)
            
            if self.use_sanitizers:
                cmd.extend(self.ASAN_FLAGS)
            
            cmd.extend(self.extra_flags)
            
            if extra_flags:
                cmd.extend(extra_flags)
            
            # Add source and output
            cmd.extend(["-o", output_path, source_path])
            
            # Add required libraries
            cmd.extend(self.REQUIRED_LIBS)
            
            self.logger.debug(f"Compile command: {' '.join(cmd)}")
            
            # Run compiler
            process_result = ProcessUtils.run_command(cmd, timeout=60)
            
            if process_result.returncode == 0:
                result.success = True
                self.logger.info(f"Compiled: {output_path}")
            else:
                result.error = process_result.stderr.decode('utf-8', errors='ignore')
                self.logger.error(f"Compilation failed: {result.error}")
            
            # Parse warnings
            stderr_text = process_result.stderr.decode('utf-8', errors='ignore')
            for line in stderr_text.split('\n'):
                if 'warning:' in line.lower():
                    result.warnings.append(line.strip())
            
        except Exception as e:
            result.error = str(e)
            self.logger.error(f"Compilation error: {e}")
        
        return result
    
    def compile_all(
        self,
        source_paths: List[str],
        extra_flags: List[str] = None
    ) -> List[CompileResult]:
        """
        Compile multiple harness files
        
        Args:
            source_paths: List of source file paths
            extra_flags: Additional compiler flags
        
        Returns:
            List of CompileResult objects
        """
        results = []
        
        self.logger.info(f"Compiling {len(source_paths)} harnesses")
        
        for source_path in source_paths:
            result = self.compile(source_path, extra_flags=extra_flags)
            results.append(result)
        
        successful = sum(1 for r in results if r.success)
        self.logger.success(f"Compiled {successful}/{len(source_paths)} harnesses")
        
        return results
    
    def compile_directory(
        self,
        directory: str,
        extra_flags: List[str] = None
    ) -> List[CompileResult]:
        """
        Compile all harness files in a directory
        
        Args:
            directory: Directory containing .c files
            extra_flags: Additional compiler flags
        
        Returns:
            List of CompileResult objects
        """
        source_files = FileUtils.list_files(directory, ".c")
        
        # Filter for harness files
        harness_files = [f for f in source_files if "harness_" in os.path.basename(f)]
        
        if not harness_files:
            self.logger.warning(f"No harness files found in {directory}")
            return []
        
        return self.compile_all(harness_files, extra_flags)
    
    def check_binary(self, binary_path: str) -> bool:
        """Check if binary was compiled correctly"""
        if not FileUtils.file_exists(binary_path):
            return False
        
        # Check if it's executable
        return os.access(binary_path, os.X_OK)
    
    def get_compiler_version(self) -> Optional[str]:
        """Get compiler version"""
        return ProcessUtils.get_command_output([self.compiler, "--version"])