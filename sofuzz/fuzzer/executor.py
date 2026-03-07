"""
SOFuzz - Target Executor
"""

import os
import subprocess
import time
from typing import Optional, List
from dataclasses import dataclass

from ..utils.logger import get_logger
from ..utils.file_utils import FileUtils
from ..utils.process_utils import ProcessUtils, ProcessResult
from ..utils.constants import DEFAULT_TIMEOUT, CRASH_SIGNALS, SIGNAL_NAMES


@dataclass
class ExecutionResult:
    """Result of target execution"""
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    execution_time: float
    is_crash: bool = False
    signal_num: Optional[int] = None
    
    @property
    def signal_name(self) -> Optional[str]:
        """Get signal name"""
        if self.signal_num:
            return SIGNAL_NAMES.get(self.signal_num, f"SIG{self.signal_num}")
        if self.returncode < 0:
            sig = abs(self.returncode)
            return SIGNAL_NAMES.get(sig, f"SIG{sig}")
        if self.returncode > 128:
            sig = self.returncode - 128
            return SIGNAL_NAMES.get(sig, f"SIG{sig}")
        return None


class Executor:
    """
    Executes target binary with fuzz input
    """
    
    def __init__(
        self,
        binary_path: str,
        timeout: float = DEFAULT_TIMEOUT,
        use_stdin: bool = True,
        env: dict = None,
        args: List[str] = None
    ):
        self.binary_path = binary_path
        self.timeout = timeout
        self.use_stdin = use_stdin
        self.env = env or os.environ.copy()
        self.args = args or []
        self.logger = get_logger()
        
        if not FileUtils.file_exists(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        
        if not os.access(binary_path, os.X_OK):
            raise PermissionError(f"Binary not executable: {binary_path}")
        
        self.temp_input_path = None
    
    def execute(self, input_data: bytes) -> ExecutionResult:
        """Execute target with input"""
        if self.use_stdin:
            return self._execute_with_stdin(input_data)
        else:
            return self._execute_with_file(input_data)
    
    def _execute_with_stdin(self, input_data: bytes) -> ExecutionResult:
        """Execute target with input via stdin"""
        cmd = [self.binary_path] + self.args
        
        process_result = ProcessUtils.run_command(
            cmd,
            timeout=self.timeout,
            env=self.env,
            stdin_data=input_data
        )
        
        return self._process_result(process_result)
    
    def _execute_with_file(self, input_data: bytes) -> ExecutionResult:
        """Execute target with input via file"""
        temp_path = FileUtils.get_temp_path(prefix="sofuzz_input_")
        
        try:
            FileUtils.write_file(temp_path, input_data)
            
            cmd = [self.binary_path] + self.args + [temp_path]
            
            process_result = ProcessUtils.run_command(
                cmd,
                timeout=self.timeout,
                env=self.env
            )
            
            return self._process_result(process_result)
            
        finally:
            FileUtils.delete_file(temp_path)
    
    def _process_result(self, process_result: ProcessResult) -> ExecutionResult:
        """Process execution result and detect crashes"""
        result = ExecutionResult(
            returncode=process_result.returncode,
            stdout=process_result.stdout,
            stderr=process_result.stderr,
            timed_out=process_result.timed_out,
            execution_time=process_result.execution_time
        )
        
        result.is_crash = self._is_crash(process_result.returncode)
        
        if result.is_crash:
            result.signal_num = self._get_signal(process_result.returncode)
        
        return result
    
    def _is_crash(self, returncode: int) -> bool:
        """Check if return code indicates crash"""
        if returncode < 0:
            return abs(returncode) in CRASH_SIGNALS
        
        if returncode > 128:
            return (returncode - 128) in CRASH_SIGNALS
        
        return False
    
    def _get_signal(self, returncode: int) -> Optional[int]:
        """Extract signal number from return code"""
        if returncode < 0:
            return abs(returncode)
        if returncode > 128:
            return returncode - 128
        return None
    
    def set_timeout(self, timeout: float) -> None:
        """Set execution timeout"""
        self.timeout = timeout
    
    def set_env(self, key: str, value: str) -> None:
        """Set environment variable"""
        self.env[key] = value
    
    def add_arg(self, arg: str) -> None:
        """Add command line argument"""
        self.args.append(arg)
    
    def clear_args(self) -> None:
        """Clear command line arguments"""
        self.args = []