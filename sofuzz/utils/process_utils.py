"""
SOFuzz - Process Utilities
"""

import os
import sys
import signal
import subprocess
import time
import resource
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass

from .constants import CRASH_SIGNALS, SIGNAL_NAMES


@dataclass
class ProcessResult:
    """Result of process execution"""
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    execution_time: float
    signal_num: Optional[int] = None
    
    @property
    def is_crash(self) -> bool:
        """Check if process crashed"""
        if self.returncode < 0:
            return abs(self.returncode) in CRASH_SIGNALS
        return self.returncode in [128 + sig for sig in CRASH_SIGNALS]
    
    @property
    def signal_name(self) -> Optional[str]:
        """Get signal name if crashed"""
        if self.signal_num:
            return SIGNAL_NAMES.get(self.signal_num, f"SIG{self.signal_num}")
        if self.returncode < 0:
            sig = abs(self.returncode)
            return SIGNAL_NAMES.get(sig, f"SIG{sig}")
        if self.returncode > 128:
            sig = self.returncode - 128
            return SIGNAL_NAMES.get(sig, f"SIG{sig}")
        return None


class ProcessUtils:
    """
    Process management utilities
    """
    
    @staticmethod
    def run_command(
        command: List[str],
        timeout: float = 10.0,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        stdin_data: Optional[bytes] = None
    ) -> ProcessResult:
        """
        Run a command with timeout
        
        Args:
            command: Command and arguments as list
            timeout: Timeout in seconds
            cwd: Working directory
            env: Environment variables
            stdin_data: Data to send to stdin
        
        Returns:
            ProcessResult with execution details
        """
        start_time = time.time()
        timed_out = False
        
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=env,
                preexec_fn=os.setsid if sys.platform != 'win32' else None
            )
            
            try:
                stdout, stderr = process.communicate(
                    input=stdin_data,
                    timeout=timeout
                )
            except subprocess.TimeoutExpired:
                # Kill the process group
                timed_out = True
                if sys.platform != 'win32':
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                else:
                    process.kill()
                stdout, stderr = process.communicate()
            
            execution_time = time.time() - start_time
            
            return ProcessResult(
                returncode=process.returncode,
                stdout=stdout,
                stderr=stderr,
                timed_out=timed_out,
                execution_time=execution_time
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            return ProcessResult(
                returncode=-1,
                stdout=b"",
                stderr=str(e).encode(),
                timed_out=False,
                execution_time=execution_time
            )
    
    @staticmethod
    def run_with_input_file(
        command: List[str],
        input_file: str,
        timeout: float = 10.0,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> ProcessResult:
        """
        Run a command with input file as argument
        
        Args:
            command: Command (input_file will be appended)
            input_file: Path to input file
            timeout: Timeout in seconds
            cwd: Working directory
            env: Environment variables
        
        Returns:
            ProcessResult with execution details
        """
        full_command = command + [input_file]
        return ProcessUtils.run_command(
            full_command,
            timeout=timeout,
            cwd=cwd,
            env=env
        )
    
    @staticmethod
    def run_with_stdin(
        command: List[str],
        stdin_data: bytes,
        timeout: float = 10.0,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> ProcessResult:
        """
        Run a command with data sent to stdin
        
        Args:
            command: Command and arguments
            stdin_data: Data to send to stdin
            timeout: Timeout in seconds
            cwd: Working directory
            env: Environment variables
        
        Returns:
            ProcessResult with execution details
        """
        return ProcessUtils.run_command(
            command,
            timeout=timeout,
            cwd=cwd,
            env=env,
            stdin_data=stdin_data
        )
    
    @staticmethod
    def check_command_exists(command: str) -> bool:
        """Check if a command exists in PATH"""
        try:
            subprocess.run(
                ["which", command] if sys.platform != 'win32' else ["where", command],
                capture_output=True,
                check=True
            )
            return True
        except subprocess.CalledProcessError:
            return False
    
    @staticmethod
    def get_command_output(command: List[str]) -> Optional[str]:
        """Get output of a command"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            return None
    
    @staticmethod
    def set_memory_limit(max_bytes: int) -> None:
        """Set memory limit for current process (Linux only)"""
        if sys.platform != 'win32':
            try:
                resource.setrlimit(
                    resource.RLIMIT_AS,
                    (max_bytes, max_bytes)
                )
            except:
                pass
    
    @staticmethod
    def set_cpu_limit(max_seconds: int) -> None:
        """Set CPU time limit for current process (Linux only)"""
        if sys.platform != 'win32':
            try:
                resource.setrlimit(
                    resource.RLIMIT_CPU,
                    (max_seconds, max_seconds)
                )
            except:
                pass
    
    @staticmethod
    def get_process_info(pid: int) -> Optional[Dict[str, Any]]:
        """Get information about a process"""
        try:
            import psutil
            process = psutil.Process(pid)
            return {
                'pid': pid,
                'name': process.name(),
                'status': process.status(),
                'cpu_percent': process.cpu_percent(),
                'memory_percent': process.memory_percent(),
                'create_time': process.create_time(),
            }
        except:
            return None
    
    @staticmethod
    def kill_process(pid: int, force: bool = False) -> bool:
        """Kill a process"""
        try:
            sig = signal.SIGKILL if force else signal.SIGTERM
            os.kill(pid, sig)
            return True
        except OSError:
            return False
    
    @staticmethod
    def kill_process_tree(pid: int) -> bool:
        """Kill a process and all its children"""
        try:
            import psutil
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            
            for child in children:
                child.kill()
            parent.kill()
            
            return True
        except:
            return False
    
    @staticmethod
    def is_process_running(pid: int) -> bool:
        """Check if a process is running"""
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    
    @staticmethod
    def wait_for_process(pid: int, timeout: float = 10.0) -> bool:
        """Wait for a process to finish"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if not ProcessUtils.is_process_running(pid):
                return True
            time.sleep(0.1)
        return False
    
    @staticmethod
    def get_return_signal(returncode: int) -> Optional[int]:
        """Get signal number from return code"""
        if returncode < 0:
            return abs(returncode)
        elif returncode > 128:
            return returncode - 128
        return None