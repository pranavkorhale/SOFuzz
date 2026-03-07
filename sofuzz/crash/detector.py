"""
SOFuzz - Crash Detector
"""

from typing import Optional, List
from dataclasses import dataclass

from ..utils.logger import get_logger
from ..utils.constants import CRASH_SIGNALS, SIGNAL_NAMES


@dataclass
class CrashInfo:
    """Information about a crash"""
    is_crash: bool
    signal_num: Optional[int] = None
    signal_name: Optional[str] = None
    crash_type: str = "unknown"
    description: str = ""
    exploitable: bool = False


class CrashDetector:
    """
    Detects and identifies crashes
    
    Usage:
        detector = CrashDetector()
        crash_info = detector.detect(returncode, stderr)
        
        if crash_info.is_crash:
            print(f"Crash: {crash_info.signal_name}")
    """
    
    def __init__(self):
        self.logger = get_logger()
        
        # Crash signals
        self.crash_signals = CRASH_SIGNALS
        
        # Keywords in stderr that indicate specific crash types
        self.crash_keywords = {
            'heap-buffer-overflow': ('Heap Buffer Overflow', True),
            'stack-buffer-overflow': ('Stack Buffer Overflow', True),
            'heap-use-after-free': ('Use After Free', True),
            'stack-use-after-return': ('Use After Return', True),
            'double-free': ('Double Free', True),
            'null-dereference': ('Null Pointer Dereference', False),
            'segmentation fault': ('Segmentation Fault', False),
            'assertion failed': ('Assertion Failure', False),
            'abort': ('Abort', False),
            'divide by zero': ('Divide By Zero', False),
            'integer overflow': ('Integer Overflow', False),
            'memory leak': ('Memory Leak', False),
            'invalid free': ('Invalid Free', True),
            'out of memory': ('Out of Memory', False),
        }
    
    def detect(self, returncode: int, stderr: bytes = b'') -> CrashInfo:
        """
        Detect crash from return code and stderr
        
        Args:
            returncode: Process return code
            stderr: Standard error output
        
        Returns:
            CrashInfo with crash details
        """
        info = CrashInfo(is_crash=False)
        
        # Check return code
        signal_num = self._get_signal(returncode)
        
        if signal_num and signal_num in self.crash_signals:
            info.is_crash = True
            info.signal_num = signal_num
            info.signal_name = SIGNAL_NAMES.get(signal_num, f"SIG{signal_num}")
            info.crash_type = self._get_crash_type_from_signal(signal_num)
        
        # Check stderr for more details
        if stderr:
            stderr_str = stderr.decode('utf-8', errors='ignore').lower()
            
            for keyword, (crash_type, exploitable) in self.crash_keywords.items():
                if keyword in stderr_str:
                    info.is_crash = True
                    info.crash_type = crash_type
                    info.exploitable = exploitable
                    info.description = self._extract_description(stderr_str, keyword)
                    break
        
        return info
    
    def _get_signal(self, returncode: int) -> Optional[int]:
        """Extract signal number from return code"""
        if returncode < 0:
            return abs(returncode)
        if returncode > 128:
            return returncode - 128
        return None
    
    def _get_crash_type_from_signal(self, signal_num: int) -> str:
        """Get crash type from signal number"""
        crash_types = {
            4: "Illegal Instruction",   # SIGILL
            6: "Abort",                 # SIGABRT
            7: "Bus Error",             # SIGBUS
            8: "Floating Point Error",  # SIGFPE
            11: "Segmentation Fault",   # SIGSEGV
        }
        return crash_types.get(signal_num, "Unknown Signal")
    
    def _extract_description(self, stderr: str, keyword: str) -> str:
        """Extract crash description from stderr"""
        lines = stderr.split('\n')
        
        for i, line in enumerate(lines):
            if keyword in line:
                # Return this line and next few lines
                desc_lines = lines[i:i+3]
                return '\n'.join(desc_lines)
        
        return ""
    
    def is_crash(self, returncode: int) -> bool:
        """Quick check if return code indicates crash"""
        signal_num = self._get_signal(returncode)
        return signal_num is not None and signal_num in self.crash_signals
    
    def is_timeout(self, returncode: int, timed_out: bool) -> bool:
        """Check if execution timed out"""
        if timed_out:
            return True
        
        signal_num = self._get_signal(returncode)
        return signal_num == 14  # SIGALRM