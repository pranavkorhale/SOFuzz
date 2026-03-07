"""
SOFuzz - Crash Deduplicator
"""

import hashlib
from typing import Set, Dict, Optional, List
from dataclasses import dataclass

from ..utils.logger import get_logger
from ..fuzzer.executor import ExecutionResult


@dataclass
class CrashSignature:
    """Unique signature of a crash"""
    hash: str
    signal: Optional[int]
    crash_location: str
    stack_hash: str


class CrashDeduplicator:
    """
    Deduplicates crashes to avoid storing duplicates
    """
    
    def __init__(self):
        self.logger = get_logger()
        self.seen_hashes: Set[str] = set()
        self.crashes: Dict[str, CrashSignature] = {}
        self.total_crashes = 0
        self.unique_crashes = 0
        self.duplicates = 0
    
    def get_hash(self, input_data: bytes, result: ExecutionResult) -> str:
        """Generate unique hash for a crash"""
        hash_data = []
        
        hash_data.append(str(result.returncode).encode())
        
        crash_loc = self._extract_crash_location(result.stderr)
        hash_data.append(crash_loc.encode())
        
        stack_hash = self._hash_stack_trace(result.stderr)
        hash_data.append(stack_hash.encode())
        
        combined = b'|'.join(hash_data)
        return hashlib.md5(combined).hexdigest()
    
    def _extract_crash_location(self, stderr: bytes) -> str:
        """Extract crash location from stderr"""
        stderr_str = stderr.decode('utf-8', errors='ignore')
        
        # Look for common patterns
        patterns = [
            '0x',           # Address pattern
            '+0x',          # Function + offset
            '.c:',          # File:line (C)
            '.cpp:',        # File:line (C++)
            '.cc:',         # File:line (C++)
            ' at ',         # GDB style
            ' in ',         # GDB style
        ]
        
        lines = stderr_str.split('\n')
        
        for line in lines:
            for pattern in patterns:
                if pattern in line:
                    # Extract relevant part
                    return line.strip()[:100]
        
        # Fallback: first non-empty line
        for line in lines:
            if line.strip():
                return line.strip()[:100]
        
        return "unknown_location"
    
    def _hash_stack_trace(self, stderr: bytes) -> str:
        """Hash the stack trace"""
        stderr_str = stderr.decode('utf-8', errors='ignore')
        
        # Extract stack frames
        stack_lines = []
        in_stack = False
        
        for line in stderr_str.split('\n'):
            line_lower = line.lower()
            
            # Detect stack trace start
            if 'stack trace' in line_lower or 'backtrace' in line_lower:
                in_stack = True
                continue
            
            # Detect stack frame
            if '#' in line and ('0x' in line or 'at ' in line):
                # Clean up the line (remove addresses that change)
                clean_line = self._clean_stack_line(line)
                stack_lines.append(clean_line)
                in_stack = True
            elif in_stack and line.strip() == '':
                break
        
        if stack_lines:
            # Hash first N frames
            top_frames = stack_lines[:5]
            return hashlib.md5('|'.join(top_frames).encode()).hexdigest()[:16]
        
        # Fallback: hash entire stderr
        return hashlib.md5(stderr).hexdigest()[:16]
    
    def _clean_stack_line(self, line: str) -> str:
        """Clean stack line by removing variable parts"""
        import re
        
        # Remove addresses
        cleaned = re.sub(r'0x[0-9a-fA-F]+', '0xADDR', line)
        
        # Remove line numbers (may vary with different builds)
        cleaned = re.sub(r':\d+$', ':LINE', cleaned)
        cleaned = re.sub(r':\d+:', ':LINE:', cleaned)
        
        return cleaned.strip()
    
    def is_unique(self, crash_hash: str) -> bool:
        """Check if crash is unique"""
        return crash_hash not in self.seen_hashes
    
    def add(self, crash_hash: str, signature: CrashSignature = None) -> bool:
        """
        Add crash to seen set
        
        Args:
            crash_hash: Crash hash
            signature: Optional crash signature
        
        Returns:
            True if added (was unique), False if duplicate
        """
        self.total_crashes += 1
        
        if crash_hash in self.seen_hashes:
            self.duplicates += 1
            return False
        
        self.seen_hashes.add(crash_hash)
        self.unique_crashes += 1
        
        if signature:
            self.crashes[crash_hash] = signature
        
        return True
    
    def get_stats(self) -> Dict:
        """Get deduplication statistics"""
        return {
            'total_crashes': self.total_crashes,
            'unique_crashes': self.unique_crashes,
            'duplicates': self.duplicates,
            'dedup_ratio': self.duplicates / max(1, self.total_crashes),
        }
    
    def clear(self) -> None:
        """Clear all seen crashes"""
        self.seen_hashes.clear()
        self.crashes.clear()
        self.total_crashes = 0
        self.unique_crashes = 0
        self.duplicates = 0
    
    def get_unique_count(self) -> int:
        """Get count of unique crashes"""
        return self.unique_crashes