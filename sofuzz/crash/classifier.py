"""
SOFuzz - Crash Classifier
"""

from typing import Optional, Dict, List
from dataclasses import dataclass
from enum import Enum

from ..utils.logger import get_logger
from ..utils.constants import CrashSeverity, SIGNAL_NAMES


class ExploitabilityRating(Enum):
    """Exploitability rating"""
    EXPLOITABLE = "EXPLOITABLE"
    PROBABLY_EXPLOITABLE = "PROBABLY_EXPLOITABLE"
    PROBABLY_NOT_EXPLOITABLE = "PROBABLY_NOT_EXPLOITABLE"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class CrashClassification:
    """Crash classification result"""
    severity: CrashSeverity
    exploitability: ExploitabilityRating
    crash_type: str
    description: str
    cwe_id: Optional[str] = None
    recommendation: str = ""


class CrashClassifier:
    """
    Classifies crashes by severity and type
    """
    
    def __init__(self):
        self.logger = get_logger()
        
        self.patterns = {
            'heap-buffer-overflow': {
                'severity': CrashSeverity.CRITICAL,
                'exploitability': ExploitabilityRating.EXPLOITABLE,
                'cwe': 'CWE-122',
                'description': 'Heap buffer overflow - write beyond allocated heap memory',
                'recommendation': 'Check buffer bounds before writing',
            },
            'stack-buffer-overflow': {
                'severity': CrashSeverity.CRITICAL,
                'exploitability': ExploitabilityRating.EXPLOITABLE,
                'cwe': 'CWE-121',
                'description': 'Stack buffer overflow - write beyond stack buffer',
                'recommendation': 'Use safe string functions, check array bounds',
            },
            'heap-use-after-free': {
                'severity': CrashSeverity.CRITICAL,
                'exploitability': ExploitabilityRating.EXPLOITABLE,
                'cwe': 'CWE-416',
                'description': 'Use after free - access to freed heap memory',
                'recommendation': 'Set pointers to NULL after freeing',
            },
            'double-free': {
                'severity': CrashSeverity.CRITICAL,
                'exploitability': ExploitabilityRating.EXPLOITABLE,
                'cwe': 'CWE-415',
                'description': 'Double free - memory freed twice',
                'recommendation': 'Track allocation state, set pointer to NULL after free',
            },
            'stack-use-after-return': {
                'severity': CrashSeverity.HIGH,
                'exploitability': ExploitabilityRating.PROBABLY_EXPLOITABLE,
                'cwe': 'CWE-562',
                'description': 'Use after return - access to stack memory after function return',
                'recommendation': 'Do not return pointers to local variables',
            },
            'null-dereference': {
                'severity': CrashSeverity.MEDIUM,
                'exploitability': ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE,
                'cwe': 'CWE-476',
                'description': 'Null pointer dereference',
                'recommendation': 'Check pointers before dereferencing',
            },
            'divide-by-zero': {
                'severity': CrashSeverity.MEDIUM,
                'exploitability': ExploitabilityRating.NOT_EXPLOITABLE,
                'cwe': 'CWE-369',
                'description': 'Division by zero',
                'recommendation': 'Check divisor before division',
            },
            'assertion-failure': {
                'severity': CrashSeverity.LOW,
                'exploitability': ExploitabilityRating.NOT_EXPLOITABLE,
                'cwe': None,
                'description': 'Assertion failure',
                'recommendation': 'Review assertion condition',
            },
            'timeout': {
                'severity': CrashSeverity.LOW,
                'exploitability': ExploitabilityRating.NOT_EXPLOITABLE,
                'cwe': 'CWE-400',
                'description': 'Execution timeout - possible infinite loop or hang',
                'recommendation': 'Review loop conditions and algorithm complexity',
            },
        }
        
        self.signal_types = {
            4: 'illegal-instruction',
            6: 'assertion-failure',
            7: 'bus-error',
            8: 'divide-by-zero',
            11: 'segmentation-fault',
        }
    
    def classify(
        self,
        signal_num: Optional[int] = None,
        stderr: bytes = b'',
        returncode: int = 0,
        timed_out: bool = False
    ) -> CrashClassification:
        """Classify a crash"""
        if timed_out:
            pattern = self.patterns['timeout']
            return CrashClassification(
                severity=pattern['severity'],
                exploitability=pattern['exploitability'],
                crash_type='timeout',
                description=pattern['description'],
                cwe_id=pattern['cwe'],
                recommendation=pattern['recommendation']
            )
        
        stderr_str = stderr.decode('utf-8', errors='ignore').lower()
        
        for pattern_name, pattern_info in self.patterns.items():
            search_term = pattern_name.replace('-', ' ').replace('_', ' ')
            alt_search = pattern_name.replace('-', '-')
            
            if search_term in stderr_str or alt_search in stderr_str:
                return CrashClassification(
                    severity=pattern_info['severity'],
                    exploitability=pattern_info['exploitability'],
                    crash_type=pattern_name,
                    description=pattern_info['description'],
                    cwe_id=pattern_info.get('cwe'),
                    recommendation=pattern_info['recommendation']
                )
        
        if signal_num:
            crash_type = self.signal_types.get(signal_num, 'unknown-signal')
            
            if signal_num == 11:
                return CrashClassification(
                    severity=CrashSeverity.MEDIUM,
                    exploitability=ExploitabilityRating.UNKNOWN,
                    crash_type=crash_type,
                    description=f"Segmentation fault (signal {signal_num})",
                    recommendation='Analyze crash with debugger'
                )
            elif signal_num == 6:
                return CrashClassification(
                    severity=CrashSeverity.LOW,
                    exploitability=ExploitabilityRating.PROBABLY_NOT_EXPLOITABLE,
                    crash_type=crash_type,
                    description=f"Abort (signal {signal_num})",
                    recommendation='Check assertion or abort() call'
                )
            else:
                return CrashClassification(
                    severity=CrashSeverity.MEDIUM,
                    exploitability=ExploitabilityRating.UNKNOWN,
                    crash_type=crash_type,
                    description=f"Crash with signal {signal_num}",
                    recommendation='Analyze crash with debugger'
                )
        
        return CrashClassification(
            severity=CrashSeverity.UNKNOWN,
            exploitability=ExploitabilityRating.UNKNOWN,
            crash_type='unknown',
            description='Unknown crash type',
            recommendation='Analyze manually with debugger'
        )
    
    def get_severity_score(self, classification: CrashClassification) -> int:
        """Get numeric severity score (higher = more severe)"""
        scores = {
            CrashSeverity.CRITICAL: 100,
            CrashSeverity.HIGH: 75,
            CrashSeverity.MEDIUM: 50,
            CrashSeverity.LOW: 25,
            CrashSeverity.UNKNOWN: 10,
        }
        return scores.get(classification.severity, 0)
    
    def is_exploitable(self, classification: CrashClassification) -> bool:
        """Check if crash is likely exploitable"""
        exploitable_ratings = [
            ExploitabilityRating.EXPLOITABLE,
            ExploitabilityRating.PROBABLY_EXPLOITABLE,
        ]
        return classification.exploitability in exploitable_ratings