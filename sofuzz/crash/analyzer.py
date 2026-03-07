"""
SOFuzz - Crash Analyzer
"""

import os
import re
import time
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

from ..utils.logger import get_logger
from ..utils.file_utils import FileUtils
from .detector import CrashDetector, CrashInfo
from .classifier import CrashClassifier, CrashClassification
from .deduplicator import CrashDeduplicator


@dataclass
class CrashReport:
    """Complete crash report"""
    crash_id: str
    input_path: str
    input_size: int
    signal_num: Optional[int]
    signal_name: Optional[str]
    classification: CrashClassification
    stderr: str
    stdout: str
    stack_trace: List[str] = field(default_factory=list)
    registers: Dict[str, str] = field(default_factory=dict)
    memory_map: List[str] = field(default_factory=list)
    timestamp: str = ""


class CrashAnalyzer:
    """
    Analyzes crashes in detail
    """
    
    def __init__(self, crash_dir: str = "crashes"):
        self.logger = get_logger()
        self.crash_dir = crash_dir
        
        self.detector = CrashDetector()
        self.classifier = CrashClassifier()
        self.deduplicator = CrashDeduplicator()
        
        FileUtils.ensure_dir(crash_dir)
    
    def analyze(
        self,
        input_data: bytes,
        stderr: bytes,
        stdout: bytes = b'',
        returncode: int = 0,
        timed_out: bool = False,
        crash_id: str = None
    ) -> CrashReport:
        """Analyze a crash"""
        if not crash_id:
            crash_id = f"crash_{int(time.time())}_{len(input_data)}"
        
        crash_info = self.detector.detect(returncode, stderr)
        
        classification = self.classifier.classify(
            signal_num=crash_info.signal_num,
            stderr=stderr,
            returncode=returncode,
            timed_out=timed_out
        )
        
        stack_trace = self._extract_stack_trace(stderr)
        registers = self._extract_registers(stderr)
        
        input_path = os.path.join(self.crash_dir, crash_id, "input.bin")
        FileUtils.ensure_dir(os.path.dirname(input_path))
        FileUtils.write_file(input_path, input_data)
        
        report = CrashReport(
            crash_id=crash_id,
            input_path=input_path,
            input_size=len(input_data),
            signal_num=crash_info.signal_num,
            signal_name=crash_info.signal_name,
            classification=classification,
            stderr=stderr.decode('utf-8', errors='ignore'),
            stdout=stdout.decode('utf-8', errors='ignore'),
            stack_trace=stack_trace,
            registers=registers,
            timestamp=time.strftime('%Y-%m-%d %H:%M:%S')
        )
        
        self._save_report(report)
        
        return report
    
    def _extract_stack_trace(self, stderr: bytes) -> List[str]:
        """Extract stack trace from stderr"""
        stderr_str = stderr.decode('utf-8', errors='ignore')
        stack_trace = []
        
        lines = stderr_str.split('\n')
        in_trace = False
        
        for line in lines:
            if any(marker in line.lower() for marker in ['stack trace', 'backtrace', 'call stack']):
                in_trace = True
                continue
            
            if '#' in line and ('0x' in line or 'at ' in line or 'in ' in line):
                stack_trace.append(line.strip())
                in_trace = True
            elif in_trace and line.strip() and not line.startswith('='):
                if '0x' in line or 'at ' in line:
                    stack_trace.append(line.strip())
            elif in_trace and line.strip() == '':
                if len(stack_trace) > 0:
                    break
        
        return stack_trace
    
    def _extract_registers(self, stderr: bytes) -> Dict[str, str]:
        """Extract register values from stderr"""
        stderr_str = stderr.decode('utf-8', errors='ignore')
        registers = {}
        
        reg_patterns = [
            r'(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r\d+)\s*[=:]\s*(0x[0-9a-fA-F]+)',
            r'(eax|ebx|ecx|edx|esi|edi|ebp|esp)\s*[=:]\s*(0x[0-9a-fA-F]+)',
            r'(x\d+|sp|lr|pc)\s*[=:]\s*(0x[0-9a-fA-F]+)',
        ]
        
        for pattern in reg_patterns:
            matches = re.findall(pattern, stderr_str, re.IGNORECASE)
            for reg_name, reg_value in matches:
                registers[reg_name.lower()] = reg_value
        
        return registers
    
    def _save_report(self, report: CrashReport) -> str:
        """Save crash report to disk"""
        report_dir = os.path.join(self.crash_dir, report.crash_id)
        FileUtils.ensure_dir(report_dir)
        
        # Save text report
        report_text = self._generate_text_report(report)
        report_path = os.path.join(report_dir, "report.txt")
        FileUtils.write_text(report_path, report_text)
        
        # Save JSON report
        report_json = self._generate_json_report(report)
        json_path = os.path.join(report_dir, "report.json")
        FileUtils.write_json(json_path, report_json)
        
        # Save stderr
        stderr_path = os.path.join(report_dir, "stderr.txt")
        FileUtils.write_text(stderr_path, report.stderr)
        
        # Save stdout
        if report.stdout:
            stdout_path = os.path.join(report_dir, "stdout.txt")
            FileUtils.write_text(stdout_path, report.stdout)
        
        return report_dir
    
    def _generate_text_report(self, report: CrashReport) -> str:
        """Generate human-readable text report"""
        lines = [
            "=" * 70,
            "CRASH REPORT",
            "=" * 70,
            "",
            f"Crash ID:      {report.crash_id}",
            f"Timestamp:     {report.timestamp}",
            f"Input Size:    {report.input_size} bytes",
            f"Input Path:    {report.input_path}",
            "",
            "-" * 70,
            "CRASH DETAILS",
            "-" * 70,
            "",
            f"Signal:        {report.signal_name} ({report.signal_num})",
            f"Type:          {report.classification.crash_type}",
            f"Severity:      {report.classification.severity.value}",
            f"Exploitable:   {report.classification.exploitability.value}",
            "",
            f"Description:   {report.classification.description}",
            "",
            f"CWE ID:        {report.classification.cwe_id or 'N/A'}",
            "",
            f"Recommendation: {report.classification.recommendation}",
            "",
        ]
        
        # Stack trace
        if report.stack_trace:
            lines.extend([
                "-" * 70,
                "STACK TRACE",
                "-" * 70,
                "",
            ])
            for frame in report.stack_trace:
                lines.append(f"  {frame}")
            lines.append("")
        
        # Registers
        if report.registers:
            lines.extend([
                "-" * 70,
                "REGISTERS",
                "-" * 70,
                "",
            ])
            for reg, value in report.registers.items():
                lines.append(f"  {reg:8s} = {value}")
            lines.append("")
        
        # Stderr preview
        lines.extend([
            "-" * 70,
            "STDERR (first 50 lines)",
            "-" * 70,
            "",
        ])
        stderr_lines = report.stderr.split('\n')[:50]
        for line in stderr_lines:
            lines.append(f"  {line}")
        
        lines.append("")
        lines.append("=" * 70)
        
        return '\n'.join(lines)
    
    def _generate_json_report(self, report: CrashReport) -> Dict[str, Any]:
        """Generate JSON report"""
        return {
            'crash_id': report.crash_id,
            'timestamp': report.timestamp,
            'input': {
                'path': report.input_path,
                'size': report.input_size,
            },
            'crash': {
                'signal_num': report.signal_num,
                'signal_name': report.signal_name,
                'type': report.classification.crash_type,
                'severity': report.classification.severity.value,
                'exploitability': report.classification.exploitability.value,
                'description': report.classification.description,
                'cwe_id': report.classification.cwe_id,
                'recommendation': report.classification.recommendation,
            },
            'stack_trace': report.stack_trace,
            'registers': report.registers,
        }
    
    def analyze_crash_dir(self, crash_dir: str = None) -> List[CrashReport]:
        """Analyze all crashes in a directory"""
        crash_dir = crash_dir or self.crash_dir
        reports = []
        
        if not FileUtils.dir_exists(crash_dir):
            return reports
        
        for item in os.listdir(crash_dir):
            item_path = os.path.join(crash_dir, item)
            
            if os.path.isdir(item_path):
                # Look for input.bin
                input_path = os.path.join(item_path, "input.bin")
                
                if FileUtils.file_exists(input_path):
                    # Load existing report if available
                    json_path = os.path.join(item_path, "report.json")
                    
                    if FileUtils.file_exists(json_path):
                        try:
                            data = FileUtils.read_json(json_path)
                            # Reconstruct report (simplified)
                            report = CrashReport(
                                crash_id=data.get('crash_id', item),
                                input_path=input_path,
                                input_size=data.get('input', {}).get('size', 0),
                                signal_num=data.get('crash', {}).get('signal_num'),
                                signal_name=data.get('crash', {}).get('signal_name'),
                                classification=CrashClassification(
                                    severity=CrashSeverity[data.get('crash', {}).get('severity', 'UNKNOWN')],
                                    exploitability=ExploitabilityRating[data.get('crash', {}).get('exploitability', 'UNKNOWN')],
                                    crash_type=data.get('crash', {}).get('type', 'unknown'),
                                    description=data.get('crash', {}).get('description', ''),
                                    cwe_id=data.get('crash', {}).get('cwe_id'),
                                    recommendation=data.get('crash', {}).get('recommendation', ''),
                                ),
                                stderr='',
                                stdout='',
                                stack_trace=data.get('stack_trace', []),
                                registers=data.get('registers', {}),
                                timestamp=data.get('timestamp', ''),
                            )
                            reports.append(report)
                        except Exception as e:
                            self.logger.debug(f"Failed to load report: {e}")
        
        return reports
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all crashes"""
        reports = self.analyze_crash_dir()
        
        summary = {
            'total_crashes': len(reports),
            'by_severity': {},
            'by_type': {},
            'exploitable': 0,
        }
        
        for report in reports:
            # Count by severity
            severity = report.classification.severity.value
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by type
            crash_type = report.classification.crash_type
            summary['by_type'][crash_type] = summary['by_type'].get(crash_type, 0) + 1
            
            # Count exploitable
            if self.classifier.is_exploitable(report.classification):
                summary['exploitable'] += 1
        
        return summary


# Import for type hints
from .classifier import ExploitabilityRating
from ..utils.constants import CrashSeverity