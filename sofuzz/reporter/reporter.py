"""
SOFuzz - Main Reporter
"""

import os
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ReportData:
    """Data for report generation"""
    target_name: str
    target_path: str
    start_time: str
    end_time: str
    duration: float
    total_iterations: int
    total_crashes: int
    unique_crashes: int
    timeouts: int
    exec_per_second: float
    crashes: List[Any] = field(default_factory=list)
    coverage_percent: float = 0.0
    unique_paths: int = 0
    config: Dict[str, Any] = field(default_factory=dict)


class Reporter:
    """
    Generates fuzzing reports
    """
    
    def __init__(self, output_dir: str = "output/reports"):
        from ..utils.logger import get_logger
        from ..utils.file_utils import FileUtils
        
        self.output_dir = output_dir
        self.logger = get_logger()
        FileUtils.ensure_dir(output_dir)
    
    def generate(
        self,
        stats,
        crashes: List[Any],
        target_name: str,
        target_path: str = "",
        config: Dict[str, Any] = None,
        formats: List[str] = None
    ) -> Dict[str, str]:
        """Generate reports in specified formats"""
        from ..utils.file_utils import FileUtils
        from .html_report import HTMLReportGenerator
        from .json_report import JSONReportGenerator
        
        formats = formats or ['html', 'json', 'txt']
        config = config or {}
        
        report_dir = os.path.join(self.output_dir, target_name)
        FileUtils.ensure_dir(report_dir)
        
        now = time.strftime('%Y-%m-%d %H:%M:%S')
        duration = time.time() - stats.start_time if stats.start_time > 0 else 0
        
        start_time_str = time.strftime(
            '%Y-%m-%d %H:%M:%S',
            time.localtime(stats.start_time)
        ) if stats.start_time > 0 else "N/A"
        
        report_data = ReportData(
            target_name=target_name,
            target_path=target_path,
            start_time=start_time_str,
            end_time=now,
            duration=duration,
            total_iterations=stats.iterations,
            total_crashes=stats.crashes,
            unique_crashes=stats.unique_crashes,
            timeouts=stats.timeouts,
            exec_per_second=stats.executions_per_second,
            crashes=crashes,
            config=config,
        )
        
        generated = {}
        
        if 'html' in formats:
            html_path = os.path.join(report_dir, "report.html")
            html_gen = HTMLReportGenerator()
            html_gen.generate(report_data, html_path)
            generated['html'] = html_path
            self.logger.info(f"Generated HTML report: {html_path}")
        
        if 'json' in formats:
            json_path = os.path.join(report_dir, "report.json")
            json_gen = JSONReportGenerator()
            json_gen.generate(report_data, json_path)
            generated['json'] = json_path
            self.logger.info(f"Generated JSON report: {json_path}")
        
        if 'txt' in formats:
            txt_path = os.path.join(report_dir, "report.txt")
            self._generate_text_report(report_data, txt_path)
            generated['txt'] = txt_path
            self.logger.info(f"Generated TXT report: {txt_path}")
        
        return generated
    
    def _generate_text_report(self, data: ReportData, output_path: str) -> None:
        """Generate plain text report"""
        from ..utils.file_utils import FileUtils
        
        lines = [
            "=" * 70,
            "SOFUZZ FUZZING REPORT",
            "=" * 70,
            "",
            f"Target:          {data.target_name}",
            f"Target Path:     {data.target_path}",
            f"Start Time:      {data.start_time}",
            f"End Time:        {data.end_time}",
            f"Duration:        {data.duration:.2f} seconds",
            "",
            "-" * 70,
            "STATISTICS",
            "-" * 70,
            "",
            f"Total Iterations:     {data.total_iterations}",
            f"Executions/Second:    {data.exec_per_second:.2f}",
            f"Total Crashes:        {data.total_crashes}",
            f"Unique Crashes:       {data.unique_crashes}",
            f"Timeouts:             {data.timeouts}",
            "",
            "=" * 70,
            "END OF REPORT",
            "=" * 70,
        ]
        
        FileUtils.write_text(output_path, '\n'.join(lines))
    
    def generate_summary(self, stats) -> str:
        """Generate a quick summary string"""
        duration = time.time() - stats.start_time if stats.start_time > 0 else 0
        
        return (
            f"Iterations: {stats.iterations} | "
            f"Crashes: {stats.unique_crashes} | "
            f"Timeouts: {stats.timeouts} | "
            f"Speed: {stats.executions_per_second:.1f}/s | "
            f"Duration: {duration:.1f}s"
        )
