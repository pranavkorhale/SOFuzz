"""
SOFuzz - JSON Report Generator
"""

from typing import Dict, Any


class JSONReportGenerator:
    """
    Generates JSON reports for fuzzing results
    """
    
    def __init__(self):
        pass
    
    def generate(self, data, output_path: str) -> None:
        """Generate JSON report"""
        from ..utils.file_utils import FileUtils
        report = self._generate_json(data)
        FileUtils.write_json(output_path, report)
    
    def _generate_json(self, data) -> Dict[str, Any]:
        """Generate JSON structure"""
        
        severity_summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        type_summary = {}
        
        crashes_list = []
        for crash in data.crashes:
            severity = getattr(crash.classification, 'severity', None)
            severity_val = severity.value if severity else 'UNKNOWN'
            severity_summary[severity_val] = severity_summary.get(severity_val, 0) + 1
            
            crash_type = getattr(crash.classification, 'crash_type', 'unknown')
            type_summary[crash_type] = type_summary.get(crash_type, 0) + 1
            
            exploitability = getattr(crash.classification, 'exploitability', None)
            exploitability_val = exploitability.value if exploitability else 'UNKNOWN'
            
            description = getattr(crash.classification, 'description', '')
            cwe_id = getattr(crash.classification, 'cwe_id', None)
            recommendation = getattr(crash.classification, 'recommendation', '')
            
            crash_dict = {
                'id': getattr(crash, 'crash_id', ''),
                'timestamp': getattr(crash, 'timestamp', ''),
                'input': {
                    'path': getattr(crash, 'input_path', ''),
                    'size': getattr(crash, 'input_size', 0),
                },
                'signal': {
                    'number': getattr(crash, 'signal_num', None),
                    'name': getattr(crash, 'signal_name', None),
                },
                'classification': {
                    'severity': severity_val,
                    'exploitability': exploitability_val,
                    'type': crash_type,
                    'description': description,
                    'cwe_id': cwe_id,
                    'recommendation': recommendation,
                },
                'stack_trace': getattr(crash, 'stack_trace', []),
                'registers': getattr(crash, 'registers', {}),
            }
            crashes_list.append(crash_dict)
        
        report = {
            'report_info': {
                'generator': 'SOFuzz',
                'version': '1.0.0',
                'generated_at': data.end_time,
            },
            'target': {
                'name': data.target_name,
                'path': data.target_path,
            },
            'session': {
                'start_time': data.start_time,
                'end_time': data.end_time,
                'duration_seconds': data.duration,
            },
            'statistics': {
                'total_iterations': data.total_iterations,
                'executions_per_second': round(data.exec_per_second, 2),
                'total_crashes': data.total_crashes,
                'unique_crashes': data.unique_crashes,
                'timeouts': data.timeouts,
                'coverage_percent': data.coverage_percent,
                'unique_paths': data.unique_paths,
            },
            'summary': {
                'by_severity': severity_summary,
                'by_type': type_summary,
            },
            'crashes': crashes_list,
            'configuration': data.config,
        }
        
        return report
