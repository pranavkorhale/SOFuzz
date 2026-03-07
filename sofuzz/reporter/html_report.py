"""
SOFuzz - HTML Report Generator
"""

from typing import List, Dict, Any


class HTMLReportGenerator:
    """
    Generates HTML reports for fuzzing results
    """
    
    def __init__(self):
        pass
    
    def generate(self, data, output_path: str) -> None:
        """Generate HTML report"""
        from ..utils.file_utils import FileUtils
        html = self._generate_html(data)
        FileUtils.write_text(output_path, html)
    
    def _generate_html(self, data) -> str:
        """Generate HTML content"""
        
        crash_rows = ""
        for i, crash in enumerate(data.crashes, 1):
            severity = getattr(crash.classification, 'severity', None)
            severity_val = severity.value if severity else 'UNKNOWN'
            severity_class = severity_val.lower()
            
            exploitability = getattr(crash.classification, 'exploitability', None)
            exploitability_val = exploitability.value if exploitability else 'UNKNOWN'
            
            crash_type = getattr(crash.classification, 'crash_type', 'unknown')
            signal_name = getattr(crash, 'signal_name', 'N/A')
            input_size = getattr(crash, 'input_size', 0)
            crash_id = getattr(crash, 'crash_id', f'crash_{i}')
            
            crash_rows += f"""
            <tr class="severity-{severity_class}">
                <td>{i}</td>
                <td>{crash_id}</td>
                <td><span class="badge badge-{severity_class}">{severity_val}</span></td>
                <td>{crash_type}</td>
                <td>{signal_name}</td>
                <td>{exploitability_val}</td>
                <td>{input_size} bytes</td>
            </tr>
            """
        
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        for crash in data.crashes:
            severity = getattr(crash.classification, 'severity', None)
            severity_val = severity.value if severity else 'UNKNOWN'
            severity_counts[severity_val] = severity_counts.get(severity_val, 0) + 1
        
        no_crashes_html = ""
        if not data.crashes:
            no_crashes_html = '<div class="no-crashes">No crashes found during fuzzing!</div>'
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOFuzz Report - {data.target_name}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #1a1a2e;
            color: #eee;
            padding: 20px;
            margin: 0;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ text-align: center; padding: 30px 0; border-bottom: 2px solid #0f3460; }}
        .header h1 {{ color: #00d9ff; font-size: 2.5em; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
        .stat-card {{ background: rgba(255,255,255,0.05); border-radius: 10px; padding: 20px; text-align: center; }}
        .stat-card .value {{ font-size: 2.5em; font-weight: bold; color: #00d9ff; }}
        .stat-card .label {{ color: #888; }}
        .stat-card.critical .value {{ color: #ff4757; }}
        .stat-card.high .value {{ color: #ffa502; }}
        .section {{ background: rgba(255,255,255,0.05); border-radius: 10px; padding: 25px; margin-bottom: 25px; }}
        .section h2 {{ color: #00d9ff; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }}
        th {{ background: rgba(0,217,255,0.1); color: #00d9ff; }}
        .badge {{ padding: 4px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
        .badge-critical {{ background: #ff4757; color: white; }}
        .badge-high {{ background: #ffa502; color: white; }}
        .badge-medium {{ background: #ffdd59; color: black; }}
        .badge-low {{ background: #2ed573; color: white; }}
        .badge-unknown {{ background: #888; color: white; }}
        .no-crashes {{ text-align: center; padding: 40px; color: #2ed573; font-size: 1.2em; }}
        .footer {{ text-align: center; padding: 20px; color: #666; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SOFuzz Report</h1>
            <p>Fuzzing Results for {data.target_name}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="value">{data.total_iterations:,}</div>
                <div class="label">Total Iterations</div>
            </div>
            <div class="stat-card">
                <div class="value">{data.exec_per_second:.1f}</div>
                <div class="label">Exec/Second</div>
            </div>
            <div class="stat-card critical">
                <div class="value">{data.unique_crashes}</div>
                <div class="label">Unique Crashes</div>
            </div>
            <div class="stat-card">
                <div class="value">{data.timeouts}</div>
                <div class="label">Timeouts</div>
            </div>
            <div class="stat-card">
                <div class="value">{data.duration:.1f}s</div>
                <div class="label">Duration</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Session Information</h2>
            <p><strong>Target:</strong> {data.target_name}</p>
            <p><strong>Path:</strong> {data.target_path or 'N/A'}</p>
            <p><strong>Start Time:</strong> {data.start_time}</p>
            <p><strong>End Time:</strong> {data.end_time}</p>
        </div>
        
        <div class="section">
            <h2>Crash Details</h2>
            {no_crashes_html}
            {"" if not data.crashes else f'''
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Crash ID</th>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Signal</th>
                        <th>Exploitability</th>
                        <th>Input Size</th>
                    </tr>
                </thead>
                <tbody>
                    {crash_rows}
                </tbody>
            </table>
            '''}
        </div>
        
        <div class="footer">
            <p>Generated by SOFuzz</p>
            <p>{data.end_time}</p>
        </div>
    </div>
</body>
</html>
"""
        return html
