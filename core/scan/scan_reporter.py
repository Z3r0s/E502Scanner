"""
Scan Reporter for E502 OSINT Terminal
Provides comprehensive scan report generation capabilities.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import pytz
from pathlib import Path
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import jinja2
import pdfkit
import weasyprint
import yaml

logger = logging.getLogger("E502OSINT.ScanReporter")
console = Console()

class ScanReporter:
    def __init__(self):
        self.scan_dir = Path("scans")
        self.report_dir = self.scan_dir / "reports"
        self.template_dir = self.scan_dir / "templates"
        self._ensure_dirs()
        self._load_templates()
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.template_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_templates(self) -> None:
        """Load report templates."""
        try:
            # Create default templates
            self._create_default_templates()
            
            # Load templates
            self.templates = {}
            for template_file in self.template_dir.glob("*.html"):
                with open(template_file, "r") as f:
                    self.templates[template_file.stem] = f.read()
            
        except Exception as e:
            logger.error(f"Error loading templates: {str(e)}")
    
    def _create_default_templates(self) -> None:
        """Create default report templates."""
        try:
            # Create summary template
            summary_template = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Scan Summary Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1 { color: #2c3e50; }
                    h2 { color: #34495e; }
                    .summary { background-color: #f8f9fa; padding: 20px; border-radius: 5px; }
                    .findings { margin-top: 20px; }
                    .finding { background-color: #fff; padding: 10px; margin: 10px 0; border-left: 5px solid #3498db; }
                    .critical { border-left-color: #e74c3c; }
                    .high { border-left-color: #e67e22; }
                    .medium { border-left-color: #f1c40f; }
                    .low { border-left-color: #2ecc71; }
                    .info { border-left-color: #95a5a6; }
                    .recommendations { margin-top: 20px; }
                    .recommendation { background-color: #fff; padding: 10px; margin: 10px 0; border-left: 5px solid #9b59b6; }
                </style>
            </head>
            <body>
                <h1>Scan Summary Report</h1>
                <div class="summary">
                    <h2>Summary</h2>
                    <p><strong>Scan ID:</strong> {{ scan_id }}</p>
                    <p><strong>Profile:</strong> {{ profile_name }}</p>
                    <p><strong>Target:</strong> {{ target }}</p>
                    <p><strong>Type:</strong> {{ scan_type }}</p>
                    <p><strong>Start Time:</strong> {{ start_time }}</p>
                    <p><strong>End Time:</strong> {{ end_time }}</p>
                    <p><strong>Duration:</strong> {{ duration }} seconds</p>
                    <p><strong>Status:</strong> {{ status }}</p>
                    <p><strong>Total Findings:</strong> {{ findings_count }}</p>
                    <p><strong>Average CVSS:</strong> {{ average_cvss }}</p>
                </div>
                <div class="findings">
                    <h2>Findings</h2>
                    {% for finding in findings %}
                    <div class="finding {{ finding.severity }}">
                        <h3>{{ finding.title }}</h3>
                        <p><strong>Severity:</strong> {{ finding.severity }}</p>
                        <p><strong>Category:</strong> {{ finding.category }}</p>
                        <p><strong>Description:</strong> {{ finding.description }}</p>
                        {% if finding.cve_id %}
                        <p><strong>CVE ID:</strong> {{ finding.cve_id }}</p>
                        {% endif %}
                        {% if finding.cvss_score %}
                        <p><strong>CVSS Score:</strong> {{ finding.cvss_score }}</p>
                        {% endif %}
                        {% if finding.recommendation %}
                        <p><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                <div class="recommendations">
                    <h2>Recommendations</h2>
                    {% for recommendation in recommendations %}
                    <div class="recommendation">
                        <p>{{ recommendation }}</p>
                    </div>
                    {% endfor %}
                </div>
            </body>
            </html>
            """
            
            # Create detailed template
            detailed_template = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>Detailed Scan Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1 { color: #2c3e50; }
                    h2 { color: #34495e; }
                    .summary { background-color: #f8f9fa; padding: 20px; border-radius: 5px; }
                    .findings { margin-top: 20px; }
                    .finding { background-color: #fff; padding: 10px; margin: 10px 0; border-left: 5px solid #3498db; }
                    .critical { border-left-color: #e74c3c; }
                    .high { border-left-color: #e67e22; }
                    .medium { border-left-color: #f1c40f; }
                    .low { border-left-color: #2ecc71; }
                    .info { border-left-color: #95a5a6; }
                    .recommendations { margin-top: 20px; }
                    .recommendation { background-color: #fff; padding: 10px; margin: 10px 0; border-left: 5px solid #9b59b6; }
                    .charts { margin-top: 20px; }
                    .chart { background-color: #fff; padding: 10px; margin: 10px 0; border: 1px solid #ddd; }
                </style>
            </head>
            <body>
                <h1>Detailed Scan Report</h1>
                <div class="summary">
                    <h2>Summary</h2>
                    <p><strong>Scan ID:</strong> {{ scan_id }}</p>
                    <p><strong>Profile:</strong> {{ profile_name }}</p>
                    <p><strong>Target:</strong> {{ target }}</p>
                    <p><strong>Type:</strong> {{ scan_type }}</p>
                    <p><strong>Start Time:</strong> {{ start_time }}</p>
                    <p><strong>End Time:</strong> {{ end_time }}</p>
                    <p><strong>Duration:</strong> {{ duration }} seconds</p>
                    <p><strong>Status:</strong> {{ status }}</p>
                    <p><strong>Total Findings:</strong> {{ findings_count }}</p>
                    <p><strong>Average CVSS:</strong> {{ average_cvss }}</p>
                </div>
                <div class="charts">
                    <h2>Charts</h2>
                    <div class="chart">
                        <h3>Severity Distribution</h3>
                        <img src="{{ severity_chart }}" alt="Severity Distribution">
                    </div>
                    <div class="chart">
                        <h3>Category Distribution</h3>
                        <img src="{{ category_chart }}" alt="Category Distribution">
                    </div>
                    <div class="chart">
                        <h3>CVE Distribution</h3>
                        <img src="{{ cve_chart }}" alt="CVE Distribution">
                    </div>
                    <div class="chart">
                        <h3>Findings Over Time</h3>
                        <img src="{{ time_chart }}" alt="Findings Over Time">
                    </div>
                </div>
                <div class="findings">
                    <h2>Findings</h2>
                    {% for finding in findings %}
                    <div class="finding {{ finding.severity }}">
                        <h3>{{ finding.title }}</h3>
                        <p><strong>Severity:</strong> {{ finding.severity }}</p>
                        <p><strong>Category:</strong> {{ finding.category }}</p>
                        <p><strong>Description:</strong> {{ finding.description }}</p>
                        {% if finding.cve_id %}
                        <p><strong>CVE ID:</strong> {{ finding.cve_id }}</p>
                        {% endif %}
                        {% if finding.cvss_score %}
                        <p><strong>CVSS Score:</strong> {{ finding.cvss_score }}</p>
                        {% endif %}
                        {% if finding.recommendation %}
                        <p><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
                        {% endif %}
                        {% if finding.evidence %}
                        <p><strong>Evidence:</strong></p>
                        <pre>{{ finding.evidence | tojson(indent=2) }}</pre>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                <div class="recommendations">
                    <h2>Recommendations</h2>
                    {% for recommendation in recommendations %}
                    <div class="recommendation">
                        <p>{{ recommendation }}</p>
                    </div>
                    {% endfor %}
                </div>
            </body>
            </html>
            """
            
            # Save templates
            with open(self.template_dir / "summary.html", "w") as f:
                f.write(summary_template)
            
            with open(self.template_dir / "detailed.html", "w") as f:
                f.write(detailed_template)
            
        except Exception as e:
            logger.error(f"Error creating default templates: {str(e)}")
    
    def generate_report(self, scan_id: str, template: str = "summary", format: str = "html", output_path: Optional[str] = None) -> Optional[str]:
        """Generate a scan report."""
        try:
            # Get result
            result = scan_result_manager.get_result(scan_id)
            if not result:
                logger.error(f"Result not found: {scan_id}")
                return None
            
            # Get analysis
            analysis = scan_analyzer.analyze_result(scan_id)
            if not analysis:
                logger.error(f"Analysis not found: {scan_id}")
                return None
            
            # Prepare template data
            template_data = {
                "scan_id": scan_id,
                "profile_name": result.profile_name,
                "target": result.target,
                "scan_type": result.scan_type,
                "start_time": result.start_time,
                "end_time": result.end_time,
                "duration": (result.end_time - result.start_time).total_seconds() if result.end_time else None,
                "status": result.status,
                "findings_count": len(result.findings),
                "average_cvss": analysis["average_cvss"],
                "findings": result.findings,
                "recommendations": analysis["recommendations"]
            }
            
            # Generate charts for detailed template
            if template == "detailed":
                # Create charts directory
                charts_dir = self.report_dir / "charts"
                charts_dir.mkdir(parents=True, exist_ok=True)
                
                # Generate charts
                scan_analyzer.plot_analysis(analysis, str(charts_dir / f"{scan_id}_severity.png"))
                scan_analyzer.plot_analysis(analysis, str(charts_dir / f"{scan_id}_category.png"))
                scan_analyzer.plot_analysis(analysis, str(charts_dir / f"{scan_id}_cve.png"))
                scan_analyzer.plot_analysis(analysis, str(charts_dir / f"{scan_id}_time.png"))
                
                # Add chart paths to template data
                template_data.update({
                    "severity_chart": f"charts/{scan_id}_severity.png",
                    "category_chart": f"charts/{scan_id}_category.png",
                    "cve_chart": f"charts/{scan_id}_cve.png",
                    "time_chart": f"charts/{scan_id}_time.png"
                })
            
            # Render template
            template = self.templates.get(template)
            if not template:
                logger.error(f"Template not found: {template}")
                return None
            
            html = jinja2.Template(template).render(**template_data)
            
            # Generate output
            if not output_path:
                output_path = str(self.report_dir / f"{scan_id}_{template}_{format}")
            
            if format == "html":
                with open(output_path, "w") as f:
                    f.write(html)
            
            elif format == "pdf":
                if os.name == "nt":
                    # Windows
                    pdfkit.from_string(html, output_path)
                else:
                    # Unix
                    weasyprint.HTML(string=html).write_pdf(output_path)
            
            else:
                logger.error(f"Unsupported format: {format}")
                return None
            
            logger.info(f"Generated report: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return None
    
    def generate_reports(self, scan_ids: List[str], template: str = "summary", format: str = "html", output_dir: Optional[str] = None) -> List[str]:
        """Generate multiple scan reports."""
        try:
            reports = []
            
            for scan_id in scan_ids:
                if output_dir:
                    output_path = os.path.join(output_dir, f"{scan_id}_{template}_{format}")
                else:
                    output_path = None
                
                report_path = self.generate_report(scan_id, template, format, output_path)
                if report_path:
                    reports.append(report_path)
            
            return reports
            
        except Exception as e:
            logger.error(f"Error generating reports: {str(e)}")
            return []
    
    def display_report(self, report_path: str) -> None:
        """Display a report."""
        try:
            # Check if report exists
            if not os.path.exists(report_path):
                console.print(f"[red]Report not found: {report_path}[/red]")
                return
            
            # Read report
            with open(report_path, "r") as f:
                report = f.read()
            
            # Display report
            console.print(Panel(report, title="Scan Report", border_style="blue"))
            
        except Exception as e:
            logger.error(f"Error displaying report: {str(e)}")
            console.print(f"[red]Error displaying report: {str(e)}[/red]")

# Create global instance
scan_reporter = ScanReporter() 