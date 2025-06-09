"""
Report Manager for E502 OSINT Terminal
Provides comprehensive report generation and management capabilities.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
import pytz
from pathlib import Path
from dataclasses import dataclass, asdict
import shutil
import hashlib
import platform
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from jinja2 import Environment, FileSystemLoader
import pdfkit
from weasyprint import HTML
import markdown
import yaml
from collections import defaultdict

logger = logging.getLogger("E502OSINT.ReportManager")
console = Console()

@dataclass
class ReportTemplate:
    """Report template data class."""
    name: str
    description: str
    template_file: str
    format: str
    sections: List[str]
    created_at: datetime
    updated_at: datetime
    author: str
    version: str
    tags: List[str] = None

@dataclass
class Report:
    """Report data class."""
    report_id: str
    title: str
    template: str
    target: str
    scan_type: str
    timestamp: datetime
    findings: Dict[str, Any]
    format: str
    status: str
    error: Optional[str] = None
    duration: Optional[float] = None
    author: Optional[str] = None
    tags: List[str] = None

class ReportManager:
    def __init__(self):
        self.report_dir = Path("reports")
        self.templates_dir = self.report_dir / "templates"
        self.exports_dir = self.report_dir / "exports"
        self.backup_dir = self.report_dir / "backups"
        self.templates_file = self.templates_dir / "templates.json"
        self.reports_file = self.report_dir / "reports.json"
        self._ensure_dirs()
        self._load_templates()
        self._load_reports()
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.exports_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_templates(self) -> None:
        """Load report templates."""
        try:
            if self.templates_file.exists():
                with open(self.templates_file, 'r') as f:
                    templates_data = json.load(f)
                    self.templates = [ReportTemplate(**template) for template in templates_data]
            else:
                self.templates = []
                self._create_default_templates()
        except Exception as e:
            logger.error(f"Error loading templates: {str(e)}")
            self.templates = []
    
    def _load_reports(self) -> None:
        """Load reports."""
        try:
            if self.reports_file.exists():
                with open(self.reports_file, 'r') as f:
                    reports_data = json.load(f)
                    self.reports = [Report(**report) for report in reports_data]
            else:
                self.reports = []
        except Exception as e:
            logger.error(f"Error loading reports: {str(e)}")
            self.reports = []
    
    def _save_templates(self) -> None:
        """Save report templates."""
        try:
            with open(self.templates_file, 'w') as f:
                json.dump([asdict(template) for template in self.templates], f, indent=4, default=str)
        except Exception as e:
            logger.error(f"Error saving templates: {str(e)}")
    
    def _save_reports(self) -> None:
        """Save reports."""
        try:
            with open(self.reports_file, 'w') as f:
                json.dump([asdict(report) for report in self.reports], f, indent=4, default=str)
        except Exception as e:
            logger.error(f"Error saving reports: {str(e)}")
    
    def _create_default_templates(self) -> None:
        """Create default report templates."""
        try:
            # Create HTML template
            html_template = """
            <!DOCTYPE html>
            <html>
            <head>
                <title>{{ title }}</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    h1 { color: #333; }
                    .section { margin: 20px 0; }
                    .finding { margin: 10px 0; padding: 10px; background: #f5f5f5; }
                    .critical { border-left: 5px solid #ff0000; }
                    .high { border-left: 5px solid #ff6600; }
                    .medium { border-left: 5px solid #ffcc00; }
                    .low { border-left: 5px solid #00cc00; }
                </style>
            </head>
            <body>
                <h1>{{ title }}</h1>
                <div class="section">
                    <h2>Scan Information</h2>
                    <p>Target: {{ target }}</p>
                    <p>Scan Type: {{ scan_type }}</p>
                    <p>Timestamp: {{ timestamp }}</p>
                    <p>Duration: {{ duration }} seconds</p>
                </div>
                <div class="section">
                    <h2>Findings</h2>
                    {% for finding in findings %}
                    <div class="finding {{ finding.severity }}">
                        <h3>{{ finding.title }}</h3>
                        <p>{{ finding.description }}</p>
                        {% if finding.recommendation %}
                        <p><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
            </body>
            </html>
            """
            
            # Create Markdown template
            markdown_template = """
            # {{ title }}
            
            ## Scan Information
            - Target: {{ target }}
            - Scan Type: {{ scan_type }}
            - Timestamp: {{ timestamp }}
            - Duration: {{ duration }} seconds
            
            ## Findings
            {% for finding in findings %}
            ### {{ finding.title }}
            {{ finding.description }}
            
            {% if finding.recommendation %}
            **Recommendation:** {{ finding.recommendation }}
            {% endif %}
            
            ---
            {% endfor %}
            """
            
            # Save templates
            html_template_path = self.templates_dir / "default.html"
            markdown_template_path = self.templates_dir / "default.md"
            
            with open(html_template_path, 'w') as f:
                f.write(html_template)
            
            with open(markdown_template_path, 'w') as f:
                f.write(markdown_template)
            
            # Create template records
            self.templates = [
                ReportTemplate(
                    name="Default HTML",
                    description="Default HTML report template",
                    template_file=str(html_template_path),
                    format="html",
                    sections=["scan_info", "findings"],
                    created_at=datetime.now(pytz.UTC),
                    updated_at=datetime.now(pytz.UTC),
                    author="E502 OSINT Terminal",
                    version="1.0.0",
                    tags=["default", "html"]
                ),
                ReportTemplate(
                    name="Default Markdown",
                    description="Default Markdown report template",
                    template_file=str(markdown_template_path),
                    format="markdown",
                    sections=["scan_info", "findings"],
                    created_at=datetime.now(pytz.UTC),
                    updated_at=datetime.now(pytz.UTC),
                    author="E502 OSINT Terminal",
                    version="1.0.0",
                    tags=["default", "markdown"]
                )
            ]
            
            self._save_templates()
            
        except Exception as e:
            logger.error(f"Error creating default templates: {str(e)}")
    
    def add_template(self, template: ReportTemplate) -> bool:
        """Add a new report template."""
        try:
            # Check if template file exists
            if not os.path.exists(template.template_file):
                logger.error(f"Template file not found: {template.template_file}")
                return False
            
            # Add template
            self.templates.append(template)
            self._save_templates()
            return True
        except Exception as e:
            logger.error(f"Error adding template: {str(e)}")
            return False
    
    def get_template(self, name: str) -> Optional[ReportTemplate]:
        """Get a report template by name."""
        try:
            for template in self.templates:
                if template.name == name:
                    return template
            return None
        except Exception as e:
            logger.error(f"Error getting template: {str(e)}")
            return None
    
    def update_template(self, name: str, updates: Dict[str, Any]) -> bool:
        """Update a report template."""
        try:
            for template in self.templates:
                if template.name == name:
                    for key, value in updates.items():
                        if hasattr(template, key):
                            setattr(template, key, value)
                    template.updated_at = datetime.now(pytz.UTC)
                    self._save_templates()
                    return True
            return False
        except Exception as e:
            logger.error(f"Error updating template: {str(e)}")
            return False
    
    def delete_template(self, name: str) -> bool:
        """Delete a report template."""
        try:
            for i, template in enumerate(self.templates):
                if template.name == name:
                    # Delete template file
                    if os.path.exists(template.template_file):
                        os.remove(template.template_file)
                    
                    # Remove template
                    del self.templates[i]
                    self._save_templates()
                    return True
            return False
        except Exception as e:
            logger.error(f"Error deleting template: {str(e)}")
            return False
    
    def generate_report(self, template_name: str, data: Dict[str, Any], output_format: str = "html") -> Optional[str]:
        """Generate a report using a template."""
        try:
            # Get template
            template = self.get_template(template_name)
            if not template:
                logger.error(f"Template not found: {template_name}")
                return None
            
            # Load template
            env = Environment(loader=FileSystemLoader(os.path.dirname(template.template_file)))
            template_obj = env.get_template(os.path.basename(template.template_file))
            
            # Render template
            content = template_obj.render(**data)
            
            # Generate output file path
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.exports_dir / f"report_{timestamp}.{output_format}"
            
            # Save report
            if output_format == "html":
                with open(output_path, 'w') as f:
                    f.write(content)
            elif output_format == "pdf":
                if template.format == "html":
                    pdfkit.from_string(content, str(output_path))
                else:
                    # Convert markdown to HTML first
                    html_content = self._markdown_to_html(content)
                    pdfkit.from_string(html_content, str(output_path))
            elif output_format == "markdown":
                with open(output_path, 'w') as f:
                    f.write(content)
            else:
                logger.error(f"Unsupported output format: {output_format}")
                return None
            
            # Create report record
            report = Report(
                report_id=hashlib.md5(str(output_path).encode()).hexdigest(),
                title=data.get("title", "Untitled Report"),
                template=template_name,
                target=data.get("target", "Unknown"),
                scan_type=data.get("scan_type", "Unknown"),
                timestamp=datetime.now(pytz.UTC),
                findings=data.get("findings", {}),
                format=output_format,
                status="completed",
                duration=data.get("duration", 0),
                author=data.get("author", "E502 OSINT Terminal"),
                tags=data.get("tags", [])
            )
            
            self.reports.append(report)
            self._save_reports()
            
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return None
    
    def _markdown_to_html(self, markdown: str) -> str:
        """Convert markdown to HTML."""
        try:
            # Simple markdown to HTML conversion
            html = markdown.replace("# ", "<h1>").replace("\n# ", "</h1>\n<h1>")
            html = html.replace("## ", "<h2>").replace("\n## ", "</h2>\n<h2>")
            html = html.replace("### ", "<h3>").replace("\n### ", "</h3>\n<h3>")
            html = html.replace("**", "<strong>").replace("**", "</strong>")
            html = html.replace("*", "<em>").replace("*", "</em>")
            html = html.replace("---", "<hr>")
            html = html.replace("\n", "<br>\n")
            
            return f"<html><body>{html}</body></html>"
        except Exception as e:
            logger.error(f"Error converting markdown to HTML: {str(e)}")
            return markdown
    
    def get_report(self, report_id: str) -> Optional[Report]:
        """Get a report by ID."""
        try:
            for report in self.reports:
                if report.report_id == report_id:
                    return report
            return None
        except Exception as e:
            logger.error(f"Error getting report: {str(e)}")
            return None
    
    def get_reports_by_template(self, template_name: str) -> List[Report]:
        """Get all reports using a specific template."""
        try:
            return [report for report in self.reports if report.template == template_name]
        except Exception as e:
            logger.error(f"Error getting reports by template: {str(e)}")
            return []
    
    def get_reports_by_target(self, target: str) -> List[Report]:
        """Get all reports for a specific target."""
        try:
            return [report for report in self.reports if report.target == target]
        except Exception as e:
            logger.error(f"Error getting reports by target: {str(e)}")
            return []
    
    def get_reports_by_scan_type(self, scan_type: str) -> List[Report]:
        """Get all reports for a specific scan type."""
        try:
            return [report for report in self.reports if report.scan_type == scan_type]
        except Exception as e:
            logger.error(f"Error getting reports by scan type: {str(e)}")
            return []
    
    def get_reports_by_date_range(self, start_date: datetime, end_date: datetime) -> List[Report]:
        """Get all reports within a date range."""
        try:
            return [
                report for report in self.reports
                if start_date <= report.timestamp <= end_date
            ]
        except Exception as e:
            logger.error(f"Error getting reports by date range: {str(e)}")
            return []
    
    def delete_report(self, report_id: str) -> bool:
        """Delete a report."""
        try:
            for i, report in enumerate(self.reports):
                if report.report_id == report_id:
                    # Delete report file
                    report_path = self.exports_dir / f"report_{report_id}.{report.format}"
                    if report_path.exists():
                        report_path.unlink()
                    
                    # Remove report
                    del self.reports[i]
                    self._save_reports()
                    return True
            return False
        except Exception as e:
            logger.error(f"Error deleting report: {str(e)}")
            return False
    
    def backup_reports(self) -> bool:
        """Create a backup of all reports."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_dir / f"reports_backup_{timestamp}.json"
            
            with open(backup_path, 'w') as f:
                json.dump([asdict(report) for report in self.reports], f, indent=4, default=str)
            
            return True
        except Exception as e:
            logger.error(f"Error backing up reports: {str(e)}")
            return False
    
    def restore_reports(self, backup_file: str) -> bool:
        """Restore reports from backup."""
        try:
            backup_path = self.backup_dir / backup_file
            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_file}")
                return False
            
            with open(backup_path, 'r') as f:
                reports_data = json.load(f)
                self.reports = [Report(**report) for report in reports_data]
            
            self._save_reports()
            return True
        except Exception as e:
            logger.error(f"Error restoring reports: {str(e)}")
            return False
    
    def display_reports(self, filters: Optional[Dict[str, Any]] = None) -> None:
        """Display reports in a formatted way."""
        try:
            # Filter reports if needed
            filtered_reports = self.reports
            if filters:
                if "template" in filters:
                    filtered_reports = [r for r in filtered_reports if r.template == filters["template"]]
                if "target" in filters:
                    filtered_reports = [r for r in filtered_reports if r.target == filters["target"]]
                if "scan_type" in filters:
                    filtered_reports = [r for r in filtered_reports if r.scan_type == filters["scan_type"]]
                if "start_date" in filters and "end_date" in filters:
                    filtered_reports = [
                        r for r in filtered_reports
                        if filters["start_date"] <= r.timestamp <= filters["end_date"]
                    ]
            
            # Create table
            table = Table(title="Reports")
            table.add_column("ID", style="cyan")
            table.add_column("Title", style="green")
            table.add_column("Template", style="yellow")
            table.add_column("Target", style="magenta")
            table.add_column("Format", style="blue")
            table.add_column("Timestamp", style="red")
            
            # Add rows
            for report in filtered_reports:
                table.add_row(
                    report.report_id[:8],
                    report.title,
                    report.template,
                    report.target,
                    report.format,
                    report.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying reports: {str(e)}")
            console.print(f"[red]Error displaying reports: {str(e)}[/]")

# Create global instance
report_manager = ReportManager() 