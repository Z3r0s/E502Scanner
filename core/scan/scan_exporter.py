"""
Scan Exporter for E502 OSINT Terminal
Provides comprehensive scan result export capabilities.
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
import yaml
import csv
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

logger = logging.getLogger("E502OSINT.ScanExporter")
console = Console()

class ScanExporter:
    def __init__(self):
        self.scan_dir = Path("scans")
        self.export_dir = self.scan_dir / "exports"
        self._ensure_dirs()
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        self.export_dir.mkdir(parents=True, exist_ok=True)
    
    def export_result(self, scan_id: str, format: str = "json", output_path: Optional[str] = None) -> Optional[str]:
        """Export a scan result."""
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
            
            # Prepare export data
            export_data = {
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
                "findings": [asdict(f) for f in result.findings],
                "recommendations": analysis["recommendations"],
                "severity_distribution": analysis["severity_distribution"],
                "category_distribution": analysis["category_distribution"],
                "cve_distribution": analysis["cve_distribution"]
            }
            
            # Generate output
            if not output_path:
                output_path = str(self.export_dir / f"{scan_id}.{format}")
            
            if format == "json":
                with open(output_path, "w") as f:
                    json.dump(export_data, f, indent=2, default=str)
            
            elif format == "yaml":
                with open(output_path, "w") as f:
                    yaml.dump(export_data, f, default_flow_style=False)
            
            elif format == "csv":
                # Convert findings to DataFrame
                findings_df = pd.DataFrame([asdict(f) for f in result.findings])
                
                # Export findings
                findings_df.to_csv(output_path, index=False)
            
            elif format == "xml":
                # Create XML structure
                root = ET.Element("scan_result")
                
                # Add basic info
                ET.SubElement(root, "scan_id").text = scan_id
                ET.SubElement(root, "profile_name").text = result.profile_name
                ET.SubElement(root, "target").text = result.target
                ET.SubElement(root, "scan_type").text = result.scan_type
                ET.SubElement(root, "start_time").text = str(result.start_time)
                ET.SubElement(root, "end_time").text = str(result.end_time)
                ET.SubElement(root, "duration").text = str(export_data["duration"])
                ET.SubElement(root, "status").text = result.status
                ET.SubElement(root, "findings_count").text = str(len(result.findings))
                ET.SubElement(root, "average_cvss").text = str(analysis["average_cvss"])
                
                # Add findings
                findings_elem = ET.SubElement(root, "findings")
                for finding in result.findings:
                    finding_elem = ET.SubElement(findings_elem, "finding")
                    ET.SubElement(finding_elem, "title").text = finding.title
                    ET.SubElement(finding_elem, "severity").text = finding.severity
                    ET.SubElement(finding_elem, "category").text = finding.category
                    ET.SubElement(finding_elem, "description").text = finding.description
                    if finding.cve_id:
                        ET.SubElement(finding_elem, "cve_id").text = finding.cve_id
                    if finding.cvss_score:
                        ET.SubElement(finding_elem, "cvss_score").text = str(finding.cvss_score)
                    if finding.recommendation:
                        ET.SubElement(finding_elem, "recommendation").text = finding.recommendation
                    if finding.evidence:
                        ET.SubElement(finding_elem, "evidence").text = json.dumps(finding.evidence)
                
                # Add recommendations
                recommendations_elem = ET.SubElement(root, "recommendations")
                for recommendation in analysis["recommendations"]:
                    ET.SubElement(recommendations_elem, "recommendation").text = recommendation
                
                # Add distributions
                distributions_elem = ET.SubElement(root, "distributions")
                
                severity_elem = ET.SubElement(distributions_elem, "severity")
                for severity, count in analysis["severity_distribution"].items():
                    ET.SubElement(severity_elem, "item", {"name": severity, "count": str(count)})
                
                category_elem = ET.SubElement(distributions_elem, "category")
                for category, count in analysis["category_distribution"].items():
                    ET.SubElement(category_elem, "item", {"name": category, "count": str(count)})
                
                cve_elem = ET.SubElement(distributions_elem, "cve")
                for cve, count in analysis["cve_distribution"].items():
                    ET.SubElement(cve_elem, "item", {"name": cve, "count": str(count)})
                
                # Write XML
                xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
                with open(output_path, "w") as f:
                    f.write(xml_str)
            
            else:
                logger.error(f"Unsupported format: {format}")
                return None
            
            logger.info(f"Exported result: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error exporting result: {str(e)}")
            return None
    
    def export_results(self, scan_ids: List[str], format: str = "json", output_dir: Optional[str] = None) -> List[str]:
        """Export multiple scan results."""
        try:
            exports = []
            
            for scan_id in scan_ids:
                if output_dir:
                    output_path = os.path.join(output_dir, f"{scan_id}.{format}")
                else:
                    output_path = None
                
                export_path = self.export_result(scan_id, format, output_path)
                if export_path:
                    exports.append(export_path)
            
            return exports
            
        except Exception as e:
            logger.error(f"Error exporting results: {str(e)}")
            return []
    
    def export_analysis(self, analysis: Dict[str, Any], format: str = "json", output_path: Optional[str] = None) -> Optional[str]:
        """Export analysis results."""
        try:
            # Generate output
            if not output_path:
                output_path = str(self.export_dir / f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}")
            
            if format == "json":
                with open(output_path, "w") as f:
                    json.dump(analysis, f, indent=2, default=str)
            
            elif format == "yaml":
                with open(output_path, "w") as f:
                    yaml.dump(analysis, f, default_flow_style=False)
            
            elif format == "csv":
                # Convert to DataFrame
                df = pd.DataFrame([{
                    "total_scans": analysis["total_scans"],
                    "completed_scans": analysis["completed_scans"],
                    "failed_scans": analysis["failed_scans"],
                    "total_findings": analysis["total_findings"],
                    "average_cvss": analysis["average_cvss"],
                    "scan_duration": analysis["scan_duration"]
                }])
                
                # Export
                df.to_csv(output_path, index=False)
            
            elif format == "xml":
                # Create XML structure
                root = ET.Element("analysis")
                
                # Add basic info
                ET.SubElement(root, "total_scans").text = str(analysis["total_scans"])
                ET.SubElement(root, "completed_scans").text = str(analysis["completed_scans"])
                ET.SubElement(root, "failed_scans").text = str(analysis["failed_scans"])
                ET.SubElement(root, "total_findings").text = str(analysis["total_findings"])
                ET.SubElement(root, "average_cvss").text = str(analysis["average_cvss"])
                ET.SubElement(root, "scan_duration").text = str(analysis["scan_duration"])
                
                # Add distributions
                distributions_elem = ET.SubElement(root, "distributions")
                
                severity_elem = ET.SubElement(distributions_elem, "severity")
                for severity, count in analysis["severity_distribution"].items():
                    ET.SubElement(severity_elem, "item", {"name": severity, "count": str(count)})
                
                category_elem = ET.SubElement(distributions_elem, "category")
                for category, count in analysis["category_distribution"].items():
                    ET.SubElement(category_elem, "item", {"name": category, "count": str(count)})
                
                cve_elem = ET.SubElement(distributions_elem, "cve")
                for cve, count in analysis["cve_distribution"].items():
                    ET.SubElement(cve_elem, "item", {"name": cve, "count": str(count)})
                
                # Add top findings
                findings_elem = ET.SubElement(root, "top_findings")
                for finding in analysis["top_findings"]:
                    finding_elem = ET.SubElement(findings_elem, "finding")
                    ET.SubElement(finding_elem, "title").text = finding.title
                    ET.SubElement(finding_elem, "severity").text = finding.severity
                    ET.SubElement(finding_elem, "category").text = finding.category
                    ET.SubElement(finding_elem, "description").text = finding.description
                    if finding.cve_id:
                        ET.SubElement(finding_elem, "cve_id").text = finding.cve_id
                    if finding.cvss_score:
                        ET.SubElement(finding_elem, "cvss_score").text = str(finding.cvss_score)
                    if finding.recommendation:
                        ET.SubElement(finding_elem, "recommendation").text = finding.recommendation
                
                # Add recommendations
                recommendations_elem = ET.SubElement(root, "recommendations")
                for recommendation in analysis["recommendations"]:
                    ET.SubElement(recommendations_elem, "recommendation").text = recommendation
                
                # Write XML
                xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
                with open(output_path, "w") as f:
                    f.write(xml_str)
            
            else:
                logger.error(f"Unsupported format: {format}")
                return None
            
            logger.info(f"Exported analysis: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error exporting analysis: {str(e)}")
            return None
    
    def display_export(self, export_path: str) -> None:
        """Display an export."""
        try:
            # Check if export exists
            if not os.path.exists(export_path):
                console.print(f"[red]Export not found: {export_path}[/red]")
                return
            
            # Read export
            with open(export_path, "r") as f:
                export = f.read()
            
            # Display export
            console.print(Panel(export, title="Scan Export", border_style="blue"))
            
        except Exception as e:
            logger.error(f"Error displaying export: {str(e)}")
            console.print(f"[red]Error displaying export: {str(e)}[/red]")

# Create global instance
scan_exporter = ScanExporter() 