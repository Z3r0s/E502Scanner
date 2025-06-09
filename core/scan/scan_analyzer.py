"""
Scan Analyzer for E502 OSINT Terminal
Provides comprehensive scan result analysis capabilities.
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

logger = logging.getLogger("E502OSINT.ScanAnalyzer")
console = Console()

class ScanAnalyzer:
    def __init__(self):
        self.scan_dir = Path("scans")
        self.analysis_dir = self.scan_dir / "analysis"
        self._ensure_dirs()
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        self.analysis_dir.mkdir(parents=True, exist_ok=True)
    
    def analyze_result(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Analyze a scan result."""
        try:
            # Get result
            result = scan_result_manager.get_result(scan_id)
            if not result:
                logger.error(f"Result not found: {scan_id}")
                return None
            
            # Initialize analysis
            analysis = {
                "scan_id": scan_id,
                "profile_name": result.profile_name,
                "target": result.target,
                "scan_type": result.scan_type,
                "start_time": result.start_time,
                "end_time": result.end_time,
                "duration": (result.end_time - result.start_time).total_seconds() if result.end_time else None,
                "status": result.status,
                "findings_count": len(result.findings),
                "severity_distribution": {},
                "category_distribution": {},
                "cve_distribution": {},
                "average_cvss": 0.0,
                "top_findings": [],
                "recommendations": []
            }
            
            # Analyze findings
            if result.findings:
                # Count severities and categories
                for finding in result.findings:
                    # Count severities
                    analysis["severity_distribution"][finding.severity] = analysis["severity_distribution"].get(finding.severity, 0) + 1
                    
                    # Count categories
                    analysis["category_distribution"][finding.category] = analysis["category_distribution"].get(finding.category, 0) + 1
                    
                    # Count CVEs
                    if finding.cve_id:
                        analysis["cve_distribution"][finding.cve_id] = analysis["cve_distribution"].get(finding.cve_id, 0) + 1
                    
                    # Calculate average CVSS
                    if finding.cvss_score:
                        analysis["average_cvss"] += finding.cvss_score
                
                # Calculate average CVSS
                if analysis["average_cvss"] > 0:
                    analysis["average_cvss"] /= len([f for f in result.findings if f.cvss_score])
                
                # Get top findings
                analysis["top_findings"] = sorted(
                    result.findings,
                    key=lambda x: (
                        {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(x.severity, 0),
                        x.cvss_score or 0
                    ),
                    reverse=True
                )[:10]
                
                # Generate recommendations
                analysis["recommendations"] = self._generate_recommendations(result.findings)
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing result: {str(e)}")
            return None
    
    def analyze_results(self, results: List[str]) -> Optional[Dict[str, Any]]:
        """Analyze multiple scan results."""
        try:
            # Initialize analysis
            analysis = {
                "total_scans": len(results),
                "completed_scans": 0,
                "failed_scans": 0,
                "total_findings": 0,
                "severity_distribution": {},
                "category_distribution": {},
                "cve_distribution": {},
                "average_cvss": 0.0,
                "scan_duration": 0.0,
                "top_findings": [],
                "recommendations": []
            }
            
            # Analyze each result
            for scan_id in results:
                result_analysis = self.analyze_result(scan_id)
                if result_analysis:
                    # Update counts
                    if result_analysis["status"] == "completed":
                        analysis["completed_scans"] += 1
                    elif result_analysis["status"] == "failed":
                        analysis["failed_scans"] += 1
                    
                    # Update findings
                    analysis["total_findings"] += result_analysis["findings_count"]
                    
                    # Update distributions
                    for severity, count in result_analysis["severity_distribution"].items():
                        analysis["severity_distribution"][severity] = analysis["severity_distribution"].get(severity, 0) + count
                    
                    for category, count in result_analysis["category_distribution"].items():
                        analysis["category_distribution"][category] = analysis["category_distribution"].get(category, 0) + count
                    
                    for cve, count in result_analysis["cve_distribution"].items():
                        analysis["cve_distribution"][cve] = analysis["cve_distribution"].get(cve, 0) + count
                    
                    # Update average CVSS
                    if result_analysis["average_cvss"] > 0:
                        analysis["average_cvss"] += result_analysis["average_cvss"]
                    
                    # Update scan duration
                    if result_analysis["duration"]:
                        analysis["scan_duration"] += result_analysis["duration"]
                    
                    # Update top findings
                    analysis["top_findings"].extend(result_analysis["top_findings"])
                    
                    # Update recommendations
                    analysis["recommendations"].extend(result_analysis["recommendations"])
            
            # Calculate averages
            if analysis["completed_scans"] > 0:
                analysis["average_cvss"] /= analysis["completed_scans"]
                analysis["scan_duration"] /= analysis["completed_scans"]
            
            # Sort top findings
            analysis["top_findings"] = sorted(
                analysis["top_findings"],
                key=lambda x: (
                    {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(x.severity, 0),
                    x.cvss_score or 0
                ),
                reverse=True
            )[:10]
            
            # Remove duplicate recommendations
            analysis["recommendations"] = list(set(analysis["recommendations"]))
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing results: {str(e)}")
            return None
    
    def _generate_recommendations(self, findings: List[ScanFinding]) -> List[str]:
        """Generate recommendations from findings."""
        try:
            recommendations = []
            
            # Group findings by category
            category_findings = {}
            for finding in findings:
                if finding.category not in category_findings:
                    category_findings[finding.category] = []
                category_findings[finding.category].append(finding)
            
            # Generate recommendations for each category
            for category, category_findings in category_findings.items():
                if category == "network":
                    # Network security recommendations
                    if any(f.severity in ["critical", "high"] for f in category_findings):
                        recommendations.append("Implement strict firewall rules and network segmentation.")
                        recommendations.append("Enable intrusion detection and prevention systems.")
                    
                    if any(f.severity in ["medium", "low"] for f in category_findings):
                        recommendations.append("Review and update network security policies.")
                        recommendations.append("Conduct regular network security assessments.")
                
                elif category == "web":
                    # Web security recommendations
                    if any(f.severity in ["critical", "high"] for f in category_findings):
                        recommendations.append("Implement web application firewall (WAF).")
                        recommendations.append("Enable secure HTTP headers and content security policy.")
                    
                    if any(f.severity in ["medium", "low"] for f in category_findings):
                        recommendations.append("Update web application security controls.")
                        recommendations.append("Conduct regular web security testing.")
                
                elif category == "ssl":
                    # SSL/TLS recommendations
                    if any(f.severity in ["critical", "high"] for f in category_findings):
                        recommendations.append("Update SSL/TLS configuration to use strong protocols and ciphers.")
                        recommendations.append("Implement certificate management and monitoring.")
                    
                    if any(f.severity in ["medium", "low"] for f in category_findings):
                        recommendations.append("Review and update SSL/TLS security policies.")
                        recommendations.append("Conduct regular SSL/TLS security assessments.")
                
                elif category == "vulnerability":
                    # Vulnerability management recommendations
                    if any(f.severity in ["critical", "high"] for f in category_findings):
                        recommendations.append("Implement vulnerability management program.")
                        recommendations.append("Enable automated vulnerability scanning and patching.")
                    
                    if any(f.severity in ["medium", "low"] for f in category_findings):
                        recommendations.append("Review and update vulnerability management policies.")
                        recommendations.append("Conduct regular vulnerability assessments.")
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")
            return []
    
    def plot_analysis(self, analysis: Dict[str, Any], output_path: Optional[str] = None) -> None:
        """Plot analysis results."""
        try:
            # Create figure
            fig = plt.figure(figsize=(15, 10))
            
            # Plot severity distribution
            plt.subplot(2, 2, 1)
            severities = list(analysis["severity_distribution"].keys())
            counts = list(analysis["severity_distribution"].values())
            plt.bar(severities, counts)
            plt.title("Severity Distribution")
            plt.xlabel("Severity")
            plt.ylabel("Count")
            
            # Plot category distribution
            plt.subplot(2, 2, 2)
            categories = list(analysis["category_distribution"].keys())
            counts = list(analysis["category_distribution"].values())
            plt.bar(categories, counts)
            plt.title("Category Distribution")
            plt.xlabel("Category")
            plt.ylabel("Count")
            plt.xticks(rotation=45)
            
            # Plot CVE distribution
            plt.subplot(2, 2, 3)
            cves = list(analysis["cve_distribution"].keys())
            counts = list(analysis["cve_distribution"].values())
            plt.bar(cves, counts)
            plt.title("CVE Distribution")
            plt.xlabel("CVE ID")
            plt.ylabel("Count")
            plt.xticks(rotation=45)
            
            # Plot findings over time
            plt.subplot(2, 2, 4)
            dates = [f.start_time for f in analysis["top_findings"]]
            severities = [{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(f.severity, 0) for f in analysis["top_findings"]]
            plt.scatter(dates, severities)
            plt.title("Findings Over Time")
            plt.xlabel("Date")
            plt.ylabel("Severity")
            plt.xticks(rotation=45)
            
            # Adjust layout
            plt.tight_layout()
            
            # Save or show plot
            if output_path:
                plt.savefig(output_path)
            else:
                plt.show()
            
        except Exception as e:
            logger.error(f"Error plotting analysis: {str(e)}")
    
    def display_analysis(self, analysis: Dict[str, Any]) -> None:
        """Display analysis results."""
        try:
            # Create summary panel
            summary_panel = Panel(
                f"[bold]Total Scans:[/bold] {analysis['total_scans']}\n"
                f"[bold]Completed Scans:[/bold] {analysis['completed_scans']}\n"
                f"[bold]Failed Scans:[/bold] {analysis['failed_scans']}\n"
                f"[bold]Total Findings:[/bold] {analysis['total_findings']}\n"
                f"[bold]Average CVSS:[/bold] {analysis['average_cvss']:.2f}\n"
                f"[bold]Average Scan Duration:[/bold] {analysis['scan_duration']:.2f} seconds",
                title="Analysis Summary",
                border_style="blue"
            )
            
            console.print(summary_panel)
            
            # Create severity table
            severity_table = Table(title="Severity Distribution")
            severity_table.add_column("Severity", style="cyan")
            severity_table.add_column("Count", style="magenta")
            
            for severity, count in analysis["severity_distribution"].items():
                severity_table.add_row(severity, str(count))
            
            console.print(severity_table)
            
            # Create category table
            category_table = Table(title="Category Distribution")
            category_table.add_column("Category", style="cyan")
            category_table.add_column("Count", style="magenta")
            
            for category, count in analysis["category_distribution"].items():
                category_table.add_row(category, str(count))
            
            console.print(category_table)
            
            # Create top findings table
            findings_table = Table(title="Top Findings")
            findings_table.add_column("Severity", style="cyan")
            findings_table.add_column("Category", style="magenta")
            findings_table.add_column("Title", style="green")
            findings_table.add_column("CVSS", style="yellow")
            
            for finding in analysis["top_findings"]:
                findings_table.add_row(
                    finding.severity,
                    finding.category,
                    finding.title,
                    str(finding.cvss_score) if finding.cvss_score else "N/A"
                )
            
            console.print(findings_table)
            
            # Create recommendations panel
            recommendations_panel = Panel(
                "\n".join(f"• {rec}" for rec in analysis["recommendations"]),
                title="Recommendations",
                border_style="green"
            )
            
            console.print(recommendations_panel)
            
        except Exception as e:
            logger.error(f"Error displaying analysis: {str(e)}")
            console.print(f"[red]Error displaying analysis: {str(e)}[/red]")

# Create global instance
scan_analyzer = ScanAnalyzer() 