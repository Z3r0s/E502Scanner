"""
Scan Importer for E502 OSINT Terminal
Provides comprehensive scan result import capabilities.
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
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import yaml
import csv
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
import hashlib

logger = logging.getLogger("E502OSINT.ScanImporter")
console = Console()

class ScanImporter:
    def __init__(self):
        self.scan_dir = Path("scans")
        self.import_dir = self.scan_dir / "imports"
        self._ensure_dirs()
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        self.import_dir.mkdir(parents=True, exist_ok=True)
    
    def import_result(self, file_path: str) -> Optional[str]:
        """Import a scan result."""
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return None
            
            # Get file format
            format = file_path.split(".")[-1].lower()
            
            # Import data
            if format == "json":
                with open(file_path, "r") as f:
                    data = json.load(f)
            
            elif format == "yaml":
                with open(file_path, "r") as f:
                    data = yaml.safe_load(f)
            
            elif format == "csv":
                # Read CSV
                df = pd.read_csv(file_path)
                
                # Convert to dict
                data = df.to_dict("records")
                
                # Create result structure
                data = {
                    "scan_id": data[0].get("scan_id", ""),
                    "profile_name": data[0].get("profile_name", ""),
                    "target": data[0].get("target", ""),
                    "scan_type": data[0].get("scan_type", ""),
                    "start_time": data[0].get("start_time", ""),
                    "end_time": data[0].get("end_time", ""),
                    "status": data[0].get("status", ""),
                    "findings": data
                }
            
            elif format == "xml":
                # Parse XML
                tree = ET.parse(file_path)
                root = tree.getroot()
                
                # Convert to dict
                data = {
                    "scan_id": root.find("scan_id").text,
                    "profile_name": root.find("profile_name").text,
                    "target": root.find("target").text,
                    "scan_type": root.find("scan_type").text,
                    "start_time": root.find("start_time").text,
                    "end_time": root.find("end_time").text,
                    "status": root.find("status").text,
                    "findings": []
                }
                
                # Parse findings
                for finding_elem in root.find("findings"):
                    finding = {
                        "title": finding_elem.find("title").text,
                        "severity": finding_elem.find("severity").text,
                        "category": finding_elem.find("category").text,
                        "description": finding_elem.find("description").text
                    }
                    
                    if finding_elem.find("cve_id") is not None:
                        finding["cve_id"] = finding_elem.find("cve_id").text
                    
                    if finding_elem.find("cvss_score") is not None:
                        finding["cvss_score"] = float(finding_elem.find("cvss_score").text)
                    
                    if finding_elem.find("recommendation") is not None:
                        finding["recommendation"] = finding_elem.find("recommendation").text
                    
                    if finding_elem.find("evidence") is not None:
                        finding["evidence"] = json.loads(finding_elem.find("evidence").text)
                    
                    data["findings"].append(finding)
            
            else:
                logger.error(f"Unsupported format: {format}")
                return None
            
            # Validate data
            if not self._validate_data(data):
                logger.error("Invalid data format")
                return None
            
            # Create result
            result = ScanResult(
                result_id=data["scan_id"],
                profile_name=data["profile_name"],
                target=data["target"],
                scan_type=data["scan_type"],
                start_time=datetime.fromisoformat(data["start_time"]),
                end_time=datetime.fromisoformat(data["end_time"]) if data["end_time"] else None,
                status=data["status"],
                findings=[
                    ScanFinding(
                        finding_id=hashlib.md5(f"{f['title']}{f['severity']}{f['category']}".encode()).hexdigest(),
                        title=f["title"],
                        description=f["description"],
                        severity=f["severity"],
                        category=f["category"],
                        cve_id=f.get("cve_id"),
                        cvss_score=f.get("cvss_score"),
                        recommendation=f.get("recommendation"),
                        evidence=f.get("evidence")
                    )
                    for f in data["findings"]
                ]
            )
            
            # Add result
            scan_result_manager.add_result(result)
            
            logger.info(f"Imported result: {result.result_id}")
            return result.result_id
            
        except Exception as e:
            logger.error(f"Error importing result: {str(e)}")
            return None
    
    def import_results(self, file_paths: List[str]) -> List[str]:
        """Import multiple scan results."""
        try:
            results = []
            
            for file_path in file_paths:
                result_id = self.import_result(file_path)
                if result_id:
                    results.append(result_id)
            
            return results
            
        except Exception as e:
            logger.error(f"Error importing results: {str(e)}")
            return []
    
    def import_analysis(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Import analysis results."""
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return None
            
            # Get file format
            format = file_path.split(".")[-1].lower()
            
            # Import data
            if format == "json":
                with open(file_path, "r") as f:
                    data = json.load(f)
            
            elif format == "yaml":
                with open(file_path, "r") as f:
                    data = yaml.safe_load(f)
            
            elif format == "csv":
                # Read CSV
                df = pd.read_csv(file_path)
                
                # Convert to dict
                data = df.to_dict("records")[0]
            
            elif format == "xml":
                # Parse XML
                tree = ET.parse(file_path)
                root = tree.getroot()
                
                # Convert to dict
                data = {
                    "total_scans": int(root.find("total_scans").text),
                    "completed_scans": int(root.find("completed_scans").text),
                    "failed_scans": int(root.find("failed_scans").text),
                    "total_findings": int(root.find("total_findings").text),
                    "average_cvss": float(root.find("average_cvss").text),
                    "scan_duration": float(root.find("scan_duration").text),
                    "severity_distribution": {},
                    "category_distribution": {},
                    "cve_distribution": {},
                    "top_findings": [],
                    "recommendations": []
                }
                
                # Parse distributions
                distributions = root.find("distributions")
                
                for item in distributions.find("severity"):
                    data["severity_distribution"][item.get("name")] = int(item.get("count"))
                
                for item in distributions.find("category"):
                    data["category_distribution"][item.get("name")] = int(item.get("count"))
                
                for item in distributions.find("cve"):
                    data["cve_distribution"][item.get("name")] = int(item.get("count"))
                
                # Parse top findings
                for finding_elem in root.find("top_findings"):
                    finding = {
                        "title": finding_elem.find("title").text,
                        "severity": finding_elem.find("severity").text,
                        "category": finding_elem.find("category").text,
                        "description": finding_elem.find("description").text
                    }
                    
                    if finding_elem.find("cve_id") is not None:
                        finding["cve_id"] = finding_elem.find("cve_id").text
                    
                    if finding_elem.find("cvss_score") is not None:
                        finding["cvss_score"] = float(finding_elem.find("cvss_score").text)
                    
                    if finding_elem.find("recommendation") is not None:
                        finding["recommendation"] = finding_elem.find("recommendation").text
                    
                    data["top_findings"].append(finding)
                
                # Parse recommendations
                for rec_elem in root.find("recommendations"):
                    data["recommendations"].append(rec_elem.text)
            
            else:
                logger.error(f"Unsupported format: {format}")
                return None
            
            # Validate data
            if not self._validate_analysis(data):
                logger.error("Invalid analysis format")
                return None
            
            logger.info(f"Imported analysis from: {file_path}")
            return data
            
        except Exception as e:
            logger.error(f"Error importing analysis: {str(e)}")
            return None
    
    def _validate_data(self, data: Dict[str, Any]) -> bool:
        """Validate imported data."""
        try:
            # Check required fields
            required_fields = ["scan_id", "profile_name", "target", "scan_type", "start_time", "status", "findings"]
            for field in required_fields:
                if field not in data:
                    logger.error(f"Missing required field: {field}")
                    return False
            
            # Validate findings
            for finding in data["findings"]:
                required_fields = ["title", "severity", "category", "description"]
                for field in required_fields:
                    if field not in finding:
                        logger.error(f"Missing required field in finding: {field}")
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating data: {str(e)}")
            return False
    
    def _validate_analysis(self, data: Dict[str, Any]) -> bool:
        """Validate imported analysis."""
        try:
            # Check required fields
            required_fields = [
                "total_scans", "completed_scans", "failed_scans", "total_findings",
                "average_cvss", "scan_duration", "severity_distribution",
                "category_distribution", "cve_distribution", "top_findings",
                "recommendations"
            ]
            for field in required_fields:
                if field not in data:
                    logger.error(f"Missing required field: {field}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating analysis: {str(e)}")
            return False
    
    def display_import(self, file_path: str) -> None:
        """Display an import."""
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                console.print(f"[red]File not found: {file_path}[/red]")
                return
            
            # Read file
            with open(file_path, "r") as f:
                content = f.read()
            
            # Display content
            console.print(Panel(content, title="Scan Import", border_style="blue"))
            
        except Exception as e:
            logger.error(f"Error displaying import: {str(e)}")
            console.print(f"[red]Error displaying import: {str(e)}[/red]")

# Create global instance
scan_importer = ScanImporter() 