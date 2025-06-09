"""
Scan Validator for E502 OSINT Terminal
Provides comprehensive scan result and configuration validation capabilities.
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
import re
import ipaddress
import socket
import dns.resolver
import requests
from urllib.parse import urlparse

logger = logging.getLogger("E502OSINT.ScanValidator")
console = Console()

class ScanValidator:
    def __init__(self):
        self.scan_dir = Path("scans")
        self._ensure_dirs()
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.scan_dir.mkdir(parents=True, exist_ok=True)
    
    def validate_target(self, target: str) -> bool:
        """Validate a scan target."""
        try:
            # Check if target is empty
            if not target:
                logger.error("Empty target")
                return False
            
            # Check if target is an IP address
            try:
                ipaddress.ip_address(target)
                return True
            except ValueError:
                pass
            
            # Check if target is a hostname
            try:
                socket.gethostbyname(target)
                return True
            except socket.gaierror:
                pass
            
            # Check if target is a URL
            try:
                result = urlparse(target)
                return all([result.scheme, result.netloc])
            except Exception:
                pass
            
            logger.error(f"Invalid target: {target}")
            return False
            
        except Exception as e:
            logger.error(f"Error validating target: {str(e)}")
            return False
    
    def validate_profile(self, profile: Dict[str, Any]) -> bool:
        """Validate a scan profile."""
        try:
            # Check required fields
            required_fields = ["name", "description", "scan_type", "target", "options"]
            for field in required_fields:
                if field not in profile:
                    logger.error(f"Missing required field: {field}")
                    return False
            
            # Validate name
            if not re.match(r"^[a-zA-Z0-9_-]+$", profile["name"]):
                logger.error("Invalid profile name")
                return False
            
            # Validate scan type
            valid_types = ["network", "web", "ssl", "vulnerability"]
            if profile["scan_type"] not in valid_types:
                logger.error(f"Invalid scan type: {profile['scan_type']}")
                return False
            
            # Validate target
            if not self.validate_target(profile["target"]):
                logger.error(f"Invalid target: {profile['target']}")
                return False
            
            # Validate options
            if not isinstance(profile["options"], dict):
                logger.error("Invalid options format")
                return False
            
            # Validate schedule if present
            if "schedule" in profile:
                if not self._validate_schedule(profile["schedule"]):
                    logger.error("Invalid schedule")
                    return False
            
            # Validate notifications if present
            if "notifications" in profile:
                if not self._validate_notifications(profile["notifications"]):
                    logger.error("Invalid notifications")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating profile: {str(e)}")
            return False
    
    def validate_result(self, result: Dict[str, Any]) -> bool:
        """Validate a scan result."""
        try:
            # Check required fields
            required_fields = ["scan_id", "profile_name", "target", "scan_type", "start_time", "status", "findings"]
            for field in required_fields:
                if field not in result:
                    logger.error(f"Missing required field: {field}")
                    return False
            
            # Validate scan ID
            if not re.match(r"^[a-zA-Z0-9_-]+$", result["scan_id"]):
                logger.error("Invalid scan ID")
                return False
            
            # Validate profile name
            if not re.match(r"^[a-zA-Z0-9_-]+$", result["profile_name"]):
                logger.error("Invalid profile name")
                return False
            
            # Validate target
            if not self.validate_target(result["target"]):
                logger.error(f"Invalid target: {result['target']}")
                return False
            
            # Validate scan type
            valid_types = ["network", "web", "ssl", "vulnerability"]
            if result["scan_type"] not in valid_types:
                logger.error(f"Invalid scan type: {result['scan_type']}")
                return False
            
            # Validate start time
            try:
                datetime.fromisoformat(result["start_time"])
            except ValueError:
                logger.error("Invalid start time")
                return False
            
            # Validate end time if present
            if result.get("end_time"):
                try:
                    datetime.fromisoformat(result["end_time"])
                except ValueError:
                    logger.error("Invalid end time")
                    return False
            
            # Validate status
            valid_statuses = ["pending", "running", "completed", "failed"]
            if result["status"] not in valid_statuses:
                logger.error(f"Invalid status: {result['status']}")
                return False
            
            # Validate findings
            if not isinstance(result["findings"], list):
                logger.error("Invalid findings format")
                return False
            
            for finding in result["findings"]:
                if not self._validate_finding(finding):
                    logger.error("Invalid finding")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating result: {str(e)}")
            return False
    
    def validate_analysis(self, analysis: Dict[str, Any]) -> bool:
        """Validate analysis results."""
        try:
            # Check required fields
            required_fields = [
                "total_scans", "completed_scans", "failed_scans", "total_findings",
                "average_cvss", "scan_duration", "severity_distribution",
                "category_distribution", "cve_distribution", "top_findings",
                "recommendations"
            ]
            for field in required_fields:
                if field not in analysis:
                    logger.error(f"Missing required field: {field}")
                    return False
            
            # Validate numeric fields
            numeric_fields = ["total_scans", "completed_scans", "failed_scans", "total_findings", "average_cvss", "scan_duration"]
            for field in numeric_fields:
                if not isinstance(analysis[field], (int, float)):
                    logger.error(f"Invalid {field} type")
                    return False
            
            # Validate distributions
            distribution_fields = ["severity_distribution", "category_distribution", "cve_distribution"]
            for field in distribution_fields:
                if not isinstance(analysis[field], dict):
                    logger.error(f"Invalid {field} format")
                    return False
            
            # Validate top findings
            if not isinstance(analysis["top_findings"], list):
                logger.error("Invalid top findings format")
                return False
            
            for finding in analysis["top_findings"]:
                if not self._validate_finding(finding):
                    logger.error("Invalid finding")
                    return False
            
            # Validate recommendations
            if not isinstance(analysis["recommendations"], list):
                logger.error("Invalid recommendations format")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating analysis: {str(e)}")
            return False
    
    def _validate_schedule(self, schedule: Dict[str, Any]) -> bool:
        """Validate a schedule configuration."""
        try:
            # Check required fields
            required_fields = ["type", "value"]
            for field in required_fields:
                if field not in schedule:
                    logger.error(f"Missing required field: {field}")
                    return False
            
            # Validate type
            valid_types = ["interval", "daily", "weekly", "monthly", "cron"]
            if schedule["type"] not in valid_types:
                logger.error(f"Invalid schedule type: {schedule['type']}")
                return False
            
            # Validate value based on type
            if schedule["type"] == "interval":
                if not isinstance(schedule["value"], int) or schedule["value"] < 1:
                    logger.error("Invalid interval value")
                    return False
            
            elif schedule["type"] == "daily":
                if not re.match(r"^([01]\d|2[0-3]):([0-5]\d)$", schedule["value"]):
                    logger.error("Invalid daily schedule value")
                    return False
            
            elif schedule["type"] == "weekly":
                if not isinstance(schedule["value"], list) or len(schedule["value"]) != 2:
                    logger.error("Invalid weekly schedule value")
                    return False
                
                if not isinstance(schedule["value"][0], int) or schedule["value"][0] < 0 or schedule["value"][0] > 6:
                    logger.error("Invalid day of week")
                    return False
                
                if not re.match(r"^([01]\d|2[0-3]):([0-5]\d)$", schedule["value"][1]):
                    logger.error("Invalid time")
                    return False
            
            elif schedule["type"] == "monthly":
                if not isinstance(schedule["value"], list) or len(schedule["value"]) != 2:
                    logger.error("Invalid monthly schedule value")
                    return False
                
                if not isinstance(schedule["value"][0], int) or schedule["value"][0] < 1 or schedule["value"][0] > 31:
                    logger.error("Invalid day of month")
                    return False
                
                if not re.match(r"^([01]\d|2[0-3]):([0-5]\d)$", schedule["value"][1]):
                    logger.error("Invalid time")
                    return False
            
            elif schedule["type"] == "cron":
                if not isinstance(schedule["value"], str):
                    logger.error("Invalid cron expression")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating schedule: {str(e)}")
            return False
    
    def _validate_notifications(self, notifications: Dict[str, Any]) -> bool:
        """Validate notification configurations."""
        try:
            # Check if notifications is a dict
            if not isinstance(notifications, dict):
                logger.error("Invalid notifications format")
                return False
            
            # Validate each notification type
            for notification_type, config in notifications.items():
                if notification_type == "discord":
                    if not self._validate_discord_notification(config):
                        logger.error("Invalid Discord notification")
                        return False
                
                elif notification_type == "email":
                    if not self._validate_email_notification(config):
                        logger.error("Invalid email notification")
                        return False
                
                elif notification_type == "webhook":
                    if not self._validate_webhook_notification(config):
                        logger.error("Invalid webhook notification")
                        return False
                
                else:
                    logger.error(f"Unsupported notification type: {notification_type}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating notifications: {str(e)}")
            return False
    
    def _validate_finding(self, finding: Dict[str, Any]) -> bool:
        """Validate a scan finding."""
        try:
            # Check required fields
            required_fields = ["title", "severity", "category", "description"]
            for field in required_fields:
                if field not in finding:
                    logger.error(f"Missing required field: {field}")
                    return False
            
            # Validate severity
            valid_severities = ["critical", "high", "medium", "low", "info"]
            if finding["severity"] not in valid_severities:
                logger.error(f"Invalid severity: {finding['severity']}")
                return False
            
            # Validate category
            valid_categories = ["security", "performance", "configuration", "compliance", "other"]
            if finding["category"] not in valid_categories:
                logger.error(f"Invalid category: {finding['category']}")
                return False
            
            # Validate CVE ID if present
            if "cve_id" in finding:
                if not re.match(r"^CVE-\d{4}-\d{4,}$", finding["cve_id"]):
                    logger.error(f"Invalid CVE ID: {finding['cve_id']}")
                    return False
            
            # Validate CVSS score if present
            if "cvss_score" in finding:
                if not isinstance(finding["cvss_score"], (int, float)) or finding["cvss_score"] < 0 or finding["cvss_score"] > 10:
                    logger.error(f"Invalid CVSS score: {finding['cvss_score']}")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating finding: {str(e)}")
            return False
    
    def _validate_discord_notification(self, config: Dict[str, Any]) -> bool:
        """Validate Discord notification configuration."""
        try:
            # Check required fields
            required_fields = ["webhook_url"]
            for field in required_fields:
                if field not in config:
                    logger.error(f"Missing required field: {field}")
                    return False
            
            # Validate webhook URL
            if not config["webhook_url"].startswith("https://discord.com/api/webhooks/"):
                logger.error("Invalid Discord webhook URL")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating Discord notification: {str(e)}")
            return False
    
    def _validate_email_notification(self, config: Dict[str, Any]) -> bool:
        """Validate email notification configuration."""
        try:
            # Check required fields
            required_fields = ["smtp_server", "smtp_port", "username", "password", "from_email", "to_email"]
            for field in required_fields:
                if field not in config:
                    logger.error(f"Missing required field: {field}")
                    return False
            
            # Validate SMTP port
            if not isinstance(config["smtp_port"], int) or config["smtp_port"] < 1 or config["smtp_port"] > 65535:
                logger.error(f"Invalid SMTP port: {config['smtp_port']}")
                return False
            
            # Validate email addresses
            email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            if not re.match(email_regex, config["from_email"]):
                logger.error(f"Invalid from email: {config['from_email']}")
                return False
            
            if not re.match(email_regex, config["to_email"]):
                logger.error(f"Invalid to email: {config['to_email']}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating email notification: {str(e)}")
            return False
    
    def _validate_webhook_notification(self, config: Dict[str, Any]) -> bool:
        """Validate webhook notification configuration."""
        try:
            # Check required fields
            required_fields = ["url"]
            for field in required_fields:
                if field not in config:
                    logger.error(f"Missing required field: {field}")
                    return False
            
            # Validate URL
            try:
                result = urlparse(config["url"])
                if not all([result.scheme, result.netloc]):
                    logger.error("Invalid webhook URL")
                    return False
            except Exception:
                logger.error("Invalid webhook URL")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating webhook notification: {str(e)}")
            return False
    
    def display_validation(self, validation_result: bool, details: Optional[str] = None) -> None:
        """Display validation results."""
        try:
            if validation_result:
                console.print("[green]Validation successful[/green]")
            else:
                console.print("[red]Validation failed[/red]")
            
            if details:
                console.print(Panel(details, title="Validation Details", border_style="blue"))
            
        except Exception as e:
            logger.error(f"Error displaying validation: {str(e)}")
            console.print(f"[red]Error displaying validation: {str(e)}[/red]")

# Create global instance
scan_validator = ScanValidator() 