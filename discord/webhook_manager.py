"""
Discord Webhook Manager for E502 OSINT Terminal
Provides comprehensive Discord integration for scan notifications and reporting.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import pytz
from pathlib import Path
from dataclasses import dataclass, asdict
import shutil
import hashlib
import platform
import aiohttp
import asyncio
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from jinja2 import Environment, FileSystemLoader
import yaml

logger = logging.getLogger("E502OSINT.DiscordWebhook")
console = Console()

@dataclass
class ScanResult:
    """Class for storing scan results."""
    target: str
    scan_type: str
    timestamp: datetime
    status: str
    findings: Dict[str, Any]
    duration: float
    error: Optional[str]
    scan_id: str
    profile: str
    tags: List[str]

class DiscordWebhookManager:
    def __init__(self):
        self.config_dir = Path("config/discord")
        self.templates_dir = Path("templates/discord")
        self.history_dir = Path("data/discord/history")
        self._ensure_dirs()
        self._load_config()
        self._load_templates()
        self.max_history = 1000
        self.history: List[ScanResult] = []
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.history_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_config(self) -> None:
        """Load Discord configuration."""
        try:
            config_path = self.config_dir / "config.json"
            if config_path.exists():
                with open(config_path, 'r') as f:
                    self.config = json.load(f)
            else:
                self.config = {
                    'webhook_url': '',
                    'username': 'E502 OSINT Scanner',
                    'avatar_url': '',
                    'color_scheme': {
                        'success': 0x00ff00,
                        'warning': 0xffff00,
                        'error': 0xff0000,
                        'info': 0x0000ff
                    },
                    'notification_settings': {
                        'scan_start': True,
                        'scan_complete': True,
                        'scan_error': True,
                        'critical_findings': True
                    }
                }
                self._save_config()
        except Exception as e:
            logger.error(f"Error loading Discord config: {str(e)}")
            self.config = {}
    
    def _save_config(self) -> None:
        """Save Discord configuration."""
        try:
            config_path = self.config_dir / "config.json"
            with open(config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving Discord config: {str(e)}")
    
    def _load_templates(self) -> None:
        """Load Discord message templates."""
        try:
            self.template_env = Environment(
                loader=FileSystemLoader(self.templates_dir)
            )
            self.templates = {
                'scan_start': self.template_env.get_template('scan_start.txt'),
                'scan_complete': self.template_env.get_template('scan_complete.txt'),
                'scan_error': self.template_env.get_template('scan_error.txt'),
                'critical_findings': self.template_env.get_template('critical_findings.txt')
            }
        except Exception as e:
            logger.error(f"Error loading Discord templates: {str(e)}")
            self.templates = {}
    
    async def send_message(self, content: str, embed: Optional[Dict[str, Any]] = None) -> bool:
        """Send a message to Discord webhook."""
        try:
            if not self.config.get('webhook_url'):
                logger.error("Discord webhook URL not configured")
                return False
            
            async with aiohttp.ClientSession() as session:
                payload = {
                    'content': content,
                    'username': self.config.get('username', 'E502 OSINT Scanner'),
                    'avatar_url': self.config.get('avatar_url', '')
                }
                
                if embed:
                    payload['embeds'] = [embed]
                
                async with session.post(self.config['webhook_url'], json=payload) as response:
                    if response.status == 204:
                        return True
                    else:
                        logger.error(f"Error sending Discord message: {response.status}")
                        return False
                
        except Exception as e:
            logger.error(f"Error sending Discord message: {str(e)}")
            return False
    
    async def send_alert(self, title: str, description: str, alert_type: str = 'info') -> bool:
        """Send an alert to Discord webhook."""
        try:
            color = self.config['color_scheme'].get(alert_type, 0x000000)
            
            embed = {
                'title': title,
                'description': description,
                'color': color,
                'timestamp': datetime.now(pytz.UTC).isoformat()
            }
            
            return await self.send_message('', embed)
            
        except Exception as e:
            logger.error(f"Error sending Discord alert: {str(e)}")
            return False
    
    async def send_network_scan_result(self, result: ScanResult) -> bool:
        """Send network scan results to Discord."""
        try:
            # Create embed
            embed = {
                'title': f"Network Scan Results: {result.target}",
                'description': f"Scan completed in {result.duration:.2f} seconds",
                'color': self.config['color_scheme']['success'] if result.status == 'success' else self.config['color_scheme']['error'],
                'timestamp': result.timestamp.isoformat(),
                'fields': []
            }
            
            # Add findings
            if result.findings:
                for key, value in result.findings.items():
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, indent=2)
                    embed['fields'].append({
                        'name': key,
                        'value': str(value),
                        'inline': False
                    })
            
            # Add error if any
            if result.error:
                embed['fields'].append({
                    'name': 'Error',
                    'value': result.error,
                    'inline': False
                })
            
            # Send message
            return await self.send_message('', embed)
            
        except Exception as e:
            logger.error(f"Error sending network scan results: {str(e)}")
            return False
    
    async def send_web_scan_result(self, result: ScanResult) -> bool:
        """Send web scan results to Discord."""
        try:
            # Create embed
            embed = {
                'title': f"Web Scan Results: {result.target}",
                'description': f"Scan completed in {result.duration:.2f} seconds",
                'color': self.config['color_scheme']['success'] if result.status == 'success' else self.config['color_scheme']['error'],
                'timestamp': result.timestamp.isoformat(),
                'fields': []
            }
            
            # Add findings
            if result.findings:
                for key, value in result.findings.items():
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, indent=2)
                    embed['fields'].append({
                        'name': key,
                        'value': str(value),
                        'inline': False
                    })
            
            # Add error if any
            if result.error:
                embed['fields'].append({
                    'name': 'Error',
                    'value': result.error,
                    'inline': False
                })
            
            # Send message
            return await self.send_message('', embed)
            
        except Exception as e:
            logger.error(f"Error sending web scan results: {str(e)}")
            return False
    
    async def send_ssl_scan_result(self, result: ScanResult) -> bool:
        """Send SSL scan results to Discord."""
        try:
            # Create embed
            embed = {
                'title': f"SSL Scan Results: {result.target}",
                'description': f"Scan completed in {result.duration:.2f} seconds",
                'color': self.config['color_scheme']['success'] if result.status == 'success' else self.config['color_scheme']['error'],
                'timestamp': result.timestamp.isoformat(),
                'fields': []
            }
            
            # Add findings
            if result.findings:
                for key, value in result.findings.items():
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, indent=2)
                    embed['fields'].append({
                        'name': key,
                        'value': str(value),
                        'inline': False
                    })
            
            # Add error if any
            if result.error:
                embed['fields'].append({
                    'name': 'Error',
                    'value': result.error,
                    'inline': False
                })
            
            # Send message
            return await self.send_message('', embed)
            
        except Exception as e:
            logger.error(f"Error sending SSL scan results: {str(e)}")
            return False
    
    async def send_vuln_scan_result(self, result: ScanResult) -> bool:
        """Send vulnerability scan results to Discord."""
        try:
            # Create embed
            embed = {
                'title': f"Vulnerability Scan Results: {result.target}",
                'description': f"Scan completed in {result.duration:.2f} seconds",
                'color': self.config['color_scheme']['success'] if result.status == 'success' else self.config['color_scheme']['error'],
                'timestamp': result.timestamp.isoformat(),
                'fields': []
            }
            
            # Add findings
            if result.findings:
                for key, value in result.findings.items():
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, indent=2)
                    embed['fields'].append({
                        'name': key,
                        'value': str(value),
                        'inline': False
                    })
            
            # Add error if any
            if result.error:
                embed['fields'].append({
                    'name': 'Error',
                    'value': result.error,
                    'inline': False
                })
            
            # Send message
            return await self.send_message('', embed)
            
        except Exception as e:
            logger.error(f"Error sending vulnerability scan results: {str(e)}")
            return False
    
    def add_scan_result(self, result: ScanResult) -> None:
        """Add scan result to history."""
        try:
            self.history.append(result)
            
            # Trim history if needed
            if len(self.history) > self.max_history:
                self.history = self.history[-self.max_history:]
            
            # Save history
            self._save_history()
            
        except Exception as e:
            logger.error(f"Error adding scan result: {str(e)}")
    
    def _save_history(self) -> None:
        """Save scan history."""
        try:
            history_path = self.history_dir / "history.json"
            with open(history_path, 'w') as f:
                json.dump([asdict(result) for result in self.history], f, indent=4, default=str)
        except Exception as e:
            logger.error(f"Error saving scan history: {str(e)}")
    
    def get_scan_history(self, scan_type: Optional[str] = None, target: Optional[str] = None,
                        profile: Optional[str] = None, tag: Optional[str] = None,
                        start_date: Optional[datetime] = None, end_date: Optional[datetime] = None) -> List[ScanResult]:
        """Get scan history with filters."""
        try:
            filtered_history = self.history
            
            if scan_type:
                filtered_history = [r for r in filtered_history if r.scan_type == scan_type]
            
            if target:
                filtered_history = [r for r in filtered_history if r.target == target]
            
            if profile:
                filtered_history = [r for r in filtered_history if r.profile == profile]
            
            if tag:
                filtered_history = [r for r in filtered_history if tag in r.tags]
            
            if start_date:
                filtered_history = [r for r in filtered_history if r.timestamp >= start_date]
            
            if end_date:
                filtered_history = [r for r in filtered_history if r.timestamp <= end_date]
            
            return filtered_history
            
        except Exception as e:
            logger.error(f"Error getting scan history: {str(e)}")
            return []
    
    def export_history(self, format: str = 'json', output_path: Optional[str] = None) -> bool:
        """Export scan history to file."""
        try:
            if not output_path:
                output_path = self.history_dir / f"history_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
            
            if format == 'json':
                with open(output_path, 'w') as f:
                    json.dump([asdict(result) for result in self.history], f, indent=4, default=str)
            elif format == 'csv':
                df = pd.DataFrame([asdict(result) for result in self.history])
                df.to_csv(output_path, index=False)
            else:
                logger.error(f"Unsupported export format: {format}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error exporting scan history: {str(e)}")
            return False
    
    def display_history(self, history: List[ScanResult]) -> None:
        """Display scan history in a formatted way."""
        try:
            # Create table
            table = Table(title="Scan History")
            table.add_column("Scan ID", style="cyan")
            table.add_column("Target", style="green")
            table.add_column("Type", style="yellow")
            table.add_column("Status", style="magenta")
            table.add_column("Timestamp", style="blue")
            table.add_column("Duration", style="red")
            
            # Add rows
            for result in history:
                table.add_row(
                    result.scan_id,
                    result.target,
                    result.scan_type,
                    result.status,
                    result.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    f"{result.duration:.2f}s"
                )
            
            # Display table
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying scan history: {str(e)}")
            console.print(f"[red]Error displaying scan history: {str(e)}[/]")

# Create global instance
discord_webhook = DiscordWebhookManager() 