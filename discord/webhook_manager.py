# Discord Webhook Manager for E502 OSINT Terminal
# Handles Discord webhook integration for real-time notifications and reporting.
# Built by z3r0s / Error502

import json
import os
import requests
from typing import Optional, Dict, Any, List
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt

console = Console()

class DiscordWebhookManager:
    def __init__(self):
        self.webhook_url: Optional[str] = None
        self.config_file = "discord_config.json"
        self.load_config()
        self.scan_history: List[Dict] = []
        self.max_history = 100

    def load_config(self) -> None:
        # Load webhook configuration from file
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.webhook_url = config.get('webhook_url')
        except Exception as e:
            console.print(f"[red]Error loading Discord configuration: {str(e)}[/]")

    def save_config(self) -> None:
        # Save webhook configuration to file
        try:
            config = {'webhook_url': self.webhook_url}
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            console.print(f"[red]Error saving Discord configuration: {str(e)}[/]")

    def set_webhook(self, webhook_url: str, save: bool = False) -> None:
        # Set the Discord webhook URL
        self.webhook_url = webhook_url
        if save:
            self.save_config()
            console.print("[green]Webhook URL saved to configuration.[/]")
        else:
            console.print("[yellow]Webhook URL set temporarily (not saved).[/]")

    def send_message(self, content: str, embed: Optional[Dict[str, Any]] = None) -> bool:
        # Send a message to Discord using the webhook
        if not self.webhook_url:
            console.print("[red]No webhook URL configured. Use 'discord set' to configure.[/]")
            return False

        try:
            payload = {'content': content}
            if embed:
                payload['embeds'] = [embed]

            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 204:
                return True
            else:
                console.print(f"[red]Error sending Discord message: {response.status_code}[/]")
                return False
        except Exception as e:
            console.print(f"[red]Error sending Discord message: {str(e)}[/]")
            return False

    def send_network_scan_result(self, target: str, results: Dict[str, Any]) -> None:
        # Send network scan results with specialized formatting
        embed = {
            "title": "🔍 E502 Network Analysis",
            "description": f"Network scan completed for `{target}`",
            "color": 0x3498db,
            "fields": [
                {
                    "name": "📊 Scan Summary",
                    "value": f"• Hosts Found: {results.get('hosts_found', 'N/A')}\n"
                            f"• Open Ports: {results.get('open_ports', 'N/A')}\n"
                            f"• Services Detected: {results.get('services', 'N/A')}",
                    "inline": False
                },
                {
                    "name": "⏰ Timestamp",
                    "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "inline": True
                }
            ],
            "footer": {
                "text": "E502 OSINT Terminal | Network Analysis Module"
            }
        }
        self.send_message("", embed=embed)
        self._add_to_history("network", target, results)

    def send_web_scan_result(self, target: str, results: Dict[str, Any]) -> None:
        # Send web scan results with specialized formatting
        embed = {
            "title": "🌐 E502 Web Analysis",
            "description": f"Web scan completed for `{target}`",
            "color": 0x2ecc71,
            "fields": [
                {
                    "name": "🔧 Technologies",
                    "value": "\n".join(f"• {tech}" for tech in results.get('technologies', [])),
                    "inline": False
                },
                {
                    "name": "🛡️ Security Headers",
                    "value": "\n".join(f"• {header}: {value}" for header, value in results.get('security_headers', {}).items()),
                    "inline": False
                },
                {
                    "name": "⏰ Timestamp",
                    "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "inline": True
                }
            ],
            "footer": {
                "text": "E502 OSINT Terminal | Web Analysis Module"
            }
        }
        self.send_message("", embed=embed)
        self._add_to_history("web", target, results)

    def send_ssl_scan_result(self, target: str, results: Dict[str, Any]) -> None:
        # Send SSL scan results with specialized formatting
        embed = {
            "title": "🔒 E502 SSL Analysis",
            "description": f"SSL scan completed for `{target}`",
            "color": 0xe74c3c,
            "fields": [
                {
                    "name": "📜 Certificate Info",
                    "value": f"• Issuer: {results.get('issuer', 'N/A')}\n"
                            f"• Valid Until: {results.get('valid_until', 'N/A')}\n"
                            f"• Key Size: {results.get('key_size', 'N/A')} bits",
                    "inline": False
                },
                {
                    "name": "🔍 Vulnerabilities",
                    "value": "\n".join(f"• {vuln}" for vuln in results.get('vulnerabilities', [])),
                    "inline": False
                },
                {
                    "name": "⏰ Timestamp",
                    "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "inline": True
                }
            ],
            "footer": {
                "text": "E502 OSINT Terminal | SSL Analysis Module"
            }
        }
        self.send_message("", embed=embed)
        self._add_to_history("ssl", target, results)

    def send_vuln_scan_result(self, target: str, results: Dict[str, Any]) -> None:
        # Send vulnerability scan results with specialized formatting
        embed = {
            "title": "⚠️ E502 Vulnerability Scan",
            "description": f"Vulnerability scan completed for `{target}`",
            "color": 0xf1c40f,
            "fields": [
                {
                    "name": "🔴 High Risk",
                    "value": "\n".join(f"• {vuln}" for vuln in results.get('high_risk', [])),
                    "inline": False
                },
                {
                    "name": "🟡 Medium Risk",
                    "value": "\n".join(f"• {vuln}" for vuln in results.get('medium_risk', [])),
                    "inline": False
                },
                {
                    "name": "🟢 Low Risk",
                    "value": "\n".join(f"• {vuln}" for vuln in results.get('low_risk', [])),
                    "inline": False
                },
                {
                    "name": "⏰ Timestamp",
                    "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "inline": True
                }
            ],
            "footer": {
                "text": "E502 OSINT Terminal | Vulnerability Scanner Module"
            }
        }
        self.send_message("", embed=embed)
        self._add_to_history("vulnerability", target, results)

    def send_alert(self, alert_type: str, message: str, severity: str = "info") -> None:
        # Send an alert to Discord
        colors = {
            "info": 0x3498db,    # Blue
            "warning": 0xf1c40f,  # Yellow
            "error": 0xe74c3c,    # Red
            "success": 0x2ecc71   # Green
        }

        icons = {
            "info": "ℹ️",
            "warning": "⚠️",
            "error": "❌",
            "success": "✅"
        }

        embed = {
            "title": f"{icons.get(severity, 'ℹ️')} E502 Alert: {alert_type}",
            "description": message,
            "color": colors.get(severity, 0x3498db),
            "timestamp": datetime.now().isoformat(),
            "footer": {
                "text": "E502 OSINT Terminal | Alert System"
            }
        }

        self.send_message("", embed=embed)

    def send_scan_summary(self) -> None:
        # Send a summary of recent scans
        if not self.scan_history:
            return

        embed = {
            "title": "📊 E502 Scan Summary",
            "description": "Recent scan activity summary",
            "color": 0x9b59b6,
            "fields": [
                {
                    "name": "📈 Scan Statistics",
                    "value": f"• Total Scans: {len(self.scan_history)}\n"
                            f"• Unique Targets: {len(set(scan['target'] for scan in self.scan_history))}\n"
                            f"• Scan Types: {', '.join(set(scan['type'] for scan in self.scan_history))}",
                    "inline": False
                },
                {
                    "name": "⏰ Last Updated",
                    "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "inline": True
                }
            ],
            "footer": {
                "text": "E502 OSINT Terminal | Scan Summary"
            }
        }

        self.send_message("", embed=embed)

    def _add_to_history(self, scan_type: str, target: str, results: Dict[str, Any]) -> None:
        # Add scan to history
        self.scan_history.append({
            'type': scan_type,
            'target': target,
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
        
        # Keep only the last max_history scans
        if len(self.scan_history) > self.max_history:
            self.scan_history = self.scan_history[-self.max_history:] 