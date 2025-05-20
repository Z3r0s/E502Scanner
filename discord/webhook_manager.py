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
import asyncio
import aiohttp
import concurrent.futures
import functools

console = Console()

class DiscordWebhookManager:
    def __init__(self):
        self.webhook_url: Optional[str] = None
        self.config_file = "discord_config.json"
        self.load_config()
        self.scan_history: List[Dict] = []
        self.max_history = 100
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=3)

    async def async_run_in_thread(self, func, *args, **kwargs):
        """Run a blocking function in a thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.thread_pool, 
            functools.partial(func, *args, **kwargs)
        )

    async def load_config_async(self) -> None:
        """Load webhook configuration from file asynchronously."""
        await self.async_run_in_thread(self.load_config)

    def load_config(self) -> None:
        # Load webhook configuration from file
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.webhook_url = config.get('webhook_url')
        except Exception as e:
            console.print(f"[red]Error loading Discord configuration: {str(e)}[/]")

    async def save_config_async(self) -> None:
        """Save webhook configuration to file asynchronously."""
        await self.async_run_in_thread(self.save_config)

    def save_config(self) -> None:
        # Save webhook configuration to file
        try:
            config = {'webhook_url': self.webhook_url}
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            console.print(f"[red]Error saving Discord configuration: {str(e)}[/]")

    async def set_webhook_async(self, webhook_url: str, save: bool = False) -> None:
        """Set the Discord webhook URL asynchronously."""
        self.webhook_url = webhook_url
        if save:
            await self.save_config_async()
            console.print("[green]Webhook URL saved to configuration.[/]")
        else:
            console.print("[yellow]Webhook URL set temporarily (not saved).[/]")

    def set_webhook(self, webhook_url: str, save: bool = False) -> None:
        # Set the Discord webhook URL
        self.webhook_url = webhook_url
        if save:
            self.save_config()
            console.print("[green]Webhook URL saved to configuration.[/]")
        else:
            console.print("[yellow]Webhook URL set temporarily (not saved).[/]")

    async def send_message_async(self, content: str, embed: Optional[Dict[str, Any]] = None) -> bool:
        """Send a message to Discord using the webhook asynchronously."""
        if not self.webhook_url:
            console.print("[red]No webhook URL configured. Use 'discord set' to configure.[/]")
            return False

        try:
            payload = {'content': content}
            if embed:
                payload['embeds'] = [embed]

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                ) as response:
                    if response.status == 204:
                        return True
                    else:
                        console.print(f"[red]Error sending Discord message: {response.status}[/]")
                        return False
        except Exception as e:
            console.print(f"[red]Error sending Discord message: {str(e)}[/]")
            return False

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

    async def send_network_scan_result_async(self, target: str, results: Dict[str, Any]) -> None:
        """Send network scan results with specialized formatting asynchronously."""
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
        await self.send_message_async("", embed=embed)
        await self._add_to_history_async("network", target, results)

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

    async def send_web_scan_result_async(self, target: str, results: Dict[str, Any]) -> None:
        """Send web scan results with specialized formatting asynchronously."""
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
        await self.send_message_async("", embed=embed)
        await self._add_to_history_async("web", target, results)

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

    async def send_ssl_scan_result_async(self, target: str, results: Dict[str, Any]) -> None:
        """Send SSL scan results with specialized formatting asynchronously."""
        embed = self._create_ssl_embed(target, results)
        await self.send_message_async("", embed=embed)
        await self._add_to_history_async("ssl", target, results)
        
    def _create_ssl_embed(self, target: str, results: Dict[str, Any]) -> Dict:
        """Create Discord embed for SSL scan results."""
        return {
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
        
    def send_ssl_scan_result(self, target: str, results: Dict[str, Any]) -> None:
        # Send SSL scan results with specialized formatting
        embed = self._create_ssl_embed(target, results)
        self.send_message("", embed=embed)
        self._add_to_history("ssl", target, results)
        
    async def send_vuln_scan_result_async(self, target: str, results: Dict[str, Any]) -> None:
        """Send vulnerability scan results with specialized formatting asynchronously."""
        embed = self._create_vuln_embed(target, results)
        await self.send_message_async("", embed=embed)
        await self._add_to_history_async("vulnerability", target, results)
        
    def _create_vuln_embed(self, target: str, results: Dict[str, Any]) -> Dict:
        """Create Discord embed for vulnerability scan results."""
        return {
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

    def send_vuln_scan_result(self, target: str, results: Dict[str, Any]) -> None:
        # Send vulnerability scan results with specialized formatting
        embed = self._create_vuln_embed(target, results)
        self.send_message("", embed=embed)
        self._add_to_history("vulnerability", target, results)

    async def send_alert_async(self, title: str, message: str, level: str = "info") -> bool:
        """Send an alert to Discord asynchronously."""
        colors = {
            "info": 0x3498db,
            "warning": 0xf1c40f,
            "error": 0xe74c3c,
            "success": 0x2ecc71
        }
        
        embed = {
            "title": f"⚠️ {title}",
            "description": message,
            "color": colors.get(level, 0x3498db),
            "timestamp": datetime.now().isoformat(),
            "footer": {
                "text": f"E502 OSINT Terminal | Alert Level: {level.upper()}"
            }
        }
        
        return await self.send_message_async("", embed=embed)

    def send_alert(self, title: str, message: str, level: str = "info") -> bool:
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
            "title": f"{icons.get(level, 'ℹ️')} E502 Alert: {title}",
            "description": message,
            "color": colors.get(level, 0x3498db),
            "timestamp": datetime.now().isoformat(),
            "footer": {
                "text": f"E502 OSINT Terminal | Alert Level: {level.upper()}"
            }
        }

        return self.send_message("", embed=embed)

    async def send_scan_summary_async(self) -> None:
        """Send a summary of recent scans asynchronously."""
        if not self.scan_history:
            await self.send_alert_async("Scan Summary", "No scans have been performed yet.", "info")
            return
        
        recent_scans = self.scan_history[-10:] if len(self.scan_history) > 10 else self.scan_history
        
        summary = "**Recent Scan Activity**\n\n"
        for i, scan in enumerate(recent_scans, 1):
            summary += f"{i}. **{scan['type'].upper()}**: {scan['target']} ({scan['timestamp']})\n"
        
        embed = {
            "title": "📊 E502 Scan Summary",
            "description": summary,
            "color": 0x3498db,
            "fields": [
                {
                    "name": "Total Scans",
                    "value": str(len(self.scan_history)),
                    "inline": True
                },
                {
                    "name": "Activity Period",
                    "value": f"{self.scan_history[0]['timestamp']} to {self.scan_history[-1]['timestamp']}",
                    "inline": True
                }
            ],
            "footer": {
                "text": "E502 OSINT Terminal | Scan History"
            }
        }
        
        await self.send_message_async("", embed=embed)

    def send_scan_summary(self) -> None:
        """Send a summary of recent scans."""
        if not self.scan_history:
            self.send_alert("Scan Summary", "No scans have been performed yet.", "info")
            return
        
        recent_scans = self.scan_history[-10:] if len(self.scan_history) > 10 else self.scan_history
        
        summary = "**Recent Scan Activity**\n\n"
        for i, scan in enumerate(recent_scans, 1):
            summary += f"{i}. **{scan['type'].upper()}**: {scan['target']} ({scan['timestamp']})\n"
        
        embed = {
            "title": "📊 E502 Scan Summary",
            "description": summary,
            "color": 0x3498db,
            "fields": [
                {
                    "name": "Total Scans",
                    "value": str(len(self.scan_history)),
                    "inline": True
                },
                {
                    "name": "Activity Period",
                    "value": f"{self.scan_history[0]['timestamp']} to {self.scan_history[-1]['timestamp']}",
                    "inline": True
                }
            ],
            "footer": {
                "text": "E502 OSINT Terminal | Scan History"
            }
        }
        
        self.send_message("", embed=embed)

    async def _add_to_history_async(self, scan_type: str, target: str, results: Dict[str, Any]) -> None:
        """Add scan to history asynchronously."""
        await self.async_run_in_thread(self._add_to_history, scan_type, target, results)

    def _add_to_history(self, scan_type: str, target: str, results: Dict[str, Any]) -> None:
        # Add scan to history
        self.scan_history.append({
            'type': scan_type,
            'target': target,
            'results': results,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
        # Keep only the last max_history scans
        if len(self.scan_history) > self.max_history:
            self.scan_history = self.scan_history[-self.max_history:] 