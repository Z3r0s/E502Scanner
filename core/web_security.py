"""
Web Security Analysis Module for E502 OSINT Terminal
Provides WAF detection, cookie analysis, and security header checking capabilities.
"""

import requests
import re
from typing import Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json
import ssl
import socket
from urllib.parse import urlparse
import aiohttp
import asyncio

console = Console()

class WebSecurityAnalyzer:
    def __init__(self):
        self.waf_signatures = {
            'cloudflare': [
                'cf-ray',
                '__cfduid',
                'cf-cache-status'
            ],
            'akamai': [
                'akamai-gtm',
                'akamai-origin-hop'
            ],
            'incapsula': [
                'incap_ses',
                'visid_incap'
            ],
            'sucuri': [
                'sucuri-cache'
            ],
            'fastly': [
                'fastly-io'
            ]
        }

        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS connections',
                'recommended': 'max-age=31536000; includeSubDomains'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'recommended': 'DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'recommended': 'nosniff'
            },
            'X-XSS-Protection': {
                'description': 'Enables browser XSS filtering',
                'recommended': '1; mode=block'
            },
            'Content-Security-Policy': {
                'description': 'Controls resource loading',
                'recommended': "default-src 'self'"
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information',
                'recommended': 'strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'description': 'Controls browser features',
                'recommended': 'geolocation=(), microphone=(), camera=()'
            }
        }

    async def detect_waf(self, url: str) -> Dict:
        """Detect Web Application Firewall (WAF)."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"

            console.print(f"[bold green]Detecting WAF for {url}...[/]")
            
            # Make request with common attack patterns
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            }
            
            # Test for SQL injection
            payloads = [
                "' OR '1'='1",
                "1' OR '1'='1",
                "1; DROP TABLE users",
                "<script>alert(1)</script>"
            ]
            
            waf_detected = False
            waf_type = None
            waf_headers = []
            
            async with aiohttp.ClientSession() as session:
                # First, get normal response
                async with session.get(url, headers=headers) as response:
                    normal_headers = dict(response.headers)
                    
                    # Check for WAF signatures in headers
                    for waf, signatures in self.waf_signatures.items():
                        if any(sig.lower() in str(normal_headers).lower() for sig in signatures):
                            waf_detected = True
                            waf_type = waf
                            waf_headers = [h for h in normal_headers if any(sig.lower() in h.lower() for sig in signatures)]
                            break
                    
                    # If no WAF detected in headers, try payloads
                    if not waf_detected:
                        for payload in payloads:
                            test_url = f"{url}?q={payload}"
                            async with session.get(test_url, headers=headers) as test_response:
                                if test_response.status in [403, 406, 429]:
                                    waf_detected = True
                                    waf_type = "Generic WAF"
                                    break
                                elif len(test_response.text) != len(await response.text()):
                                    waf_detected = True
                                    waf_type = "Generic WAF"
                                    break

            return {
                'waf_detected': waf_detected,
                'waf_type': waf_type,
                'waf_headers': waf_headers
            }

        except Exception as e:
            console.print(f"[red]Error detecting WAF: {str(e)}[/]")
            return {
                'waf_detected': False,
                'waf_type': None,
                'waf_headers': []
            }

    async def analyze_cookies(self, url: str) -> Dict:
        """Analyze cookie security settings."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"

            console.print(f"[bold green]Analyzing cookies for {url}...[/]")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    cookies = response.cookies
                    
                    cookie_analysis = []
                    for cookie in cookies:
                        analysis = {
                            'name': cookie.key,
                            'secure': cookie.get('secure', False),
                            'httponly': cookie.get('httponly', False),
                            'samesite': cookie.get('samesite', 'Not Set'),
                            'path': cookie.get('path', '/'),
                            'domain': cookie.get('domain', 'Not Set'),
                            'expires': cookie.get('expires', 'Session'),
                            'max_age': cookie.get('max-age', 'Not Set')
                        }
                        cookie_analysis.append(analysis)

            return {
                'cookies': cookie_analysis,
                'total_cookies': len(cookie_analysis)
            }

        except Exception as e:
            console.print(f"[red]Error analyzing cookies: {str(e)}[/]")
            return {
                'cookies': [],
                'total_cookies': 0
            }

    async def check_security_headers(self, url: str) -> Dict:
        """Check security headers."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"

            console.print(f"[bold green]Checking security headers for {url}...[/]")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    headers = dict(response.headers)
                    
                    header_analysis = {}
                    for header, info in self.security_headers.items():
                        value = headers.get(header, 'Not Set')
                        header_analysis[header] = {
                            'value': value,
                            'description': info['description'],
                            'recommended': info['recommended'],
                            'status': 'Good' if value != 'Not Set' else 'Missing'
                        }

            return {
                'headers': header_analysis,
                'total_headers': len(header_analysis)
            }

        except Exception as e:
            console.print(f"[red]Error checking security headers: {str(e)}[/]")
            return {
                'headers': {},
                'total_headers': 0
            }

    def display_waf_results(self, results: Dict) -> None:
        """Display WAF detection results."""
        table = Table(title="WAF Detection Results")
        table.add_column("Status", style="cyan")
        table.add_column("Details", style="green")

        if results['waf_detected']:
            table.add_row(
                "[bold green]WAF Detected[/]",
                f"Type: {results['waf_type']}\nHeaders: {', '.join(results['waf_headers'])}"
            )
        else:
            table.add_row(
                "[bold yellow]No WAF Detected[/]",
                "No WAF signatures found in response"
            )

        console.print(table)

    def display_cookie_results(self, results: Dict) -> None:
        """Display cookie analysis results."""
        table = Table(title="Cookie Analysis Results")
        table.add_column("Cookie", style="cyan")
        table.add_column("Security Settings", style="green")
        table.add_column("Status", style="yellow")

        for cookie in results['cookies']:
            security_settings = []
            if cookie['secure']:
                security_settings.append("Secure")
            if cookie['httponly']:
                security_settings.append("HttpOnly")
            if cookie['samesite'] != 'Not Set':
                security_settings.append(f"SameSite={cookie['samesite']}")

            status = []
            if not cookie['secure']:
                status.append("[red]Missing Secure flag[/]")
            if not cookie['httponly']:
                status.append("[red]Missing HttpOnly flag[/]")
            if cookie['samesite'] == 'Not Set':
                status.append("[yellow]SameSite not set[/]")

            table.add_row(
                cookie['name'],
                "\n".join(security_settings) or "No security flags",
                "\n".join(status) or "[green]Secure[/]"
            )

        console.print(table)

    def display_security_headers_results(self, results: Dict) -> None:
        """Display security headers results."""
        table = Table(title="Security Headers Analysis")
        table.add_column("Header", style="cyan")
        table.add_column("Value", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Recommendation", style="blue")

        for header, info in results['headers'].items():
            status = "[green]Good[/]" if info['status'] == 'Good' else "[red]Missing[/]"
            table.add_row(
                header,
                info['value'],
                status,
                info['recommended']
            )

        console.print(table) 