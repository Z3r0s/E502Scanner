"""
E502 OSINT Terminal – Advanced Reconnaissance Toolkit
----------------------------------------------------
Author: z3r0s / Error502
Version: 1.1.0
Last Updated: 2025

A comprehensive OSINT tool built for security researchers and penetration testers.
Features include DNS analysis, SSL inspection, port scanning, and Tor integration.

Install: pip install -r requirements.txt
Run:     python E502OSINT.py

Note: This tool is designed for authorized security testing and research purposes only.
All reconnaissance is performed using standard protocols and public resources.
"""

import os
import sys
import socket
import random
import subprocess
import platform
import signal
from typing import Optional, Dict, List, Union, Any, Coroutine
import dns.resolver
import whois
import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup
import socks
import socket
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.tree import Tree
from rich.live import Live
from rich.layout import Layout
from rich import box
from rich.theme import Theme
from art import text2art
import threading
import time
from datetime import datetime
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import functools
import json
import aiohttp
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import pathlib

# Configure logging
log_dir = pathlib.Path("logs")
log_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler(
            log_dir / "e502.log",
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        ),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("E502OSINT")

# Import core modules
from core.privacy_manager import PrivacyManager
from core.image_intel import ImageIntelligence
from core.notification_manager import NotificationManager
from core.report_manager import ReportManager
from core.config_manager import ConfigManager
from core.web_security import WebSecurity

# Import scan modules from scan package
from core.scan import (
    ScanEngine, ScanController, ScanAnalyzer, ScanReporter,
    ScanExporter, ScanImporter, ScanValidator, ScanMonitor,
    ScanLogger, ScanConfigurator, ScanManager, ScanConfig,
    VulnerabilityScanner, WebScanner, SSLAnalyzer, NetworkAnalyzer
)

# Import Discord integration
from discord.webhook_manager import DiscordWebhookManager

# Initialize Rich console with custom theme
console = Console(theme=Theme({
    "info": "cyan",
    "warning": "yellow",
    "danger": "red",
    "success": "green",
    "scanning": "blue",
    "vulnerability.high": "red",
    "vulnerability.medium": "yellow",
    "vulnerability.low": "green"
}))

# Global variables
VERSION = "1.1.0"
AUTHOR = "z3r0s / Error502"
USE_PROXY = False
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 9050
SCAN_STATUS = "Ready"
LAST_COMMAND = None
DISCORD_ENABLED = False
CURRENT_TASK = None  # Track current running task

# Thread pool for parallel execution
thread_pool = ThreadPoolExecutor(max_workers=10)
# Event loop for async operations
event_loop = asyncio.new_event_loop()
asyncio.set_event_loop(event_loop)

# Initialize analyzers and managers
network_analyzer = NetworkAnalyzer()
web_analyzer = WebScanner()
ssl_analyzer = SSLAnalyzer()
privacy_manager = PrivacyManager()
vuln_scanner = VulnerabilityScanner()
discord_manager = DiscordWebhookManager()
image_intelligence = ImageIntelligence()
notification_manager = NotificationManager()
report_manager = ReportManager()
config_manager = ConfigManager()
web_security = WebSecurity()

# Cyber tips and quotes
CYBER_TIPS = [
    "Always verify SSL certificates before connecting to websites.",
    "Use a password manager to generate and store strong, unique passwords.",
    "Enable two-factor authentication wherever possible.",
    "Keep your software and systems updated regularly.",
    "Be cautious of phishing attempts and suspicious links.",
    "Use a VPN when connecting to public Wi-Fi networks.",
    "Regularly backup your important data.",
    "Monitor your accounts for suspicious activity.",
    "Use strong encryption for sensitive communications.",
    "Practice the principle of least privilege."
]

HACKER_QUOTES = [
    "The best way to predict the future is to implement it yourself.",
    "The only truly secure system is one that is powered off, cast in a block of concrete and sealed in a lead-lined room with armed guards.",
    "If you think technology can solve your security problems, then you don't understand the problems and you don't understand the technology.",
    "The Internet is not just one thing, it's a collection of things - of numerous communications networks that all speak the same digital language.",
    "The more you know, the more you realize you don't know.",
    "The best way to find a vulnerability is to look for it.",
    "Security is not a product, but a process.",
    "The only way to do great work is to love what you do.",
    "The best defense is a good offense.",
    "The more you learn, the more you earn."
]

async def run_in_thread(func, *args, **kwargs):
    """Run a blocking function in a thread pool."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        thread_pool, 
        functools.partial(func, *args, **kwargs)
    )

async def run_concurrent_tasks(coroutines: List[Coroutine]) -> List[Any]:
    """Run multiple async tasks concurrently and wait for all to complete."""
    return await asyncio.gather(*coroutines, return_exceptions=True)

def create_progress_bar(description: str) -> Progress:
    """Create a progress bar with custom styling."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(complete_style="green", finished_style="green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    )

def display_banner() -> None:
    """Display the E502 banner with version and author information."""
    banner = text2art("E502", font="block")
    console.print(Panel(banner, style="bold blue", box=box.DOUBLE))
    
    # Display version and author information
    console.print(f"[bold green]Version:[/] {VERSION}")
    console.print(f"[bold green]Author:[/] {AUTHOR}")
    
    # Display a random security tip or quote
    tip_or_quote = random.choice(CYBER_TIPS + HACKER_QUOTES)
    console.print(Panel(tip_or_quote, title="Security Tip", style="bold yellow", box=box.ROUNDED))

def create_command_prompt() -> str:
    """Create a dynamic command prompt with status indicators."""
    status_color = {
        "Ready": "green",
        "Scanning": "yellow",
        "Error": "red"
    }.get(SCAN_STATUS, "white")
    
    proxy_status = "[green]✓[/]" if USE_PROXY else "[red]✗[/]"
    
    return f"[bold blue]E502[/] [bold {status_color}]{SCAN_STATUS}[/] {proxy_status} > "

def display_network_tree(topology: Dict) -> None:
    """Display network topology as a tree structure."""
    tree = Tree("[bold blue]Network Topology[/]")
    
    # Add target node
    target_node = tree.add(f"[bold green]{topology['target']}[/]")
    
    # Add discovered devices
    for device in topology.get('devices', []):
        device_node = target_node.add(f"[yellow]{device['ip']}[/]")
        
        # Add services
        if device.get('services'):
            services_node = device_node.add("[cyan]Services[/]")
            for service in device['services']:
                services_node.add(
                    f"[green]{service['name']}[/] "
                    f"([blue]Port {service['port']}[/])"
                )
    
    console.print(tree)

def display_vulnerability_table(vulnerabilities: List[Dict]) -> None:
    """Display vulnerabilities in a color-coded table."""
    table = Table(
        title="Vulnerability Scan Results",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta"
    )
    
    table.add_column("Severity", style="bold")
    table.add_column("Type", style="cyan")
    table.add_column("Location", style="green")
    table.add_column("Description", style="white")
    
    for vuln in vulnerabilities:
        severity_style = {
            "high": "red",
            "medium": "yellow",
            "low": "green"
        }.get(vuln.get('severity', 'low'), 'white')
        
        table.add_row(
            f"[{severity_style}]{vuln.get('severity', 'unknown')}[/]",
            vuln.get('type', 'unknown'),
            vuln.get('location', 'unknown'),
            vuln.get('description', 'unknown')
        )
    
    console.print(table)

def display_port_scan_results(results: List[Dict]) -> None:
    """Display port scan results with visual indicators."""
    table = Table(
        title="Port Scan Results",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta"
    )
    
    table.add_column("Port", style="cyan")
    table.add_column("Service", style="green")
    table.add_column("State", style="bold")
    table.add_column("Version", style="yellow")
    
    for result in results:
        state_style = "green" if result.get('state') == 'open' else "red"
        table.add_row(
            str(result.get('port', '')),
            result.get('service', ''),
            f"[{state_style}]{result.get('state', '')}[/]",
            result.get('version', '')
        )
    
    console.print(table)

def display_web_analysis(analysis: Dict) -> None:
    """Display web analysis results in a collapsible format."""
    layout = Layout()
    layout.split_column(
        Layout(name="header"),
        Layout(name="body"),
        Layout(name="footer")
    )
    
    # Header with basic info
    layout["header"].update(Panel(
        f"[bold blue]Web Analysis Results for {analysis.get('url', 'Unknown')}[/]\n"
        f"Status Code: [bold green]{analysis.get('status_code', 'Unknown')}[/]",
        box=box.ROUNDED
    ))
    
    # Body with detailed analysis
    body_content = []
    
    # Technologies
    if analysis.get('technologies'):
        tech_table = Table(box=box.SIMPLE)
        tech_table.add_column("Technology", style="cyan")
        tech_table.add_column("Version", style="green")
        for tech, version in analysis['technologies'].items():
            tech_table.add_row(tech, version)
        body_content.append(Panel(tech_table, title="Technologies", box=box.ROUNDED))
    
    # Security Headers
    if analysis.get('security_headers'):
        headers_table = Table(box=box.SIMPLE)
        headers_table.add_column("Header", style="cyan")
        headers_table.add_column("Value", style="green")
        headers_table.add_column("Status", style="bold")
        for header, info in analysis['security_headers'].items():
            status = "[green]✓[/]" if info.get('present') else "[red]✗[/]"
            headers_table.add_row(header, info.get('value', ''), status)
        body_content.append(Panel(headers_table, title="Security Headers", box=box.ROUNDED))
    
    layout["body"].update(Panel(
        "\n".join(str(content) for content in body_content),
        box=box.ROUNDED
    ))
    
    # Footer with recommendations
    if analysis.get('recommendations'):
        layout["footer"].update(Panel(
            "\n".join(f"• {rec}" for rec in analysis['recommendations']),
            title="Recommendations",
            box=box.ROUNDED
        ))
    
    console.print(layout)

def check_tor_port() -> bool:
    """Check if Tor is running on the default port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((PROXY_HOST, PROXY_PORT))
        sock.close()
        return result == 0
    except:
        return False

def setup_proxy() -> None:
    """Setup or disable Tor proxy."""
    global USE_PROXY
    
    if USE_PROXY:
        # Disable proxy
        socks.set_default_proxy()
        socket.socket = socket.socket
        USE_PROXY = False
        console.print("[bold red]Proxy disabled.[/]")
        return

    response = Prompt.ask(
        "Do you want to route all supported requests through Tor SOCKS5 proxy on 127.0.0.1:9050?",
        choices=["y", "n"],
        default="n"
    )

    if response.lower() == "y":
        if check_tor_port():
            # Enable proxy
            socks.set_default_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT)
            socket.socket = socks.socksocket
            USE_PROXY = True
            console.print("[bold green]Proxy enabled.[/]")
        else:
            console.print("[bold red]Tor is not running on port 9050.[/]")
            response = Prompt.ask(
                "Would you like the script to try to start Tor for you?",
                choices=["y", "n"],
                default="n"
            )
            
            if response.lower() == "y":
                if platform.system() == "Linux":
                    try:
                        subprocess.Popen(["tor"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        console.print("[bold yellow]Attempting to start Tor...[/]")
                        time.sleep(5)  # Wait for Tor to start
                        if check_tor_port():
                            setup_proxy()
                        else:
                            console.print("[bold red]Failed to start Tor.[/]")
                    except Exception as e:
                        console.print(f"[bold red]Error starting Tor: {str(e)}[/]")
                else:
                    console.print("[bold red]Automatic Tor startup is only supported on Linux.[/]")
                    console.print("Please install and start Tor manually:")
                    console.print("1. Download Tor from https://www.torproject.org/download/")
                    console.print("2. Install and start the Tor service")
                    console.print("3. Ensure it's running on port 9050")

def get_system_info() -> Dict[str, str]:
    """Get system information."""
    return {
        "Username": os.getlogin(),
        "OS": platform.system(),
        "OS Version": platform.version(),
        "Architecture": platform.machine(),
        "Python Version": platform.python_version()
    }

def dns_lookup(domain: str) -> None:
    """Perform DNS lookup on a domain."""
    try:
        resolver = dns.resolver.Resolver()
        
        # Show available record types
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        table = Table(title=f"DNS Records for {domain}")
        table.add_column("Record Type", style="cyan")
        table.add_column("Value", style="green")
        
        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    table.add_row(rtype, str(rdata))
            except:
                continue
        
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error performing DNS lookup: {str(e)}[/]")

def whois_lookup(target: str) -> None:
    """Perform WHOIS lookup on a domain or IP."""
    try:
        w = whois.whois(target)
        table = Table(title=f"WHOIS Information for {target}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in w.items():
            if value and key not in ['raw', 'status']:
                if isinstance(value, list):
                    value = ', '.join(str(v) for v in value)
                table.add_row(key, str(value))
        
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error performing WHOIS lookup: {str(e)}[/]")

def reverse_ip_lookup(ip: str) -> None:
    """Perform reverse IP lookup."""
    try:
        hostname = socket.gethostbyaddr(ip)
        console.print(f"[bold green]Hostname:[/] {hostname[0]}")
        if hostname[1]:
            console.print("[bold green]Aliases:[/]")
            for alias in hostname[1]:
                console.print(f"  - {alias}")
    except socket.herror:
        console.print(f"[bold red]No hostname found for {ip}[/]")
    except Exception as e:
        console.print(f"[bold red]Error performing reverse IP lookup: {str(e)}[/]")

def find_subdomains(domain: str) -> None:
    """Find subdomains using DNS brute force."""
    common_subdomains = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'ns3', 'ns4', 'admin', 'forum', 'blog', 'dev', 'test', 'stage', 'api',
        'secure', 'vpn', 'm', 'shop', 'beta', 'portal', 'app', 'cloud', 'cdn'
    ]
    
    table = Table(title=f"Subdomains for {domain}")
    table.add_column("Subdomain", style="cyan")
    table.add_column("IP Address", style="green")
    
    for subdomain in common_subdomains:
        try:
            full_domain = f"{subdomain}.{domain}"
            ip = socket.gethostbyname(full_domain)
            table.add_row(full_domain, ip)
        except:
            continue
    
    console.print(table)

def check_leaks(target: str) -> None:
    """Check for potential data leaks."""
    console.print("[bold yellow]Note: This is a basic check. For comprehensive leak detection, use specialized tools.[/]")
    
    table = Table(title=f"Potential Leaks for {target}")
    table.add_column("Source", style="cyan")
    table.add_column("Status", style="green")
    
    # Check common paste sites
    paste_sites = [
        f"https://pastebin.com/search?q={target}",
        f"https://ghostbin.com/search?q={target}",
        f"https://rentry.co/search?q={target}"
    ]
    
    for site in paste_sites:
        try:
            response = requests.get(site, timeout=5)
            if response.status_code == 200:
                table.add_row(site, "Check manually")
        except:
            table.add_row(site, "Unavailable")
    
    console.print(table)

def github_recon(target: str) -> None:
    """Perform basic GitHub reconnaissance."""
    console.print("[bold yellow]Note: This is a basic check. For comprehensive GitHub recon, use specialized tools.[/]")
    
    table = Table(title=f"GitHub Information for {target}")
    table.add_column("Type", style="cyan")
    table.add_column("Value", style="green")
    
    # Check if target is a username
    try:
        response = requests.get(f"https://github.com/{target}", timeout=5)
        if response.status_code == 200:
            table.add_row("Username", "Valid")
        else:
            table.add_row("Username", "Invalid")
    except:
        table.add_row("Username", "Check failed")
    
    # Check if target is an organization
    try:
        response = requests.get(f"https://github.com/orgs/{target}", timeout=5)
        if response.status_code == 200:
            table.add_row("Organization", "Valid")
        else:
            table.add_row("Organization", "Invalid")
    except:
        table.add_row("Organization", "Check failed")
    
    console.print(table)

def check_headers(url: str) -> None:
    """Check HTTP headers of a domain or URL."""
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    try:
        response = requests.get(url, timeout=5)
        table = Table(title=f"HTTP Headers for {url}")
        table.add_column("Header", style="cyan")
        table.add_column("Value", style="green")
        
        for header, value in response.headers.items():
            table.add_row(header, value)
        
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Error checking headers: {str(e)}[/]")

def check_ssl(domain: str) -> None:
    """Perform detailed SSL/TLS certificate analysis and security assessment.
    
    This function provides comprehensive certificate information including:
    - Certificate details and validity
    - Public key information
    - Subject Alternative Names
    - Key usage and extended key usage
    - Security recommendations
    
    Args:
        domain (str): Target domain for SSL analysis
    """
    if not domain.startswith(('http://', 'https://')):
        domain = f"https://{domain}"
    
    try:
        import ssl
        import socket
        import datetime
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect and get certificate
        with socket.create_connection((domain.split('://')[1], 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain.split('://')[1]) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                
                # Basic SSL info
                table = Table(title=f"SSL Certificate Information for {domain}")
                table.add_column("Field", style="cyan")
                table.add_column("Value", style="green")
                
                # Certificate details
                table.add_row("Subject", str(cert_obj.subject))
                table.add_row("Issuer", str(cert_obj.issuer))
                table.add_row("Version", str(cert_obj.version))
                table.add_row("Serial Number", str(cert_obj.serial_number))
                
                # Validity period
                not_before = cert_obj.not_valid_before
                not_after = cert_obj.not_valid_after
                table.add_row("Valid From", not_before.strftime("%Y-%m-%d %H:%M:%S"))
                table.add_row("Valid Until", not_after.strftime("%Y-%m-%d %H:%M:%S"))
                
                # Check if certificate is expired
                now = datetime.datetime.now()
                if now > not_after:
                    table.add_row("Status", "[bold red]EXPIRED[/]")
                elif now < not_before:
                    table.add_row("Status", "[bold yellow]NOT YET VALID[/]")
                else:
                    days_left = (not_after - now).days
                    if days_left < 30:
                        table.add_row("Status", f"[bold yellow]EXPIRING SOON ({days_left} days left)[/]")
                    else:
                        table.add_row("Status", f"[bold green]VALID ({days_left} days left)[/]")
                
                # Signature algorithm
                table.add_row("Signature Algorithm", str(cert_obj.signature_algorithm_oid))
                
                # Public key info
                public_key = cert_obj.public_key()
                table.add_row("Public Key Type", str(type(public_key).__name__))
                table.add_row("Public Key Size", str(public_key.key_size))
                
                # Subject Alternative Names
                try:
                    san = cert_obj.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    if san:
                        table.add_row("Subject Alternative Names", "\n".join(str(name.value) for name in san.value))
                except:
                    pass
                
                # Key Usage
                try:
                    key_usage = cert_obj.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
                    if key_usage:
                        table.add_row("Key Usage", str(key_usage.value))
                except:
                    pass
                
                # Extended Key Usage
                try:
                    ext_key_usage = cert_obj.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
                    if ext_key_usage:
                        table.add_row("Extended Key Usage", "\n".join(str(usage) for usage in ext_key_usage.value))
                except:
                    pass
                
                console.print(table)
                
                # Security recommendations
                recommendations = []
                
                # Check certificate age
                cert_age = (not_after - not_before).days
                if cert_age > 365:
                    recommendations.append("Consider using shorter certificate validity periods (1 year or less)")
                
                # Check key size
                if public_key.key_size < 2048:
                    recommendations.append("Consider upgrading to a stronger key size (2048 bits or more)")
                
                if recommendations:
                    console.print("\n[bold yellow]Security Recommendations:[/]")
                    for rec in recommendations:
                        console.print(f"  • {rec}")
                
                # Ask if user wants to save results
                save_results = Prompt.ask(
                    "Save SSL certificate information to file?",
                    choices=["y", "n"],
                    default="n"
                )
                
                if save_results == "y":
                    filename = f"ssl_{domain.split('://')[1]}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
                    try:
                        with open(filename, "w") as f:
                            f.write(f"SSL Certificate Information for {domain}\n")
                            f.write(f"Analysis time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                            for row in table.rows:
                                f.write(f"{row[0]}: {row[1]}\n")
                            if recommendations:
                                f.write("\nSecurity Recommendations:\n")
                                for rec in recommendations:
                                    f.write(f"  • {rec}\n")
                        console.print(f"[bold green]Results saved to {filename}[/]")
                    except Exception as e:
                        console.print(f"[bold red]Error saving results: {str(e)}[/]")
    
    except Exception as e:
        console.print(f"[bold red]Error checking SSL: {str(e)}[/]")

async def async_scan_target(target: str) -> None:
    """Asynchronous version of scan_target function."""
    global SCAN_STATUS
    SCAN_STATUS = "Scanning"
    
    try:
        # Create a progress bar
        with create_progress_bar("Scanning target...") as progress:
            task = progress.add_task("Scanning...", total=100)
            
            # Validate target
            if not target:
                console.print("[red]Error: Target cannot be empty[/]")
                return
            
            console.print(f"[bold green]Scanning target: {target}[/]")
            
            # Update progress
            progress.update(task, advance=10)
            
            # Tasks to run concurrently
            tasks = []
            
            # DNS lookup
            tasks.append(run_in_thread(dns_lookup, target))
            
            # WHOIS lookup
            tasks.append(run_in_thread(whois_lookup, target))
            
            # Port scan for common ports
            # ... code for port scanning ...
            
            # Update progress
            progress.update(task, advance=20)
            
            # Run concurrent tasks
            await run_concurrent_tasks(tasks)
            
            # Update progress
            progress.update(task, advance=70)
            
            console.print(f"[bold green]Scan completed for {target}[/]")
            
            if DISCORD_ENABLED:
                # Send scan results to Discord
                await run_in_thread(
                    discord_manager.send_message,
                    f"Scan completed for {target}",
                    {
                        "title": f"Scan Results: {target}",
                        "description": "Comprehensive scan completed successfully",
                        "color": 0x00ff00,
                        "footer": {"text": f"E502 OSINT Terminal v{VERSION}"}
                    }
                )
            
            # Complete progress
            progress.update(task, completed=100)
    
    except Exception as e:
        console.print(f"[red]Error during scan: {str(e)}[/]")
    
    finally:
        SCAN_STATUS = "Ready"

# Replace the original scan_target function with a wrapper that calls the async version
def scan_target(target: str) -> None:
    """Wrapper around async_scan_target to run it in the event loop."""
    asyncio.run_coroutine_threadsafe(async_scan_target(target), event_loop)

async def async_handle_network_scan(target: str) -> None:
    """Asynchronous network scan handler."""
    console.print(f"[bold green]Starting network analysis for {target}...[/]")
    
    # Use the comprehensive network analysis function that runs multiple operations in parallel
    results = await network_analyzer.analyze_network(target)
    await network_analyzer.display_network_info_async(results)
    
    if DISCORD_ENABLED:
        await run_in_thread(discord_manager.send_network_scan_result, target, results)

def handle_network_scan(target: str) -> None:
    """Wrapper for async_handle_network_scan."""
    asyncio.run_coroutine_threadsafe(async_handle_network_scan(target), event_loop)

async def async_handle_web_analysis(url: str) -> None:
    """Asynchronous web analysis handler."""
    console.print(f"[bold green]Starting web analysis for {url}...[/]")
    
    # Use the fully async implementation instead of the thread-wrapped version
    analysis = await web_analyzer.full_analysis_async(url)
    await web_analyzer.display_web_analysis_async(analysis)
    
    if DISCORD_ENABLED:
        await run_in_thread(discord_manager.send_web_scan_result, url, analysis)

def handle_web_analysis(url: str) -> None:
    """Wrapper for async_handle_web_analysis."""
    asyncio.run_coroutine_threadsafe(async_handle_web_analysis(url), event_loop)

async def async_handle_ssl_analysis(hostname: str) -> None:
    """Asynchronous SSL analysis handler."""
    console.print(f"[bold green]Starting SSL analysis for {hostname}...[/]")
    try:
        analysis = await ssl_analyzer.analyze_ssl(hostname)
        ssl_analyzer.display_ssl_analysis(analysis)
        
        if DISCORD_ENABLED:
            await run_in_thread(discord_manager.send_ssl_scan_result, hostname, analysis)
    except Exception as e:
        console.print(f"[red]Error during SSL analysis: {str(e)}[/]")

def handle_ssl_analysis(hostname: str) -> None:
    """Wrapper for async_handle_ssl_analysis."""
    asyncio.run_coroutine_threadsafe(async_handle_ssl_analysis(hostname), event_loop)

async def async_handle_vuln_scan(target: str) -> None:
    """Asynchronous vulnerability scan handler."""
    console.print(f"[bold green]Starting vulnerability scan for {target}...[/]")
    results = await run_in_thread(vuln_scanner.scan_target, target)
    vuln_scanner.display_scan_results(results)
    
    if DISCORD_ENABLED:
        await run_in_thread(discord_manager.send_vuln_scan_result, target, results)

def handle_vuln_scan(target: str) -> None:
    """Wrapper for async_handle_vuln_scan."""
    asyncio.run_coroutine_threadsafe(async_handle_vuln_scan(target), event_loop)

async def async_handle_privacy_status() -> None:
    """Asynchronous privacy status handler."""
    console.print(f"[bold green]Showing privacy status...[/]")
    await run_in_thread(privacy_manager.display_privacy_status)

def handle_privacy_status() -> None:
    """Wrapper for async_handle_privacy_status."""
    asyncio.run_coroutine_threadsafe(async_handle_privacy_status(), event_loop)

async def async_handle_add_proxy(name: str, host: str, port: int, proxy_type: str) -> None:
    """Asynchronous add proxy handler."""
    console.print(f"[bold green]Adding proxy {name}...[/]")
    await run_in_thread(privacy_manager.add_proxy, name, host, port, proxy_type)

def handle_add_proxy(name: str, host: str, port: int, proxy_type: str) -> None:
    """Wrapper for async_handle_add_proxy."""
    asyncio.run_coroutine_threadsafe(async_handle_add_proxy(name, host, port, proxy_type), event_loop)

async def async_handle_proxy_chain(proxy_names: List[str]) -> None:
    """Asynchronous proxy chain handler."""
    console.print(f"[bold green]Creating proxy chain with {len(proxy_names)} proxies...[/]")
    await run_in_thread(privacy_manager.create_proxy_chain, proxy_names)

def handle_proxy_chain(proxy_names: List[str]) -> None:
    """Wrapper for async_handle_proxy_chain."""
    asyncio.run_coroutine_threadsafe(async_handle_proxy_chain(proxy_names), event_loop)

async def async_handle_rate_limit(domain: str, requests_per_second: float) -> None:
    """Asynchronous rate limit handler."""
    console.print(f"[bold green]Setting rate limit for {domain} to {requests_per_second} requests/second...[/]")
    await run_in_thread(privacy_manager.set_rate_limit, domain, requests_per_second)

def handle_rate_limit(domain: str, requests_per_second: float) -> None:
    """Wrapper for async_handle_rate_limit."""
    asyncio.run_coroutine_threadsafe(async_handle_rate_limit(domain, requests_per_second), event_loop)

async def async_handle_rotate_user_agent() -> None:
    """Asynchronous user agent rotation handler."""
    console.print(f"[bold green]Rotating user agent...[/]")
    await run_in_thread(privacy_manager.rotate_user_agent)

def handle_rotate_user_agent() -> None:
    """Wrapper for async_handle_rotate_user_agent."""
    asyncio.run_coroutine_threadsafe(async_handle_rotate_user_agent(), event_loop)

async def async_handle_discord_command(parts: List[str]) -> None:
    """Asynchronous Discord command handler."""
    global DISCORD_ENABLED
    
    if len(parts) < 2:
        console.print("[red]Invalid Discord command. Use 'discord help' for available commands.[/]")
        return

    subcommand = parts[1].lower()
    
    if subcommand == "help":
        console.print("""
[bold cyan]Discord Commands:[/]
  discord enable          - Enable Discord integration
  discord disable         - Disable Discord integration
  discord set <url>       - Set webhook URL
  discord save           - Save current webhook URL
  discord test           - Send test message
  discord status         - Show Discord integration status
  discord summary        - Send scan activity summary
  discord clear          - Clear scan history
""")
    elif subcommand == "enable":
        if not discord_manager.webhook_url:
            webhook_url = Prompt.ask("Enter Discord webhook URL")
            save = Prompt.ask("Save webhook URL?", choices=["y", "n"], default="n") == "y"
            discord_manager.set_webhook(webhook_url, save)
        DISCORD_ENABLED = True
        console.print("[green]Discord integration enabled.[/]")
        discord_manager.send_alert("Integration Enabled", "E502 OSINT Terminal Discord integration has been enabled.", "success")
    elif subcommand == "disable":
        DISCORD_ENABLED = False
        console.print("[yellow]Discord integration disabled.[/]")
    elif subcommand == "set" and len(parts) > 2:
        webhook_url = parts[2]
        save = Prompt.ask("Save webhook URL?", choices=["y", "n"], default="n") == "y"
        discord_manager.set_webhook(webhook_url, save)
    elif subcommand == "save":
        if discord_manager.webhook_url:
            discord_manager.save_config()
        else:
            console.print("[red]No webhook URL configured to save.[/]")
    elif subcommand == "test":
        if discord_manager.webhook_url:
            discord_manager.send_alert("Test Message", "This is a test message from E502 OSINT Terminal.", "info")
        else:
            console.print("[red]No webhook URL configured. Use 'discord set' to configure.[/]")
    elif subcommand == "status":
        status = "Enabled" if DISCORD_ENABLED else "Disabled"
        webhook_status = "Configured" if discord_manager.webhook_url else "Not configured"
        console.print(f"[bold]Discord Integration:[/] {status}")
        console.print(f"[bold]Webhook Status:[/] {webhook_status}")
    elif subcommand == "summary":
        if DISCORD_ENABLED:
            discord_manager.send_scan_summary()
        else:
            console.print("[red]Discord integration is disabled.[/]")
    elif subcommand == "clear":
        discord_manager.scan_history.clear()
        console.print("[green]Scan history cleared.[/]")
    else:
        console.print("[red]Unknown Discord command. Use 'discord help' for available commands.[/]")

def handle_discord_command(parts: List[str]) -> None:
    """Wrapper for async_handle_discord_command."""
    asyncio.run_coroutine_threadsafe(async_handle_discord_command(parts), event_loop)

async def async_handle_check_tor() -> None:
    """Asynchronous handler for checking Tor status."""
    console.print("[bold green]Checking Tor status...[/]")
    is_running = check_tor_port()
    if is_running:
        console.print("[bold green]✓ Tor is running on port 9050[/]")
    else:
        console.print("[bold red]✗ Tor is not running on port 9050[/]")
        console.print("[yellow]To use Tor, please ensure it's installed and running on port 9050[/]")

def handle_check_tor() -> None:
    """Wrapper for async_handle_check_tor."""
    asyncio.run_coroutine_threadsafe(async_handle_check_tor(), event_loop)

def handle_cancel_signal(signum, frame):
    """Handle cancellation signal (SIGTSTP on Unix, SIGINT on Windows)."""
    global SCAN_STATUS, CURRENT_TASK
    
    if CURRENT_TASK and not CURRENT_TASK.done():
        console.print("\n[yellow]Cancelling current operation...[/]")
        CURRENT_TASK.cancel()
        SCAN_STATUS = "Ready"
        console.print("[green]Operation cancelled.[/]")
    else:
        console.print("\n[yellow]No operation in progress to cancel.[/]")

# Register signal handler based on platform
if platform.system() == 'Windows':
    # On Windows, use Ctrl+C (SIGINT) for cancellation
    signal.signal(signal.SIGINT, handle_cancel_signal)
    console.print("[yellow]Note: Use Ctrl+C to cancel operations on Windows[/]")
else:
    # On Unix-like systems, use Ctrl+Z (SIGTSTP) for cancellation
    signal.signal(signal.SIGTSTP, handle_cancel_signal)
    console.print("[yellow]Note: Use Ctrl+Z to cancel operations on Unix[/]")

async def async_main() -> None:
    """Asynchronous main function."""
    # Start a background thread to run the event loop
    threading.Thread(target=lambda: event_loop.run_forever(), daemon=True).start()
    
    display_banner()
    
    try:
        while True:
            command = Prompt.ask(create_command_prompt())
            
            if not command:
                continue
                
            # Process commands asynchronously
            await process_command(command)
            
    except KeyboardInterrupt:
        console.print("[bold yellow]Exiting E502 OSINT Terminal...[/]")
    finally:
        # Cleanup
        thread_pool.shutdown()
        event_loop.stop()

async def process_command(command: str) -> None:
    """Process user commands."""
    global SCAN_STATUS, LAST_COMMAND, USE_PROXY, CURRENT_TASK
    
    try:
        parts = command.strip().split()
        if not parts:
            return
            
        cmd = parts[0].lower()
        args = parts[1:]
        
        # Create task for command execution
        if cmd == 'help':
            show_help()
        elif cmd == 'network':
            if not args:
                console.print("[red]Please specify a target[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Analyzing network..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(async_handle_network_scan(args[0]))
                result = await CURRENT_TASK
                display_network_analysis(result)
        elif cmd == 'web':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Analyzing website..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(web_analyzer.analyze_website_async(args[0]))
                result = await CURRENT_TASK
                display_web_analysis(result)
        elif cmd == 'api':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Discovering API endpoints..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(web_analyzer._discover_api_endpoints(args[0]))
                result = await CURRENT_TASK
                display_api_endpoints(result)
        elif cmd == 'graphql':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Analyzing GraphQL..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(web_analyzer._analyze_graphql(args[0]))
                result = await CURRENT_TASK
                display_graphql_analysis(result)
        elif cmd == 'websocket':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Checking WebSocket security..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(web_analyzer._check_websocket_security(args[0]))
                result = await CURRENT_TASK
                display_websocket_security(result)
        elif cmd == 'content':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Analyzing content..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(web_analyzer._analyze_content(args[0]))
                result = await CURRENT_TASK
                display_content_analysis(result)
        elif cmd == 'tech':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Detecting technologies..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(web_analyzer._detect_technologies(args[0]))
                result = await CURRENT_TASK
                display_technologies(result)
        elif cmd == 'security':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Checking security issues..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(web_analyzer._check_security_issues(args[0]))
                result = await CURRENT_TASK
                display_security_issues(result)
        elif cmd == 'headers':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Analyzing headers..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(web_analyzer.analyze_website_async(args[0]))
                result = await CURRENT_TASK
                display_security_headers(result.get('security_headers', {}))
        elif cmd == 'waf':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Detecting WAF..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(web_analyzer.analyze_website_async(args[0]))
                result = await CURRENT_TASK
                display_waf_detection(result.get('waf_detection', {}))
        elif cmd == 'cookies':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Analyzing cookies..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(web_analyzer.analyze_website_async(args[0]))
                result = await CURRENT_TASK
                display_cookie_analysis(result.get('cookies', {}))
        elif cmd == 'ssl':
            if not args:
                console.print("[red]Please specify a hostname[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Analyzing SSL/TLS..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(ssl_analyzer.analyze_ssl_async(args[0]))
                result = await CURRENT_TASK
                display_ssl_analysis(result)
        elif cmd == 'cert':
            if not args:
                console.print("[red]Please specify a hostname[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Checking certificate..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(ssl_analyzer.analyze_ssl_async(args[0]))
                result = await CURRENT_TASK
                display_certificate_info(result.get('certificate', {}))
        elif cmd == 'ciphers':
            if not args:
                console.print("[red]Please specify a hostname[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Analyzing cipher suites..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(ssl_analyzer.analyze_ssl_async(args[0]))
                result = await CURRENT_TASK
                display_cipher_suites(result.get('ciphers', {}))
        elif cmd == 'vuln':
            if not args:
                console.print("[red]Please specify a target[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Scanning for vulnerabilities..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(vuln_scanner.scan_target_async(args[0]))
                result = await CURRENT_TASK
                display_vulnerability_table(result)
        elif cmd == 'ports':
            if not args:
                console.print("[red]Please specify a target[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Scanning ports..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(network_analyzer._scan_ports(args[0]))
                result = await CURRENT_TASK
                display_port_scan_results(result)
        elif cmd == 'services':
            if not args:
                console.print("[red]Please specify a target[/]")
                return
            SCAN_STATUS = "Scanning"
            with Live(create_progress_bar("Enumerating services..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(network_analyzer._enumerate_services(args[0]))
                result = await CURRENT_TASK
                display_service_enumeration(result)
        elif cmd == 'image':
            if not args:
                console.print("[red]Please specify an image file[/]")
                return
            SCAN_STATUS = "Scanning"
            image_path = args[0]
            if not os.path.exists(image_path):
                console.print(f"[red]Image file not found: {image_path}[/]")
                return
            with Live(create_progress_bar("Analyzing image..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(run_in_thread(image_intelligence.analyze_image, image_path))
                result = await CURRENT_TASK
                image_intelligence.display_image_analysis(result)
        elif cmd == 'exif':
            if not args:
                console.print("[red]Please specify an image file[/]")
                return
            SCAN_STATUS = "Scanning"
            image_path = args[0]
            if not os.path.exists(image_path):
                console.print(f"[red]Image file not found: {image_path}[/]")
                return
            with Live(create_progress_bar("Extracting EXIF data..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(run_in_thread(image_intelligence._extract_exif, image_path))
                result = await CURRENT_TASK
                display_exif_data(result)
        elif cmd == 'geo':
            if not args:
                console.print("[red]Please specify an image file[/]")
                return
            SCAN_STATUS = "Scanning"
            image_path = args[0]
            if not os.path.exists(image_path):
                console.print(f"[red]Image file not found: {image_path}[/]")
                return
            with Live(create_progress_bar("Extracting geolocation data..."), refresh_per_second=10) as live:
                CURRENT_TASK = asyncio.create_task(run_in_thread(image_intelligence.extract_geo_data, image_path))
                result = await CURRENT_TASK
                display_geo_data(result)
        elif cmd == 'proxy':
            if len(args) < 2:
                console.print("[red]Invalid proxy command. Use 'proxy help' for usage.[/]")
                return
            subcmd = args[0].lower()
            if subcmd == 'add':
                if len(args) < 5:
                    console.print("[red]Usage: proxy add <name> <host> <port> <type>[/]")
                    return
                await async_handle_add_proxy(args[1], args[2], int(args[3]), args[4])
            elif subcmd == 'chain':
                if len(args) < 2:
                    console.print("[red]Usage: proxy chain <proxy1> <proxy2> ...[/]")
                    return
                await async_handle_proxy_chain(args[1:])
            elif subcmd == 'status':
                await async_handle_privacy_status()
            else:
                console.print("[red]Unknown proxy command. Use 'proxy help' for usage.[/]")
        elif cmd == 'tor':
            if not args or args[0] != 'check':
                console.print("[red]Usage: tor check[/]")
                return
            await async_handle_check_tor()
        elif cmd == 'rotate':
            await async_handle_rotate_user_agent()
        elif cmd == 'rate':
            if len(args) < 2:
                console.print("[red]Usage: rate <domain> <requests_per_second>[/]")
                return
            try:
                rate = float(args[1])
                await async_handle_rate_limit(args[0], rate)
            except ValueError:
                console.print("[red]Invalid rate value. Must be a number.[/]")
        elif cmd == 'discord':
            if not args:
                console.print("[red]Please specify a Discord command. Use 'discord help' for usage.[/]")
                return
            await async_handle_discord_command(args)
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
        elif cmd == 'exit':
            console.print("[bold yellow]Exiting E502 OSINT Terminal...[/]")
            sys.exit(0)
        else:
            console.print(f"[red]Unknown command: {cmd}[/]")
            console.print("Use 'help' to see available commands.")
            
    except Exception as e:
        console.print(f"[red]Error executing command: {str(e)}[/]")
        SCAN_STATUS = "Error"
    finally:
        SCAN_STATUS = "Ready"
        CURRENT_TASK = None

def show_help() -> None:
    """Display help information."""
    console.print("\n[bold cyan]E502 OSINT Terminal - Available Commands[/]")
    console.print("=" * 50)
    
    # Network Analysis
    console.print("\n[bold yellow]Network Analysis[/]")
    console.print("-" * 30)
    console.print("network <target>     - Perform comprehensive network analysis")
    console.print("ports <target>       - Scan for open ports")
    console.print("services <target>    - Enumerate running services")
    
    # Web Analysis
    console.print("\n[bold yellow]Web Analysis[/]")
    console.print("-" * 30)
    console.print("web <url>           - Perform comprehensive website analysis")
    console.print("api <url>           - Discover and analyze API endpoints")
    console.print("graphql <url>       - Analyze GraphQL endpoint")
    console.print("websocket <url>     - Check WebSocket security")
    console.print("content <url>       - Analyze website content")
    console.print("tech <url>          - Detect technologies used")
    console.print("security <url>      - Check for security issues")
    console.print("headers <url>       - Analyze security headers")
    console.print("waf <url>           - Detect Web Application Firewall")
    console.print("cookies <url>       - Analyze cookies")
    
    # SSL/TLS Analysis
    console.print("\n[bold yellow]SSL/TLS Analysis[/]")
    console.print("-" * 30)
    console.print("ssl <hostname>      - Analyze SSL/TLS configuration")
    console.print("cert <hostname>     - Check SSL certificate")
    console.print("ciphers <hostname>  - Analyze cipher suites")
    
    # Vulnerability Scanning
    console.print("\n[bold yellow]Vulnerability Scanning[/]")
    console.print("-" * 30)
    console.print("vuln <target>       - Scan for vulnerabilities")
    
    # Image Analysis
    console.print("\n[bold yellow]Image Analysis[/]")
    console.print("-" * 30)
    console.print("image <file>        - Analyze image file")
    console.print("exif <file>         - Extract EXIF data")
    console.print("geo <file>          - Extract geolocation data")
    
    # Privacy & Proxy
    console.print("\n[bold yellow]Privacy & Proxy[/]")
    console.print("-" * 30)
    console.print("proxy add <name> <host> <port> <type>  - Add proxy")
    console.print("proxy chain <proxy1> <proxy2> ...      - Chain proxies")
    console.print("proxy status                            - Check privacy status")
    console.print("tor check                              - Check Tor connection")
    
    # Other
    console.print("\n[bold yellow]Other[/]")
    console.print("-" * 30)
    console.print("help                 - Show this help message")
    console.print("exit                 - Exit the program")

def display_network_analysis(analysis: Dict) -> None:
    """Display network analysis results in a detailed format."""
    if not analysis:
        console.print("[red]No analysis results available[/]")
        return
        
    # Create main layout
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=10)
    )
    
    # Header section
    header = Table.grid()
    header.add_row(f"[bold blue]Target:[/] {analysis['target']}")
    header.add_row(f"[bold blue]IP:[/] {analysis['ip']}")
    header.add_row(f"[bold blue]Timestamp:[/] {analysis['timestamp']}")
    layout["header"].update(Panel(header, title="Network Analysis Summary", border_style="blue"))
    
    # Body section with multiple panels
    body_layout = Layout()
    body_layout.split_row(
        Layout(name="topology", ratio=1),
        Layout(name="protocols", ratio=1)
    )
    
    # Topology panel
    topology_table = Table(title="Network Topology", box=box.ROUNDED)
    topology_table.add_column("Device", style="cyan")
    topology_table.add_column("IP", style="green")
    topology_table.add_column("Status", style="yellow")
    
    for device in analysis.get('topology', {}).get('devices', []):
        topology_table.add_row(
            device.get('hostname', 'Unknown'),
            device.get('ip', 'Unknown'),
            device.get('status', 'Unknown')
        )
    body_layout["topology"].update(Panel(topology_table, border_style="cyan"))
    
    # Protocols panel
    protocols_table = Table(title="Modern Protocols", box=box.ROUNDED)
    protocols_table.add_column("Protocol", style="cyan")
    protocols_table.add_column("Supported", style="green")
    protocols_table.add_column("Version", style="yellow")
    
    for proto, info in analysis.get('modern_protocols', {}).get('protocols', {}).items():
        protocols_table.add_row(
            proto.upper(),
            "✓" if info.get('supported') else "✗",
            info.get('version', 'N/A')
        )
    body_layout["protocols"].update(Panel(protocols_table, border_style="cyan"))
    
    layout["body"].update(body_layout)
    
    # Footer section with traffic patterns
    traffic_table = Table(title="Traffic Patterns", box=box.ROUNDED)
    traffic_table.add_column("Metric", style="cyan")
    traffic_table.add_column("Value", style="green")
    
    patterns = analysis.get('traffic_patterns', {}).get('patterns', {})
    if patterns:
        traffic_table.add_row("Protocols", str(patterns.get('protocols', {})))
        traffic_table.add_row("Ports", str(patterns.get('ports', {})))
        traffic_table.add_row("Avg Packet Size", f"{sum(patterns.get('packet_sizes', [0]))/len(patterns.get('packet_sizes', [1])):.2f} bytes")
        traffic_table.add_row("Avg Interval", f"{sum(patterns.get('intervals', [0]))/len(patterns.get('intervals', [1])):.2f} seconds")
    
    layout["footer"].update(Panel(traffic_table, border_style="cyan"))
    
    # Display the complete layout
    console.print(layout)

def display_modern_protocols(analysis: Dict) -> None:
    """Display modern protocol analysis results."""
    if not analysis:
        console.print("[red]No protocol analysis results available[/]")
        return
        
    # Create layout
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body")
    )
    
    # Header
    header = Table.grid()
    header.add_row(f"[bold blue]Target:[/] {analysis.get('target', 'Unknown')}")
    header.add_row(f"[bold blue]Timestamp:[/] {analysis.get('timestamp', 'Unknown')}")
    layout["header"].update(Panel(header, title="Modern Protocol Analysis", border_style="blue"))
    
    # Protocol details
    table = Table(title="Protocol Support", box=box.ROUNDED)
    table.add_column("Protocol", style="cyan")
    table.add_column("Supported", style="green")
    table.add_column("Version", style="yellow")
    table.add_column("Details", style="blue")
    
    for proto, info in analysis.get('protocols', {}).items():
        details = []
        if proto == 'quic':
            details.append("QUIC is a transport layer protocol")
        elif proto == 'http3':
            details.append("HTTP/3 is the latest HTTP version")
        elif proto == 'http2':
            details.append("HTTP/2 provides multiplexing")
        elif proto == 'tls13':
            details.append("TLS 1.3 is the latest TLS version")
            
        table.add_row(
            proto.upper(),
            "✓" if info.get('supported') else "✗",
            info.get('version', 'N/A'),
            "\n".join(details)
        )
    
    layout["body"].update(Panel(table, border_style="cyan"))
    console.print(layout)

def display_traffic_patterns(analysis: Dict) -> None:
    """Display traffic pattern analysis results."""
    if not analysis:
        console.print("[red]No traffic pattern analysis results available[/]")
        return
        
    patterns = analysis.get('patterns', {})
    
    # Create layout
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body")
    )
    
    # Header
    header = Table.grid()
    header.add_row(f"[bold blue]Target:[/] {analysis.get('target', 'Unknown')}")
    header.add_row(f"[bold blue]Timestamp:[/] {analysis.get('timestamp', 'Unknown')}")
    layout["header"].update(Panel(header, title="Traffic Pattern Analysis", border_style="blue"))
    
    # Body with two panels
    body_layout = Layout()
    body_layout.split_row(
        Layout(name="protocols", ratio=1),
        Layout(name="statistics", ratio=1)
    )
    
    # Protocols panel
    protocols_table = Table(title="Protocol Distribution", box=box.ROUNDED)
    protocols_table.add_column("Protocol", style="cyan")
    protocols_table.add_column("Count", style="green")
    protocols_table.add_column("Percentage", style="yellow")
    
    total_packets = sum(patterns.get('protocols', {}).values())
    for proto, count in patterns.get('protocols', {}).items():
        percentage = (count / total_packets * 100) if total_packets > 0 else 0
        protocols_table.add_row(
            proto,
            str(count),
            f"{percentage:.1f}%"
        )
    
    body_layout["protocols"].update(Panel(protocols_table, border_style="cyan"))
    
    # Statistics panel
    stats_table = Table(title="Traffic Statistics", box=box.ROUNDED)
    stats_table.add_column("Metric", style="cyan")
    stats_table.add_column("Value", style="green")
    
    packet_sizes = patterns.get('packet_sizes', [])
    intervals = patterns.get('intervals', [])
    
    if packet_sizes:
        stats_table.add_row("Average Packet Size", f"{sum(packet_sizes)/len(packet_sizes):.2f} bytes")
        stats_table.add_row("Min Packet Size", f"{min(packet_sizes)} bytes")
        stats_table.add_row("Max Packet Size", f"{max(packet_sizes)} bytes")
    
    if intervals:
        stats_table.add_row("Average Interval", f"{sum(intervals)/len(intervals):.2f} seconds")
        stats_table.add_row("Min Interval", f"{min(intervals):.2f} seconds")
        stats_table.add_row("Max Interval", f"{max(intervals):.2f} seconds")
    
    body_layout["statistics"].update(Panel(stats_table, border_style="cyan"))
    
    layout["body"].update(body_layout)
    console.print(layout)

def display_security_headers(headers: Dict) -> None:
    """Display security headers analysis."""
    if not headers:
        console.print("[yellow]No security headers found[/]")
        return
        
    table = Table(title="Security Headers Analysis", box=box.ROUNDED)
    table.add_column("Header", style="cyan")
    table.add_column("Present", style="green")
    table.add_column("Value", style="yellow")
    table.add_column("Recommendation", style="blue")
    
    for header, info in headers.items():
        table.add_row(
            header,
            "✓" if info.get('present') else "✗",
            info.get('value', 'N/A'),
            info.get('recommendation', '')
        )
    
    console.print(table)

def display_waf_detection(waf_info: Dict) -> None:
    """Display WAF detection results."""
    if not waf_info:
        console.print("[yellow]No WAF detection results available[/]")
        return
        
    table = Table(title="WAF Detection Results", box=box.ROUNDED)
    table.add_column("Status", style="cyan")
    table.add_column("Detected WAFs", style="green")
    
    table.add_row(
        "Detected" if waf_info.get('detected') else "Not Detected",
        ", ".join(waf_info.get('wafs', [])) if waf_info.get('wafs') else "None"
    )
    
    console.print(table)

def display_cookie_analysis(cookies: Dict) -> None:
    """Display cookie analysis results."""
    if not cookies:
        console.print("[yellow]No cookies found[/]")
        return
        
    table = Table(title="Cookie Analysis", box=box.ROUNDED)
    table.add_column("Cookie", style="cyan")
    table.add_column("Value", style="green")
    table.add_column("Flags", style="yellow")
    table.add_column("Security", style="blue")
    
    for cookie, info in cookies.items():
        flags = []
        if info.get('secure'):
            flags.append("Secure")
        if info.get('httponly'):
            flags.append("HttpOnly")
        if info.get('samesite'):
            flags.append(f"SameSite={info['samesite']}")
            
        security = []
        if not info.get('secure'):
            security.append("Missing Secure flag")
        if not info.get('httponly'):
            security.append("Missing HttpOnly flag")
        if not info.get('samesite'):
            security.append("Missing SameSite attribute")
            
        table.add_row(
            cookie,
            info.get('value', 'N/A'),
            ", ".join(flags) if flags else "None",
            ", ".join(security) if security else "Secure"
        )
    
    console.print(table)

def display_ssl_analysis(analysis: Dict) -> None:
    """Display SSL/TLS analysis results."""
    if not analysis:
        console.print("[yellow]No SSL/TLS analysis results available[/]")
        return
        
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body")
    )
    
    # Header
    header = Table.grid()
    header.add_row(f"[bold blue]Hostname:[/] {analysis.get('hostname', 'Unknown')}")
    header.add_row(f"[bold blue]Timestamp:[/] {analysis.get('timestamp', 'Unknown')}")
    layout["header"].update(Panel(header, title="SSL/TLS Analysis", border_style="blue"))
    
    # Body with multiple panels
    body_layout = Layout()
    body_layout.split_row(
        Layout(name="protocols", ratio=1),
        Layout(name="certificate", ratio=1)
    )
    
    # Protocols panel
    protocols_table = Table(title="Protocol Support", box=box.ROUNDED)
    protocols_table.add_column("Protocol", style="cyan")
    protocols_table.add_column("Supported", style="green")
    protocols_table.add_column("Version", style="yellow")
    
    for proto, info in analysis.get('protocols', {}).items():
        protocols_table.add_row(
            proto.upper(),
            "✓" if info.get('supported') else "✗",
            info.get('version', 'N/A')
        )
    
    body_layout["protocols"].update(Panel(protocols_table, border_style="cyan"))
    
    # Certificate panel
    cert_table = Table(title="Certificate Information", box=box.ROUNDED)
    cert_table.add_column("Field", style="cyan")
    cert_table.add_column("Value", style="green")
    
    cert = analysis.get('certificate', {})
    if cert:
        cert_table.add_row("Subject", cert.get('subject', 'N/A'))
        cert_table.add_row("Issuer", cert.get('issuer', 'N/A'))
        cert_table.add_row("Valid From", cert.get('not_before', 'N/A'))
        cert_table.add_row("Valid Until", cert.get('not_after', 'N/A'))
        cert_table.add_row("Serial Number", cert.get('serial_number', 'N/A'))
    
    body_layout["certificate"].update(Panel(cert_table, border_style="cyan"))
    
    layout["body"].update(body_layout)
    console.print(layout)

def display_certificate_info(cert: Dict) -> None:
    """Display SSL certificate information."""
    if not cert:
        console.print("[yellow]No certificate information available[/]")
        return
        
    table = Table(title="SSL Certificate Information", box=box.ROUNDED)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    
    for field, value in cert.items():
        table.add_row(field.replace('_', ' ').title(), str(value))
    
    console.print(table)

def display_cipher_suites(ciphers: Dict) -> None:
    """Display cipher suite information."""
    if not ciphers:
        console.print("[yellow]No cipher suite information available[/]")
        return
        
    table = Table(title="Cipher Suites", box=box.ROUNDED)
    table.add_column("Cipher", style="cyan")
    table.add_column("Strength", style="green")
    table.add_column("Protocol", style="yellow")
    
    for cipher, info in ciphers.items():
        strength = "Strong" if info.get('strength', 0) >= 128 else "Weak"
        table.add_row(
            cipher,
            strength,
            info.get('protocol', 'N/A')
        )
    
    console.print(table)

def display_service_enumeration(services: List[Dict]) -> None:
    """Display service enumeration results."""
    if not services:
        console.print("[yellow]No services found[/]")
        return
        
    table = Table(title="Service Enumeration", box=box.ROUNDED)
    table.add_column("Port", style="cyan")
    table.add_column("Service", style="green")
    table.add_column("Version", style="yellow")
    table.add_column("State", style="blue")
    
    for service in services:
        table.add_row(
            str(service.get('port', 'N/A')),
            service.get('name', 'Unknown'),
            service.get('version', 'N/A'),
            service.get('state', 'Unknown')
        )
    
    console.print(table)

def display_exif_data(exif: Dict) -> None:
    """Display EXIF data from image."""
    if not exif:
        console.print("[yellow]No EXIF data found[/]")
        return
        
    table = Table(title="EXIF Data", box=box.ROUNDED)
    table.add_column("Tag", style="cyan")
    table.add_column("Value", style="green")
    
    for tag, value in exif.items():
        table.add_row(tag, str(value))
    
    console.print(table)

def display_geo_data(geo: Dict) -> None:
    """Display geolocation data from image."""
    if not geo:
        console.print("[yellow]No geolocation data found[/]")
        return
        
    table = Table(title="Geolocation Data", box=box.ROUNDED)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="green")
    
    for field, value in geo.items():
        table.add_row(field, str(value))
    
    console.print(table)

def display_api_endpoints(endpoints: List[Dict]) -> None:
    """Display API endpoint discovery results."""
    console.print("\n[bold cyan]API Endpoint Discovery Results[/]")
    console.print("=" * 50)
    
    if not endpoints:
        console.print("[yellow]No API endpoints discovered[/]")
        return
    
    for endpoint in endpoints:
        console.print(f"\n[bold yellow]Endpoint: {endpoint['path']}[/]")
        console.print("-" * 30)
        console.print(f"Status Code: {endpoint['status_code']}")
        console.print(f"Content Type: {endpoint['content_type']}")
        
        console.print("\n[bold]Supported Methods:[/]")
        for method in endpoint['methods']:
            console.print(f"  • {method}")
        
        console.print("\n[bold]Authentication:[/]")
        if endpoint['authentication']['required']:
            console.print(f"  • Required: Yes")
            console.print(f"  • Type: {endpoint['authentication']['type']}")
        else:
            console.print("  • Required: No")
        
        console.print("\n[bold]Parameters:[/]")
        for param in endpoint['parameters']:
            console.print(f"  • {param['name']} ({param['type']})")
            if param['description']:
                console.print(f"    Description: {param['description']}")

def display_graphql_analysis(results: Dict) -> None:
    """Display GraphQL analysis results."""
    console.print("\n[bold cyan]GraphQL Analysis Results[/]")
    console.print("=" * 50)
    
    if not results['endpoint']:
        console.print("[yellow]No GraphQL endpoint found[/]")
        return
    
    console.print(f"\n[bold yellow]Endpoint: {results['endpoint']}[/]")
    console.print("-" * 30)
    
    console.print(f"Introspection Enabled: {'[green]Yes[/]' if results['introspection_enabled'] else '[red]No[/]'}")
    
    if results['security_issues']:
        console.print("\n[bold red]Security Issues:[/]")
        for issue in results['security_issues']:
            console.print(f"  • {issue}")
    
    if results['introspection_enabled'] and 'schema' in results:
        console.print("\n[bold yellow]Schema Types:[/]")
        for type_info in results['schema'].get('data', {}).get('__schema', {}).get('types', []):
            console.print(f"  • {type_info.get('name', '')}")

def display_websocket_security(results: Dict) -> None:
    """Display WebSocket security analysis results."""
    console.print("\n[bold cyan]WebSocket Security Analysis Results[/]")
    console.print("=" * 50)
    
    if not results['endpoint']:
        console.print("[yellow]No WebSocket endpoint found[/]")
        return
    
    console.print(f"\n[bold yellow]Endpoint: {results['endpoint']}[/]")
    console.print("-" * 30)
    
    if results['security_issues']:
        console.print("\n[bold red]Security Issues:[/]")
        for issue in results['security_issues']:
            console.print(f"  • {issue}")
    
    if results['recommendations']:
        console.print("\n[bold yellow]Recommendations:[/]")
        for rec in results['recommendations']:
            console.print(f"  • {rec}")

def display_content_analysis(results: Dict) -> None:
    """Display content analysis results."""
    console.print("\n[bold cyan]Content Analysis Results[/]")
    console.print("=" * 50)
    
    # Title
    if results['title']:
        console.print(f"\n[bold yellow]Title:[/] {results['title']}")
    
    # Meta Tags
    console.print("\n[bold yellow]Meta Tags:[/]")
    console.print("-" * 30)
    for tag in results['meta_tags']:
        if tag['name'] or tag['property']:
            name = tag['name'] or tag['property']
            console.print(f"  • {name}: {tag['content']}")
    
    # Links
    console.print("\n[bold yellow]Links:[/]")
    console.print("-" * 30)
    for link in results['links']:
        console.print(f"  • {link['text']} -> {link['url']}")
    
    # Forms
    console.print("\n[bold yellow]Forms:[/]")
    console.print("-" * 30)
    for form in results['forms']:
        console.print(f"  • Action: {form['action']}")
        console.print(f"    Method: {form['method']}")
        console.print("    Inputs:")
        for input_field in form['inputs']:
            console.print(f"      - {input_field['name']} ({input_field['type']})")
    
    # Scripts
    console.print("\n[bold yellow]Scripts:[/]")
    console.print("-" * 30)
    for script in results['scripts']:
        if script['src']:
            console.print(f"  • External: {script['src']}")
        else:
            console.print("  • Inline script")
    
    # Images
    console.print("\n[bold yellow]Images:[/]")
    console.print("-" * 30)
    for img in results['images']:
        console.print(f"  • {img['src']}")
        if img['alt']:
            console.print(f"    Alt: {img['alt']}")
    
    # Text Content
    console.print("\n[bold yellow]Text Content:[/]")
    console.print("-" * 30)
    console.print(f"Word Count: {results['text_content']['word_count']}")
    console.print(f"Line Count: {results['text_content']['line_count']}")

def display_technologies(technologies: List[str]) -> None:
    """Display detected technologies."""
    console.print("\n[bold cyan]Detected Technologies[/]")
    console.print("=" * 50)
    
    if not technologies:
        console.print("[yellow]No technologies detected[/]")
        return
    
    # Group technologies by category
    categories = {
        'Web Server': ['Apache', 'Nginx', 'IIS'],
        'Programming Language': ['PHP', 'ASP.NET', 'Python'],
        'Frontend Framework': ['jQuery', 'React', 'Angular', 'Vue.js'],
        'CMS': ['WordPress', 'Drupal', 'Joomla']
    }
    
    for category, tech_list in categories.items():
        matching_techs = [tech for tech in technologies if tech in tech_list]
        if matching_techs:
            console.print(f"\n[bold yellow]{category}:[/]")
            for tech in matching_techs:
                console.print(f"  • {tech}")
    
    # Display other technologies
    other_techs = [tech for tech in technologies if not any(tech in tech_list for tech_list in categories.values())]
    if other_techs:
        console.print("\n[bold yellow]Other Technologies:[/]")
        for tech in other_techs:
            console.print(f"  • {tech}")

def display_security_issues(issues: List[Dict]) -> None:
    """Display security issues."""
    console.print("\n[bold cyan]Security Issues[/]")
    console.print("=" * 50)
    
    if not issues:
        console.print("[green]No security issues found[/]")
        return
    
    # Group issues by severity
    severity_groups = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
    
    for issue in issues:
        severity_groups[issue['severity']].append(issue)
    
    # Display issues by severity
    for severity, issues_list in severity_groups.items():
        if issues_list:
            severity_color = {
                'critical': 'red',
                'high': 'red',
                'medium': 'yellow',
                'low': 'blue',
                'info': 'cyan'
            }.get(severity, 'white')
            
            console.print(f"\n[bold {severity_color}]{severity.upper()} Issues:[/]")
            for issue in issues_list:
                console.print(f"  • {issue['type']}")
                console.print(f"    Description: {issue['description']}")
                console.print(f"    Recommendation: {issue['recommendation']}")

def main() -> None:
    """Main entry point for the application."""
    asyncio.run(async_main())

if __name__ == "__main__":
    main() 