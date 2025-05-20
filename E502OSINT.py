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

# Import new modules from core package
from core.network_analysis import NetworkAnalyzer
from core.web_recon import WebAnalyzer
from core.ssl_analyzer import SSLAnalyzer
from core.privacy_manager import PrivacyManager
from core.vulnerability_scanner import VulnerabilityScanner
from core.image_intel import ImageIntelligence

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

# Initialize analyzers
network_analyzer = NetworkAnalyzer()
web_analyzer = WebAnalyzer()
ssl_analyzer = SSLAnalyzer()
privacy_manager = PrivacyManager()
vuln_scanner = VulnerabilityScanner()
discord_manager = DiscordWebhookManager()
image_intelligence = ImageIntelligence()

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
            CURRENT_TASK = asyncio.create_task(async_handle_network_scan(args[0]))
            await CURRENT_TASK
        elif cmd == 'arp':
            if not args:
                console.print("[red]Please specify a network interface (e.g., eth0)[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_network_scan(args[0]))
            await CURRENT_TASK
        elif cmd == 'fingerprint':
            if not args:
                console.print("[red]Please specify a target[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_network_scan(args[0]))
            await CURRENT_TASK
        elif cmd == 'web':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_web_analysis(args[0]))
            await CURRENT_TASK
        elif cmd == 'headers':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_web_analysis(args[0]))
            await CURRENT_TASK
        elif cmd == 'waf':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_web_analysis(args[0]))
            await CURRENT_TASK
        elif cmd == 'cookies':
            if not args:
                console.print("[red]Please specify a URL[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_web_analysis(args[0]))
            await CURRENT_TASK
        elif cmd == 'ssl':
            if not args:
                console.print("[red]Please specify a hostname[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_ssl_analysis(args[0]))
            await CURRENT_TASK
        elif cmd == 'cert':
            if not args:
                console.print("[red]Please specify a hostname[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_ssl_analysis(args[0]))
            await CURRENT_TASK
        elif cmd == 'ciphers':
            if not args:
                console.print("[red]Please specify a hostname[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_ssl_analysis(args[0]))
            await CURRENT_TASK
        elif cmd == 'hsts':
            if not args:
                console.print("[red]Please specify a hostname[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_ssl_analysis(args[0]))
            await CURRENT_TASK
        elif cmd == 'vuln':
            if not args:
                console.print("[red]Please specify a target[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_vuln_scan(args[0]))
            await CURRENT_TASK
        elif cmd == 'ports':
            if not args:
                console.print("[red]Please specify a target[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_vuln_scan(args[0]))
            await CURRENT_TASK
        elif cmd == 'services':
            if not args:
                console.print("[red]Please specify a target[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_vuln_scan(args[0]))
            await CURRENT_TASK
        elif cmd == 'creds':
            if not args:
                console.print("[red]Please specify a target[/]")
                return
            SCAN_STATUS = "Scanning"
            CURRENT_TASK = asyncio.create_task(async_handle_vuln_scan(args[0]))
            await CURRENT_TASK
        elif cmd == 'image':
            if not args:
                console.print("[red]Please specify an image file[/]")
                return
            SCAN_STATUS = "Scanning"
            image_path = args[0]
            if not os.path.exists(image_path):
                console.print(f"[red]Image file not found: {image_path}[/]")
                return
            CURRENT_TASK = asyncio.create_task(run_in_thread(image_intelligence.analyze_image, image_path))
            analysis = await CURRENT_TASK
            image_intelligence.display_image_analysis(analysis)
        elif cmd == 'exif':
            if not args:
                console.print("[red]Please specify an image file[/]")
                return
            SCAN_STATUS = "Scanning"
            image_path = args[0]
            if not os.path.exists(image_path):
                console.print(f"[red]Image file not found: {image_path}[/]")
                return
            CURRENT_TASK = asyncio.create_task(run_in_thread(image_intelligence._extract_exif, image_path))
            exif_data = await CURRENT_TASK
            table = Table(title="EXIF Data")
            table.add_column("Tag", style="cyan")
            table.add_column("Value", style="green")
            for tag, value in exif_data.items():
                table.add_row(tag, str(value))
            console.print(table)
        elif cmd == 'geo':
            if not args:
                console.print("[red]Please specify an image file[/]")
                return
            SCAN_STATUS = "Scanning"
            image_path = args[0]
            if not os.path.exists(image_path):
                console.print(f"[red]Image file not found: {image_path}[/]")
                return
            CURRENT_TASK = asyncio.create_task(run_in_thread(image_intelligence.extract_geo_data, image_path))
            geo_data = await CURRENT_TASK
            if geo_data:
                table = Table(title="Geolocation Data")
                table.add_column("Field", style="cyan")
                table.add_column("Value", style="green")
                for field, value in geo_data.items():
                    table.add_row(field, str(value))
                console.print(table)
            else:
                console.print("[yellow]No geolocation data found in image[/]")
        elif cmd == 'stego':
            if not args:
                console.print("[red]Please specify an image file[/]")
                return
            SCAN_STATUS = "Scanning"
            image_path = args[0]
            if not os.path.exists(image_path):
                console.print(f"[red]Image file not found: {image_path}[/]")
                return
            CURRENT_TASK = asyncio.create_task(run_in_thread(image_intelligence.check_steganography, image_path))
            stego_data = await CURRENT_TASK
            if stego_data:
                table = Table(title="Steganography Analysis")
                table.add_column("Type", style="cyan")
                table.add_column("Result", style="green")
                for stego_type, result in stego_data.items():
                    table.add_row(stego_type, str(result))
                console.print(table)
            else:
                console.print("[yellow]No steganography detected[/]")
        elif cmd == 'hash':
            if not args:
                console.print("[red]Please specify a file to hash[/]")
                return
            SCAN_STATUS = "Scanning"
            file_path = args[0]
            if not os.path.exists(file_path):
                console.print(f"[red]File not found: {file_path}[/]")
                return
            CURRENT_TASK = asyncio.create_task(run_in_thread(lambda: open(file_path, 'rb').read()))
            content = await CURRENT_TASK
            md5_hash = hashlib.md5(content).hexdigest()
            sha1_hash = hashlib.sha1(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
            console.print(f"[green]MD5:[/] {md5_hash}")
            console.print(f"[green]SHA1:[/] {sha1_hash}")
            console.print(f"[green]SHA256:[/] {sha256_hash}")
        elif cmd == 'proxy':
            if len(args) >= 4 and args[0] == 'add':
                name, host, port, proxy_type = args[1:5]
                CURRENT_TASK = asyncio.create_task(async_handle_add_proxy(name, host, int(port), proxy_type))
                await CURRENT_TASK
            elif args and args[0] == 'chain':
                CURRENT_TASK = asyncio.create_task(async_handle_proxy_chain(args[1:]))
                await CURRENT_TASK
            elif args and args[0] == 'status':
                console.print("[yellow]Current proxy status:[/]", "Enabled" if USE_PROXY else "Disabled")
            elif args and args[0] == 'on':
                setup_proxy()
            elif args and args[0] == 'off':
                USE_PROXY = False
                console.print("[green]Proxy disabled[/]")
            else:
                console.print("[yellow]Current proxy status:[/]", "Enabled" if USE_PROXY else "Disabled")
        elif cmd == 'rate':
            if len(args) < 2:
                console.print("[red]Please specify domain and requests per second[/]")
                return
            domain = args[0]
            try:
                rate = float(args[1])
                CURRENT_TASK = asyncio.create_task(async_handle_rate_limit(domain, rate))
                await CURRENT_TASK
            except ValueError:
                console.print("[red]Invalid rate limit value[/]")
        elif cmd == 'rotate':
            CURRENT_TASK = asyncio.create_task(async_handle_rotate_user_agent())
            await CURRENT_TASK
        elif cmd == 'check' and args and args[0] == 'tor':
            CURRENT_TASK = asyncio.create_task(async_handle_check_tor())
            await CURRENT_TASK
        elif cmd == 'discord':
            CURRENT_TASK = asyncio.create_task(async_handle_discord_command(parts))
            await CURRENT_TASK
        elif cmd == 'clear':
            os.system('cls' if os.name == 'nt' else 'clear')
            display_banner()
        elif cmd == 'exit':
            console.print("[bold yellow]Exiting E502 OSINT Terminal...[/]")
            sys.exit(0)
        elif cmd == 'version':
            console.print(f"[bold green]Version:[/] {VERSION}")
            console.print(f"[bold green]Author:[/] {AUTHOR}")
        else:
            console.print("[red]Unknown command. Type 'help' for available commands.[/]")
            
        SCAN_STATUS = "Ready"
        LAST_COMMAND = command
        CURRENT_TASK = None
        
    except asyncio.CancelledError:
        console.print("\n[yellow]Operation cancelled by user.[/]")
        SCAN_STATUS = "Ready"
        CURRENT_TASK = None
    except Exception as e:
        console.print(f"[red]Error processing command: {str(e)}[/]")
        SCAN_STATUS = "Error"
        CURRENT_TASK = None

def show_help() -> None:
    """Display help information."""
    console.print("\n[bold blue]E502 OSINT Terminal Commands[/]")
    
    commands = {
        "Network Analysis": [
            ("network <target>", "Perform network topology mapping"),
            ("arp <interface>", "Perform ARP scan on interface"),
            ("fingerprint <target>", "Perform device fingerprinting")
        ],
        "Web Analysis": [
            ("web <url>", "Analyze website technology stack"),
            ("headers <url>", "Check security headers"),
            ("waf <url>", "Detect web application firewall"),
            ("cookies <url>", "Analyze cookie security")
        ],
        "SSL/TLS Analysis": [
            ("ssl <hostname>", "Analyze SSL/TLS configuration"),
            ("cert <hostname>", "Check SSL certificate"),
            ("ciphers <hostname>", "Analyze cipher suites"),
            ("hsts <hostname>", "Check HSTS configuration")
        ],
        "Vulnerability Assessment": [
            ("vuln <target>", "Perform vulnerability scan"),
            ("ports <target>", "Scan for open ports"),
            ("services <target>", "Enumerate services"),
            ("creds <target>", "Check default credentials")
        ],
        "Image Intelligence": [
            ("image <path>", "Analyze image metadata and content"),
            ("exif <path>", "Extract EXIF data"),
            ("geo <path>", "Extract geolocation data"),
            ("stego <path>", "Check for hidden content"),
            ("hash <path>", "Generate image hashes")
        ],
        "Privacy Features": [
            ("proxy add <n> <host> <port> <type>", "Add new proxy"),
            ("proxy chain <proxy1> <proxy2> ...", "Create proxy chain"),
            ("proxy status", "Show proxy status"),
            ("rate <domain> <requests/sec>", "Set rate limit"),
            ("rotate", "Rotate user agent"),
            ("check tor", "Check if Tor is running")
        ],
        "Discord Integration": [
            ("discord help", "Show Discord commands"),
            ("discord enable", "Enable Discord integration"),
            ("discord disable", "Disable Discord integration"),
            ("discord set <url>", "Set webhook URL"),
            ("discord save", "Save webhook URL"),
            ("discord test", "Send test message"),
            ("discord status", "Show integration status"),
            ("discord summary", "Send scan summary"),
            ("discord clear", "Clear scan history")
        ],
        "System": [
            ("help", "Show this help message"),
            ("clear", "Clear screen"),
            ("exit", "Exit program"),
            ("version", "Show version information")
        ]
    }
    
    for category, cmds in commands.items():
        console.print(f"\n[bold yellow]{category}[/]")
        for cmd, desc in cmds:
            console.print(f"  [cyan]{cmd}[/] - {desc}")
    
    console.print("\n[bold green]Examples:[/]")
    console.print("  network 192.168.1.0/24")
    console.print("  arp eth0")
    console.print("  fingerprint 192.168.1.1")
    console.print("  web example.com")
    console.print("  headers example.com")
    console.print("  waf example.com")
    console.print("  ssl example.com")
    console.print("  vuln example.com")
    console.print("  ports example.com")
    console.print("  image photo.jpg")
    console.print("  exif photo.jpg")
    console.print("  geo photo.jpg")
    console.print("  stego photo.jpg")
    console.print("  proxy add tor 127.0.0.1 9050 socks5")
    console.print("  rate example.com 10")
    console.print("  rotate")
    console.print("  check tor")
    console.print("  discord enable")

def main() -> None:
    """Main entry point for the application."""
    asyncio.run(async_main())

if __name__ == "__main__":
    main() 