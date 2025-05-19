"""
E502 OSINT Terminal – Advanced Reconnaissance Toolkit
----------------------------------------------------
Author: z3r0s / Error502
Version: 1.0.0
Last Updated: 2024

A comprehensive OSINT tool built for security researchers and penetration testers.
Features include DNS analysis, SSL inspection, port scanning, and Tor integration.

Install: pip install rich art2text requests[socks] dnspython python-whois beautifulsoup4 PySocks cryptography
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
from typing import Optional, Dict, List, Union
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
from art2text import text2art
import threading
import time

# Initialize Rich console
console = Console()

# Global variables
VERSION = "1.0.0"
AUTHOR = "z3r0s / Error502"
USE_PROXY = False
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 9050

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

def display_banner() -> None:
    """Display the E502 banner with version and author information.
    The banner is generated using art2text for a clean, professional look.
    """
    banner = text2art("E502", font="block")
    console.print(Panel(banner, style="bold blue"))
    
    # Display version and author information
    console.print(f"[bold green]Version:[/] {VERSION}")
    console.print(f"[bold green]Author:[/] {AUTHOR}")
    
    # Display a random security tip or quote
    tip_or_quote = random.choice(CYBER_TIPS + HACKER_QUOTES)
    console.print(Panel(tip_or_quote, title="Security Tip", style="bold yellow"))

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
    """Perform comprehensive DNS analysis with extended reconnaissance capabilities.
    
    This function provides detailed DNS record analysis and can perform additional
    reconnaissance on discovered records, including port scanning and service detection.
    
    Args:
        domain (str): Target domain for DNS analysis
    """
    try:
        resolver = dns.resolver.Resolver()
        if USE_PROXY:
            # Use Cloudflare DNS over TCP when proxy is enabled
            resolver.nameservers = ['1.1.1.1']
        
        # Show available record types
        record_types = {
            'A': 'IPv4 address',
            'AAAA': 'IPv6 address',
            'MX': 'Mail exchange',
            'NS': 'Name server',
            'TXT': 'Text record',
            'SOA': 'Start of authority',
            'CNAME': 'Canonical name',
            'PTR': 'Pointer record',
            'SRV': 'Service record',
            'CAA': 'Certificate Authority Authorization',
            'all': 'All record types'
        }
        
        table = Table(title="Available DNS Record Types")
        table.add_column("Type", style="cyan")
        table.add_column("Description", style="green")
        
        for rtype, desc in record_types.items():
            if rtype != 'all':
                table.add_row(rtype, desc)
        
        console.print(table)
        
        # Get record type selection
        record_type = Prompt.ask(
            "Select record type to lookup (or 'all' for all records)",
            choices=list(record_types.keys()),
            default="all"
        )
        
        results = {}
        if record_type == 'all':
            types_to_check = [t for t in record_types.keys() if t != 'all']
        else:
            types_to_check = [record_type]
        
        for rtype in types_to_check:
            try:
                answers = resolver.resolve(domain, rtype)
                results[rtype] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                console.print(f"[bold red]Domain {domain} does not exist.[/]")
                return
            except Exception as e:
                console.print(f"[bold red]Error resolving {rtype} records: {str(e)}[/]")
                continue
        
        # Display results
        table = Table(title=f"DNS Records for {domain}")
        table.add_column("Record Type", style="cyan")
        table.add_column("Value", style="green")
        
        for rtype, values in results.items():
            for value in values:
                table.add_row(rtype, value)
        
        console.print(table)
        
        # Ask if user wants to perform additional reconnaissance
        if results:
            recon = Prompt.ask(
                "Perform additional reconnaissance on discovered records?",
                choices=["y", "n"],
                default="n"
            )
            
            if recon == "y":
                # Collect all IPs for scanning
                ips_to_scan = []
                for rtype, values in results.items():
                    if rtype in ['A', 'AAAA']:
                        ips_to_scan.extend(values)
                
                if ips_to_scan:
                    scan_ips = Prompt.ask(
                        "Scan discovered IP addresses?",
                        choices=["y", "n"],
                        default="n"
                    )
                    
                    if scan_ips == "y":
                        for ip in ips_to_scan:
                            console.print(f"\n[bold blue]Scanning IP: {ip}[/]")
                            scan_target(ip)
                
                # Check for web servers
                web_servers = []
                for rtype, values in results.items():
                    if rtype in ['A', 'AAAA', 'CNAME']:
                        web_servers.extend(values)
                
                if web_servers:
                    check_web = Prompt.ask(
                        "Check web server headers and SSL?",
                        choices=["y", "n"],
                        default="n"
                    )
                    
                    if check_web == "y":
                        for server in web_servers:
                            console.print(f"\n[bold blue]Checking web server: {server}[/]")
                            check_headers(server)
                            check_ssl(server)
                
                # Check for mail servers
                if 'MX' in results:
                    check_mx = Prompt.ask(
                        "Check mail server configuration?",
                        choices=["y", "n"],
                        default="n"
                    )
                    
                    if check_mx == "y":
                        for mx in results['MX']:
                            console.print(f"\n[bold blue]Checking mail server: {mx}[/]")
                            check_headers(mx)
                            check_ssl(mx)
                
                # Save results
                save_results = Prompt.ask(
                    "Save DNS lookup results to file?",
                    choices=["y", "n"],
                    default="n"
                )
                
                if save_results == "y":
                    filename = f"dns_{domain}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
                    try:
                        with open(filename, "w") as f:
                            f.write(f"DNS Lookup Results for {domain}\n")
                            f.write(f"Lookup time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                            for rtype, values in results.items():
                                f.write(f"{rtype} Records:\n")
                                for value in values:
                                    f.write(f"  {value}\n")
                                f.write("\n")
                        console.print(f"[bold green]Results saved to {filename}[/]")
                    except Exception as e:
                        console.print(f"[bold red]Error saving results: {str(e)}[/]")
    
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

def scan_target(target: str) -> None:
    """Perform advanced port scanning with multiple scanning options.
    
    Features:
    - Common port scanning
    - Custom port range selection
    - Full port range scanning
    - Concurrent scanning capability
    - Service detection
    - Results export
    
    Args:
        target (str): Target IP or domain to scan
    """
    # Common ports with their standard services
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
        5432: "PostgreSQL",
        1433: "MSSQL",
        1521: "Oracle",
        6379: "Redis",
        9200: "Elasticsearch",
        27015: "Steam",
        25565: "Minecraft"
    }
    
    # Ask for scan type
    scan_type = Prompt.ask(
        "Choose scan type",
        choices=["common", "custom", "all"],
        default="common"
    )
    
    ports_to_scan = []
    
    if scan_type == "common":
        ports_to_scan = list(common_ports.keys())
    elif scan_type == "custom":
        # Show available ports
        table = Table(title="Available Ports")
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="green")
        table.add_column("Description", style="yellow")
        
        for port, service in common_ports.items():
            table.add_row(str(port), service, f"Common {service} port")
        
        console.print(table)
        
        # Get port range
        port_input = Prompt.ask(
            "Enter ports to scan (comma-separated or range, e.g., '80,443' or '1-1000')"
        )
        
        if "-" in port_input:
            # Handle range
            start, end = map(int, port_input.split("-"))
            ports_to_scan = list(range(start, end + 1))
        else:
            # Handle comma-separated
            ports_to_scan = [int(p.strip()) for p in port_input.split(",")]
    else:  # all
        ports_to_scan = list(range(1, 65536))
    
    # Ask for timeout
    timeout = Prompt.ask(
        "Enter timeout in seconds (1-10)",
        default="1",
        choices=[str(i) for i in range(1, 11)]
    )
    timeout = float(timeout)
    
    # Ask for concurrent scanning
    concurrent = Prompt.ask(
        "Enable concurrent scanning? (faster but more resource-intensive)",
        choices=["y", "n"],
        default="n"
    )
    
    table = Table(title=f"Port Scan Results for {target}")
    table.add_column("Port", style="cyan")
    table.add_column("Service", style="green")
    table.add_column("Status", style="yellow")
    
    if concurrent == "y":
        # Concurrent scanning
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = common_ports.get(port, socket.getservbyport(port))
                    return (port, service, "Open")
                sock.close()
            except:
                pass
            return None
        
        # Create thread pool
        threads = []
        results = []
        
        for port in ports_to_scan:
            thread = threading.Thread(target=lambda p=port: results.append(scan_port(p)))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Add results to table
        for result in results:
            if result:
                port, service, status = result
                table.add_row(str(port), service, status)
    else:
        # Sequential scanning
        for port in ports_to_scan:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service = common_ports.get(port, socket.getservbyport(port))
                    table.add_row(str(port), service, "Open")
                sock.close()
            except:
                continue
    
    console.print(table)
    
    # Ask if user wants to save results
    save_results = Prompt.ask(
        "Save scan results to file?",
        choices=["y", "n"],
        default="n"
    )
    
    if save_results == "y":
        filename = f"scan_{target}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, "w") as f:
                f.write(f"Scan results for {target}\n")
                f.write(f"Scan time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total ports scanned: {len(ports_to_scan)}\n")
                f.write("\nOpen ports:\n")
                for row in table.rows:
                    f.write(f"{row[0]}: {row[1]} - {row[2]}\n")
            console.print(f"[bold green]Results saved to {filename}[/]")
        except Exception as e:
            console.print(f"[bold red]Error saving results: {str(e)}[/]")

def show_help() -> None:
    """Display help information."""
    table = Table(title="Available Commands")
    table.add_column("Command", style="cyan")
    table.add_column("Description", style="green")
    
    commands = {
        "help": "Display this help message",
        "banner": "Display the E502 banner",
        "whoami": "Display system information",
        "dns <domain>": "Perform DNS lookup",
        "whois <domain/IP>": "Perform WHOIS lookup",
        "reverseip <ip>": "Perform reverse IP lookup",
        "subdomains <domain>": "Find subdomains",
        "leaks <email/domain>": "Check for potential data leaks",
        "github <username/domain>": "Perform GitHub reconnaissance",
        "headers <domain/URL>": "Check HTTP headers",
        "ssl <domain>": "Check SSL certificate",
        "scan <domain/IP>": "Perform port scan",
        "proxy": "Enable/disable Tor proxy",
        "clear": "Clear the screen",
        "exit/quit": "Exit the program"
    }
    
    for cmd, desc in commands.items():
        table.add_row(cmd, desc)
    
    console.print(table)

def main() -> None:
    """Main entry point for the E502 OSINT Terminal.
    
    Handles command processing and execution of various reconnaissance functions.
    Implements a clean, interactive command-line interface with rich formatting.
    """
    display_banner()
    
    while True:
        try:
            command = Prompt.ask("\nE502>")
            
            if not command:
                continue
            
            cmd_parts = command.split()
            cmd = cmd_parts[0].lower()
            
            # Process commands
            if cmd == "exit" or cmd == "quit":
                console.print("[bold red]Goodbye![/]")
                break
            elif cmd == "help":
                show_help()
            elif cmd == "banner":
                display_banner()
            elif cmd == "whoami":
                info = get_system_info()
                table = Table(title="System Information")
                table.add_column("Field", style="cyan")
                table.add_column("Value", style="green")
                for key, value in info.items():
                    table.add_row(key, value)
                console.print(table)
            elif cmd == "dns" and len(cmd_parts) > 1:
                dns_lookup(cmd_parts[1])
            elif cmd == "whois" and len(cmd_parts) > 1:
                whois_lookup(cmd_parts[1])
            elif cmd == "reverseip" and len(cmd_parts) > 1:
                reverse_ip_lookup(cmd_parts[1])
            elif cmd == "subdomains" and len(cmd_parts) > 1:
                find_subdomains(cmd_parts[1])
            elif cmd == "leaks" and len(cmd_parts) > 1:
                check_leaks(cmd_parts[1])
            elif cmd == "github" and len(cmd_parts) > 1:
                github_recon(cmd_parts[1])
            elif cmd == "headers" and len(cmd_parts) > 1:
                check_headers(cmd_parts[1])
            elif cmd == "ssl" and len(cmd_parts) > 1:
                check_ssl(cmd_parts[1])
            elif cmd == "scan" and len(cmd_parts) > 1:
                scan_target(cmd_parts[1])
            elif cmd == "proxy":
                setup_proxy()
            elif cmd == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
                display_banner()
            else:
                console.print("[bold red]Unknown command. Type 'help' for available commands.[/]")
        
        except KeyboardInterrupt:
            console.print("\n[bold red]Use 'exit' or 'quit' to exit the program.[/]")
        except Exception as e:
            console.print(f"[bold red]Error: {str(e)}[/]")

if __name__ == "__main__":
    main() 