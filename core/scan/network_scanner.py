"""
Network Analysis Module for E502 OSINT Terminal
Provides network topology mapping, device fingerprinting, and service enumeration.
"""

import socket
import dns.resolver
import nmap
import platform
import subprocess
import json
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.table import Table
from datetime import datetime
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import re
import ssl
import quic
import http3
import asyncio
import struct
import ipaddress
from scapy.all import *
import requests
import time
import logging
from functools import wraps
import signal
from contextlib import contextmanager

logger = logging.getLogger("E502OSINT.NetworkAnalyzer")
console = Console()

def timeout_handler(signum, frame):
    raise TimeoutError("Operation timed out")

@contextmanager
def timeout(seconds):
    """Context manager for timeout handling."""
    if platform.system() != 'Windows':
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(seconds)
    try:
        yield
    finally:
        if platform.system() != 'Windows':
            signal.alarm(0)

def handle_timeout(func):
    """Decorator for handling timeouts."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        timeout_seconds = kwargs.pop('timeout', 30)
        try:
            with timeout(timeout_seconds):
                return func(*args, **kwargs)
        except TimeoutError:
            logger.error(f"Operation timed out after {timeout_seconds} seconds")
            return None
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {str(e)}")
            return None
    return wrapper

class NetworkAnalyzer:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.session = requests.Session()
        self.session.verify = False
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080]
        self.os_fingerprints = {
            'linux': ['Linux', 'Ubuntu', 'Debian', 'CentOS', 'Red Hat'],
            'windows': ['Windows', 'Microsoft'],
            'macos': ['MacOS', 'Darwin'],
            'ios': ['iOS', 'iPhone', 'iPad'],
            'android': ['Android']
        }
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        self.quic_client = None
        self.http3_client = None
        self.timeout = 30
        self.retry_count = 3
        self.retry_delay = 1

    @handle_timeout
    def analyze_network(self, target: str) -> Dict:
        """Perform comprehensive network analysis."""
        try:
            logger.info(f"Starting network analysis for {target}")
            
            analysis_results = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'ipv4_info': self._analyze_ipv4(target),
                'ipv6_info': self._analyze_ipv6(target),
                'network_topology': self._map_network_topology(target),
                'device_fingerprint': self._fingerprint_device(target),
                'services': self._enumerate_services(target),
                'traffic_patterns': self._analyze_traffic_patterns(target),
                'modern_protocols': self._check_modern_protocols(target)
            }
            
            logger.info(f"Network analysis completed for {target}")
            return analysis_results
        except Exception as e:
            logger.error(f"Error during network analysis: {str(e)}")
            return {}

    @handle_timeout
    def _analyze_ipv4(self, target: str) -> Dict:
        """Analyze IPv4 information."""
        try:
            ip_info = {}
            ip = socket.gethostbyname(target)
            ip_info['address'] = ip
            
            # Get reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                ip_info['hostname'] = hostname
            except:
                ip_info['hostname'] = None
            
            # Get ASN information
            try:
                import whois
                w = whois.whois(ip)
                ip_info['asn'] = w.asn
                ip_info['org'] = w.org
            except:
                ip_info['asn'] = None
                ip_info['org'] = None
            
            return ip_info
        except Exception as e:
            logger.error(f"Error analyzing IPv4: {str(e)}")
            return {}

    @handle_timeout
    def _analyze_ipv6(self, target: str) -> Dict:
        """Analyze IPv6 information."""
        try:
            ipv6_info = {}
            try:
                ipv6 = socket.getaddrinfo(target, None, socket.AF_INET6)[0][4][0]
                ipv6_info['address'] = ipv6
                
                # Get reverse DNS
                try:
                    hostname = socket.gethostbyaddr(ipv6)[0]
                    ipv6_info['hostname'] = hostname
                except:
                    ipv6_info['hostname'] = None
            except:
                ipv6_info['address'] = None
                ipv6_info['hostname'] = None
            
            return ipv6_info
        except Exception as e:
            logger.error(f"Error analyzing IPv6: {str(e)}")
            return {}

    @handle_timeout
    def _map_network_topology(self, target: str) -> Dict:
        """Map network topology."""
        try:
            topology = {
                'target': target,
                'devices': [],
                'routes': self._get_routing_paths(target)
            }
            
            # Scan network for devices
            network = self._get_network_range(target)
            if network:
                devices = self._scan_network(network)
                topology['devices'] = devices
            
            return topology
        except Exception as e:
            logger.error(f"Error mapping network topology: {str(e)}")
            return {}

    @handle_timeout
    def _fingerprint_device(self, target: str) -> Dict:
        """Fingerprint target device."""
        try:
            fingerprint = {
                'os': self._detect_os(target),
                'services': self._enumerate_services(target),
                'banners': self._get_banner_info(target)
            }
            return fingerprint
        except Exception as e:
            logger.error(f"Error fingerprinting device: {str(e)}")
            return {}

    @handle_timeout
    def _enumerate_services(self, target: str) -> List[Dict]:
        """Enumerate services on target."""
        try:
            services = []
            self.nm.scan(target, arguments='-sV -sC')
            
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        services.append({
                            'port': port,
                            'protocol': proto,
                            'name': service.get('name', 'unknown'),
                            'product': service.get('product', 'unknown'),
                            'version': service.get('version', 'unknown'),
                            'state': service.get('state', 'unknown')
                        })
            
            return services
        except Exception as e:
            logger.error(f"Error enumerating services: {str(e)}")
            return []

    @handle_timeout
    def _analyze_traffic_patterns(self, target: str) -> Dict:
        """Analyze network traffic patterns."""
        try:
            patterns = {
                'protocols': {},
                'ports': {},
                'packet_sizes': [],
                'intervals': []
            }
            
            # Capture traffic for analysis
            with timeout(self.timeout):
                packets = sniff(filter=f"host {target}", count=100)
                
                for packet in packets:
                    # Protocol analysis
                    if IP in packet:
                        proto = packet[IP].proto
                        patterns['protocols'][proto] = patterns['protocols'].get(proto, 0) + 1
                    
                    # Port analysis
                    if TCP in packet:
                        port = packet[TCP].dport
                        patterns['ports'][port] = patterns['ports'].get(port, 0) + 1
                    
                    # Packet size analysis
                    patterns['packet_sizes'].append(len(packet))
                    
                    # Interval analysis
                    if hasattr(packet, 'time'):
                        patterns['intervals'].append(packet.time)
            
            return patterns
        except Exception as e:
            logger.error(f"Error analyzing traffic patterns: {str(e)}")
            return {}

    @handle_timeout
    def _check_modern_protocols(self, target: str) -> Dict:
        """Check support for modern protocols."""
        try:
            protocols = {
                'quic': self._check_quic(target),
                'http3': self._check_http3(target),
                'http2': self._check_http2(target),
                'tls13': self._check_tls13(target)
            }
            return protocols
        except Exception as e:
            logger.error(f"Error checking modern protocols: {str(e)}")
            return {}

    def _get_network_range(self, target: str) -> Optional[str]:
        """Get network range for target."""
        try:
            ip = socket.gethostbyname(target)
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(network)
        except:
            return None

    def _scan_network(self, network: str) -> List[Dict]:
        """Scan network for devices."""
        try:
            devices = []
            self.nm.scan(hosts=network, arguments='-sn')
            
            for host in self.nm.all_hosts():
                device = {
                    'ip': host,
                    'hostname': self._get_hostname(host),
                    'status': 'up'
                }
                devices.append(device)
            
            return devices
        except Exception as e:
            logger.error(f"Error scanning network: {str(e)}")
            return []

    def _get_hostname(self, ip: str) -> Optional[str]:
        """Get hostname for IP address."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None

    def _detect_os(self, target: str) -> Dict:
        """Detect operating system."""
        try:
            os_info = {}
            self.nm.scan(target, arguments='-O')
            
            for host in self.nm.all_hosts():
                if 'osmatch' in self.nm[host]:
                    os_info['name'] = self.nm[host]['osmatch'][0]['name']
                    os_info['accuracy'] = self.nm[host]['osmatch'][0]['accuracy']
            
            return os_info
        except Exception as e:
            logger.error(f"Error detecting OS: {str(e)}")
            return {}

    def _check_quic(self, target: str) -> Dict:
        """Check QUIC support."""
        try:
            if not self.quic_client:
                self.quic_client = quic.Client()
            
            result = self.quic_client.connect(target, 443)
            return {
                'supported': result is not None,
                'version': result.version if result else None
            }
        except:
            return {'supported': False, 'version': None}

    def _check_http3(self, target: str) -> Dict:
        """Check HTTP/3 support."""
        try:
            if not self.http3_client:
                self.http3_client = http3.Client()
            
            result = self.http3_client.get(f"https://{target}")
            return {
                'supported': result.status_code == 200,
                'version': '3.0'
            }
        except:
            return {'supported': False, 'version': None}

    def _check_http2(self, target: str) -> Dict:
        """Check HTTP/2 support."""
        try:
            response = requests.get(f"https://{target}", timeout=self.timeout)
            return {
                'supported': response.raw.version == 20,
                'version': '2.0'
            }
        except:
            return {'supported': False, 'version': None}

    def _check_tls13(self, target: str) -> Dict:
        """Check TLS 1.3 support."""
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            with socket.create_connection((target, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    return {
                        'supported': True,
                        'version': ssock.version()
                    }
        except:
            return {'supported': False, 'version': None}

    def _get_routing_paths(self, target: str) -> List[Dict]:
        """Get routing paths to target."""
        try:
            paths = []
            process = subprocess.Popen(['traceroute', target], stdout=subprocess.PIPE)
            output = process.communicate()[0].decode()
            
            for line in output.split('\n'):
                if line.strip():
                    hop = {
                        'ttl': line.split()[0],
                        'ip': line.split()[1],
                        'hostname': line.split()[2] if len(line.split()) > 2 else None,
                        'latency': line.split()[3] if len(line.split()) > 3 else None
                    }
                    paths.append(hop)
            
            return paths
        except:
            return []

    def _get_banner_info(self, target: str) -> Dict:
        """Get banner information from services."""
        try:
            banners = {}
            self.nm.scan(target, arguments='-sV -sC')
            
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        if 'script' in service:
                            banners[f"{proto}/{port}"] = service['script']
            
            return banners
        except:
            return {}

# Create global instance
network_analyzer = NetworkAnalyzer() 