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
from typing import Dict, List, Optional
from rich.console import Console
from rich.table import Table
from datetime import datetime
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import re

console = Console()

class NetworkAnalyzer:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.session = aiohttp.ClientSession()
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        
    async def analyze_network(self, target: str) -> Dict:
        """Perform comprehensive network analysis."""
        try:
            console.print(f"[bold green]Starting network analysis for {target}...[/]")
            
            # Resolve domain to IP if needed
            ip = await self._resolve_domain(target)
            if not ip:
                console.print(f"[red]Could not resolve {target} to an IP address[/]")
                return {}
            
            # Run analysis tasks concurrently
            tasks = [
                self._get_network_topology(ip),
                self._fingerprint_device(ip),
                self._scan_ports(ip),
                self._enumerate_services(ip)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Combine results
            analysis = {
                'target': target,
                'ip': ip,
                'timestamp': datetime.now().isoformat(),
                'topology': results[0] if not isinstance(results[0], Exception) else {},
                'fingerprint': results[1] if not isinstance(results[1], Exception) else {},
                'ports': results[2] if not isinstance(results[2], Exception) else [],
                'services': results[3] if not isinstance(results[3], Exception) else []
            }
            
            return analysis
            
        except Exception as e:
            console.print(f"[red]Error during network analysis: {str(e)}[/]")
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
            
    async def _get_network_topology(self, ip: str) -> Dict:
        """Get network topology information."""
        try:
            # Get network range
            network = '.'.join(ip.split('.')[:-1]) + '.0/24'
            
            # Scan network
            self.nm.scan(hosts=network, arguments='-sn')
            
            devices = []
            for host in self.nm.all_hosts():
                if host != ip:  # Exclude target
                    devices.append({
                        'ip': host,
                        'hostname': self._get_hostname(host),
                        'status': self.nm[host].state()
                    })
            
            return {
                'target': ip,
                'timestamp': datetime.now().isoformat(),
                'network': network,
                'devices': devices
            }
            
        except Exception as e:
            console.print(f"[red]Error getting network topology: {str(e)}[/]")
            return {}
            
    def _get_hostname(self, ip: str) -> Optional[str]:
        """Get hostname for IP address."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
            
    async def _fingerprint_device(self, ip: str) -> Dict:
        """Perform device fingerprinting."""
        try:
            # OS detection
            self.nm.scan(ip, arguments='-O')
            os_info = {}
            if 'osmatch' in self.nm[ip]:
                os_info = {
                    'name': self.nm[ip]['osmatch'][0]['name'],
                    'accuracy': self.nm[ip]['osmatch'][0]['accuracy']
                }
            
            # Service detection
            self.nm.scan(ip, arguments='-sV')
            services = []
            if 'tcp' in self.nm[ip]:
                for port, data in self.nm[ip]['tcp'].items():
                    if data['state'] == 'open':
                        services.append({
                            'port': port,
                            'name': data['name'],
                            'product': data.get('product', ''),
                            'version': data.get('version', '')
                        })
            
            return {
                'ip': ip,
                'timestamp': datetime.now().isoformat(),
                'os_info': os_info,
                'services': services
            }
            
        except Exception as e:
            console.print(f"[red]Error fingerprinting device: {str(e)}[/]")
            return {}
            
    async def _scan_ports(self, ip: str) -> List[Dict]:
        """Scan for open ports."""
        try:
            # Scan common ports
            self.nm.scan(ip, arguments='-F')
            
            ports = []
            if 'tcp' in self.nm[ip]:
                for port, data in self.nm[ip]['tcp'].items():
                    if data['state'] == 'open':
                        ports.append({
                            'port': port,
                            'state': data['state'],
                            'service': data.get('name', 'unknown')
                        })
            
            return ports
            
        except Exception as e:
            console.print(f"[red]Error scanning ports: {str(e)}[/]")
            return []
            
    async def _enumerate_services(self, ip: str) -> List[Dict]:
        """Enumerate services on open ports."""
        try:
            # Detailed service scan
            self.nm.scan(ip, arguments='-sV --version-intensity 5')
            
            services = []
            if 'tcp' in self.nm[ip]:
                for port, data in self.nm[ip]['tcp'].items():
                    if data['state'] == 'open':
                        service = {
                            'port': port,
                            'name': data['name'],
                            'state': data['state']
                        }
                        
                        if 'product' in data:
                            service['product'] = data['product']
                        if 'version' in data:
                            service['version'] = data['version']
                        if 'extrainfo' in data:
                            service['extrainfo'] = data['extrainfo']
                            
                        services.append(service)
            
            return services
            
        except Exception as e:
            console.print(f"[red]Error enumerating services: {str(e)}[/]")
            return []
            
    def display_network_info(self, analysis: Dict) -> None:
        """Display network analysis results."""
        if not analysis:
            console.print("[red]No network analysis results available.[/]")
            return
            
        # Create main table
        table = Table(title="Network Analysis Results")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        # Add basic info
        table.add_row("Target", analysis.get('target', 'Unknown'))
        table.add_row("IP", analysis.get('ip', 'Unknown'))
        table.add_row("Timestamp", analysis.get('timestamp', 'Unknown'))
        
        # Add topology info
        topology = analysis.get('topology', {})
        if topology:
            table.add_row("Network", topology.get('network', 'Unknown'))
            devices = topology.get('devices', [])
            table.add_row("Devices Found", str(len(devices)))
            
            if devices:
                devices_table = Table(title="Discovered Devices")
                devices_table.add_column("IP", style="cyan")
                devices_table.add_column("Hostname", style="green")
                devices_table.add_column("Status", style="yellow")
                
                for device in devices:
                    devices_table.add_row(
                        device.get('ip', 'Unknown'),
                        device.get('hostname', 'Unknown'),
                        device.get('status', 'Unknown')
                    )
                console.print(devices_table)
        
        # Add fingerprint info
        fingerprint = analysis.get('fingerprint', {})
        if fingerprint:
            os_info = fingerprint.get('os_info', {})
            if os_info:
                table.add_row("OS", f"{os_info.get('name', 'Unknown')} ({os_info.get('accuracy', '0')}%)")
            
            services = fingerprint.get('services', [])
            if services:
                services_table = Table(title="Detected Services")
                services_table.add_column("Port", style="cyan")
                services_table.add_column("Service", style="green")
                services_table.add_column("Version", style="yellow")
                
                for service in services:
                    services_table.add_row(
                        str(service.get('port', '')),
                        service.get('name', 'Unknown'),
                        f"{service.get('product', '')} {service.get('version', '')}"
                    )
                console.print(services_table)
        
        # Display main table
        console.print(table) 