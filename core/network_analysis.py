"""
Network Analysis Module for E502 OSINT Terminal
Provides advanced network analysis capabilities including topology mapping,
ARP scanning, MAC address lookup, and device fingerprinting.
"""

import scapy.all as scapy
import nmap
import netifaces
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import socket
import struct
import json
import requests
from datetime import datetime

console = Console()

class NetworkAnalyzer:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.mac_vendors = self._load_mac_vendors()
        
    def _load_mac_vendors(self) -> Dict[str, str]:
        """Load MAC vendor database."""
        try:
            response = requests.get('https://macvendors.co/api/vendors')
            return response.json()
        except:
            return {}

    def get_network_interfaces(self) -> List[Dict[str, str]]:
        """Get all available network interfaces."""
        interfaces = []
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    interfaces.append({
                        'interface': iface,
                        'ip': addr.get('addr', ''),
                        'netmask': addr.get('netmask', ''),
                        'broadcast': addr.get('broadcast', '')
                    })
        return interfaces

    def arp_scan(self, interface: str) -> List[Dict[str, str]]:
        """Perform ARP scan on the specified interface."""
        try:
            # Get network address
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET not in addrs:
                return []

            ip = addrs[netifaces.AF_INET][0]['addr']
            netmask = addrs[netifaces.AF_INET][0]['netmask']
            
            # Calculate network address
            ip_parts = list(map(int, ip.split('.')))
            mask_parts = list(map(int, netmask.split('.')))
            network = '.'.join([str(ip_parts[i] & mask_parts[i]) for i in range(4)])
            
            # Create ARP request packet
            arp = scapy.ARP(pdst=f"{network}/24")
            ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Send packet and capture responses
            result = scapy.srp(packet, timeout=3, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': self.mac_vendors.get(received.hwsrc[:8].upper(), 'Unknown')
                })
            
            return devices
        except Exception as e:
            console.print(f"[red]Error during ARP scan: {str(e)}[/]")
            return []

    def network_topology(self, target: str) -> Dict:
        """Map network topology starting from target."""
        try:
            # Perform initial scan
            self.nm.scan(target, arguments='-sn')
            
            topology = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'devices': []
            }
            
            # Scan each discovered host
            for host in self.nm.all_hosts():
                device_info = {
                    'ip': host,
                    'hostname': self.nm[host].hostname(),
                    'state': self.nm[host].state(),
                    'services': []
                }
                
                # Scan for open ports and services
                self.nm.scan(host, arguments='-sV')
                if host in self.nm.all_hosts():
                    for proto in self.nm[host].all_protocols():
                        ports = self.nm[host][proto].keys()
                        for port in ports:
                            service = self.nm[host][proto][port]
                            device_info['services'].append({
                                'port': port,
                                'name': service.get('name', ''),
                                'product': service.get('product', ''),
                                'version': service.get('version', '')
                            })
                
                topology['devices'].append(device_info)
            
            return topology
        except Exception as e:
            console.print(f"[red]Error during topology mapping: {str(e)}[/]")
            return {}

    def device_fingerprint(self, target: str) -> Dict:
        """Perform detailed device fingerprinting."""
        try:
            fingerprint = {
                'ip': target,
                'timestamp': datetime.now().isoformat(),
                'os_info': {},
                'services': [],
                'vulnerabilities': []
            }
            
            # OS detection
            self.nm.scan(target, arguments='-O')
            if target in self.nm.all_hosts():
                if 'osmatch' in self.nm[target]:
                    fingerprint['os_info'] = {
                        'name': self.nm[target]['osmatch'][0]['name'],
                        'accuracy': self.nm[target]['osmatch'][0]['accuracy']
                    }
            
            # Service detection
            self.nm.scan(target, arguments='-sV --version-intensity 9')
            if target in self.nm.all_hosts():
                for proto in self.nm[target].all_protocols():
                    for port, service in self.nm[target][proto].items():
                        fingerprint['services'].append({
                            'port': port,
                            'protocol': proto,
                            'name': service.get('name', ''),
                            'product': service.get('product', ''),
                            'version': service.get('version', ''),
                            'extrainfo': service.get('extrainfo', '')
                        })
            
            # Basic vulnerability check
            self.nm.scan(target, arguments='-sV --script vuln')
            if target in self.nm.all_hosts():
                for proto in self.nm[target].all_protocols():
                    for port, service in self.nm[target][proto].items():
                        if 'script' in service:
                            fingerprint['vulnerabilities'].append({
                                'port': port,
                                'protocol': proto,
                                'details': service['script']
                            })
            
            return fingerprint
        except Exception as e:
            console.print(f"[red]Error during device fingerprinting: {str(e)}[/]")
            return {}

    def display_network_info(self, info: Dict) -> None:
        """Display network information in a formatted table."""
        table = Table(title="Network Analysis Results")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in info.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value, indent=2)
            table.add_row(str(key), str(value))
        
        console.print(table) 