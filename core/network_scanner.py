"""
Network Scanner Module for E502 OSINT Terminal
Provides ARP scanning, device fingerprinting, and port scanning capabilities.
"""

import socket
import struct
import binascii
import platform
import subprocess
import re
from typing import Dict, List, Optional, Tuple
import asyncio
import aiohttp
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import nmap
import netifaces
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, TCP

console = Console()

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.known_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Proxy"
        }

    async def arp_scan(self, interface: str) -> List[Dict]:
        """Perform ARP scan on specified interface."""
        try:
            # Get network address
            network = self._get_network_address(interface)
            if not network:
                console.print(f"[red]Could not determine network for interface {interface}[/]")
                return []

            console.print(f"[bold green]Starting ARP scan on {network}...[/]")
            
            # Create ARP request packet
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp

            # Send packet and capture responses
            result = scapy.srp(packet, timeout=3, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                device = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'vendor': self._get_vendor(received.hwsrc)
                }
                devices.append(device)

            return devices

        except Exception as e:
            console.print(f"[red]Error during ARP scan: {str(e)}[/]")
            return []

    def _get_network_address(self, interface: str) -> Optional[str]:
        """Get network address for specified interface."""
        try:
            if platform.system() == "Windows":
                # Windows implementation
                output = subprocess.check_output("ipconfig", shell=True).decode()
                for line in output.split('\n'):
                    if interface in line:
                        ip_match = re.search(r'IPv4 Address.*?:\s*(\d+\.\d+\.\d+\.\d+)', output)
                        if ip_match:
                            ip = ip_match.group(1)
                            return f"{ip.rsplit('.', 1)[0]}.0/24"
            else:
                # Linux/Unix implementation
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    ip = addrs[netifaces.AF_INET][0]['addr']
                    netmask = addrs[netifaces.AF_INET][0]['netmask']
                    return f"{ip}/{self._netmask_to_cidr(netmask)}"
        except Exception as e:
            console.print(f"[red]Error getting network address: {str(e)}[/]")
        return None

    def _netmask_to_cidr(self, netmask: str) -> int:
        """Convert netmask to CIDR notation."""
        return sum([bin(int(x)).count('1') for x in netmask.split('.')])

    def _get_vendor(self, mac: str) -> str:
        """Get vendor information from MAC address."""
        try:
            # Remove separators and convert to uppercase
            mac = mac.replace(':', '').replace('-', '').upper()
            # Get first 6 characters (OUI)
            oui = mac[:6]
            
            # Query MAC vendor database
            url = f"https://api.macvendors.com/{oui}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return response.text
        except:
            pass
        return "Unknown"

    async def device_fingerprint(self, target: str) -> Dict:
        """Perform device fingerprinting on target."""
        try:
            console.print(f"[bold green]Fingerprinting {target}...[/]")
            
            # Initialize results
            fingerprint = {
                'os': 'Unknown',
                'services': [],
                'open_ports': [],
                'device_type': 'Unknown'
            }

            # OS detection
            self.nm.scan(target, arguments='-O')
            if target in self.nm.all_hosts():
                if 'osmatch' in self.nm[target]:
                    fingerprint['os'] = self.nm[target]['osmatch'][0]['name']

            # Port scan
            self.nm.scan(target, arguments='-sS -sV -F')
            if target in self.nm.all_hosts():
                for proto in self.nm[target].all_protocols():
                    ports = self.nm[target][proto].keys()
                    for port in ports:
                        service = self.nm[target][proto][port]
                        fingerprint['open_ports'].append({
                            'port': port,
                            'service': service.get('name', 'unknown'),
                            'version': service.get('version', 'unknown')
                        })

            # Device type detection
            fingerprint['device_type'] = self._detect_device_type(fingerprint)

            return fingerprint

        except Exception as e:
            console.print(f"[red]Error during device fingerprinting: {str(e)}[/]")
            return {}

    def _detect_device_type(self, fingerprint: Dict) -> str:
        """Detect device type based on fingerprint."""
        # Check for common device signatures
        if any(port['service'] == 'http' for port in fingerprint['open_ports']):
            return "Web Server"
        elif any(port['service'] == 'ssh' for port in fingerprint['open_ports']):
            return "Server"
        elif any(port['service'] == 'printer' for port in fingerprint['open_ports']):
            return "Printer"
        elif any(port['service'] == 'camera' for port in fingerprint['open_ports']):
            return "Camera"
        elif any(port['service'] == 'router' for port in fingerprint['open_ports']):
            return "Router"
        return "Unknown"

    def display_arp_results(self, devices: List[Dict]) -> None:
        """Display ARP scan results."""
        table = Table(title="ARP Scan Results")
        table.add_column("IP Address", style="cyan")
        table.add_column("MAC Address", style="green")
        table.add_column("Vendor", style="yellow")

        for device in devices:
            table.add_row(
                device['ip'],
                device['mac'],
                device['vendor']
            )

        console.print(table)

    def display_fingerprint_results(self, fingerprint: Dict) -> None:
        """Display device fingerprint results."""
        table = Table(title="Device Fingerprint Results")
        table.add_column("Attribute", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Operating System", fingerprint.get('os', 'Unknown'))
        table.add_row("Device Type", fingerprint.get('device_type', 'Unknown'))

        # Display open ports and services
        if fingerprint.get('open_ports'):
            services = []
            for port in fingerprint['open_ports']:
                services.append(f"{port['service']} ({port['port']}) - {port['version']}")
            table.add_row("Services", "\n".join(services))

        console.print(table) 