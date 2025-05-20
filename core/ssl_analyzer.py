"""
SSL/TLS Analysis Module for E502 OSINT Terminal
Provides certificate analysis, cipher suite checking, and HSTS verification.
"""

import ssl
import socket
import OpenSSL
from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from typing import Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import datetime
import asyncio
import aiohttp
from urllib.parse import urlparse
import re

console = Console()

class SSLAnalyzer:
    def __init__(self):
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    async def analyze_ssl(self, hostname: str) -> Dict:
        """Perform comprehensive SSL/TLS analysis."""
        try:
            if not hostname.startswith(('http://', 'https://')):
                hostname = f"https://{hostname}"

            console.print(f"[bold green]Analyzing SSL/TLS for {hostname}...[/]")
            
            # Parse hostname
            parsed = urlparse(hostname)
            host = parsed.netloc or parsed.path
            
            # Get certificate
            cert = await self._get_certificate(host)
            if not cert:
                return {}

            # Analyze certificate
            cert_analysis = self._analyze_certificate(cert)
            
            # Get cipher suites
            cipher_suites = await self._get_cipher_suites(host)
            
            # Check HSTS
            hsts_info = await self._check_hsts(hostname)
            
            return {
                'certificate': cert_analysis,
                'ciphers': cipher_suites,
                'hsts': hsts_info
            }

        except Exception as e:
            console.print(f"[red]Error during SSL analysis: {str(e)}[/]")
            return {}

    async def _get_certificate(self, host: str) -> Optional[x509.Certificate]:
        """Get SSL certificate for host."""
        try:
            # Create SSL context
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Try direct socket connection first
            sock = socket.create_connection((host, 443), timeout=5)
            with ssl_context.wrap_socket(sock, server_hostname=host) as ssl_sock:
                cert_data = ssl_sock.getpeercert(binary_form=True)
                return x509.load_der_x509_certificate(cert_data, default_backend())
                
        except Exception as e:
            console.print(f"[red]Error getting certificate: {str(e)}[/]")
            return None

    def _analyze_certificate(self, cert: x509.Certificate) -> Dict:
        """Analyze SSL certificate."""
        try:
            # Basic certificate info
            subject = {}
            for name in cert.subject:
                subject[name.oid._name] = name.value
                
            issuer = {}
            for name in cert.issuer:
                issuer[name.oid._name] = name.value
            
            # Validity period using UTC datetime
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            now = datetime.datetime.now(datetime.timezone.utc)
            
            # Check if certificate is expired
            is_expired = now > not_after
            is_not_yet_valid = now < not_before
            
            # Calculate days remaining
            days_remaining = (not_after - now).days if not is_expired else 0
            
            # Get public key info
            public_key = cert.public_key()
            key_size = public_key.key_size if hasattr(public_key, 'key_size') else 'Unknown'
            
            # Get subject alternative names
            try:
                san = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                alt_names = san.value.get_values_for_type(x509.DNSName)
            except:
                alt_names = []
            
            return {
                'subject': subject,
                'issuer': issuer,
                'validity': {
                    'not_before': not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    'not_after': not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    'is_expired': is_expired,
                    'is_not_yet_valid': is_not_yet_valid,
                    'days_remaining': days_remaining
                },
                'public_key': {
                    'type': type(public_key).__name__,
                    'size': key_size
                },
                'alt_names': alt_names
            }
            
        except Exception as e:
            console.print(f"[red]Error analyzing certificate: {str(e)}[/]")
            return {}

    async def _get_cipher_suites(self, host: str) -> List[Dict]:
        """Get supported cipher suites."""
        try:
            # Create SSL context
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            # Create socket connection
            sock = socket.create_connection((host, 443), timeout=5)
            with ssl_context.wrap_socket(sock, server_hostname=host) as ssl_sock:
                cipher = ssl_sock.cipher()
                return [{
                    'name': cipher[0],
                    'version': cipher[1],
                    'bits': cipher[2]
                }]
            
        except Exception as e:
            console.print(f"[red]Error getting cipher suites: {str(e)}[/]")
            return []

    async def _check_hsts(self, url: str) -> Dict:
        """Check HSTS configuration."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    hsts_header = response.headers.get('Strict-Transport-Security', '')
                    
                    if hsts_header:
                        # Parse HSTS header
                        max_age = re.search(r'max-age=(\d+)', hsts_header)
                        includes_subdomains = 'includeSubDomains' in hsts_header
                        preload = 'preload' in hsts_header
                        
                        return {
                            'enabled': True,
                            'max_age': int(max_age.group(1)) if max_age else 0,
                            'includes_subdomains': includes_subdomains,
                            'preload': preload
                        }
                    
                    return {
                        'enabled': False,
                        'max_age': 0,
                        'includes_subdomains': False,
                        'preload': False
                    }
                    
        except Exception as e:
            console.print(f"[red]Error checking HSTS: {str(e)}[/]")
            return {
                'enabled': False,
                'max_age': 0,
                'includes_subdomains': False,
                'preload': False
            }

    def display_ssl_analysis(self, results: Dict) -> None:
        """Display SSL analysis results."""
        if not results:
            console.print("[red]No SSL analysis results available.[/]")
            return

        # Certificate Information
        cert_table = Table(title="Certificate Information", show_header=True, header_style="bold magenta")
        cert_table.add_column("Field", style="cyan", width=20)
        cert_table.add_column("Value", style="green", width=60)

        if 'certificate' in results:
            cert = results['certificate']
            
            # Subject
            subject = cert.get('subject', {})
            cert_table.add_row("Subject", "\n".join(f"{k}: {v}" for k, v in subject.items()))
            
            # Issuer
            issuer = cert.get('issuer', {})
            cert_table.add_row("Issuer", "\n".join(f"{k}: {v}" for k, v in issuer.items()))
            
            # Validity
            validity = cert.get('validity', {})
            cert_table.add_row("Valid From", validity.get('not_before', 'Unknown'))
            cert_table.add_row("Valid Until", validity.get('not_after', 'Unknown'))
            
            # Status
            if validity.get('is_expired'):
                status = "[red]EXPIRED[/]"
            elif validity.get('is_not_yet_valid'):
                status = "[yellow]NOT YET VALID[/]"
            else:
                days = validity.get('days_remaining', 0)
                if days < 30:
                    status = f"[yellow]EXPIRING SOON ({days} days)[/]"
                else:
                    status = f"[green]VALID ({days} days)[/]"
            cert_table.add_row("Status", status)
            
            # Public Key
            public_key = cert.get('public_key', {})
            cert_table.add_row(
                "Public Key",
                f"{public_key.get('type', 'Unknown')} ({public_key.get('size', 'Unknown')} bits)"
            )
            
            # Subject Alternative Names
            alt_names = cert.get('alt_names', [])
            if alt_names:
                cert_table.add_row("Alternative Names", "\n".join(alt_names))

        console.print(cert_table)

        # Cipher Suites
        if 'ciphers' in results and results['ciphers']:
            cipher_table = Table(title="Cipher Suites", show_header=True, header_style="bold magenta")
            cipher_table.add_column("Cipher", style="cyan", width=30)
            cipher_table.add_column("Version", style="green", width=15)
            cipher_table.add_column("Bits", style="yellow", width=10)

            for cipher in results['ciphers']:
                cipher_table.add_row(
                    cipher.get('name', 'Unknown'),
                    cipher.get('version', 'Unknown'),
                    str(cipher.get('bits', 'Unknown'))
                )

            console.print(cipher_table)

        # HSTS Information
        if 'hsts' in results:
            hsts = results['hsts']
            hsts_table = Table(title="HSTS Configuration", show_header=True, header_style="bold magenta")
            hsts_table.add_column("Setting", style="cyan", width=20)
            hsts_table.add_column("Value", style="green", width=40)

            hsts_table.add_row(
                "HSTS Enabled",
                "[green]Yes[/]" if hsts.get('enabled') else "[red]No[/]"
            )
            if hsts.get('enabled'):
                hsts_table.add_row("Max Age", str(hsts.get('max_age', 0)))
                hsts_table.add_row(
                    "Include Subdomains",
                    "[green]Yes[/]" if hsts.get('includes_subdomains') else "[red]No[/]"
                )
                hsts_table.add_row(
                    "Preload",
                    "[green]Yes[/]" if hsts.get('preload') else "[red]No[/]"
                )

            console.print(hsts_table) 