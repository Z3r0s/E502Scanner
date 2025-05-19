"""
SSL/TLS Analysis Module for E502 OSINT Terminal
Provides comprehensive SSL/TLS certificate analysis including cipher suite analysis,
certificate transparency checking, and security validation.
"""

import ssl
import socket
import OpenSSL
from OpenSSL import SSL
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json
from datetime import datetime
import requests
import re
import urllib3
urllib3.disable_warnings()

console = Console()

class SSLAnalyzer:
    def __init__(self):
        self.context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        self.context.set_verify(SSL.VERIFY_NONE)
        self.context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3)

    def analyze_ssl(self, hostname: str, port: int = 443) -> Dict:
        """Perform comprehensive SSL/TLS analysis."""
        try:
            analysis = {
                'hostname': hostname,
                'port': port,
                'timestamp': datetime.now().isoformat(),
                'certificate': self._get_certificate_info(hostname, port),
                'cipher_suites': self._analyze_cipher_suites(hostname, port),
                'protocol_versions': self._analyze_protocol_versions(hostname, port),
                'hsts': self._check_hsts(hostname),
                'certificate_transparency': self._check_certificate_transparency(hostname),
                'security_issues': []
            }

            # Check for common security issues
            self._check_security_issues(analysis)
            
            return analysis
        except Exception as e:
            console.print(f"[red]Error during SSL analysis: {str(e)}[/]")
            return {}

    def _get_certificate_info(self, hostname: str, port: int) -> Dict:
        """Get detailed certificate information."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((hostname, port))
            
            ssl_sock = SSL.Connection(self.context, sock)
            ssl_sock.set_connect_state()
            ssl_sock.set_tlsext_host_name(hostname.encode())
            ssl_sock.do_handshake()
            
            cert = ssl_sock.get_peer_certificate()
            
            cert_info = {
                'subject': dict(cert.get_subject().get_components()),
                'issuer': dict(cert.get_issuer().get_components()),
                'version': cert.get_version(),
                'serial_number': cert.get_serial_number(),
                'not_before': cert.get_notBefore().decode(),
                'not_after': cert.get_notAfter().decode(),
                'signature_algorithm': cert.get_signature_algorithm().decode(),
                'extensions': []
            }
            
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                cert_info['extensions'].append({
                    'name': ext.get_short_name().decode(),
                    'value': str(ext)
                })
            
            ssl_sock.close()
            sock.close()
            
            return cert_info
        except Exception as e:
            console.print(f"[red]Error getting certificate info: {str(e)}[/]")
            return {}

    def _analyze_cipher_suites(self, hostname: str, port: int) -> Dict:
        """Analyze supported cipher suites."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((hostname, port))
            
            ssl_sock = SSL.Connection(self.context, sock)
            ssl_sock.set_connect_state()
            ssl_sock.set_tlsext_host_name(hostname.encode())
            
            # Get all supported cipher suites
            ciphers = ssl_sock.get_cipher_list()
            
            analysis = {
                'total_ciphers': len(ciphers),
                'ciphers': [],
                'weak_ciphers': [],
                'recommended_ciphers': []
            }
            
            for cipher in ciphers:
                cipher_info = {
                    'name': cipher.decode(),
                    'strength': self._get_cipher_strength(cipher.decode())
                }
                analysis['ciphers'].append(cipher_info)
                
                if cipher_info['strength'] == 'weak':
                    analysis['weak_ciphers'].append(cipher_info)
                elif cipher_info['strength'] == 'strong':
                    analysis['recommended_ciphers'].append(cipher_info)
            
            ssl_sock.close()
            sock.close()
            
            return analysis
        except Exception as e:
            console.print(f"[red]Error analyzing cipher suites: {str(e)}[/]")
            return {}

    def _analyze_protocol_versions(self, hostname: str, port: int) -> Dict:
        """Analyze supported SSL/TLS protocol versions."""
        versions = {
            'SSLv2': False,
            'SSLv3': False,
            'TLSv1.0': False,
            'TLSv1.1': False,
            'TLSv1.2': False,
            'TLSv1.3': False
        }
        
        try:
            for version in versions.keys():
                context = SSL.Context(SSL.TLS_CLIENT_METHOD)
                if version == 'SSLv2':
                    context.set_options(SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1 | SSL.OP_NO_TLSv1_2)
                elif version == 'SSLv3':
                    context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1 | SSL.OP_NO_TLSv1_2)
                elif version == 'TLSv1.0':
                    context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1_1 | SSL.OP_NO_TLSv1_2)
                elif version == 'TLSv1.1':
                    context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_2)
                elif version == 'TLSv1.2':
                    context.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((hostname, port))
                    
                    ssl_sock = SSL.Connection(context, sock)
                    ssl_sock.set_connect_state()
                    ssl_sock.set_tlsext_host_name(hostname.encode())
                    ssl_sock.do_handshake()
                    
                    versions[version] = True
                    ssl_sock.close()
                except:
                    pass
                finally:
                    sock.close()
            
            return versions
        except Exception as e:
            console.print(f"[red]Error analyzing protocol versions: {str(e)}[/]")
            return {}

    def _check_hsts(self, hostname: str) -> Dict:
        """Check HSTS configuration."""
        try:
            response = requests.get(f'https://{hostname}', verify=False, timeout=10)
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            
            analysis = {
                'present': bool(hsts_header),
                'header_value': hsts_header,
                'max_age': None,
                'include_subdomains': False,
                'preload': False
            }
            
            if hsts_header:
                if 'max-age=' in hsts_header:
                    analysis['max_age'] = int(re.search(r'max-age=(\d+)', hsts_header).group(1))
                analysis['include_subdomains'] = 'includeSubDomains' in hsts_header
                analysis['preload'] = 'preload' in hsts_header
            
            return analysis
        except Exception as e:
            console.print(f"[red]Error checking HSTS: {str(e)}[/]")
            return {}

    def _check_certificate_transparency(self, hostname: str) -> Dict:
        """Check Certificate Transparency logs."""
        try:
            response = requests.get(f'https://{hostname}', verify=False, timeout=10)
            sct_header = response.headers.get('X-Signed-Certificate-Timestamp', '')
            
            analysis = {
                'present': bool(sct_header),
                'header_value': sct_header,
                'logs': []
            }
            
            if sct_header:
                # Parse SCT header
                scts = sct_header.split(',')
                for sct in scts:
                    analysis['logs'].append({
                        'version': sct[:2],
                        'log_id': sct[2:66],
                        'timestamp': int(sct[66:78], 16),
                        'signature': sct[78:]
                    })
            
            return analysis
        except Exception as e:
            console.print(f"[red]Error checking certificate transparency: {str(e)}[/]")
            return {}

    def _get_cipher_strength(self, cipher: str) -> str:
        """Determine the strength of a cipher suite."""
        weak_patterns = [
            r'NULL', r'aNULL', r'EXPORT', r'LOW', r'DES', r'RC4', r'MD5',
            r'PSK', r'SRP', r'KRB5', r'CBC'
        ]
        
        strong_patterns = [
            r'AES256', r'CHACHA20', r'ECDHE', r'DHE', r'GCM', r'POLY1305'
        ]
        
        for pattern in weak_patterns:
            if re.search(pattern, cipher, re.I):
                return 'weak'
        
        for pattern in strong_patterns:
            if re.search(pattern, cipher, re.I):
                return 'strong'
        
        return 'medium'

    def _check_security_issues(self, analysis: Dict) -> None:
        """Check for common security issues."""
        issues = []
        
        # Check certificate expiration
        if 'certificate' in analysis and 'not_after' in analysis['certificate']:
            not_after = datetime.strptime(analysis['certificate']['not_after'], '%Y%m%d%H%M%SZ')
            if (not_after - datetime.now()).days < 30:
                issues.append('Certificate expires in less than 30 days')
        
        # Check for weak protocols
        if analysis.get('protocol_versions', {}).get('SSLv2', False):
            issues.append('SSLv2 is enabled (insecure)')
        if analysis.get('protocol_versions', {}).get('SSLv3', False):
            issues.append('SSLv3 is enabled (insecure)')
        if analysis.get('protocol_versions', {}).get('TLSv1.0', False):
            issues.append('TLSv1.0 is enabled (deprecated)')
        
        # Check for weak ciphers
        if analysis.get('cipher_suites', {}).get('weak_ciphers'):
            issues.append(f"Found {len(analysis['cipher_suites']['weak_ciphers'])} weak cipher suites")
        
        # Check HSTS
        if not analysis.get('hsts', {}).get('present'):
            issues.append('HSTS is not enabled')
        
        analysis['security_issues'] = issues

    def display_ssl_analysis(self, analysis: Dict) -> None:
        """Display SSL analysis results in a formatted table."""
        table = Table(title="SSL/TLS Analysis Results")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in analysis.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value, indent=2)
            table.add_row(str(key), str(value))
        
        console.print(table) 