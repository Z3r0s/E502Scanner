"""
SSL Analyzer Module for E502 OSINT Terminal
Provides comprehensive SSL/TLS analysis and security assessment.
"""

import ssl
import socket
import logging
import time
import json
import os
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import asyncio
import aiohttp
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from functools import wraps
import signal
from contextlib import contextmanager
import platform

logger = logging.getLogger("E502OSINT.SSLAnalyzer")
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

class SSLAnalyzer:
    def __init__(self):
        self.timeout = 30
        self.retry_count = 3
        self.retry_delay = 1
        self.ssl_versions = {
            'SSLv2': ssl.PROTOCOL_SSLv2,
            'SSLv3': ssl.PROTOCOL_SSLv3,
            'TLSv1': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.3': ssl.PROTOCOL_TLSv1_3
        }
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'SHA1',
            'EXPORT', 'NULL', 'LOW', 'MEDIUM'
        ]

    @handle_timeout
    async def analyze_ssl(self, hostname: str) -> Dict:
        """Perform comprehensive SSL/TLS analysis."""
        try:
            results = {
                'hostname': hostname,
                'timestamp': datetime.now().isoformat(),
                'protocols': {},
                'certificate': {},
                'ciphers': {},
                'security_issues': [],
                'recommendations': []
            }

            # Analyze protocols
            results['protocols'] = await self._analyze_protocols(hostname)

            # Analyze certificate
            results['certificate'] = await self._analyze_certificate(hostname)

            # Analyze cipher suites
            results['ciphers'] = await self._analyze_ciphers(hostname)

            # Check for security issues
            results['security_issues'] = self._check_security_issues(results)

            # Generate recommendations
            results['recommendations'] = self._generate_recommendations(results)

            return results

        except Exception as e:
            logger.error(f"Error analyzing SSL: {str(e)}")
            return None

    @handle_timeout
    async def _analyze_protocols(self, hostname: str) -> Dict:
        """Analyze supported SSL/TLS protocols."""
        protocols = {}
        
        for name, version in self.ssl_versions.items():
            try:
                context = ssl.SSLContext(version)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocols[name] = {
                            'supported': True,
                            'version': ssock.version()
                        }
            except:
                protocols[name] = {
                    'supported': False,
                    'version': None
                }
        
        return protocols

    @handle_timeout
    async def _analyze_certificate(self, hostname: str) -> Dict:
        """Analyze SSL certificate."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'subject_alt_names': cert.get('subjectAltName', []),
                        'signature_algorithm': cert.get('signatureAlgorithm', ''),
                        'fingerprint': cert.get('fingerprint', '')
                    }
        except Exception as e:
            logger.error(f"Error analyzing certificate: {str(e)}")
            return {}

    @handle_timeout
    async def _analyze_ciphers(self, hostname: str) -> Dict:
        """Analyze supported cipher suites."""
        ciphers = {}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    ciphers[cipher[0]] = {
                        'version': cipher[1],
                        'strength': cipher[2],
                        'protocol': ssock.version()
                    }
        except Exception as e:
            logger.error(f"Error analyzing ciphers: {str(e)}")
        
        return ciphers

    def _check_security_issues(self, results: Dict) -> List[Dict]:
        """Check for security issues in SSL/TLS configuration."""
        issues = []
        
        # Check protocols
        for proto, info in results['protocols'].items():
            if info['supported'] and proto in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                issues.append({
                    'type': 'weak_protocol',
                    'severity': 'high',
                    'description': f'Weak protocol {proto} is supported',
                    'recommendation': f'Disable {proto} support'
                })
        
        # Check certificate
        cert = results['certificate']
        if cert:
            # Check expiration
            not_after = datetime.strptime(cert['not_after'], '%b %d %H:%M:%S %Y %Z')
            if not_after < datetime.now():
                issues.append({
                    'type': 'expired_certificate',
                    'severity': 'critical',
                    'description': 'SSL certificate has expired',
                    'recommendation': 'Renew the SSL certificate'
                })
            
            # Check key size
            if 'subject' in cert and 'CN' in cert['subject']:
                if cert['subject']['CN'].startswith('*'):
                    issues.append({
                        'type': 'wildcard_certificate',
                        'severity': 'medium',
                        'description': 'Wildcard certificate in use',
                        'recommendation': 'Consider using specific certificates for each subdomain'
                    })
        
        # Check ciphers
        for cipher, info in results['ciphers'].items():
            if any(weak in cipher.upper() for weak in self.weak_ciphers):
                issues.append({
                    'type': 'weak_cipher',
                    'severity': 'high',
                    'description': f'Weak cipher {cipher} is supported',
                    'recommendation': 'Disable weak cipher support'
                })
        
        return issues

    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        # Protocol recommendations
        weak_protocols = [proto for proto, info in results['protocols'].items() 
                         if info['supported'] and proto in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']]
        if weak_protocols:
            recommendations.append(f"Disable support for weak protocols: {', '.join(weak_protocols)}")
        
        # Certificate recommendations
        cert = results['certificate']
        if cert:
            if 'subject' in cert and 'CN' in cert['subject']:
                if cert['subject']['CN'].startswith('*'):
                    recommendations.append("Consider using specific certificates for each subdomain instead of wildcard certificates")
        
        # Cipher recommendations
        weak_ciphers = [cipher for cipher, info in results['ciphers'].items() 
                       if any(weak in cipher.upper() for weak in self.weak_ciphers)]
        if weak_ciphers:
            recommendations.append(f"Disable support for weak ciphers: {', '.join(weak_ciphers)}")
        
        # General recommendations
        recommendations.extend([
            "Enable HSTS (HTTP Strict Transport Security)",
            "Configure secure cipher suite order",
            "Enable OCSP stapling",
            "Use strong certificate key sizes (2048 bits or more)",
            "Implement certificate transparency"
        ])
        
        return recommendations

    def display_ssl_analysis(self, analysis: Dict) -> None:
        """Display SSL/TLS analysis results."""
        if not analysis:
            console.print("[yellow]No SSL/TLS analysis results available[/]")
            return
        
        # Create layout
        layout = Panel(
            f"[bold blue]SSL/TLS Analysis for {analysis['hostname']}[/]\n"
            f"Timestamp: {analysis['timestamp']}\n\n"
            f"[bold yellow]Protocols:[/]\n" + 
            "\n".join(f"  • {proto}: {'✓' if info['supported'] else '✗'} ({info['version'] or 'N/A'})" 
                     for proto, info in analysis['protocols'].items()) + "\n\n" +
            f"[bold yellow]Certificate:[/]\n" +
            "\n".join(f"  • {key}: {value}" for key, value in analysis['certificate'].items()) + "\n\n" +
            f"[bold yellow]Ciphers:[/]\n" +
            "\n".join(f"  • {cipher}: {info['version']} ({info['strength']} bits)" 
                     for cipher, info in analysis['ciphers'].items()) + "\n\n" +
            f"[bold yellow]Security Issues:[/]\n" +
            "\n".join(f"  • {issue['type']} ({issue['severity']}): {issue['description']}" 
                     for issue in analysis['security_issues']) + "\n\n" +
            f"[bold yellow]Recommendations:[/]\n" +
            "\n".join(f"  • {rec}" for rec in analysis['recommendations']),
            title="SSL/TLS Analysis Results",
            border_style="blue"
        )
        
        console.print(layout)

# Create global instance
ssl_analyzer = SSLAnalyzer() 