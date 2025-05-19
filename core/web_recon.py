"""
Web Reconnaissance Module for E502 OSINT Terminal
Provides advanced web analysis capabilities including technology stack detection,
CSP analysis, WAF detection, and security header analysis.
"""

import requests
from bs4 import BeautifulSoup
from python_wappalyzer import Wappalyzer, WebPage
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json
import re
from urllib.parse import urlparse
import ssl
import socket
from datetime import datetime

console = Console()

class WebAnalyzer:
    def __init__(self):
        self.wappalyzer = Wappalyzer.latest()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })

    def analyze_website(self, url: str) -> Dict:
        """Perform comprehensive website analysis."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url

            response = self.session.get(url, timeout=10, verify=False)
            webpage = WebPage.new_from_response(url, response)
            
            analysis = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'technologies': self.wappalyzer.analyze_with_versions(webpage),
                'security_headers': self._analyze_security_headers(response.headers),
                'csp_analysis': self._analyze_csp(response.headers.get('Content-Security-Policy', '')),
                'waf_detection': self._detect_waf(response),
                'javascript_analysis': self._analyze_javascript(response.text),
                'cookie_analysis': self._analyze_cookies(response.cookies)
            }
            
            return analysis
        except Exception as e:
            console.print(f"[red]Error during website analysis: {str(e)}[/]")
            return {}

    def _analyze_security_headers(self, headers: Dict) -> Dict:
        """Analyze security-related headers."""
        security_headers = {
            'Strict-Transport-Security': {
                'present': 'Strict-Transport-Security' in headers,
                'value': headers.get('Strict-Transport-Security', ''),
                'recommendation': 'Should be present with max-age and includeSubDomains'
            },
            'X-Frame-Options': {
                'present': 'X-Frame-Options' in headers,
                'value': headers.get('X-Frame-Options', ''),
                'recommendation': 'Should be set to DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'present': 'X-Content-Type-Options' in headers,
                'value': headers.get('X-Content-Type-Options', ''),
                'recommendation': 'Should be set to nosniff'
            },
            'X-XSS-Protection': {
                'present': 'X-XSS-Protection' in headers,
                'value': headers.get('X-XSS-Protection', ''),
                'recommendation': 'Should be set to 1; mode=block'
            },
            'Referrer-Policy': {
                'present': 'Referrer-Policy' in headers,
                'value': headers.get('Referrer-Policy', ''),
                'recommendation': 'Should be set to strict-origin-when-cross-origin'
            }
        }
        return security_headers

    def _analyze_csp(self, csp: str) -> Dict:
        """Analyze Content Security Policy."""
        if not csp:
            return {'present': False, 'recommendation': 'Should implement a CSP'}

        directives = {}
        for directive in csp.split(';'):
            if ' ' in directive:
                key, value = directive.strip().split(' ', 1)
                directives[key] = value.split(' ')

        analysis = {
            'present': True,
            'directives': directives,
            'recommendations': []
        }

        # Check for common security issues
        if 'default-src' not in directives:
            analysis['recommendations'].append('Missing default-src directive')
        if 'script-src' not in directives:
            analysis['recommendations'].append('Missing script-src directive')
        if 'unsafe-inline' in str(directives):
            analysis['recommendations'].append('Avoid using unsafe-inline')
        if 'unsafe-eval' in str(directives):
            analysis['recommendations'].append('Avoid using unsafe-eval')

        return analysis

    def _detect_waf(self, response: requests.Response) -> Dict:
        """Detect Web Application Firewall."""
        waf_signatures = {
            'Cloudflare': ['__cfduid', 'cf-ray'],
            'ModSecurity': ['mod_security', 'NOYB'],
            'Akamai': ['AkamaiGHost'],
            'Imperva': ['incap_ses', 'visid_incap'],
            'F5': ['TS', 'F5_HT_shrinked']
        }

        detected_wafs = []
        for waf, signatures in waf_signatures.items():
            for signature in signatures:
                if signature in str(response.headers) or signature in response.text:
                    detected_wafs.append(waf)
                    break

        return {
            'detected': bool(detected_wafs),
            'wafs': detected_wafs
        }

    def _analyze_javascript(self, html: str) -> Dict:
        """Analyze JavaScript libraries and frameworks."""
        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script')
        
        analysis = {
            'external_scripts': [],
            'inline_scripts': 0,
            'frameworks': set()
        }

        # Common framework signatures
        framework_patterns = {
            'React': r'react|react-dom',
            'Angular': r'angular',
            'Vue': r'vue',
            'jQuery': r'jquery',
            'Bootstrap': r'bootstrap'
        }

        for script in scripts:
            if script.get('src'):
                analysis['external_scripts'].append(script['src'])
            else:
                analysis['inline_scripts'] += 1
                script_content = script.string or ''
                for framework, pattern in framework_patterns.items():
                    if re.search(pattern, script_content, re.I):
                        analysis['frameworks'].add(framework)

        analysis['frameworks'] = list(analysis['frameworks'])
        return analysis

    def _analyze_cookies(self, cookies: requests.cookies.RequestsCookieJar) -> Dict:
        """Analyze cookie security."""
        analysis = {
            'total_cookies': len(cookies),
            'secure_cookies': 0,
            'http_only_cookies': 0,
            'same_site_cookies': 0,
            'cookies_details': []
        }

        for cookie in cookies:
            cookie_info = {
                'name': cookie.name,
                'secure': cookie.secure,
                'http_only': cookie.has_nonstandard_attr('HttpOnly'),
                'same_site': cookie.get_nonstandard_attr('SameSite', 'Not Set')
            }
            
            if cookie.secure:
                analysis['secure_cookies'] += 1
            if cookie.has_nonstandard_attr('HttpOnly'):
                analysis['http_only_cookies'] += 1
            if cookie.get_nonstandard_attr('SameSite'):
                analysis['same_site_cookies'] += 1

            analysis['cookies_details'].append(cookie_info)

        return analysis

    def display_web_analysis(self, analysis: Dict) -> None:
        """Display web analysis results in a formatted table."""
        table = Table(title="Web Analysis Results")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in analysis.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value, indent=2)
            table.add_row(str(key), str(value))
        
        console.print(table) 