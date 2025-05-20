"""
Web Reconnaissance Module for E502 OSINT Terminal
Provides advanced web analysis capabilities including technology stack detection,
CSP analysis, WAF detection, and security header analysis.
"""

import warnings
warnings.filterwarnings('ignore', message='Caught.*compiling regex')

import requests
from bs4 import BeautifulSoup
from Wappalyzer import Wappalyzer, WebPage
from typing import Dict, List, Optional, Tuple, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json
import re
from urllib.parse import urlparse
import ssl
import socket
from datetime import datetime
import asyncio
import concurrent.futures
import functools
import aiohttp

console = Console()

class WebAnalyzer:
    def __init__(self):
        self.wappalyzer = Wappalyzer.latest()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=5)

    async def async_run_in_thread(self, func, *args, **kwargs):
        """Run a blocking function in a thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.thread_pool, 
            functools.partial(func, *args, **kwargs)
        )

    async def analyze_website_async(self, url: str) -> Dict:
        """Perform comprehensive website analysis asynchronously."""
        return await self.async_run_in_thread(self.analyze_website, url)

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

    async def _analyze_security_headers_async(self, headers: Dict) -> Dict:
        """Analyze security-related headers asynchronously."""
        return await self.async_run_in_thread(self._analyze_security_headers, headers)

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

    async def _analyze_csp_async(self, csp: str) -> Dict:
        """Analyze Content Security Policy asynchronously."""
        return await self.async_run_in_thread(self._analyze_csp, csp)

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

    async def _detect_waf_async(self, response: requests.Response) -> Dict:
        """Detect Web Application Firewall asynchronously."""
        return await self.async_run_in_thread(self._detect_waf, response)

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

    async def _analyze_javascript_async(self, html: str) -> Dict:
        """Analyze JavaScript libraries and frameworks asynchronously."""
        return await self.async_run_in_thread(self._analyze_javascript, html)

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

    async def _analyze_cookies_async(self, cookies: requests.cookies.RequestsCookieJar) -> Dict:
        """Analyze cookie security asynchronously."""
        return await self.async_run_in_thread(self._analyze_cookies, cookies)

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
        """Display web analysis results."""
        table = Table(title=f"Web Analysis for {analysis.get('url', 'Unknown')}")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Status Code", str(analysis.get('status_code', 'Unknown')))
        
        # Technologies
        tech_list = []
        for tech, version in analysis.get('technologies', {}).items():
            if version:
                tech_list.append(f"{tech} ({version})")
            else:
                tech_list.append(tech)
        
        table.add_row("Technologies", ", ".join(tech_list))
        
        # WAF Detection
        waf_info = analysis.get('waf_detection', {})
        if waf_info.get('detected'):
            table.add_row("WAF", ", ".join(waf_info.get('wafs', [])))
        else:
            table.add_row("WAF", "Not Detected")
        
        # Security Headers
        sec_headers = analysis.get('security_headers', {})
        headers_present = []
        headers_missing = []
        
        for header, info in sec_headers.items():
            if info.get('present'):
                headers_present.append(header)
            else:
                headers_missing.append(header)
        
        table.add_row("Security Headers Present", ", ".join(headers_present))
        table.add_row("Security Headers Missing", ", ".join(headers_missing))
        
        # Cookie Analysis
        cookie_info = analysis.get('cookie_analysis', {})
        cookie_summary = (
            f"Total: {cookie_info.get('total_cookies', 0)}, "
            f"Secure: {cookie_info.get('secure_cookies', 0)}, "
            f"HttpOnly: {cookie_info.get('http_only_cookies', 0)}, "
            f"SameSite: {cookie_info.get('same_site_cookies', 0)}"
        )
        table.add_row("Cookies", cookie_summary)
        
        console.print(table)
        
    async def display_web_analysis_async(self, analysis: Dict) -> None:
        """Display web analysis results asynchronously."""
        await self.async_run_in_thread(self.display_web_analysis, analysis)
        
    async def full_analysis_async(self, url: str) -> Dict:
        """Perform a full analysis using parallel async operations."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            # Use aiohttp for async HTTP requests
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    status = response.status
                    headers = dict(response.headers)
                    text = await response.text()
                    
                    # Create tasks for parallel execution
                    tasks = [
                        self._analyze_security_headers_async(headers),
                        self._analyze_csp_async(headers.get('Content-Security-Policy', '')),
                        self._analyze_javascript_async(text)
                    ]
                    
                    # Execute tasks in parallel
                    security_headers, csp_analysis, js_analysis = await asyncio.gather(*tasks)
                    
                    # Create WebPage object for Wappalyzer (this has to be done in a thread)
                    webpage = await self.async_run_in_thread(
                        lambda: WebPage.new_from_url(url)
                    )
                    technologies = await self.async_run_in_thread(
                        lambda: self.wappalyzer.analyze_with_versions(webpage)
                    )
                    
                    analysis = {
                        'url': url,
                        'timestamp': datetime.now().isoformat(),
                        'status_code': status,
                        'headers': headers,
                        'technologies': technologies,
                        'security_headers': security_headers,
                        'csp_analysis': csp_analysis,
                        'javascript_analysis': js_analysis
                    }
                    
                    return analysis
        except Exception as e:
            console.print(f"[red]Error during async website analysis: {str(e)}[/]")
            return {} 