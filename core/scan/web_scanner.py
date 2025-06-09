"""
Web Analysis Module for E502 OSINT Terminal
Provides web technology detection, security header analysis, and API endpoint discovery.
"""

import requests
import json
import re
import ssl
import socket
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from datetime import datetime
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import whois
import builtwith
import wappalyzer
from functools import wraps
import signal
from contextlib import contextmanager

logger = logging.getLogger("E502OSINT.WebAnalyzer")
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

class WebAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.wappalyzer = wappalyzer.Wappalyzer()
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        self.timeout = 30
        self.retry_count = 3
        self.retry_delay = 1
        self.common_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.security_headers = [
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Content-Security-Policy',
            'Referrer-Policy',
            'Permissions-Policy',
            'Cross-Origin-Opener-Policy',
            'Cross-Origin-Embedder-Policy',
            'Cross-Origin-Resource-Policy'
        ]

    @handle_timeout
    def analyze_website(self, url: str) -> Dict:
        """Perform comprehensive web analysis."""
        try:
            logger.info(f"Starting web analysis for {url}")
            
            # Normalize URL
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            analysis_results = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'basic_info': self._get_basic_info(url),
                'technology_stack': self._detect_technologies(url),
                'security_headers': self._analyze_security_headers(url),
                'api_endpoints': self._discover_api_endpoints(url),
                'content_analysis': self._analyze_content(url),
                'dns_info': self._analyze_dns(url),
                'ssl_info': self._analyze_ssl(url),
                'performance_metrics': self._analyze_performance(url)
            }
            
            logger.info(f"Web analysis completed for {url}")
            return analysis_results
        except Exception as e:
            logger.error(f"Error during web analysis: {str(e)}")
            return {}

    @handle_timeout
    def _get_basic_info(self, url: str) -> Dict:
        """Get basic website information."""
        try:
            response = self.session.get(url, headers=self.common_headers, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            info = {
                'title': soup.title.string if soup.title else None,
                'description': self._get_meta_description(soup),
                'status_code': response.status_code,
                'server': response.headers.get('Server'),
                'content_type': response.headers.get('Content-Type'),
                'content_length': len(response.content),
                'last_modified': response.headers.get('Last-Modified'),
                'headers': dict(response.headers)
            }
            
            return info
        except Exception as e:
            logger.error(f"Error getting basic info: {str(e)}")
            return {}

    @handle_timeout
    def _detect_technologies(self, url: str) -> Dict:
        """Detect technologies used by the website."""
        try:
            # Use multiple tools for better detection
            technologies = {
                'wappalyzer': self.wappalyzer.analyze_with_versions(url),
                'builtwith': builtwith.parse(url),
                'custom_detection': self._custom_technology_detection(url)
            }
            
            return technologies
        except Exception as e:
            logger.error(f"Error detecting technologies: {str(e)}")
            return {}

    @handle_timeout
    def _analyze_security_headers(self, url: str) -> Dict:
        """Analyze security headers."""
        try:
            response = self.session.get(url, headers=self.common_headers, timeout=self.timeout)
            headers = dict(response.headers)
            
            security_analysis = {}
            for header in self.security_headers:
                if header in headers:
                    security_analysis[header] = {
                        'present': True,
                        'value': headers[header],
                        'recommendation': self._get_header_recommendation(header, headers[header])
                    }
                else:
                    security_analysis[header] = {
                        'present': False,
                        'recommendation': self._get_header_recommendation(header)
                    }
            
            return security_analysis
        except Exception as e:
            logger.error(f"Error analyzing security headers: {str(e)}")
            return {}

    @handle_timeout
    def _discover_api_endpoints(self, url: str) -> List[Dict]:
        """Discover API endpoints."""
        try:
            endpoints = []
            
            # Analyze JavaScript files
            js_endpoints = self._find_js_endpoints(url)
            endpoints.extend(js_endpoints)
            
            # Analyze HTML for API references
            html_endpoints = self._find_html_endpoints(url)
            endpoints.extend(html_endpoints)
            
            # Common API patterns
            common_patterns = self._check_common_api_patterns(url)
            endpoints.extend(common_patterns)
            
            return endpoints
        except Exception as e:
            logger.error(f"Error discovering API endpoints: {str(e)}")
            return []

    @handle_timeout
    def _analyze_content(self, url: str) -> Dict:
        """Analyze website content."""
        try:
            response = self.session.get(url, headers=self.common_headers, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            content_analysis = {
                'meta_tags': self._analyze_meta_tags(soup),
                'links': self._analyze_links(soup, url),
                'forms': self._analyze_forms(soup),
                'images': self._analyze_images(soup),
                'text_content': self._analyze_text_content(soup)
            }
            
            return content_analysis
        except Exception as e:
            logger.error(f"Error analyzing content: {str(e)}")
            return {}

    @handle_timeout
    def _analyze_dns(self, url: str) -> Dict:
        """Analyze DNS information."""
        try:
            domain = urlparse(url).netloc
            dns_info = {
                'a_records': self._get_dns_records(domain, 'A'),
                'aaaa_records': self._get_dns_records(domain, 'AAAA'),
                'mx_records': self._get_dns_records(domain, 'MX'),
                'ns_records': self._get_dns_records(domain, 'NS'),
                'txt_records': self._get_dns_records(domain, 'TXT'),
                'whois': self._get_whois_info(domain)
            }
            
            return dns_info
        except Exception as e:
            logger.error(f"Error analyzing DNS: {str(e)}")
            return {}

    @handle_timeout
    def _analyze_ssl(self, url: str) -> Dict:
        """Analyze SSL/TLS configuration."""
        try:
            domain = urlparse(url).netloc
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'certificate': {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert['version'],
                            'not_before': cert['notBefore'],
                            'not_after': cert['notAfter'],
                            'serial_number': cert['serialNumber']
                        }
                    }
                    
                    return ssl_info
        except Exception as e:
            logger.error(f"Error analyzing SSL: {str(e)}")
            return {}

    @handle_timeout
    def _analyze_performance(self, url: str) -> Dict:
        """Analyze website performance."""
        try:
            start_time = time.time()
            response = self.session.get(url, headers=self.common_headers, timeout=self.timeout)
            load_time = time.time() - start_time
            
            performance = {
                'load_time': load_time,
                'status_code': response.status_code,
                'content_size': len(response.content),
                'headers_size': len(str(response.headers)),
                'total_size': len(response.content) + len(str(response.headers))
            }
            
            return performance
        except Exception as e:
            logger.error(f"Error analyzing performance: {str(e)}")
            return {}

    def _get_meta_description(self, soup: BeautifulSoup) -> Optional[str]:
        """Get meta description from HTML."""
        try:
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            return meta_desc['content'] if meta_desc else None
        except:
            return None

    def _custom_technology_detection(self, url: str) -> Dict:
        """Custom technology detection logic."""
        try:
            response = self.session.get(url, headers=self.common_headers, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            technologies = {}
            
            # Check for common frameworks
            if soup.find('script', src=re.compile(r'jquery')):
                technologies['jquery'] = True
            if soup.find('script', src=re.compile(r'react')):
                technologies['react'] = True
            if soup.find('script', src=re.compile(r'angular')):
                technologies['angular'] = True
            if soup.find('script', src=re.compile(r'vue')):
                technologies['vue'] = True
            
            # Check for common CMS
            if soup.find('meta', attrs={'name': 'generator', 'content': re.compile(r'WordPress')}):
                technologies['wordpress'] = True
            if soup.find('meta', attrs={'name': 'generator', 'content': re.compile(r'Drupal')}):
                technologies['drupal'] = True
            if soup.find('meta', attrs={'name': 'generator', 'content': re.compile(r'Joomla')}):
                technologies['joomla'] = True
            
            return technologies
        except:
            return {}

    def _get_header_recommendation(self, header: str, value: Optional[str] = None) -> str:
        """Get security header recommendations."""
        recommendations = {
            'Strict-Transport-Security': 'Set to "max-age=31536000; includeSubDomains"',
            'X-Frame-Options': 'Set to "DENY" or "SAMEORIGIN"',
            'X-Content-Type-Options': 'Set to "nosniff"',
            'X-XSS-Protection': 'Set to "1; mode=block"',
            'Content-Security-Policy': 'Implement a strong CSP policy',
            'Referrer-Policy': 'Set to "strict-origin-when-cross-origin"',
            'Permissions-Policy': 'Implement appropriate permissions policy',
            'Cross-Origin-Opener-Policy': 'Set to "same-origin"',
            'Cross-Origin-Embedder-Policy': 'Set to "require-corp"',
            'Cross-Origin-Resource-Policy': 'Set to "same-origin"'
        }
        
        return recommendations.get(header, 'Implement this security header')

    def _find_js_endpoints(self, url: str) -> List[Dict]:
        """Find API endpoints in JavaScript files."""
        try:
            response = self.session.get(url, headers=self.common_headers, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            endpoints = []
            for script in soup.find_all('script', src=True):
                js_url = urljoin(url, script['src'])
                try:
                    js_response = self.session.get(js_url, headers=self.common_headers, timeout=self.timeout)
                    js_content = js_response.text
                    
                    # Look for common API patterns
                    api_patterns = [
                        r'https?://[^\s"\']+/api/[^\s"\']+',
                        r'https?://[^\s"\']+/v\d+/[^\s"\']+',
                        r'https?://[^\s"\']+/graphql',
                        r'https?://[^\s"\']+/rest/[^\s"\']+'
                    ]
                    
                    for pattern in api_patterns:
                        matches = re.finditer(pattern, js_content)
                        for match in matches:
                            endpoints.append({
                                'url': match.group(),
                                'source': js_url,
                                'type': 'javascript'
                            })
                except:
                    continue
            
            return endpoints
        except:
            return []

    def _find_html_endpoints(self, url: str) -> List[Dict]:
        """Find API endpoints in HTML content."""
        try:
            response = self.session.get(url, headers=self.common_headers, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            endpoints = []
            
            # Check form actions
            for form in soup.find_all('form'):
                if form.get('action'):
                    endpoints.append({
                        'url': urljoin(url, form['action']),
                        'method': form.get('method', 'GET'),
                        'type': 'form'
                    })
            
            # Check data attributes
            for element in soup.find_all(attrs={'data-api': True}):
                endpoints.append({
                    'url': urljoin(url, element['data-api']),
                    'type': 'data-attribute'
                })
            
            return endpoints
        except:
            return []

    def _check_common_api_patterns(self, url: str) -> List[Dict]:
        """Check for common API patterns."""
        try:
            common_paths = [
                '/api',
                '/api/v1',
                '/api/v2',
                '/graphql',
                '/rest',
                '/swagger',
                '/openapi',
                '/docs'
            ]
            
            endpoints = []
            for path in common_paths:
                try:
                    api_url = urljoin(url, path)
                    response = self.session.get(api_url, headers=self.common_headers, timeout=self.timeout)
                    if response.status_code != 404:
                        endpoints.append({
                            'url': api_url,
                            'status_code': response.status_code,
                            'type': 'common-pattern'
                        })
                except:
                    continue
            
            return endpoints
        except:
            return []

    def _analyze_meta_tags(self, soup: BeautifulSoup) -> Dict:
        """Analyze meta tags."""
        try:
            meta_tags = {}
            for meta in soup.find_all('meta'):
                if meta.get('name'):
                    meta_tags[meta['name']] = meta.get('content', '')
                elif meta.get('property'):
                    meta_tags[meta['property']] = meta.get('content', '')
            
            return meta_tags
        except:
            return {}

    def _analyze_links(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Analyze links in the page."""
        try:
            links = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith(('http://', 'https://', '//')):
                    links.append({
                        'url': href,
                        'text': link.get_text(strip=True),
                        'type': 'external'
                    })
                else:
                    links.append({
                        'url': urljoin(base_url, href),
                        'text': link.get_text(strip=True),
                        'type': 'internal'
                    })
            
            return links
        except:
            return []

    def _analyze_forms(self, soup: BeautifulSoup) -> List[Dict]:
        """Analyze forms in the page."""
        try:
            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET'),
                    'inputs': []
                }
                
                for input_field in form.find_all('input'):
                    form_data['inputs'].append({
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text'),
                        'required': input_field.get('required') is not None
                    })
                
                forms.append(form_data)
            
            return forms
        except:
            return []

    def _analyze_images(self, soup: BeautifulSoup) -> List[Dict]:
        """Analyze images in the page."""
        try:
            images = []
            for img in soup.find_all('img'):
                image_data = {
                    'src': img.get('src', ''),
                    'alt': img.get('alt', ''),
                    'title': img.get('title', ''),
                    'width': img.get('width', ''),
                    'height': img.get('height', '')
                }
                images.append(image_data)
            
            return images
        except:
            return []

    def _analyze_text_content(self, soup: BeautifulSoup) -> Dict:
        """Analyze text content of the page."""
        try:
            text_content = {
                'headings': {},
                'paragraphs': [],
                'lists': [],
                'tables': []
            }
            
            # Analyze headings
            for i in range(1, 7):
                headings = soup.find_all(f'h{i}')
                text_content['headings'][f'h{i}'] = [h.get_text(strip=True) for h in headings]
            
            # Analyze paragraphs
            for p in soup.find_all('p'):
                text_content['paragraphs'].append(p.get_text(strip=True))
            
            # Analyze lists
            for ul in soup.find_all(['ul', 'ol']):
                items = [li.get_text(strip=True) for li in ul.find_all('li')]
                text_content['lists'].append(items)
            
            # Analyze tables
            for table in soup.find_all('table'):
                table_data = []
                for row in table.find_all('tr'):
                    cells = [cell.get_text(strip=True) for cell in row.find_all(['td', 'th'])]
                    table_data.append(cells)
                text_content['tables'].append(table_data)
            
            return text_content
        except:
            return {}

    def _get_dns_records(self, domain: str, record_type: str) -> List[str]:
        """Get DNS records of specified type."""
        try:
            records = dns.resolver.resolve(domain, record_type)
            return [str(record) for record in records]
        except:
            return []

    def _get_whois_info(self, domain: str) -> Dict:
        """Get WHOIS information."""
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers,
                'status': w.status
            }
        except:
            return {}

# Create global instance
web_analyzer = WebAnalyzer() 