"""
Privacy Management Module for E502 OSINT Terminal
Provides advanced privacy features including multiple proxy support,
proxy chain configuration, user agent rotation, and request rate limiting.
"""

import requests
import random
import time
from typing import Dict, List, Optional, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json
from datetime import datetime
import socks
import socket
from fake_useragent import UserAgent
import threading
from queue import Queue
import asyncio
import aiohttp
from urllib.parse import urlparse

console = Console()

class PrivacyManager:
    def __init__(self):
        self.proxies = {
            'tor': {
                'host': '127.0.0.1',
                'port': 9050,
                'type': 'socks5'
            }
        }
        self.proxy_chains = []
        self.user_agents = UserAgent()
        self.rate_limits = {}
        self.request_history = {}
        self.lock = threading.Lock()
        self.session = requests.Session()
        self._setup_default_session()

    def _setup_default_session(self) -> None:
        """Setup default session with privacy features."""
        self.session.headers.update({
            'User-Agent': self.user_agents.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        })

    def add_proxy(self, name: str, host: str, port: int, proxy_type: str = 'socks5') -> None:
        """Add a new proxy to the proxy list."""
        self.proxies[name] = {
            'host': host,
            'port': port,
            'type': proxy_type
        }

    def remove_proxy(self, name: str) -> None:
        """Remove a proxy from the proxy list."""
        if name in self.proxies:
            del self.proxies[name]

    def create_proxy_chain(self, proxy_names: List[str]) -> None:
        """Create a chain of proxies."""
        if all(name in self.proxies for name in proxy_names):
            self.proxy_chains.append(proxy_names)

    def rotate_user_agent(self) -> None:
        """Rotate the user agent to a new random one."""
        with self.lock:
            self.session.headers.update({
                'User-Agent': self.user_agents.random
            })

    def set_rate_limit(self, domain: str, requests_per_second: float) -> None:
        """Set rate limit for a specific domain."""
        self.rate_limits[domain] = {
            'requests_per_second': requests_per_second,
            'last_request': 0
        }

    def _check_rate_limit(self, url: str) -> None:
        """Check and enforce rate limiting."""
        domain = urlparse(url).netloc
        if domain in self.rate_limits:
            with self.lock:
                current_time = time.time()
                time_since_last = current_time - self.rate_limits[domain]['last_request']
                min_interval = 1.0 / self.rate_limits[domain]['requests_per_second']
                
                if time_since_last < min_interval:
                    sleep_time = min_interval - time_since_last
                    time.sleep(sleep_time)
                
                self.rate_limits[domain]['last_request'] = time.time()

    def _get_proxy_url(self, proxy_name: str) -> str:
        """Get proxy URL for a specific proxy."""
        proxy = self.proxies[proxy_name]
        return f"{proxy['type']}://{proxy['host']}:{proxy['port']}"

    def _setup_proxy_chain(self, chain: List[str]) -> Dict:
        """Setup a chain of proxies."""
        if not chain:
            return {}
        
        proxies = {}
        for i, proxy_name in enumerate(chain):
            proxy = self.proxies[proxy_name]
            if proxy['type'] == 'socks5':
                if i == 0:
                    proxies['http'] = f"socks5://{proxy['host']}:{proxy['port']}"
                    proxies['https'] = f"socks5://{proxy['host']}:{proxy['port']}"
                else:
                    # For chained SOCKS proxies, we need to use a different approach
                    # This is a simplified version - in reality, you'd need to handle
                    # the chaining of SOCKS proxies differently
                    pass
            else:
                proxies['http'] = f"http://{proxy['host']}:{proxy['port']}"
                proxies['https'] = f"https://{proxy['host']}:{proxy['port']}"
        
        return proxies

    def make_request(self, url: str, method: str = 'GET', 
                    use_proxy: Optional[str] = None,
                    use_chain: Optional[List[str]] = None,
                    **kwargs) -> requests.Response:
        """Make a request with privacy features."""
        try:
            # Rotate user agent
            self.rotate_user_agent()
            
            # Check rate limit
            self._check_rate_limit(url)
            
            # Setup proxies
            if use_chain:
                proxies = self._setup_proxy_chain(use_chain)
            elif use_proxy and use_proxy in self.proxies:
                proxies = {
                    'http': self._get_proxy_url(use_proxy),
                    'https': self._get_proxy_url(use_proxy)
                }
            else:
                proxies = {}
            
            # Make request
            response = self.session.request(
                method=method,
                url=url,
                proxies=proxies,
                **kwargs
            )
            
            # Update request history
            with self.lock:
                if url not in self.request_history:
                    self.request_history[url] = []
                self.request_history[url].append({
                    'timestamp': datetime.now().isoformat(),
                    'method': method,
                    'status_code': response.status_code,
                    'proxy_used': use_proxy or use_chain
                })
            
            return response
        except Exception as e:
            console.print(f"[red]Error making request: {str(e)}[/]")
            raise

    async def make_async_request(self, url: str, method: str = 'GET',
                               use_proxy: Optional[str] = None,
                               use_chain: Optional[List[str]] = None,
                               **kwargs) -> aiohttp.ClientResponse:
        """Make an asynchronous request with privacy features."""
        try:
            # Rotate user agent
            self.rotate_user_agent()
            
            # Check rate limit
            self._check_rate_limit(url)
            
            # Setup proxies
            if use_chain:
                proxies = self._setup_proxy_chain(use_chain)
            elif use_proxy and use_proxy in self.proxies:
                proxies = {
                    'http': self._get_proxy_url(use_proxy),
                    'https': self._get_proxy_url(use_proxy)
                }
            else:
                proxies = {}
            
            # Make async request
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method=method,
                    url=url,
                    proxy=proxies.get('http'),
                    **kwargs
                ) as response:
                    # Update request history
                    with self.lock:
                        if url not in self.request_history:
                            self.request_history[url] = []
                        self.request_history[url].append({
                            'timestamp': datetime.now().isoformat(),
                            'method': method,
                            'status_code': response.status,
                            'proxy_used': use_proxy or use_chain
                        })
                    
                    return response
        except Exception as e:
            console.print(f"[red]Error making async request: {str(e)}[/]")
            raise

    def get_request_history(self, url: Optional[str] = None) -> Dict:
        """Get request history for a specific URL or all URLs."""
        with self.lock:
            if url:
                return self.request_history.get(url, [])
            return self.request_history

    def clear_request_history(self) -> None:
        """Clear request history."""
        with self.lock:
            self.request_history.clear()

    def display_privacy_status(self) -> None:
        """Display current privacy configuration."""
        table = Table(title="Privacy Configuration")
        table.add_column("Feature", style="cyan")
        table.add_column("Status", style="green")
        
        # Display proxies
        table.add_row("Available Proxies", json.dumps(list(self.proxies.keys()), indent=2))
        
        # Display proxy chains
        table.add_row("Proxy Chains", json.dumps(self.proxy_chains, indent=2))
        
        # Display rate limits
        rate_limits = {domain: info['requests_per_second'] 
                      for domain, info in self.rate_limits.items()}
        table.add_row("Rate Limits", json.dumps(rate_limits, indent=2))
        
        # Display current user agent
        table.add_row("Current User Agent", self.session.headers.get('User-Agent', ''))
        
        console.print(table) 