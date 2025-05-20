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
import os

console = Console()

class PrivacyManager:
    def __init__(self):
        self.user_agent = UserAgent()
        self.current_user_agent = self.user_agent.random
        self.proxies = {}
        self.proxy_chains = []
        self.rate_limits = {}
        self.last_request_time = {}
        self.config_file = "privacy_config.json"
        self.load_config()
        self.request_history = {}
        self.lock = threading.Lock()
        self.session = requests.Session()
        self._setup_default_session()

    def load_config(self) -> None:
        """Load privacy configuration from file."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.proxies = config.get('proxies', {})
                    self.proxy_chains = config.get('proxy_chains', [])
                    self.rate_limits = config.get('rate_limits', {})
        except Exception as e:
            console.print(f"[red]Error loading privacy configuration: {str(e)}[/]")

    def save_config(self) -> None:
        """Save privacy configuration to file."""
        try:
            config = {
                'proxies': self.proxies,
                'proxy_chains': self.proxy_chains,
                'rate_limits': self.rate_limits
            }
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            console.print(f"[red]Error saving privacy configuration: {str(e)}[/]")

    def _setup_default_session(self) -> None:
        """Setup default session with privacy features."""
        self.session.headers.update({
            'User-Agent': self.current_user_agent,
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

    def rotate_user_agent(self) -> None:
        """Rotate to a new random user agent."""
        self.current_user_agent = self.user_agent.random
        console.print(f"[green]New User-Agent:[/] {self.current_user_agent}")
        with self.lock:
            self.session.headers.update({
                'User-Agent': self.current_user_agent
            })

    def add_proxy(self, name: str, host: str, port: int, proxy_type: str) -> None:
        """Add a new proxy configuration."""
        self.proxies[name] = {
            'host': host,
            'port': port,
            'type': proxy_type
        }
        console.print(f"[green]Added proxy:[/] {name} ({proxy_type}://{host}:{port})")
        self.save_config()

    def remove_proxy(self, name: str) -> None:
        """Remove a proxy from the proxy list."""
        if name in self.proxies:
            del self.proxies[name]
            self.save_config()

    def create_proxy_chain(self, proxy_names: List[str]) -> None:
        """Create a chain of proxies."""
        chain = []
        for name in proxy_names:
            if name in self.proxies:
                chain.append(self.proxies[name])
            else:
                console.print(f"[red]Proxy not found:[/] {name}")
                return
        
        self.proxy_chains.append(chain)
        console.print(f"[green]Created proxy chain with {len(chain)} proxies[/]")
        self.save_config()

    def set_rate_limit(self, domain: str, requests_per_second: float) -> None:
        """Set rate limit for a domain."""
        self.rate_limits[domain] = requests_per_second
        console.print(f"[green]Set rate limit for {domain}:[/] {requests_per_second} requests/second")
        self.save_config()

    def check_rate_limit(self, domain: str) -> bool:
        """Check if a request to a domain should be rate limited."""
        if domain not in self.rate_limits:
            return True
        
        current_time = time.time()
        if domain not in self.last_request_time:
            self.last_request_time[domain] = current_time
            return True
        
        time_diff = current_time - self.last_request_time[domain]
        min_interval = 1.0 / self.rate_limits[domain]
        
        if time_diff < min_interval:
            time.sleep(min_interval - time_diff)
        
        self.last_request_time[domain] = time.time()
        return True

    def _get_proxy_url(self, proxy_name: str) -> str:
        """Get proxy URL for a specific proxy."""
        proxy = self.proxies[proxy_name]
        return f"{proxy['type']}://{proxy['host']}:{proxy['port']}"

    def _setup_proxy_chain(self, chain: List[dict]) -> Dict:
        """Setup a chain of proxies."""
        if not chain:
            return {}
        
        proxies = {}
        for i, proxy in enumerate(chain):
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
            self.check_rate_limit(urlparse(url).netloc)
            
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
            self.check_rate_limit(urlparse(url).netloc)
            
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
        """Display current privacy settings."""
        table = Table(title="Privacy Status")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        
        # User Agent
        table.add_row("Current User-Agent", self.current_user_agent)
        
        # Proxies
        proxy_count = len(self.proxies)
        table.add_row("Configured Proxies", str(proxy_count))
        
        # Proxy Chains
        chain_count = len(self.proxy_chains)
        table.add_row("Active Proxy Chains", str(chain_count))
        
        # Rate Limits
        rate_limits = ", ".join(f"{domain}: {rate}/s" for domain, rate in self.rate_limits.items())
        table.add_row("Rate Limits", rate_limits or "None")
        
        console.print(table)

    def get_session(self) -> requests.Session:
        """Get a requests session with current privacy settings."""
        session = requests.Session()
        session.headers.update({'User-Agent': self.current_user_agent})
        
        # Apply proxy if configured
        if self.proxy_chains:
            # Use the first proxy chain
            chain = self.proxy_chains[0]
            if chain:
                proxy = chain[0]  # Use the first proxy in the chain
                session.proxies = {
                    'http': f"{proxy['type']}://{proxy['host']}:{proxy['port']}",
                    'https': f"{proxy['type']}://{proxy['host']}:{proxy['port']}"
                }
        
        return session 