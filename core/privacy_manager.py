"""
Privacy Manager Module for E502 OSINT Terminal
Provides comprehensive privacy and anonymity features.
"""

import requests
import random
import json
import logging
import time
import socket
import ssl
import urllib3
import aiohttp
import asyncio
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import os
import sys
import platform
import hashlib
import base64
import urllib.parse
from functools import wraps
import signal
from contextlib import contextmanager
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("E502OSINT.PrivacyManager")
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

class PrivacyManager:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.proxies = []
        self.current_proxy = None
        self.user_agents = []
        self.current_user_agent = None
        self.timeout = 30
        self.retry_count = 3
        self.retry_delay = 1
        self.proxy_chain = []
        self.proxy_rotation_interval = 300  # 5 minutes
        self.last_proxy_rotation = 0
        self.user_agent_rotation_interval = 60  # 1 minute
        self.last_user_agent_rotation = 0
        self._load_user_agents()
        self._load_proxies()

    def _load_user_agents(self) -> None:
        """Load user agents from file or default list."""
        try:
            # Try to load from file
            if os.path.exists('data/user_agents.json'):
                with open('data/user_agents.json', 'r') as f:
                    self.user_agents = json.load(f)
            else:
                # Use default list
                self.user_agents = [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
                    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.254',
                    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
                    'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
                    'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
                    'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36'
                ]
        except Exception as e:
            logger.error(f"Error loading user agents: {str(e)}")
            self.user_agents = []

    def _load_proxies(self) -> None:
        """Load proxies from file or API."""
        try:
            # Try to load from file
            if os.path.exists('data/proxies.json'):
                with open('data/proxies.json', 'r') as f:
                    self.proxies = json.load(f)
            else:
                # Use default list
                self.proxies = [
                    'http://proxy1.example.com:8080',
                    'http://proxy2.example.com:8080',
                    'http://proxy3.example.com:8080'
                ]
        except Exception as e:
            logger.error(f"Error loading proxies: {str(e)}")
            self.proxies = []

    @handle_timeout
    def rotate_proxy(self) -> None:
        """Rotate to a new proxy."""
        try:
            if not self.proxies:
                logger.warning("No proxies available")
                return

            # Check if it's time to rotate
            current_time = time.time()
            if current_time - self.last_proxy_rotation < self.proxy_rotation_interval:
                return

            # Select a new proxy
            new_proxy = random.choice(self.proxies)
            while new_proxy == self.current_proxy and len(self.proxies) > 1:
                new_proxy = random.choice(self.proxies)

            # Test the proxy
            if self._test_proxy(new_proxy):
                self.current_proxy = new_proxy
                self.session.proxies = {
                    'http': new_proxy,
                    'https': new_proxy
                }
                self.last_proxy_rotation = current_time
                logger.info(f"Rotated to new proxy: {new_proxy}")
            else:
                logger.warning(f"Proxy test failed: {new_proxy}")
        except Exception as e:
            logger.error(f"Error rotating proxy: {str(e)}")

    @handle_timeout
    def rotate_user_agent(self) -> None:
        """Rotate to a new user agent."""
        try:
            if not self.user_agents:
                logger.warning("No user agents available")
                return

            # Check if it's time to rotate
            current_time = time.time()
            if current_time - self.last_user_agent_rotation < self.user_agent_rotation_interval:
                return

            # Select a new user agent
            new_user_agent = random.choice(self.user_agents)
            while new_user_agent == self.current_user_agent and len(self.user_agents) > 1:
                new_user_agent = random.choice(self.user_agents)

            self.current_user_agent = new_user_agent
            self.session.headers.update({'User-Agent': new_user_agent})
            self.last_user_agent_rotation = current_time
            logger.info(f"Rotated to new user agent: {new_user_agent}")
        except Exception as e:
            logger.error(f"Error rotating user agent: {str(e)}")

    @handle_timeout
    def _test_proxy(self, proxy: str) -> bool:
        """Test if a proxy is working."""
        try:
            test_url = 'https://api.ipify.org?format=json'
            proxies = {
                'http': proxy,
                'https': proxy
            }
            response = requests.get(test_url, proxies=proxies, timeout=self.timeout)
            return response.status_code == 200
        except:
            return False

    @handle_timeout
    def setup_proxy_chain(self, chain: List[str]) -> None:
        """Set up a chain of proxies."""
        try:
            if not chain:
                logger.warning("No proxies in chain")
                return

            # Test each proxy in the chain
            working_proxies = []
            for proxy in chain:
                if self._test_proxy(proxy):
                    working_proxies.append(proxy)
                else:
                    logger.warning(f"Proxy test failed: {proxy}")

            if working_proxies:
                self.proxy_chain = working_proxies
                self.current_proxy = working_proxies[0]
                self.session.proxies = {
                    'http': self.current_proxy,
                    'https': self.current_proxy
                }
                logger.info(f"Set up proxy chain with {len(working_proxies)} working proxies")
            else:
                logger.warning("No working proxies in chain")
        except Exception as e:
            logger.error(f"Error setting up proxy chain: {str(e)}")

    @handle_timeout
    def rotate_proxy_chain(self) -> None:
        """Rotate through the proxy chain."""
        try:
            if not self.proxy_chain:
                logger.warning("No proxy chain available")
                return

            # Check if it's time to rotate
            current_time = time.time()
            if current_time - self.last_proxy_rotation < self.proxy_rotation_interval:
                return

            # Get current proxy index
            current_index = self.proxy_chain.index(self.current_proxy) if self.current_proxy in self.proxy_chain else -1

            # Select next proxy
            next_index = (current_index + 1) % len(self.proxy_chain)
            new_proxy = self.proxy_chain[next_index]

            # Test the proxy
            if self._test_proxy(new_proxy):
                self.current_proxy = new_proxy
                self.session.proxies = {
                    'http': new_proxy,
                    'https': new_proxy
                }
                self.last_proxy_rotation = current_time
                logger.info(f"Rotated to next proxy in chain: {new_proxy}")
            else:
                logger.warning(f"Proxy test failed: {new_proxy}")
        except Exception as e:
            logger.error(f"Error rotating proxy chain: {str(e)}")

    @handle_timeout
    def add_proxy(self, proxy: str) -> None:
        """Add a new proxy to the list."""
        try:
            if proxy in self.proxies:
                logger.warning(f"Proxy already exists: {proxy}")
                return

            # Test the proxy
            if self._test_proxy(proxy):
                self.proxies.append(proxy)
                logger.info(f"Added new proxy: {proxy}")
            else:
                logger.warning(f"Proxy test failed: {proxy}")
        except Exception as e:
            logger.error(f"Error adding proxy: {str(e)}")

    @handle_timeout
    def remove_proxy(self, proxy: str) -> None:
        """Remove a proxy from the list."""
        try:
            if proxy not in self.proxies:
                logger.warning(f"Proxy not found: {proxy}")
                return

            self.proxies.remove(proxy)
            if proxy == self.current_proxy:
                self.current_proxy = None
                self.session.proxies = {}
            logger.info(f"Removed proxy: {proxy}")
        except Exception as e:
            logger.error(f"Error removing proxy: {str(e)}")

    @handle_timeout
    def add_user_agent(self, user_agent: str) -> None:
        """Add a new user agent to the list."""
        try:
            if user_agent in self.user_agents:
                logger.warning(f"User agent already exists: {user_agent}")
                return

            self.user_agents.append(user_agent)
            logger.info(f"Added new user agent: {user_agent}")
        except Exception as e:
            logger.error(f"Error adding user agent: {str(e)}")

    @handle_timeout
    def remove_user_agent(self, user_agent: str) -> None:
        """Remove a user agent from the list."""
        try:
            if user_agent not in self.user_agents:
                logger.warning(f"User agent not found: {user_agent}")
                return

            self.user_agents.remove(user_agent)
            if user_agent == self.current_user_agent:
                self.current_user_agent = None
                self.session.headers.pop('User-Agent', None)
            logger.info(f"Removed user agent: {user_agent}")
        except Exception as e:
            logger.error(f"Error removing user agent: {str(e)}")

    @handle_timeout
    def get_current_proxy(self) -> Optional[str]:
        """Get the current proxy."""
        return self.current_proxy

    @handle_timeout
    def get_current_user_agent(self) -> Optional[str]:
        """Get the current user agent."""
        return self.current_user_agent

    @handle_timeout
    def get_proxy_list(self) -> List[str]:
        """Get the list of proxies."""
        return self.proxies

    @handle_timeout
    def get_user_agent_list(self) -> List[str]:
        """Get the list of user agents."""
        return self.user_agents

    @handle_timeout
    def get_proxy_chain(self) -> List[str]:
        """Get the current proxy chain."""
        return self.proxy_chain

    @handle_timeout
    def clear_proxy_chain(self) -> None:
        """Clear the proxy chain."""
        try:
            self.proxy_chain = []
            self.current_proxy = None
            self.session.proxies = {}
            logger.info("Cleared proxy chain")
        except Exception as e:
            logger.error(f"Error clearing proxy chain: {str(e)}")

    @handle_timeout
    def save_proxies(self) -> None:
        """Save proxies to file."""
        try:
            os.makedirs('data', exist_ok=True)
            with open('data/proxies.json', 'w') as f:
                json.dump(self.proxies, f)
            logger.info("Saved proxies to file")
        except Exception as e:
            logger.error(f"Error saving proxies: {str(e)}")

    @handle_timeout
    def save_user_agents(self) -> None:
        """Save user agents to file."""
        try:
            os.makedirs('data', exist_ok=True)
            with open('data/user_agents.json', 'w') as f:
                json.dump(self.user_agents, f)
            logger.info("Saved user agents to file")
        except Exception as e:
            logger.error(f"Error saving user agents: {str(e)}")

    @handle_timeout
    def load_proxies(self) -> None:
        """Load proxies from file."""
        try:
            if os.path.exists('data/proxies.json'):
                with open('data/proxies.json', 'r') as f:
                    self.proxies = json.load(f)
                logger.info("Loaded proxies from file")
            else:
                logger.warning("Proxies file not found")
        except Exception as e:
            logger.error(f"Error loading proxies: {str(e)}")

    @handle_timeout
    def load_user_agents(self) -> None:
        """Load user agents from file."""
        try:
            if os.path.exists('data/user_agents.json'):
                with open('data/user_agents.json', 'r') as f:
                    self.user_agents = json.load(f)
                logger.info("Loaded user agents from file")
            else:
                logger.warning("User agents file not found")
        except Exception as e:
            logger.error(f"Error loading user agents: {str(e)}")

    @handle_timeout
    def update_proxy_rotation_interval(self, interval: int) -> None:
        """Update the proxy rotation interval."""
        try:
            if interval < 0:
                logger.warning("Invalid interval: must be positive")
                return

            self.proxy_rotation_interval = interval
            logger.info(f"Updated proxy rotation interval to {interval} seconds")
        except Exception as e:
            logger.error(f"Error updating proxy rotation interval: {str(e)}")

    @handle_timeout
    def update_user_agent_rotation_interval(self, interval: int) -> None:
        """Update the user agent rotation interval."""
        try:
            if interval < 0:
                logger.warning("Invalid interval: must be positive")
                return

            self.user_agent_rotation_interval = interval
            logger.info(f"Updated user agent rotation interval to {interval} seconds")
        except Exception as e:
            logger.error(f"Error updating user agent rotation interval: {str(e)}")

    @handle_timeout
    def get_proxy_rotation_interval(self) -> int:
        """Get the current proxy rotation interval."""
        return self.proxy_rotation_interval

    @handle_timeout
    def get_user_agent_rotation_interval(self) -> int:
        """Get the current user agent rotation interval."""
        return self.user_agent_rotation_interval

    @handle_timeout
    def get_last_proxy_rotation(self) -> float:
        """Get the timestamp of the last proxy rotation."""
        return self.last_proxy_rotation

    @handle_timeout
    def get_last_user_agent_rotation(self) -> float:
        """Get the timestamp of the last user agent rotation."""
        return self.last_user_agent_rotation

    @handle_timeout
    def get_session(self) -> requests.Session:
        """Get the current session."""
        return self.session

    @handle_timeout
    def update_session(self, session: requests.Session) -> None:
        """Update the current session."""
        try:
            self.session = session
            logger.info("Updated session")
        except Exception as e:
            logger.error(f"Error updating session: {str(e)}")

    @handle_timeout
    def clear_session(self) -> None:
        """Clear the current session."""
        try:
            self.session = requests.Session()
            self.session.verify = False
            logger.info("Cleared session")
        except Exception as e:
            logger.error(f"Error clearing session: {str(e)}")

    @handle_timeout
    def update_timeout(self, timeout: int) -> None:
        """Update the timeout value."""
        try:
            if timeout < 0:
                logger.warning("Invalid timeout: must be positive")
                return

            self.timeout = timeout
            logger.info(f"Updated timeout to {timeout} seconds")
        except Exception as e:
            logger.error(f"Error updating timeout: {str(e)}")

    @handle_timeout
    def update_retry_count(self, count: int) -> None:
        """Update the retry count."""
        try:
            if count < 0:
                logger.warning("Invalid retry count: must be positive")
                return

            self.retry_count = count
            logger.info(f"Updated retry count to {count}")
        except Exception as e:
            logger.error(f"Error updating retry count: {str(e)}")

    @handle_timeout
    def update_retry_delay(self, delay: int) -> None:
        """Update the retry delay."""
        try:
            if delay < 0:
                logger.warning("Invalid retry delay: must be positive")
                return

            self.retry_delay = delay
            logger.info(f"Updated retry delay to {delay} seconds")
        except Exception as e:
            logger.error(f"Error updating retry delay: {str(e)}")

    @handle_timeout
    def get_timeout(self) -> int:
        """Get the current timeout value."""
        return self.timeout

    @handle_timeout
    def get_retry_count(self) -> int:
        """Get the current retry count."""
        return self.retry_count

    @handle_timeout
    def get_retry_delay(self) -> int:
        """Get the current retry delay."""
        return self.retry_delay

# Create global instance
privacy_manager = PrivacyManager() 