"""
Scan Engine for E502 OSINT Terminal
Provides comprehensive scan execution capabilities.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import pytz
from pathlib import Path
import asyncio
import aiohttp
import socket
import ssl
import nmap
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
import yaml
import hashlib
import platform
from dataclasses import dataclass, asdict
import time
from aiohttp import ClientTimeout
from asyncio import Semaphore
import backoff

# Import managers
from core.scan.scan_profile_manager import ScanProfileManager
from core.scan.scan_result_manager import ScanResultManager
from core.scan.notification_manager import NotificationManager
from core.scan.scan_config_manager import ScanConfigManager

logger = logging.getLogger("E502OSINT.ScanEngine")
console = Console()

# Initialize managers
scan_profile_manager = ScanProfileManager()
scan_result_manager = ScanResultManager()
notification_manager = NotificationManager()
scan_config_manager = ScanConfigManager()

@dataclass
class ScanFinding:
    """Data class for storing scan findings."""
    finding_id: str
    title: str
    description: str
    severity: str
    category: str
    evidence: Dict[str, Any]
    recommendation: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None

class ScanEngine:
    def __init__(self):
        self.scan_dir = Path("scans")
        self.temp_dir = self.scan_dir / "temp"
        self._ensure_dirs()
        
        # Initialize nmap scanner with error handling
        try:
            self.nm = nmap.PortScanner()
        except Exception as e:
            logger.error(f"Failed to initialize nmap scanner: {str(e)}")
            self.nm = None
        
        # Initialize session with proper timeout and retry settings
        timeout = ClientTimeout(total=300)  # 5 minutes total timeout
        self.session = aiohttp.ClientSession(timeout=timeout)
        
        # Initialize rate limiting
        self.rate_limits = {}
        self.rate_limit_semaphores = {}
        
        # Initialize scan cache
        self.scan_cache = {}
        self.cache_ttl = 3600  # 1 hour cache TTL
        
        # Initialize scan state
        self.paused_scans = set()
        self.scan_priorities = {}
        
        # Initialize concurrent scan limit
        self.max_concurrent_scans = 5
        self.concurrent_scan_semaphore = Semaphore(self.max_concurrent_scans)
        
        # Enhanced error handling
        self.error_handlers = {
            "network": self._handle_network_error,
            "web": self._handle_web_error,
            "ssl": self._handle_ssl_error,
            "vulnerability": self._handle_vulnerability_error
        }
        self.error_retry_delays = {
            "network": [1, 5, 15],  # seconds
            "web": [2, 10, 30],
            "ssl": [1, 5, 15],
            "vulnerability": [5, 15, 45]
        }
        self.max_retries = 3
        self.error_counts = {}
        
        # Load configuration
        self.config = scan_config_manager.load_config()
        
        # Initialize scan profiles
        self.profiles = scan_profile_manager.load_profiles()
        
        # Initialize result storage
        self.results = scan_result_manager.load_results()
    
    def __del__(self):
        """Cleanup resources."""
        if hasattr(self, 'session') and not self.session.closed:
            asyncio.create_task(self.session.close())
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
    
    def set_rate_limit(self, domain: str, requests_per_second: float) -> None:
        """Set rate limit for a domain."""
        self.rate_limits[domain] = requests_per_second
        self.rate_limit_semaphores[domain] = Semaphore(1)
    
    def set_scan_priority(self, scan_id: str, priority: int) -> None:
        """Set priority for a scan (higher number = higher priority)."""
        self.scan_priorities[scan_id] = priority
    
    def pause_scan(self, scan_id: str) -> None:
        """Pause a running scan."""
        self.paused_scans.add(scan_id)
    
    def resume_scan(self, scan_id: str) -> None:
        """Resume a paused scan."""
        self.paused_scans.discard(scan_id)
    
    def clear_cache(self) -> None:
        """Clear the scan cache."""
        self.scan_cache.clear()
    
    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    async def execute_scan(self, profile_name: str, target: str) -> Optional[str]:
        """Execute a scan using a profile with retry logic."""
        try:
            # Check cache first
            cache_key = f"{profile_name}:{target}"
            if cache_key in self.scan_cache:
                cache_entry = self.scan_cache[cache_key]
                if time.time() - cache_entry['timestamp'] < self.cache_ttl:
                    return cache_entry['result_id']
            
            # Acquire concurrent scan semaphore
            async with self.concurrent_scan_semaphore:
                # Get profile
                profile = scan_profile_manager.get_profile(profile_name)
                if not profile:
                    logger.error(f"Profile not found: {profile_name}")
                    return None
                
                # Create result
                result = ScanResult(
                    result_id=hashlib.md5(f"{profile_name}{target}{datetime.now().isoformat()}".encode()).hexdigest(),
                    profile_name=profile_name,
                    target=target,
                    scan_type=profile.scan_type,
                    start_time=datetime.now(pytz.UTC),
                    end_time=None,
                    status="running",
                    findings=[],
                    summary={},
                    metadata={
                        "profile_options": profile.options,
                        "platform": platform.platform(),
                        "python_version": platform.python_version()
                    }
                )
                
                # Add result
                scan_result_manager.add_result(result)
                
                try:
                    # Check if scan is paused
                    while result.result_id in self.paused_scans:
                        await asyncio.sleep(1)
                    
                    # Execute scan based on type
                    if profile.scan_type == "network":
                        findings = await self._execute_with_retry("network", target, profile.options, self._execute_network_scan)
                    elif profile.scan_type == "web":
                        findings = await self._execute_with_retry("web", target, profile.options, self._execute_web_scan)
                    elif profile.scan_type == "ssl":
                        findings = await self._execute_with_retry("ssl", target, profile.options, self._execute_ssl_scan)
                    elif profile.scan_type == "vulnerability":
                        findings = await self._execute_with_retry("vulnerability", target, profile.options, self._execute_vulnerability_scan)
                    else:
                        raise ValueError(f"Unsupported scan type: {profile.scan_type}")
                    
                    # Update result
                    result.findings = findings
                    result.status = "completed"
                    result.end_time = datetime.now(pytz.UTC)
                    result.summary = self._generate_summary(findings)
                    
                    # Update result
                    scan_result_manager.update_result(result.result_id, asdict(result))
                    
                    # Cache result
                    self.scan_cache[cache_key] = {
                        'result_id': result.result_id,
                        'timestamp': time.time()
                    }
                    
                    # Send notifications
                    if profile.notifications:
                        if profile.notifications.get("discord"):
                            await notification_manager.send_notification(
                                "discord",
                                f"Scan Completed: {profile_name}",
                                f"Target: {target}\nType: {profile.scan_type}\nFindings: {len(findings)}",
                                "success",
                                {
                                    "result_id": result.result_id,
                                    "profile_name": profile_name,
                                    "target": target,
                                    "scan_type": profile.scan_type,
                                    "findings_count": len(findings)
                                }
                            )
                    
                    return result.result_id
                    
                except Exception as e:
                    # Update result with error
                    result.status = "failed"
                    result.error = str(e)
                    result.end_time = datetime.now(pytz.UTC)
                    scan_result_manager.update_result(result.result_id, asdict(result))
                    
                    # Send error notification
                    if profile.notifications:
                        if profile.notifications.get("discord"):
                            await notification_manager.send_notification(
                                "discord",
                                f"Scan Failed: {profile_name}",
                                f"Target: {target}\nType: {profile.scan_type}\nError: {str(e)}",
                                "error",
                                {
                                    "result_id": result.result_id,
                                    "profile_name": profile_name,
                                    "target": target,
                                    "scan_type": profile.scan_type,
                                    "error": str(e)
                                }
                            )
                    
                    raise  # Re-raise for backoff retry
                
        except Exception as e:
            logger.error(f"Error executing scan: {str(e)}")
            return None
    
    async def _handle_network_error(self, error: Exception, target: str, retry_count: int) -> bool:
        """Handle network-related errors with retry logic."""
        error_key = f"network:{target}"
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
        
        if retry_count >= self.max_retries:
            logger.error(f"Max retries exceeded for network scan of {target}: {str(error)}")
            return False
            
        delay = self.error_retry_delays["network"][min(retry_count, len(self.error_retry_delays["network"]) - 1)]
        logger.warning(f"Network error for {target}, retrying in {delay} seconds: {str(error)}")
        await asyncio.sleep(delay)
        return True

    async def _handle_web_error(self, error: Exception, target: str, retry_count: int) -> bool:
        """Handle web-related errors with retry logic."""
        error_key = f"web:{target}"
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
        
        if retry_count >= self.max_retries:
            logger.error(f"Max retries exceeded for web scan of {target}: {str(error)}")
            return False
            
        delay = self.error_retry_delays["web"][min(retry_count, len(self.error_retry_delays["web"]) - 1)]
        logger.warning(f"Web error for {target}, retrying in {delay} seconds: {str(error)}")
        await asyncio.sleep(delay)
        return True

    async def _handle_ssl_error(self, error: Exception, target: str, retry_count: int) -> bool:
        """Handle SSL-related errors with retry logic."""
        error_key = f"ssl:{target}"
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
        
        if retry_count >= self.max_retries:
            logger.error(f"Max retries exceeded for SSL scan of {target}: {str(error)}")
            return False
            
        delay = self.error_retry_delays["ssl"][min(retry_count, len(self.error_retry_delays["ssl"]) - 1)]
        logger.warning(f"SSL error for {target}, retrying in {delay} seconds: {str(error)}")
        await asyncio.sleep(delay)
        return True

    async def _handle_vulnerability_error(self, error: Exception, target: str, retry_count: int) -> bool:
        """Handle vulnerability scan errors with retry logic."""
        error_key = f"vulnerability:{target}"
        self.error_counts[error_key] = self.error_counts.get(error_key, 0) + 1
        
        if retry_count >= self.max_retries:
            logger.error(f"Max retries exceeded for vulnerability scan of {target}: {str(error)}")
            return False
            
        delay = self.error_retry_delays["vulnerability"][min(retry_count, len(self.error_retry_delays["vulnerability"]) - 1)]
        logger.warning(f"Vulnerability scan error for {target}, retrying in {delay} seconds: {str(error)}")
        await asyncio.sleep(delay)
        return True

    async def _execute_with_retry(self, scan_type: str, target: str, options: Dict[str, Any], 
                                scan_func: callable) -> List[ScanFinding]:
        """Execute a scan function with retry logic."""
        retry_count = 0
        last_error = None
        
        while retry_count <= self.max_retries:
            try:
                # Check if scan is paused
                while target in self.paused_scans:
                    await asyncio.sleep(1)
                
                # Execute scan
                findings = await scan_func(target, options)
                return findings
                
            except Exception as e:
                last_error = e
                retry_count += 1
                
                # Handle error based on scan type
                if scan_type in self.error_handlers:
                    should_retry = await self.error_handlers[scan_type](e, target, retry_count)
                    if not should_retry:
                        break
                else:
                    logger.error(f"Unknown scan type {scan_type} for target {target}")
                    break
        
        # If we get here, all retries failed
        error_msg = f"Failed to execute {scan_type} scan for {target} after {retry_count} retries"
        if last_error:
            error_msg += f": {str(last_error)}"
        logger.error(error_msg)
        
        # Create error finding
        return [ScanFinding(
            finding_id=hashlib.md5(f"error:{target}:{time.time()}".encode()).hexdigest(),
            title=f"{scan_type.capitalize()} Scan Failed",
            description=error_msg,
            severity="error",
            category="scan_error",
            evidence={"error": str(last_error) if last_error else "Unknown error"},
            recommendation="Check target availability and scan configuration"
        )]
    
    async def _execute_network_scan(self, target: str, options: Dict[str, Any]) -> List[ScanFinding]:
        """Execute network scan with enhanced error handling and resource management."""
        findings = []
        
        try:
            # Validate target
            if not target:
                raise ValueError("Target cannot be empty")
            
            # Check if nmap is available
            if not self.nm:
                raise RuntimeError("Nmap scanner not initialized")
            
            # Get scan options
            ports = options.get("ports", "1-1000")
            scan_type = options.get("scan_type", "-sS")
            timing = options.get("timing", "-T4")
            
            # Execute scan with timeout
            try:
                scan_result = await asyncio.wait_for(
                    asyncio.to_thread(
                        self.nm.scan,
                        target,
                        f"{scan_type} {timing} -p {ports}"
                    ),
                    timeout=300  # 5 minutes timeout
                )
            except asyncio.TimeoutError:
                raise TimeoutError(f"Network scan timed out for {target}")
            
            # Process results
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        state = self.nm[host][proto][port]["state"]
                        service = self.nm[host][proto][port].get("name", "unknown")
                        version = self.nm[host][proto][port].get("version", "unknown")
                        
                        # Create finding
                        finding = ScanFinding(
                            finding_id=hashlib.md5(f"{host}:{port}:{time.time()}".encode()).hexdigest(),
                            title=f"Port {port} ({service}) is {state}",
                            description=f"Port {port} running {service} {version} is {state}",
                            severity="info" if state == "closed" else "medium",
                            category="network",
                            evidence={
                                "host": host,
                                "port": port,
                                "protocol": proto,
                                "service": service,
                                "version": version,
                                "state": state
                            },
                            recommendation="Review open ports and services for security implications"
                        )
                        findings.append(finding)
            
            return findings
            
        except Exception as e:
            logger.error(f"Error in network scan for {target}: {str(e)}")
            raise
    
    async def _execute_web_scan(self, target: str, options: Dict[str, Any]) -> List[ScanFinding]:
        """Execute web scan with enhanced error handling and resource management."""
        findings = []
        
        try:
            # Validate target
            if not target:
                raise ValueError("Target cannot be empty")
            
            # Ensure target has protocol
            if not target.startswith(("http://", "https://")):
                target = f"https://{target}"
            
            # Get scan options
            timeout = options.get("timeout", 30)
            verify_ssl = options.get("verify_ssl", True)
            headers = options.get("headers", {})
            
            # Execute scan with timeout
            try:
                async with self.session.get(
                    target,
                    timeout=timeout,
                    ssl=verify_ssl,
                    headers=headers
                ) as response:
                    # Check response
                    if response.status != 200:
                        finding = ScanFinding(
                            finding_id=hashlib.md5(f"{target}:{time.time()}".encode()).hexdigest(),
                            title=f"HTTP {response.status} Response",
                            description=f"Target returned HTTP {response.status}",
                            severity="warning",
                            category="web",
                            evidence={
                                "url": target,
                                "status": response.status,
                                "headers": dict(response.headers)
                            },
                            recommendation="Check server configuration and availability"
                        )
                        findings.append(finding)
                    
                    # Get content
                    content = await response.text()
                    
                    # Parse with BeautifulSoup
                    soup = BeautifulSoup(content, "html.parser")
                    
                    # Check for common security headers
                    security_headers = {
                        "X-Frame-Options": "Missing X-Frame-Options header",
                        "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                        "X-XSS-Protection": "Missing X-XSS-Protection header",
                        "Content-Security-Policy": "Missing Content-Security-Policy header",
                        "Strict-Transport-Security": "Missing HSTS header"
                    }
                    
                    for header, message in security_headers.items():
                        if header not in response.headers:
                            finding = ScanFinding(
                                finding_id=hashlib.md5(f"{target}:{header}:{time.time()}".encode()).hexdigest(),
                                title=message,
                                description=f"Security header {header} is not set",
                                severity="medium",
                                category="web",
                                evidence={
                                    "url": target,
                                    "missing_header": header,
                                    "headers": dict(response.headers)
                                },
                                recommendation=f"Implement {header} header"
                            )
                            findings.append(finding)
                    
                    # Check for forms
                    forms = soup.find_all("form")
                    for form in forms:
                        if not form.get("action"):
                            finding = ScanFinding(
                                finding_id=hashlib.md5(f"{target}:form:{time.time()}".encode()).hexdigest(),
                                title="Form Missing Action",
                                description="Form found without action attribute",
                                severity="low",
                                category="web",
                                evidence={
                                    "url": target,
                                    "form": str(form)
                                },
                                recommendation="Add action attribute to form"
                            )
                            findings.append(finding)
                    
                    return findings
                    
            except asyncio.TimeoutError:
                raise TimeoutError(f"Web scan timed out for {target}")
            except aiohttp.ClientError as e:
                raise ConnectionError(f"Failed to connect to {target}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error in web scan for {target}: {str(e)}")
            raise
    
    async def _execute_ssl_scan(self, target: str, options: Dict[str, Any]) -> List[ScanFinding]:
        """Execute SSL scan with enhanced error handling and resource management."""
        findings = []
        
        try:
            # Validate target
            if not target:
                raise ValueError("Target cannot be empty")
            
            # Ensure target has protocol
            if not target.startswith(("http://", "https://")):
                target = f"https://{target}"
            
            # Get scan options
            timeout = options.get("timeout", 30)
            verify_ssl = options.get("verify_ssl", True)
            
            # Create SSL context
            context = ssl.create_default_context()
            if not verify_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            # Execute scan with timeout
            try:
                hostname = target.split("://")[1]
                async with self.session.get(
                    target,
                    timeout=timeout,
                    ssl=context
                ) as response:
                    # Get SSL info
                    ssl_info = response.connection.transport.get_extra_info("ssl_object")
                    if not ssl_info:
                        raise ValueError("No SSL information available")
                    
                    # Check certificate
                    cert = ssl_info.getpeercert()
                    if not cert:
                        finding = ScanFinding(
                            finding_id=hashlib.md5(f"{target}:cert:{time.time()}".encode()).hexdigest(),
                            title="Invalid SSL Certificate",
                            description="No valid SSL certificate found",
                            severity="high",
                            category="ssl",
                            evidence={
                                "url": target,
                                "ssl_info": str(ssl_info)
                            },
                            recommendation="Install valid SSL certificate"
                        )
                        findings.append(finding)
                    else:
                        # Check certificate expiration
                        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        if not_after < datetime.now():
                            finding = ScanFinding(
                                finding_id=hashlib.md5(f"{target}:expired:{time.time()}".encode()).hexdigest(),
                                title="Expired SSL Certificate",
                                description=f"SSL certificate expired on {not_after}",
                                severity="high",
                                category="ssl",
                                evidence={
                                    "url": target,
                                    "expiration": not_after.isoformat(),
                                    "cert": cert
                                },
                                recommendation="Renew SSL certificate"
                            )
                            findings.append(finding)
                    
                    # Check protocol version
                    protocol = ssl_info.version()
                    if protocol in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                        finding = ScanFinding(
                            finding_id=hashlib.md5(f"{target}:protocol:{time.time()}".encode()).hexdigest(),
                            title=f"Outdated SSL Protocol: {protocol}",
                            description=f"Server is using outdated SSL protocol {protocol}",
                            severity="high",
                            category="ssl",
                            evidence={
                                "url": target,
                                "protocol": protocol
                            },
                            recommendation="Upgrade to TLS 1.2 or higher"
                        )
                        findings.append(finding)
                    
                    return findings
                    
            except asyncio.TimeoutError:
                raise TimeoutError(f"SSL scan timed out for {target}")
            except ssl.SSLError as e:
                raise ConnectionError(f"SSL error for {target}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error in SSL scan for {target}: {str(e)}")
            raise
    
    async def _execute_vulnerability_scan(self, target: str, options: Dict[str, Any]) -> List[ScanFinding]:
        """Execute vulnerability scan with enhanced error handling and resource management."""
        findings = []
        
        try:
            # Validate target
            if not target:
                raise ValueError("Target cannot be empty")
            
            # Get scan options
            timeout = options.get("timeout", 30)
            verify_ssl = options.get("verify_ssl", True)
            headers = options.get("headers", {})
            
            # Ensure target has protocol
            if not target.startswith(("http://", "https://")):
                target = f"https://{target}"
            
            # Execute scan with timeout
            try:
                async with self.session.get(
                    target,
                    timeout=timeout,
                    ssl=verify_ssl,
                    headers=headers
                ) as response:
                    # Check for common vulnerabilities
                    
                    # Check for directory listing
                    if "Index of /" in await response.text():
                        finding = ScanFinding(
                            finding_id=hashlib.md5(f"{target}:dirlist:{time.time()}".encode()).hexdigest(),
                            title="Directory Listing Enabled",
                            description="Server has directory listing enabled",
                            severity="high",
                            category="vulnerability",
                            evidence={
                                "url": target,
                                "response": await response.text()
                            },
                            recommendation="Disable directory listing"
                        )
                        findings.append(finding)
                    
                    # Check for server information disclosure
                    server = response.headers.get("Server")
                    if server:
                        finding = ScanFinding(
                            finding_id=hashlib.md5(f"{target}:server:{time.time()}".encode()).hexdigest(),
                            title="Server Information Disclosure",
                            description=f"Server header reveals: {server}",
                            severity="low",
                            category="vulnerability",
                            evidence={
                                "url": target,
                                "server": server
                            },
                            recommendation="Remove or obfuscate Server header"
                        )
                        findings.append(finding)
                    
                    # Check for X-Powered-By header
                    powered_by = response.headers.get("X-Powered-By")
                    if powered_by:
                        finding = ScanFinding(
                            finding_id=hashlib.md5(f"{target}:powered:{time.time()}".encode()).hexdigest(),
                            title="Technology Information Disclosure",
                            description=f"X-Powered-By header reveals: {powered_by}",
                            severity="low",
                            category="vulnerability",
                            evidence={
                                "url": target,
                                "powered_by": powered_by
                            },
                            recommendation="Remove X-Powered-By header"
                        )
                        findings.append(finding)
                    
                    return findings
                    
            except asyncio.TimeoutError:
                raise TimeoutError(f"Vulnerability scan timed out for {target}")
            except aiohttp.ClientError as e:
                raise ConnectionError(f"Failed to connect to {target}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error in vulnerability scan for {target}: {str(e)}")
            raise
    
    def _generate_summary(self, findings: List[ScanFinding]) -> Dict[str, Any]:
        """Generate a summary of findings."""
        try:
            summary = {
                "total_findings": len(findings),
                "severity_counts": {},
                "category_counts": {},
                "cve_counts": {},
                "average_cvss": 0.0
            }
            
            # Count severities and categories
            for finding in findings:
                # Count severities
                summary["severity_counts"][finding.severity] = summary["severity_counts"].get(finding.severity, 0) + 1
                
                # Count categories
                summary["category_counts"][finding.category] = summary["category_counts"].get(finding.category, 0) + 1
                
                # Count CVEs
                if finding.cve_id:
                    summary["cve_counts"][finding.cve_id] = summary["cve_counts"].get(finding.cve_id, 0) + 1
                
                # Calculate average CVSS
                if finding.cvss_score:
                    summary["average_cvss"] += finding.cvss_score
            
            # Calculate average CVSS
            if summary["average_cvss"] > 0:
                summary["average_cvss"] /= len([f for f in findings if f.cvss_score])
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating summary: {str(e)}")
            return {}

# Create global instance
scan_engine = ScanEngine() 