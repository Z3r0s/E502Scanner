"""
Scan Monitor for E502 OSINT Terminal
Provides comprehensive scan monitoring capabilities by tracking scan metrics and resource usage.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import pytz
from pathlib import Path
import pandas as pd
import numpy as np
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import asyncio
import threading
from queue import Queue
import time
from dataclasses import dataclass
import psutil
import platform
import uuid

logger = logging.getLogger("E502OSINT.ScanMonitor")
console = Console()

@dataclass
class ResourceMetrics:
    """Data class for resource metrics."""
    cpu_percent: float
    memory_percent: float
    disk_usage_percent: float
    network_io: Dict[str, float]
    timestamp: datetime

@dataclass
class ScanMetrics:
    """Data class for scan metrics."""
    scan_id: str
    profile_name: str
    target: str
    scan_type: str
    start_time: datetime
    status: str
    progress: float
    findings_count: int
    error: Optional[str] = None
    end_time: Optional[datetime] = None
    resource_usage: Optional[ResourceMetrics] = None

class ScanMonitor:
    def __init__(self):
        self.scan_dir = Path("scans")
        self._ensure_dirs()
        
        # Initialize monitoring state
        self.active_scans = {}
        self.scan_metrics = {}
        self.resource_history = []
        self.monitoring = False
        self.monitor_thread = None
        self.monitor_lock = threading.Lock()
        self.monitor_interval = 1.0  # seconds
        self.max_history = 3600  # 1 hour
        
        # Enhanced resource thresholds
        self.resource_thresholds = {
            "cpu": {
                "warning": 70.0,
                "critical": 90.0
            },
            "memory": {
                "warning": 70.0,
                "critical": 90.0
            },
            "disk": {
                "warning": 70.0,
                "critical": 90.0
            },
            "network": {
                "warning": 1000000,  # bytes per second
                "critical": 2000000
            }
        }
        
        # Alert configuration
        self.alert_channels = {
            "console": True,
            "log": True,
            "email": False,
            "discord": False
        }
        self.alert_cooldown = 300  # seconds
        self.last_alerts = {}
        
        # Performance metrics
        self.performance_metrics = {
            "scan_duration": [],
            "findings_per_scan": [],
            "resource_efficiency": [],
            "error_rate": []
        }
        
        # Initialize components
        self.logger = scan_logger
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.scan_dir.mkdir(parents=True, exist_ok=True)
    
    def start_monitoring(self) -> None:
        """Start resource monitoring."""
        try:
            with self.monitor_lock:
                if self.monitoring:
                    logger.warning("Monitoring already started")
                    return
                
                self.monitoring = True
                self.monitor_thread = threading.Thread(target=self._monitor_resources)
                self.monitor_thread.daemon = True
                self.monitor_thread.start()
                
                logger.info("Resource monitoring started")
            
        except Exception as e:
            logger.error(f"Error starting monitoring: {str(e)}")
            self.monitoring = False
    
    def stop_monitoring(self) -> None:
        """Stop resource monitoring."""
        try:
            with self.monitor_lock:
                if not self.monitoring:
                    logger.warning("Monitoring not started")
                    return
                
                self.monitoring = False
                if self.monitor_thread:
                    self.monitor_thread.join()
                
                logger.info("Resource monitoring stopped")
            
        except Exception as e:
            logger.error(f"Error stopping monitoring: {str(e)}")
    
    def add_scan(self, scan_id: str, scan_info: Dict[str, Any]) -> None:
        """Add a scan to monitoring."""
        try:
            with self.monitor_lock:
                # Create scan metrics
                metrics = ScanMetrics(
                    scan_id=scan_id,
                    profile_name=scan_info["profile_name"],
                    target=scan_info["target"],
                    scan_type=scan_info["scan_type"],
                    start_time=datetime.fromisoformat(scan_info["start_time"]),
                    status=scan_info["status"],
                    progress=0.0,
                    findings_count=0
                )
                
                # Add to active scans
                self.active_scans[scan_id] = metrics
                self.scan_metrics[scan_id] = []
                
                logger.info(f"Added scan to monitoring: {scan_id}")
            
        except Exception as e:
            logger.error(f"Error adding scan to monitoring: {str(e)}")
    
    def update_scan_status(self, scan_id: str, status: str) -> None:
        """Update scan status."""
        try:
            with self.monitor_lock:
                if scan_id not in self.active_scans:
                    logger.warning(f"Scan not found: {scan_id}")
                    return
                
                metrics = self.active_scans[scan_id]
                metrics.status = status
                
                if status in ["completed", "failed", "cancelled"]:
                    metrics.end_time = datetime.now(pytz.UTC)
                
                logger.info(f"Updated scan status: {scan_id} -> {status}")
            
        except Exception as e:
            logger.error(f"Error updating scan status: {str(e)}")
    
    def update_scan_progress(self, scan_id: str, progress: float) -> None:
        """Update scan progress."""
        try:
            with self.monitor_lock:
                if scan_id not in self.active_scans:
                    logger.warning(f"Scan not found: {scan_id}")
                    return
                
                metrics = self.active_scans[scan_id]
                metrics.progress = progress
                
                logger.debug(f"Updated scan progress: {scan_id} -> {progress:.1%}")
            
        except Exception as e:
            logger.error(f"Error updating scan progress: {str(e)}")
    
    def update_scan_findings(self, scan_id: str, findings_count: int) -> None:
        """Update scan findings count."""
        try:
            with self.monitor_lock:
                if scan_id not in self.active_scans:
                    logger.warning(f"Scan not found: {scan_id}")
                    return
                
                metrics = self.active_scans[scan_id]
                metrics.findings_count = findings_count
                
                logger.debug(f"Updated scan findings: {scan_id} -> {findings_count}")
            
        except Exception as e:
            logger.error(f"Error updating scan findings: {str(e)}")
    
    def remove_scan(self, scan_id: str) -> None:
        """Remove a scan from monitoring."""
        try:
            with self.monitor_lock:
                if scan_id not in self.active_scans:
                    logger.warning(f"Scan not found: {scan_id}")
                    return
                
                # Get final metrics
                metrics = self.active_scans[scan_id]
                if metrics.status not in ["completed", "failed", "cancelled"]:
                    metrics.status = "cancelled"
                    metrics.end_time = datetime.now(pytz.UTC)
                
                # Save metrics
                self.scan_metrics[scan_id].append(metrics)
                
                # Remove from active scans
                del self.active_scans[scan_id]
                
                logger.info(f"Removed scan from monitoring: {scan_id}")
            
        except Exception as e:
            logger.error(f"Error removing scan from monitoring: {str(e)}")
    
    def get_scan_metrics(self, scan_id: str) -> Optional[ScanMetrics]:
        """Get scan metrics."""
        try:
            with self.monitor_lock:
                if scan_id not in self.active_scans:
                    return None
                
                return self.active_scans[scan_id]
            
        except Exception as e:
            logger.error(f"Error getting scan metrics: {str(e)}")
            return None
    
    def get_active_scans(self) -> List[ScanMetrics]:
        """Get all active scans."""
        try:
            with self.monitor_lock:
                return list(self.active_scans.values())
            
        except Exception as e:
            logger.error(f"Error getting active scans: {str(e)}")
            return []
    
    def get_resource_usage(self) -> ResourceMetrics:
        """Get current resource usage."""
        try:
            # Get CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            
            # Get memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Get disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Get network I/O
            net_io = psutil.net_io_counters()
            network_io = {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv
            }
            
            return ResourceMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                disk_usage_percent=disk_percent,
                network_io=network_io,
                timestamp=datetime.now(pytz.UTC)
            )
            
        except Exception as e:
            logger.error(f"Error getting resource usage: {str(e)}")
            return None
    
    def check_resource_thresholds(self) -> bool:
        """Check if resource usage exceeds thresholds."""
        try:
            metrics = self.get_resource_usage()
            if not metrics:
                return False
            
            # Check thresholds
            if metrics.cpu_percent > self.resource_thresholds["cpu"]["critical"]:
                logger.warning(f"CPU usage exceeds critical threshold: {metrics.cpu_percent:.1f}%")
                return True
            
            if metrics.memory_percent > self.resource_thresholds["memory"]["critical"]:
                logger.warning(f"Memory usage exceeds critical threshold: {metrics.memory_percent:.1f}%")
                return True
            
            if metrics.disk_usage_percent > self.resource_thresholds["disk"]["critical"]:
                logger.warning(f"Disk usage exceeds critical threshold: {metrics.disk_usage_percent:.1f}%")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking resource thresholds: {str(e)}")
            return False
    
    def _monitor_resources(self) -> None:
        """Monitor system resources and scan performance."""
        while self.monitoring:
            try:
                # Get current resource usage
                cpu_percent = psutil.cpu_percent()
                memory_percent = psutil.virtual_memory().percent
                disk_percent = psutil.disk_usage('/').percent
                net_io = psutil.net_io_counters()
                network_io = {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv
                }
                
                # Create resource metrics
                metrics = ResourceMetrics(
                    cpu_percent=cpu_percent,
                    memory_percent=memory_percent,
                    disk_usage_percent=disk_percent,
                    network_io=network_io,
                    timestamp=datetime.now(pytz.UTC)
                )
                
                # Add to history
                self.resource_history.append(metrics)
                if len(self.resource_history) > self.max_history:
                    self.resource_history.pop(0)
                
                # Check resource thresholds
                self._check_resource_thresholds(metrics)
                
                # Update scan metrics
                self._update_scan_metrics()
                
                # Calculate performance metrics
                self._calculate_performance_metrics()
                
                # Sleep for monitoring interval
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                logger.error(f"Error monitoring resources: {str(e)}")
                time.sleep(self.monitor_interval)
    
    def _check_resource_thresholds(self, metrics: ResourceMetrics) -> None:
        """Check resource usage against thresholds and trigger alerts."""
        try:
            # Check CPU usage
            if metrics.cpu_percent >= self.resource_thresholds["cpu"]["critical"]:
                self._trigger_alert("critical", "CPU", metrics.cpu_percent)
            elif metrics.cpu_percent >= self.resource_thresholds["cpu"]["warning"]:
                self._trigger_alert("warning", "CPU", metrics.cpu_percent)
            
            # Check memory usage
            if metrics.memory_percent >= self.resource_thresholds["memory"]["critical"]:
                self._trigger_alert("critical", "Memory", metrics.memory_percent)
            elif metrics.memory_percent >= self.resource_thresholds["memory"]["warning"]:
                self._trigger_alert("warning", "Memory", metrics.memory_percent)
            
            # Check disk usage
            if metrics.disk_usage_percent >= self.resource_thresholds["disk"]["critical"]:
                self._trigger_alert("critical", "Disk", metrics.disk_usage_percent)
            elif metrics.disk_usage_percent >= self.resource_thresholds["disk"]["warning"]:
                self._trigger_alert("warning", "Disk", metrics.disk_usage_percent)
            
            # Check network usage
            total_network = metrics.network_io["bytes_sent"] + metrics.network_io["bytes_recv"]
            if total_network >= self.resource_thresholds["network"]["critical"]:
                self._trigger_alert("critical", "Network", total_network)
            elif total_network >= self.resource_thresholds["network"]["warning"]:
                self._trigger_alert("warning", "Network", total_network)
                
        except Exception as e:
            logger.error(f"Error checking resource thresholds: {str(e)}")

    def _trigger_alert(self, level: str, resource: str, value: float) -> None:
        """Trigger an alert for resource usage."""
        try:
            alert_key = f"{level}:{resource}"
            current_time = time.time()
            
            # Check alert cooldown
            if alert_key in self.last_alerts:
                if current_time - self.last_alerts[alert_key] < self.alert_cooldown:
                    return
            
            # Update last alert time
            self.last_alerts[alert_key] = current_time
            
            # Prepare alert message
            message = f"{level.upper()} ALERT: {resource} usage at {value:.1f}%"
            
            # Send alerts through configured channels
            if self.alert_channels["console"]:
                console.print(f"[{'red' if level == 'critical' else 'yellow'}]{message}[/]")
            
            if self.alert_channels["log"]:
                if level == "critical":
                    logger.critical(message)
                else:
                    logger.warning(message)
            
            if self.alert_channels["email"]:
                # TODO: Implement email alerts
                pass
            
            if self.alert_channels["discord"]:
                # TODO: Implement Discord alerts
                pass
                
        except Exception as e:
            logger.error(f"Error triggering alert: {str(e)}")

    def _calculate_performance_metrics(self) -> None:
        """Calculate performance metrics for scans."""
        try:
            # Calculate scan duration
            completed_scans = [
                scan for scan in self.active_scans.values()
                if scan.status == "completed" and scan.end_time
            ]
            if completed_scans:
                durations = [
                    (scan.end_time - scan.start_time).total_seconds()
                    for scan in completed_scans
                ]
                self.performance_metrics["scan_duration"].append(sum(durations) / len(durations))
            
            # Calculate findings per scan
            if completed_scans:
                findings = [scan.findings_count for scan in completed_scans]
                self.performance_metrics["findings_per_scan"].append(sum(findings) / len(findings))
            
            # Calculate resource efficiency
            if self.resource_history:
                recent_metrics = self.resource_history[-10:]  # Last 10 measurements
                cpu_avg = sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics)
                memory_avg = sum(m.memory_percent for m in recent_metrics) / len(recent_metrics)
                efficiency = (cpu_avg + memory_avg) / 2
                self.performance_metrics["resource_efficiency"].append(efficiency)
            
            # Calculate error rate
            total_scans = len(self.active_scans)
            if total_scans > 0:
                error_scans = len([s for s in self.active_scans.values() if s.status == "failed"])
                error_rate = error_scans / total_scans
                self.performance_metrics["error_rate"].append(error_rate)
            
            # Trim metrics history
            for metric in self.performance_metrics.values():
                if len(metric) > self.max_history:
                    metric.pop(0)
                    
        except Exception as e:
            logger.error(f"Error calculating performance metrics: {str(e)}")

    def get_performance_report(self) -> Dict[str, Any]:
        """Get a performance report for all scans."""
        try:
            report = {
                "average_scan_duration": 0.0,
                "average_findings_per_scan": 0.0,
                "average_resource_efficiency": 0.0,
                "average_error_rate": 0.0,
                "total_scans": len(self.active_scans),
                "active_scans": len([s for s in self.active_scans.values() if s.status == "running"]),
                "completed_scans": len([s for s in self.active_scans.values() if s.status == "completed"]),
                "failed_scans": len([s for s in self.active_scans.values() if s.status == "failed"]),
                "total_findings": sum(s.findings_count for s in self.active_scans.values()),
                "resource_usage": {
                    "cpu": self.resource_history[-1].cpu_percent if self.resource_history else 0.0,
                    "memory": self.resource_history[-1].memory_percent if self.resource_history else 0.0,
                    "disk": self.resource_history[-1].disk_usage_percent if self.resource_history else 0.0
                }
            }
            
            # Calculate averages
            for metric, values in self.performance_metrics.items():
                if values:
                    report[f"average_{metric}"] = sum(values) / len(values)
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating performance report: {str(e)}")
            return {}
    
    def display_resource_usage(self) -> None:
        """Display current resource usage."""
        try:
            # Get resource usage
            metrics = self.get_resource_usage()
            if not metrics:
                console.print("[red]Error getting resource usage[/red]")
                return
            
            # Create usage panel
            usage_panel = Panel(
                f"[bold]CPU Usage:[/bold] {metrics.cpu_percent:.1f}%\n"
                f"[bold]Memory Usage:[/bold] {metrics.memory_percent:.1f}%\n"
                f"[bold]Disk Usage:[/bold] {metrics.disk_usage_percent:.1f}%\n"
                f"[bold]Network I/O:[/bold]\n"
                f"  Sent: {metrics.network_io['bytes_sent'] / 1024 / 1024:.1f} MB\n"
                f"  Received: {metrics.network_io['bytes_recv'] / 1024 / 1024:.1f} MB\n"
                f"  Packets Sent: {metrics.network_io['packets_sent']}\n"
                f"  Packets Received: {metrics.network_io['packets_recv']}",
                title="Resource Usage",
                border_style="blue"
            )
            
            console.print(usage_panel)
            
        except Exception as e:
            logger.error(f"Error displaying resource usage: {str(e)}")
            console.print(f"[red]Error displaying resource usage: {str(e)}[/red]")
    
    def display_scan_status(self) -> None:
        """Display status of all active scans."""
        try:
            # Get active scans
            active_scans = self.get_active_scans()
            if not active_scans:
                console.print("[yellow]No active scans[/yellow]")
                return
            
            # Create table
            table = Table(title="Active Scans")
            table.add_column("Scan ID", style="cyan")
            table.add_column("Profile", style="magenta")
            table.add_column("Target", style="green")
            table.add_column("Type", style="blue")
            table.add_column("Status", style="yellow")
            table.add_column("Progress", style="white")
            table.add_column("Findings", style="red")
            table.add_column("Start Time", style="white")
            
            # Add rows
            for scan in active_scans:
                table.add_row(
                    scan.scan_id,
                    scan.profile_name,
                    scan.target,
                    scan.scan_type,
                    scan.status,
                    f"{scan.progress:.1%}",
                    str(scan.findings_count),
                    scan.start_time.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying scan status: {str(e)}")
            console.print(f"[red]Error displaying scan status: {str(e)}[/red]")

# Create global instance
scan_monitor = ScanMonitor() 