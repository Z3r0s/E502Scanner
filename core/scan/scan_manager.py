"""
Scan Manager for E502 OSINT Terminal
Provides comprehensive scan management capabilities by coordinating all scan-related functionality.
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
from queue import PriorityQueue
import time
from dataclasses import dataclass
import backoff
import psutil

logger = logging.getLogger("E502OSINT.ScanManager")
console = Console()

@dataclass
class ScanTask:
    """Data class for scan tasks with priority."""
    priority: int
    timestamp: float
    scan_info: Dict[str, Any]
    
    def __lt__(self, other):
        """Compare tasks for priority queue ordering."""
        if self.priority != other.priority:
            return self.priority > other.priority  # Higher priority first
        return self.timestamp < other.timestamp  # Earlier timestamp first

class ScanManager:
    def __init__(self):
        self.scan_dir = Path("scans")
        self._ensure_dirs()
        
        # Initialize scan state
        self.active_scans = {}
        self.scan_queue = PriorityQueue()
        self.scanning = False
        self.scan_thread = None
        self.scan_lock = threading.Lock()
        self.error_count = {}
        self.max_retries = 3
        
        # Resource management
        self.resource_limits = {
            "cpu_percent": 80,  # Maximum CPU usage percentage
            "memory_percent": 80,  # Maximum memory usage percentage
            "disk_percent": 90,  # Maximum disk usage percentage
            "network_bandwidth": 1000000  # Maximum network bandwidth in bytes per second
        }
        self.resource_usage = {
            "cpu_percent": 0,
            "memory_percent": 0,
            "disk_percent": 0,
            "network_bandwidth": 0
        }
        self.resource_monitor_thread = None
        self.resource_monitor_interval = 5  # seconds
        
        # Initialize components
        self.engine = scan_engine
        self.controller = scan_controller
        self.analyzer = scan_analyzer
        self.reporter = scan_reporter
        self.exporter = scan_exporter
        self.importer = scan_importer
        self.validator = scan_validator
        self.monitor = scan_monitor
        self.logger = scan_logger
        self.configurator = scan_configurator
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.scan_dir.mkdir(parents=True, exist_ok=True)
    
    def start_scanning(self) -> None:
        """Start scan processing."""
        try:
            with self.scan_lock:
                if self.scanning:
                    logger.warning("Scanning already started")
                    return
                
                self.scanning = True
                self.scan_thread = threading.Thread(target=self._process_scans)
                self.scan_thread.daemon = True
                self.scan_thread.start()
                
                # Start resource monitoring
                self.resource_monitor_thread = threading.Thread(target=self._monitor_resources)
                self.resource_monitor_thread.daemon = True
                self.resource_monitor_thread.start()
                
                # Start monitoring
                self.monitor.start_monitoring()
                
                # Start logging
                self.logger.start_logging()
                
                logger.info("Scan processing started")
            
        except Exception as e:
            logger.error(f"Error starting scanning: {str(e)}")
            self.scanning = False
    
    def stop_scanning(self) -> None:
        """Stop scan processing."""
        try:
            with self.scan_lock:
                if not self.scanning:
                    logger.warning("Scanning not started")
                    return
                
                self.scanning = False
                if self.scan_thread:
                    self.scan_thread.join()
                
                # Stop resource monitoring
                if self.resource_monitor_thread:
                    self.resource_monitor_thread.join()
                
                # Stop monitoring
                self.monitor.stop_monitoring()
                
                # Stop logging
                self.logger.stop_logging()
                
                logger.info("Scan processing stopped")
            
        except Exception as e:
            logger.error(f"Error stopping scanning: {str(e)}")
    
    def add_scan(self, scan_info: Dict[str, Any], priority: int = 0) -> None:
        """Add a scan to the queue with priority."""
        try:
            task = ScanTask(
                priority=priority,
                timestamp=time.time(),
                scan_info=scan_info
            )
            self.scan_queue.put(task)
            logger.info(f"Added scan to queue: {scan_info['profile_name']}")
        except Exception as e:
            logger.error(f"Error adding scan to queue: {str(e)}")
    
    def pause_scan(self, scan_id: str) -> None:
        """Pause a running scan."""
        try:
            if scan_id in self.active_scans:
                self.engine.pause_scan(scan_id)
                logger.info(f"Paused scan: {scan_id}")
        except Exception as e:
            logger.error(f"Error pausing scan: {str(e)}")
    
    def resume_scan(self, scan_id: str) -> None:
        """Resume a paused scan."""
        try:
            if scan_id in self.active_scans:
                self.engine.resume_scan(scan_id)
                logger.info(f"Resumed scan: {scan_id}")
        except Exception as e:
            logger.error(f"Error resuming scan: {str(e)}")
    
    def cancel_scan(self, scan_id: str) -> None:
        """Cancel a running scan."""
        try:
            if scan_id in self.active_scans:
                # Remove from active scans
                del self.active_scans[scan_id]
                self.monitor.remove_scan(scan_id)
                logger.info(f"Cancelled scan: {scan_id}")
        except Exception as e:
            logger.error(f"Error cancelling scan: {str(e)}")
    
    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    def _process_scans(self) -> None:
        """Process scan queue with retry logic."""
        try:
            while self.scanning:
                try:
                    # Get scan from queue
                    task = self.scan_queue.get(timeout=1)
                    if task is None:
                        continue
                    
                    scan_info = task.scan_info
                    scan_id = scan_info.get("scan_id")
                    
                    # Check error count
                    if scan_id in self.error_count and self.error_count[scan_id] >= self.max_retries:
                        logger.error(f"Max retries exceeded for scan: {scan_id}")
                        continue
                    
                    # Get scan configuration
                    config = self.configurator.get_config(scan_info["profile_name"])
                    if not config:
                        logger.error(f"Configuration {scan_info['profile_name']} not found")
                        continue
                    
                    # Validate configuration
                    if not self.validator.validate_profile(asdict(config)):
                        logger.error(f"Invalid configuration: {scan_info['profile_name']}")
                        continue
                    
                    # Start scan
                    scan_id = self.controller.start_scan(config)
                    if not scan_id:
                        logger.error(f"Failed to start scan: {scan_info['profile_name']}")
                        continue
                    
                    # Add to active scans
                    self.active_scans[scan_id] = {
                        "scan_id": scan_id,
                        "profile_name": config.name,
                        "target": config.target,
                        "scan_type": config.scan_type,
                        "start_time": datetime.now(pytz.UTC).isoformat(),
                        "status": "running"
                    }
                    
                    # Add to monitoring
                    self.monitor.add_scan(scan_id, self.active_scans[scan_id])
                    
                    # Log scan start
                    self.logger.log_scan_start(
                        scan_id,
                        config.name,
                        config.target,
                        config.scan_type
                    )
                    
                    try:
                        # Wait for scan to complete
                        result = self.controller.wait_for_scan(scan_id)
                        if not result:
                            raise Exception("Scan failed")
                        
                        # Analyze result
                        analysis = self.analyzer.analyze_result(result)
                        if not analysis:
                            raise Exception("Analysis failed")
                        
                        # Generate report
                        report_path = self.reporter.generate_report(scan_id)
                        if not report_path:
                            raise Exception("Report generation failed")
                        
                        # Export result
                        export_path = self.exporter.export_result(scan_id)
                        if not export_path:
                            raise Exception("Export failed")
                        
                        # Update scan status
                        self.active_scans[scan_id]["status"] = "completed"
                        self.monitor.update_scan_status(scan_id, "completed")
                        
                        # Log scan end
                        self.logger.log_scan_end(
                            scan_id,
                            "completed",
                            len(result.findings)
                        )
                        
                        # Clear error count
                        if scan_id in self.error_count:
                            del self.error_count[scan_id]
                        
                    except Exception as e:
                        # Increment error count
                        self.error_count[scan_id] = self.error_count.get(scan_id, 0) + 1
                        
                        # Update scan status
                        self.active_scans[scan_id]["status"] = "failed"
                        self.monitor.update_scan_status(scan_id, "failed")
                        
                        # Log error
                        self.logger.log_scan_error(scan_id, str(e))
                        
                        # Re-raise for backoff retry
                        raise
                    
                    finally:
                        # Remove from active scans
                        if scan_id in self.active_scans:
                            del self.active_scans[scan_id]
                            self.monitor.remove_scan(scan_id)
                        
                        # Mark task as done
                        self.scan_queue.task_done()
                
                except queue.Empty:
                    continue
                
                except Exception as e:
                    logger.error(f"Error processing scan: {str(e)}")
                    time.sleep(1)  # Prevent tight loop on errors
            
        except Exception as e:
            logger.error(f"Error in scan processing loop: {str(e)}")
            self.scanning = False
    
    def start_scan(self, profile_name: str) -> Optional[str]:
        """Start a scan."""
        try:
            # Check if scanning is started
            if not self.scanning:
                logger.error("Scanning not started")
                return None
            
            # Add scan to queue
            scan_info = {
                "profile_name": profile_name,
                "timestamp": datetime.now(pytz.UTC).isoformat()
            }
            self.scan_queue.put(scan_info)
            
            logger.info(f"Added scan to queue: {profile_name}")
            return profile_name
            
        except Exception as e:
            logger.error(f"Error starting scan: {str(e)}")
            return None
    
    def stop_scan(self, scan_id: str) -> bool:
        """Stop a scan."""
        try:
            # Check if scan is active
            if scan_id not in self.active_scans:
                logger.error(f"Scan {scan_id} not found")
                return False
            
            # Stop scan
            if not self.controller.stop_scan(scan_id):
                logger.error(f"Failed to stop scan: {scan_id}")
                return False
            
            # Update scan status
            self.active_scans[scan_id]["status"] = "stopped"
            self.monitor.update_scan_status(scan_id, "stopped")
            
            # Log scan end
            self.logger.log_scan_end(
                scan_id,
                "stopped",
                0
            )
            
            # Remove from active scans
            del self.active_scans[scan_id]
            self.monitor.remove_scan(scan_id)
            
            logger.info(f"Stopped scan: {scan_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping scan: {str(e)}")
            return False
    
    def get_scan_status(self, scan_id: str) -> Optional[str]:
        """Get scan status."""
        try:
            # Check if scan is active
            if scan_id in self.active_scans:
                return self.active_scans[scan_id]["status"]
            
            # Get scan result
            result = self.controller.get_scan_result(scan_id)
            if result:
                return result.status
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting scan status: {str(e)}")
            return None
    
    def get_active_scans(self) -> List[Dict[str, Any]]:
        """Get active scans."""
        try:
            return list(self.active_scans.values())
            
        except Exception as e:
            logger.error(f"Error getting active scans: {str(e)}")
            return []
    
    def get_scan_results(self, profile_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get scan results."""
        try:
            # Get scan results
            results = self.controller.get_scan_results()
            
            # Filter by profile name
            if profile_name:
                results = [
                    result for result in results
                    if result.profile_name == profile_name
                ]
            
            return results
            
        except Exception as e:
            logger.error(f"Error getting scan results: {str(e)}")
            return []
    
    def get_scan_analysis(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan analysis."""
        try:
            # Get scan result
            result = self.controller.get_scan_result(scan_id)
            if not result:
                return None
            
            # Analyze result
            return self.analyzer.analyze_result(result)
            
        except Exception as e:
            logger.error(f"Error getting scan analysis: {str(e)}")
            return None
    
    def get_scan_report(self, scan_id: str) -> Optional[str]:
        """Get scan report."""
        try:
            # Get scan result
            result = self.controller.get_scan_result(scan_id)
            if not result:
                return None
            
            # Generate report
            return self.reporter.generate_report(scan_id)
            
        except Exception as e:
            logger.error(f"Error getting scan report: {str(e)}")
            return None
    
    def get_scan_export(self, scan_id: str) -> Optional[str]:
        """Get scan export."""
        try:
            # Get scan result
            result = self.controller.get_scan_result(scan_id)
            if not result:
                return None
            
            # Export result
            return self.exporter.export_result(scan_id)
            
        except Exception as e:
            logger.error(f"Error getting scan export: {str(e)}")
            return None
    
    def import_scan_result(self, file_path: str) -> Optional[str]:
        """Import scan result."""
        try:
            # Import result
            return self.importer.import_result(file_path)
            
        except Exception as e:
            logger.error(f"Error importing scan result: {str(e)}")
            return None
    
    def display_active_scans(self) -> None:
        """Display active scans."""
        try:
            # Get active scans
            active_scans = self.get_active_scans()
            
            if not active_scans:
                console.print("[yellow]No active scans[/yellow]")
                return
            
            # Create table
            table = Table(title="Active Scans")
            
            # Add columns
            table.add_column("Scan ID", style="cyan")
            table.add_column("Profile", style="magenta")
            table.add_column("Target", style="green")
            table.add_column("Type", style="blue")
            table.add_column("Start Time", style="yellow")
            table.add_column("Status", style="red")
            
            # Add rows
            for scan in active_scans:
                table.add_row(
                    scan["scan_id"],
                    scan["profile_name"],
                    scan["target"],
                    scan["scan_type"],
                    scan["start_time"],
                    scan["status"]
                )
            
            # Display table
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying active scans: {str(e)}")
            console.print(f"[red]Error displaying active scans: {str(e)}[/red]")
    
    def display_scan_results(self, profile_name: Optional[str] = None) -> None:
        """Display scan results."""
        try:
            # Get scan results
            results = self.get_scan_results(profile_name)
            
            if not results:
                console.print("[yellow]No scan results available[/yellow]")
                return
            
            # Create table
            table = Table(title="Scan Results")
            
            # Add columns
            table.add_column("Scan ID", style="cyan")
            table.add_column("Profile", style="magenta")
            table.add_column("Target", style="green")
            table.add_column("Type", style="blue")
            table.add_column("Start Time", style="yellow")
            table.add_column("End Time", style="yellow")
            table.add_column("Status", style="red")
            table.add_column("Findings", style="red")
            
            # Add rows
            for result in results:
                table.add_row(
                    result.scan_id,
                    result.profile_name,
                    result.target,
                    result.scan_type,
                    result.start_time.isoformat(),
                    result.end_time.isoformat() if result.end_time else "",
                    result.status,
                    str(len(result.findings))
                )
            
            # Display table
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying scan results: {str(e)}")
            console.print(f"[red]Error displaying scan results: {str(e)}[/red]")
    
    def display_scan_analysis(self, scan_id: str) -> None:
        """Display scan analysis."""
        try:
            # Get scan analysis
            analysis = self.get_scan_analysis(scan_id)
            
            if not analysis:
                console.print(f"[red]Analysis not available for scan: {scan_id}[/red]")
                return
            
            # Create table
            table = Table(title=f"Scan Analysis: {scan_id}")
            
            # Add rows
            table.add_row("Total Scans", str(analysis["total_scans"]))
            table.add_row("Completed Scans", str(analysis["completed_scans"]))
            table.add_row("Failed Scans", str(analysis["failed_scans"]))
            table.add_row("Total Findings", str(analysis["total_findings"]))
            table.add_row("Average CVSS", f"{analysis['average_cvss']:.2f}")
            table.add_row("Scan Duration", f"{analysis['scan_duration']:.2f}s")
            
            # Add severity distribution
            table.add_row("Severity Distribution", json.dumps(analysis["severity_distribution"], indent=2))
            
            # Add category distribution
            table.add_row("Category Distribution", json.dumps(analysis["category_distribution"], indent=2))
            
            # Add CVE distribution
            table.add_row("CVE Distribution", json.dumps(analysis["cve_distribution"], indent=2))
            
            # Add top findings
            table.add_row("Top Findings", json.dumps(analysis["top_findings"], indent=2))
            
            # Add recommendations
            table.add_row("Recommendations", json.dumps(analysis["recommendations"], indent=2))
            
            # Display table
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying scan analysis: {str(e)}")
            console.print(f"[red]Error displaying scan analysis: {str(e)}[/red]")

    def _monitor_resources(self) -> None:
        """Monitor system resources and adjust scan behavior accordingly."""
        while self.scanning:
            try:
                # Get current resource usage
                self.resource_usage["cpu_percent"] = psutil.cpu_percent()
                self.resource_usage["memory_percent"] = psutil.virtual_memory().percent
                self.resource_usage["disk_percent"] = psutil.disk_usage('/').percent
                
                # Get network usage
                net_io = psutil.net_io_counters()
                self.resource_usage["network_bandwidth"] = net_io.bytes_sent + net_io.bytes_recv
                
                # Check resource limits
                if self._check_resource_limits():
                    # Pause new scans if resources are constrained
                    self._handle_resource_constraints()
                
                # Sleep for monitoring interval
                time.sleep(self.resource_monitor_interval)
                
            except Exception as e:
                logger.error(f"Error monitoring resources: {str(e)}")
                time.sleep(self.resource_monitor_interval)

    def _check_resource_limits(self) -> bool:
        """Check if any resource limits are exceeded."""
        return (
            self.resource_usage["cpu_percent"] > self.resource_limits["cpu_percent"] or
            self.resource_usage["memory_percent"] > self.resource_limits["memory_percent"] or
            self.resource_usage["disk_percent"] > self.resource_limits["disk_percent"] or
            self.resource_usage["network_bandwidth"] > self.resource_limits["network_bandwidth"]
        )

    def _handle_resource_constraints(self) -> None:
        """Handle resource constraints by adjusting scan behavior."""
        try:
            # Get active scans sorted by priority
            active_scans = sorted(
                self.active_scans.items(),
                key=lambda x: x[1].get("priority", 0),
                reverse=True
            )
            
            # Pause lower priority scans if needed
            for scan_id, scan_info in active_scans[1:]:  # Skip highest priority scan
                if self._check_resource_limits():
                    self.pause_scan(scan_id)
                    logger.warning(f"Paused scan {scan_id} due to resource constraints")
                else:
                    break
            
            # Resume paused scans if resources are available
            for scan_id, scan_info in active_scans:
                if scan_info.get("status") == "paused" and not self._check_resource_limits():
                    self.resume_scan(scan_id)
                    logger.info(f"Resumed scan {scan_id} as resources are available")
                
        except Exception as e:
            logger.error(f"Error handling resource constraints: {str(e)}")

# Create global instance
scan_manager = ScanManager() 