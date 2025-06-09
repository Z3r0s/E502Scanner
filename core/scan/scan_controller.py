"""
Scan Controller for E502 OSINT Terminal
Provides comprehensive scan control capabilities by managing scan execution and lifecycle.
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
import backoff
import uuid

logger = logging.getLogger("E502OSINT.ScanController")
console = Console()

@dataclass
class ScanState:
    """Data class for scan state."""
    scan_id: str
    profile_name: str
    target: str
    scan_type: str
    start_time: datetime
    status: str
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    analysis: Optional[Dict[str, Any]] = None
    report_path: Optional[str] = None
    export_path: Optional[str] = None

class ScanController:
    def __init__(self):
        self.scan_dir = Path("scans")
        self._ensure_dirs()
        
        # Initialize scan state
        self.active_scans = {}
        self.scan_tasks = {}
        self.scan_lock = threading.Lock()
        self.scan_events = {}
        self.error_count = {}
        self.max_retries = 3
        
        # Enhanced scan prioritization
        self.priority_levels = {
            "critical": 100,
            "high": 75,
            "medium": 50,
            "low": 25,
            "background": 0
        }
        self.priority_weights = {
            "severity": 0.4,
            "age": 0.2,
            "dependencies": 0.2,
            "resource_impact": 0.2
        }
        self.scan_dependencies = {}
        self.scan_impact_scores = {}
        
        # Initialize components
        self.engine = scan_engine
        self.analyzer = scan_analyzer
        self.reporter = scan_reporter
        self.exporter = scan_exporter
        self.validator = scan_validator
        self.monitor = scan_monitor
        self.logger = scan_logger
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.scan_dir.mkdir(parents=True, exist_ok=True)
    
    def start_scan(self, config: Dict[str, Any]) -> Optional[str]:
        """Start a new scan with the given configuration."""
        try:
            # Generate scan ID
            scan_id = str(uuid.uuid4())
            
            # Create scan state
            scan_state = ScanState(
                scan_id=scan_id,
                profile_name=config["name"],
                target=config["target"],
                scan_type=config["scan_type"],
                start_time=datetime.now(pytz.UTC),
                status="starting"
            )
            
            # Add to active scans
            with self.scan_lock:
                self.active_scans[scan_id] = scan_state
                self.scan_events[scan_id] = asyncio.Event()
            
            # Create scan task
            task = asyncio.create_task(self._execute_scan(scan_id, config))
            self.scan_tasks[scan_id] = task
            
            # Update monitor
            self.monitor.add_scan(scan_id, {
                "scan_id": scan_id,
                "profile_name": config["name"],
                "target": config["target"],
                "scan_type": config["scan_type"],
                "start_time": scan_state.start_time.isoformat(),
                "status": "starting"
            })
            
            # Log scan start
            self.logger.log_scan_start(
                scan_id,
                config["name"],
                config["target"],
                config["scan_type"]
            )
            
            return scan_id
            
        except Exception as e:
            logger.error(f"Error starting scan: {str(e)}")
            return None
    
    def pause_scan(self, scan_id: str) -> bool:
        """Pause a running scan."""
        try:
            with self.scan_lock:
                if scan_id not in self.active_scans:
                    logger.warning(f"Scan not found: {scan_id}")
                    return False
                
                scan_state = self.active_scans[scan_id]
                if scan_state.status != "running":
                    logger.warning(f"Scan not running: {scan_id}")
                    return False
                
                # Pause scan
                self.engine.pause_scan(scan_id)
                scan_state.status = "paused"
                
                # Update monitor
                self.monitor.update_scan_status(scan_id, "paused")
                
                # Log pause
                self.logger.log_scan_pause(scan_id)
                
                return True
                
        except Exception as e:
            logger.error(f"Error pausing scan: {str(e)}")
            return False
    
    def resume_scan(self, scan_id: str) -> bool:
        """Resume a paused scan."""
        try:
            with self.scan_lock:
                if scan_id not in self.active_scans:
                    logger.warning(f"Scan not found: {scan_id}")
                    return False
                
                scan_state = self.active_scans[scan_id]
                if scan_state.status != "paused":
                    logger.warning(f"Scan not paused: {scan_id}")
                    return False
                
                # Resume scan
                self.engine.resume_scan(scan_id)
                scan_state.status = "running"
                
                # Update monitor
                self.monitor.update_scan_status(scan_id, "running")
                
                # Log resume
                self.logger.log_scan_resume(scan_id)
                
                return True
                
        except Exception as e:
            logger.error(f"Error resuming scan: {str(e)}")
            return False
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan."""
        try:
            with self.scan_lock:
                if scan_id not in self.active_scans:
                    logger.warning(f"Scan not found: {scan_id}")
                    return False
                
                scan_state = self.active_scans[scan_id]
                if scan_state.status not in ["running", "paused"]:
                    logger.warning(f"Scan not active: {scan_id}")
                    return False
                
                # Cancel scan task
                if scan_id in self.scan_tasks:
                    self.scan_tasks[scan_id].cancel()
                    del self.scan_tasks[scan_id]
                
                # Update state
                scan_state.status = "cancelled"
                scan_state.error = "Scan cancelled by user"
                
                # Update monitor
                self.monitor.update_scan_status(scan_id, "cancelled")
                
                # Log cancellation
                self.logger.log_scan_cancel(scan_id)
                
                # Cleanup
                self._cleanup_scan(scan_id)
                
                return True
                
        except Exception as e:
            logger.error(f"Error cancelling scan: {str(e)}")
            return False
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of a scan."""
        try:
            with self.scan_lock:
                if scan_id not in self.active_scans:
                    return None
                
                scan_state = self.active_scans[scan_id]
                return {
                    "scan_id": scan_state.scan_id,
                    "profile_name": scan_state.profile_name,
                    "target": scan_state.target,
                    "scan_type": scan_state.scan_type,
                    "start_time": scan_state.start_time.isoformat(),
                    "status": scan_state.status,
                    "error": scan_state.error,
                    "result": scan_state.result is not None,
                    "analysis": scan_state.analysis is not None,
                    "report_path": scan_state.report_path,
                    "export_path": scan_state.export_path
                }
                
        except Exception as e:
            logger.error(f"Error getting scan status: {str(e)}")
            return None
    
    def wait_for_scan(self, scan_id: str, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """Wait for a scan to complete."""
        try:
            if scan_id not in self.scan_events:
                logger.warning(f"Scan not found: {scan_id}")
                return None
            
            # Wait for scan completion
            event = self.scan_events[scan_id]
            if not event.wait(timeout):
                logger.warning(f"Scan timeout: {scan_id}")
                return None
            
            # Get scan state
            with self.scan_lock:
                if scan_id not in self.active_scans:
                    return None
                
                scan_state = self.active_scans[scan_id]
                if scan_state.status != "completed":
                    return None
                
                return scan_state.result
                
        except Exception as e:
            logger.error(f"Error waiting for scan: {str(e)}")
            return None
    
    @backoff.on_exception(backoff.expo, Exception, max_tries=3)
    async def _execute_scan(self, scan_id: str, config: Dict[str, Any]) -> None:
        """Execute a scan with retry logic."""
        try:
            # Update status
            with self.scan_lock:
                scan_state = self.active_scans[scan_id]
                scan_state.status = "running"
                self.monitor.update_scan_status(scan_id, "running")
            
            # Execute scan
            result = await self.engine.execute_scan(config)
            if not result:
                raise Exception("Scan execution failed")
            
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
            
            # Update state
            with self.scan_lock:
                scan_state = self.active_scans[scan_id]
                scan_state.status = "completed"
                scan_state.result = result
                scan_state.analysis = analysis
                scan_state.report_path = report_path
                scan_state.export_path = export_path
            
            # Update monitor
            self.monitor.update_scan_status(scan_id, "completed")
            
            # Log completion
            self.logger.log_scan_end(
                scan_id,
                "completed",
                len(result.get("findings", []))
            )
            
        except asyncio.CancelledError:
            # Handle cancellation
            with self.scan_lock:
                scan_state = self.active_scans[scan_id]
                scan_state.status = "cancelled"
                scan_state.error = "Scan cancelled by user"
            
            self.monitor.update_scan_status(scan_id, "cancelled")
            self.logger.log_scan_cancel(scan_id)
            
        except Exception as e:
            # Handle error
            with self.scan_lock:
                scan_state = self.active_scans[scan_id]
                scan_state.status = "failed"
                scan_state.error = str(e)
            
            self.monitor.update_scan_status(scan_id, "failed")
            self.logger.log_scan_error(scan_id, str(e))
            
            # Re-raise for backoff retry
            raise
            
        finally:
            # Signal completion
            if scan_id in self.scan_events:
                self.scan_events[scan_id].set()
            
            # Cleanup
            self._cleanup_scan(scan_id)
    
    def _cleanup_scan(self, scan_id: str) -> None:
        """Clean up scan resources."""
        try:
            with self.scan_lock:
                # Remove from active scans
                if scan_id in self.active_scans:
                    del self.active_scans[scan_id]
                
                # Remove from tasks
                if scan_id in self.scan_tasks:
                    del self.scan_tasks[scan_id]
                
                # Remove from events
                if scan_id in self.scan_events:
                    del self.scan_events[scan_id]
                
                # Remove from error count
                if scan_id in self.error_count:
                    del self.error_count[scan_id]
                
                # Remove from monitor
                self.monitor.remove_scan(scan_id)
                
        except Exception as e:
            logger.error(f"Error cleaning up scan: {str(e)}")

    def calculate_scan_priority(self, scan_info: Dict[str, Any]) -> int:
        """Calculate scan priority based on multiple factors."""
        try:
            priority_score = 0
            
            # Base priority from level
            priority_level = scan_info.get("priority_level", "medium")
            priority_score += self.priority_levels.get(priority_level, 50)
            
            # Weighted factors
            weights = self.priority_weights
            
            # Severity factor
            severity = scan_info.get("severity", "medium")
            severity_score = {
                "critical": 100,
                "high": 75,
                "medium": 50,
                "low": 25
            }.get(severity, 50)
            priority_score += severity_score * weights["severity"]
            
            # Age factor (older scans get higher priority)
            age = time.time() - scan_info.get("created_at", time.time())
            age_score = min(age / 3600, 24) * 100  # Cap at 24 hours
            priority_score += age_score * weights["age"]
            
            # Dependencies factor
            scan_id = scan_info.get("scan_id")
            if scan_id in self.scan_dependencies:
                dep_score = len(self.scan_dependencies[scan_id]) * 25
                priority_score += dep_score * weights["dependencies"]
            
            # Resource impact factor
            if scan_id in self.scan_impact_scores:
                impact_score = self.scan_impact_scores[scan_id] * 100
                priority_score += impact_score * weights["resource_impact"]
            
            return int(priority_score)
            
        except Exception as e:
            logger.error(f"Error calculating scan priority: {str(e)}")
            return 50  # Default to medium priority

    def add_scan_dependency(self, scan_id: str, dependency_id: str) -> None:
        """Add a dependency between scans."""
        try:
            if scan_id not in self.scan_dependencies:
                self.scan_dependencies[scan_id] = set()
            self.scan_dependencies[scan_id].add(dependency_id)
        except Exception as e:
            logger.error(f"Error adding scan dependency: {str(e)}")

    def remove_scan_dependency(self, scan_id: str, dependency_id: str) -> None:
        """Remove a dependency between scans."""
        try:
            if scan_id in self.scan_dependencies:
                self.scan_dependencies[scan_id].discard(dependency_id)
                if not self.scan_dependencies[scan_id]:
                    del self.scan_dependencies[scan_id]
        except Exception as e:
            logger.error(f"Error removing scan dependency: {str(e)}")

    def set_scan_impact_score(self, scan_id: str, impact_score: float) -> None:
        """Set the resource impact score for a scan."""
        try:
            self.scan_impact_scores[scan_id] = max(0.0, min(1.0, impact_score))
        except Exception as e:
            logger.error(f"Error setting scan impact score: {str(e)}")

    def get_next_scan(self) -> Optional[Dict[str, Any]]:
        """Get the next scan to execute based on priority and dependencies."""
        try:
            # Get all pending scans
            pending_scans = {
                scan_id: scan_info
                for scan_id, scan_info in self.scan_tasks.items()
                if scan_info.get("status") == "pending"
            }
            
            if not pending_scans:
                return None
            
            # Calculate priorities
            scan_priorities = {
                scan_id: self.calculate_scan_priority(scan_info)
                for scan_id, scan_info in pending_scans.items()
            }
            
            # Sort by priority
            sorted_scans = sorted(
                scan_priorities.items(),
                key=lambda x: x[1],
                reverse=True
            )
            
            # Find first scan with satisfied dependencies
            for scan_id, priority in sorted_scans:
                scan_info = pending_scans[scan_id]
                dependencies = self.scan_dependencies.get(scan_id, set())
                
                # Check if all dependencies are completed
                if all(
                    dep_id in self.active_scans and
                    self.active_scans[dep_id].get("status") == "completed"
                    for dep_id in dependencies
                ):
                    return scan_info
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting next scan: {str(e)}")
            return None

# Create global instance
scan_controller = ScanController() 