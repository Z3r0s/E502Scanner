"""
Scan Logger for E502 OSINT Terminal
Provides comprehensive scan execution and system event logging capabilities.
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
import logging.handlers
import traceback
import sys
import threading
from queue import Queue
import time

logger = logging.getLogger("E502OSINT.ScanLogger")
console = Console()

class ScanLogger:
    def __init__(self):
        self.scan_dir = Path("scans")
        self.log_dir = self.scan_dir / "logs"
        self._ensure_dirs()
        
        # Initialize logging state
        self.log_queue = Queue()
        self.logging = False
        self.log_thread = None
        
        # Initialize loggers
        self._setup_loggers()
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
    
    def _setup_loggers(self) -> None:
        """Setup loggers."""
        try:
            # Create formatters
            file_formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            console_formatter = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s"
            )
            
            # Create file handler
            file_handler = logging.handlers.RotatingFileHandler(
                self.log_dir / "scan.log",
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            file_handler.setFormatter(file_formatter)
            
            # Create console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(console_formatter)
            
            # Setup root logger
            root_logger = logging.getLogger()
            root_logger.setLevel(logging.INFO)
            root_logger.addHandler(file_handler)
            root_logger.addHandler(console_handler)
            
            # Setup scan logger
            scan_logger = logging.getLogger("E502OSINT.Scan")
            scan_logger.setLevel(logging.INFO)
            
            # Create scan file handler
            scan_file_handler = logging.handlers.RotatingFileHandler(
                self.log_dir / "scan_execution.log",
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            scan_file_handler.setFormatter(file_formatter)
            scan_logger.addHandler(scan_file_handler)
            
            # Setup error logger
            error_logger = logging.getLogger("E502OSINT.Error")
            error_logger.setLevel(logging.ERROR)
            
            # Create error file handler
            error_file_handler = logging.handlers.RotatingFileHandler(
                self.log_dir / "error.log",
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            error_file_handler.setFormatter(file_formatter)
            error_logger.addHandler(error_file_handler)
            
            # Setup system logger
            system_logger = logging.getLogger("E502OSINT.System")
            system_logger.setLevel(logging.INFO)
            
            # Create system file handler
            system_file_handler = logging.handlers.RotatingFileHandler(
                self.log_dir / "system.log",
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            system_file_handler.setFormatter(file_formatter)
            system_logger.addHandler(system_file_handler)
            
        except Exception as e:
            logger.error(f"Error setting up loggers: {str(e)}")
    
    def start_logging(self) -> None:
        """Start logging."""
        try:
            if self.logging:
                logger.warning("Logging already started")
                return
            
            self.logging = True
            self.log_thread = threading.Thread(target=self._process_logs)
            self.log_thread.daemon = True
            self.log_thread.start()
            
            logger.info("Logging started")
            
        except Exception as e:
            logger.error(f"Error starting logging: {str(e)}")
            self.logging = False
    
    def stop_logging(self) -> None:
        """Stop logging."""
        try:
            if not self.logging:
                logger.warning("Logging not started")
                return
            
            self.logging = False
            if self.log_thread:
                self.log_thread.join()
            
            logger.info("Logging stopped")
            
        except Exception as e:
            logger.error(f"Error stopping logging: {str(e)}")
    
    def _process_logs(self) -> None:
        """Process log queue."""
        try:
            while self.logging:
                # Get log entry
                log_entry = self.log_queue.get()
                
                if log_entry is None:
                    continue
                
                # Get logger
                logger_name = log_entry.get("logger", "E502OSINT")
                log_logger = logging.getLogger(logger_name)
                
                # Log message
                level = getattr(logging, log_entry["level"])
                log_logger.log(level, log_entry["message"])
                
                # Mark task as done
                self.log_queue.task_done()
                
                # Sleep for a bit
                time.sleep(0.1)
            
        except Exception as e:
            logger.error(f"Error processing logs: {str(e)}")
            self.logging = False
    
    def log_scan_start(self, scan_id: str, profile_name: str, target: str, scan_type: str) -> None:
        """Log scan start."""
        try:
            message = f"Scan started - ID: {scan_id}, Profile: {profile_name}, Target: {target}, Type: {scan_type}"
            self.log_queue.put({
                "logger": "E502OSINT.Scan",
                "level": "INFO",
                "message": message
            })
            
        except Exception as e:
            logger.error(f"Error logging scan start: {str(e)}")
    
    def log_scan_end(self, scan_id: str, status: str, findings: int) -> None:
        """Log scan end."""
        try:
            message = f"Scan ended - ID: {scan_id}, Status: {status}, Findings: {findings}"
            self.log_queue.put({
                "logger": "E502OSINT.Scan",
                "level": "INFO",
                "message": message
            })
            
        except Exception as e:
            logger.error(f"Error logging scan end: {str(e)}")
    
    def log_scan_error(self, scan_id: str, error: Exception) -> None:
        """Log scan error."""
        try:
            message = f"Scan error - ID: {scan_id}, Error: {str(error)}\n{traceback.format_exc()}"
            self.log_queue.put({
                "logger": "E502OSINT.Error",
                "level": "ERROR",
                "message": message
            })
            
        except Exception as e:
            logger.error(f"Error logging scan error: {str(e)}")
    
    def log_system_event(self, event: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Log system event."""
        try:
            message = f"System event - {event}"
            if details:
                message += f", Details: {json.dumps(details)}"
            
            self.log_queue.put({
                "logger": "E502OSINT.System",
                "level": "INFO",
                "message": message
            })
            
        except Exception as e:
            logger.error(f"Error logging system event: {str(e)}")
    
    def log_system_error(self, error: Exception) -> None:
        """Log system error."""
        try:
            message = f"System error - {str(error)}\n{traceback.format_exc()}"
            self.log_queue.put({
                "logger": "E502OSINT.Error",
                "level": "ERROR",
                "message": message
            })
            
        except Exception as e:
            logger.error(f"Error logging system error: {str(e)}")
    
    def get_scan_logs(self, scan_id: Optional[str] = None, level: str = "INFO") -> List[Dict[str, Any]]:
        """Get scan logs."""
        try:
            # Read log file
            log_file = self.log_dir / "scan_execution.log"
            if not log_file.exists():
                return []
            
            logs = []
            with open(log_file, "r") as f:
                for line in f:
                    try:
                        # Parse log entry
                        parts = line.split(" - ", 3)
                        if len(parts) != 4:
                            continue
                        
                        timestamp = parts[0]
                        logger_name = parts[1]
                        log_level = parts[2]
                        message = parts[3].strip()
                        
                        # Filter by level
                        if log_level != level:
                            continue
                        
                        # Filter by scan ID
                        if scan_id and scan_id not in message:
                            continue
                        
                        logs.append({
                            "timestamp": timestamp,
                            "logger": logger_name,
                            "level": log_level,
                            "message": message
                        })
                    
                    except Exception:
                        continue
            
            return logs
            
        except Exception as e:
            logger.error(f"Error getting scan logs: {str(e)}")
            return []
    
    def get_error_logs(self) -> List[Dict[str, Any]]:
        """Get error logs."""
        try:
            # Read log file
            log_file = self.log_dir / "error.log"
            if not log_file.exists():
                return []
            
            logs = []
            with open(log_file, "r") as f:
                for line in f:
                    try:
                        # Parse log entry
                        parts = line.split(" - ", 3)
                        if len(parts) != 4:
                            continue
                        
                        timestamp = parts[0]
                        logger_name = parts[1]
                        log_level = parts[2]
                        message = parts[3].strip()
                        
                        logs.append({
                            "timestamp": timestamp,
                            "logger": logger_name,
                            "level": log_level,
                            "message": message
                        })
                    
                    except Exception:
                        continue
            
            return logs
            
        except Exception as e:
            logger.error(f"Error getting error logs: {str(e)}")
            return []
    
    def get_system_logs(self) -> List[Dict[str, Any]]:
        """Get system logs."""
        try:
            # Read log file
            log_file = self.log_dir / "system.log"
            if not log_file.exists():
                return []
            
            logs = []
            with open(log_file, "r") as f:
                for line in f:
                    try:
                        # Parse log entry
                        parts = line.split(" - ", 3)
                        if len(parts) != 4:
                            continue
                        
                        timestamp = parts[0]
                        logger_name = parts[1]
                        log_level = parts[2]
                        message = parts[3].strip()
                        
                        logs.append({
                            "timestamp": timestamp,
                            "logger": logger_name,
                            "level": log_level,
                            "message": message
                        })
                    
                    except Exception:
                        continue
            
            return logs
            
        except Exception as e:
            logger.error(f"Error getting system logs: {str(e)}")
            return []
    
    def display_scan_logs(self, scan_id: Optional[str] = None, level: str = "INFO") -> None:
        """Display scan logs."""
        try:
            # Get scan logs
            logs = self.get_scan_logs(scan_id, level)
            
            if not logs:
                console.print("[yellow]No scan logs available[/yellow]")
                return
            
            # Create table
            table = Table(title="Scan Logs")
            
            # Add columns
            table.add_column("Timestamp", style="cyan")
            table.add_column("Level", style="magenta")
            table.add_column("Message", style="green")
            
            # Add rows
            for log in logs:
                table.add_row(
                    log["timestamp"],
                    log["level"],
                    log["message"]
                )
            
            # Display table
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying scan logs: {str(e)}")
            console.print(f"[red]Error displaying scan logs: {str(e)}[/red]")
    
    def display_error_logs(self) -> None:
        """Display error logs."""
        try:
            # Get error logs
            logs = self.get_error_logs()
            
            if not logs:
                console.print("[yellow]No error logs available[/yellow]")
                return
            
            # Create table
            table = Table(title="Error Logs")
            
            # Add columns
            table.add_column("Timestamp", style="cyan")
            table.add_column("Logger", style="magenta")
            table.add_column("Message", style="red")
            
            # Add rows
            for log in logs:
                table.add_row(
                    log["timestamp"],
                    log["logger"],
                    log["message"]
                )
            
            # Display table
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying error logs: {str(e)}")
            console.print(f"[red]Error displaying error logs: {str(e)}[/red]")
    
    def display_system_logs(self) -> None:
        """Display system logs."""
        try:
            # Get system logs
            logs = self.get_system_logs()
            
            if not logs:
                console.print("[yellow]No system logs available[/yellow]")
                return
            
            # Create table
            table = Table(title="System Logs")
            
            # Add columns
            table.add_column("Timestamp", style="cyan")
            table.add_column("Logger", style="magenta")
            table.add_column("Message", style="green")
            
            # Add rows
            for log in logs:
                table.add_row(
                    log["timestamp"],
                    log["logger"],
                    log["message"]
                )
            
            # Display table
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying system logs: {str(e)}")
            console.print(f"[red]Error displaying system logs: {str(e)}[/red]")

# Create global instance
scan_logger = ScanLogger() 