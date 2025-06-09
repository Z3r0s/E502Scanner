"""
Configuration Manager for E502 OSINT Terminal
Provides comprehensive configuration management for all components.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import pytz
from pathlib import Path
from dataclasses import dataclass, asdict
import shutil
import hashlib
import platform
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from jinja2 import Environment, FileSystemLoader
import yaml

logger = logging.getLogger("E502OSINT.ConfigManager")
console = Console()

@dataclass
class NetworkConfig:
    """Network scanning configuration."""
    timeout: int = 30
    retry_count: int = 3
    retry_delay: int = 1
    max_threads: int = 10
    ports: List[int] = None
    protocols: List[str] = None
    scan_types: List[str] = None
    exclude_ports: List[int] = None
    exclude_hosts: List[str] = None
    rate_limit: int = 100
    dns_servers: List[str] = None
    proxy_settings: Dict[str, Any] = None

@dataclass
class WebConfig:
    """Web scanning configuration."""
    timeout: int = 30
    retry_count: int = 3
    retry_delay: int = 1
    max_threads: int = 10
    user_agent: str = None
    headers: Dict[str, str] = None
    cookies: Dict[str, str] = None
    proxy_settings: Dict[str, Any] = None
    follow_redirects: bool = True
    max_redirects: int = 5
    verify_ssl: bool = True
    scan_types: List[str] = None
    exclude_paths: List[str] = None
    rate_limit: int = 100

@dataclass
class PrivacyConfig:
    """Privacy and anonymity configuration."""
    use_proxy: bool = False
    proxy_type: str = None
    proxy_host: str = None
    proxy_port: int = None
    proxy_username: str = None
    proxy_password: str = None
    rotate_user_agent: bool = True
    user_agents: List[str] = None
    rotate_proxy: bool = False
    proxy_list: List[Dict[str, Any]] = None
    use_tor: bool = False
    tor_control_port: int = 9051
    tor_control_password: str = None
    dns_servers: List[str] = None
    clear_cookies: bool = True
    clear_cache: bool = True

@dataclass
class ScanConfig:
    """Scan configuration."""
    scan_id: str = None
    target: str = None
    scan_type: str = None
    profile: str = None
    tags: List[str] = None
    start_time: datetime = None
    end_time: datetime = None
    status: str = None
    findings: Dict[str, Any] = None
    error: str = None
    duration: float = None
    max_depth: int = 3
    max_pages: int = 100
    max_links: int = 1000
    max_files: int = 100
    max_size: int = 10485760  # 10MB
    exclude_patterns: List[str] = None
    include_patterns: List[str] = None
    rate_limit: int = 100
    timeout: int = 30
    retry_count: int = 3
    retry_delay: int = 1

@dataclass
class DiscordConfig:
    """Discord integration configuration."""
    webhook_url: str = None
    username: str = "E502 OSINT Scanner"
    avatar_url: str = None
    color_scheme: Dict[str, int] = None
    notification_settings: Dict[str, bool] = None
    templates_dir: str = None
    history_dir: str = None
    max_history: int = 1000
    export_format: str = "json"
    export_dir: str = None

@dataclass
class Config:
    """Main configuration class."""
    version: str = "1.0.0"
    last_updated: datetime = None
    network: NetworkConfig = None
    web: WebConfig = None
    privacy: PrivacyConfig = None
    scan: ScanConfig = None
    discord: DiscordConfig = None
    settings: Dict[str, Any] = None

class ConfigManager:
    def __init__(self):
        self.config_dir = Path("config")
        self.backup_dir = Path("config/backups")
        self.profiles_dir = Path("config/profiles")
        self._ensure_dirs()
        self._load_config()
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_config(self) -> None:
        """Load configuration."""
        try:
            config_path = self.config_dir / "config.json"
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
                    self.config = self._dict_to_config(config_data)
            else:
                self.config = self._create_default_config()
                self._save_config()
        except Exception as e:
            logger.error(f"Error loading config: {str(e)}")
            self.config = self._create_default_config()
    
    def _create_default_config(self) -> Config:
        """Create default configuration."""
        return Config(
            version="1.0.0",
            last_updated=datetime.now(pytz.UTC),
            network=NetworkConfig(
                ports=[21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080],
                protocols=["tcp", "udp"],
                scan_types=["port", "service", "os", "vulnerability"],
                dns_servers=["8.8.8.8", "8.8.4.4"]
            ),
            web=WebConfig(
                user_agent="E502 OSINT Scanner/1.0",
                headers={"Accept": "*/*"},
                scan_types=["content", "links", "forms", "headers", "ssl"],
                exclude_paths=["/admin", "/private", "/internal"]
            ),
            privacy=PrivacyConfig(
                user_agents=[
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                ],
                dns_servers=["8.8.8.8", "8.8.4.4"]
            ),
            scan=ScanConfig(
                exclude_patterns=["*.git/*", "*.svn/*", "*.env"],
                include_patterns=["*.html", "*.php", "*.asp", "*.aspx", "*.jsp"]
            ),
            discord=DiscordConfig(
                color_scheme={
                    "success": 0x00ff00,
                    "warning": 0xffff00,
                    "error": 0xff0000,
                    "info": 0x0000ff
                },
                notification_settings={
                    "scan_start": True,
                    "scan_complete": True,
                    "scan_error": True,
                    "critical_findings": True
                }
            ),
            settings={
                "log_level": "INFO",
                "log_file": "logs/e502osint.log",
                "max_log_size": 10485760,  # 10MB
                "max_log_files": 5,
                "data_dir": "data",
                "cache_dir": "cache",
                "temp_dir": "temp",
                "export_dir": "exports",
                "report_dir": "reports"
            }
        )
    
    def _save_config(self) -> None:
        """Save configuration."""
        try:
            config_path = self.config_dir / "config.json"
            with open(config_path, 'w') as f:
                json.dump(asdict(self.config), f, indent=4, default=str)
        except Exception as e:
            logger.error(f"Error saving config: {str(e)}")
    
    def _dict_to_config(self, data: Dict[str, Any]) -> Config:
        """Convert dictionary to Config object."""
        try:
            # Convert nested dictionaries to dataclass instances
            if 'network' in data:
                data['network'] = NetworkConfig(**data['network'])
            if 'web' in data:
                data['web'] = WebConfig(**data['web'])
            if 'privacy' in data:
                data['privacy'] = PrivacyConfig(**data['privacy'])
            if 'scan' in data:
                data['scan'] = ScanConfig(**data['scan'])
            if 'discord' in data:
                data['discord'] = DiscordConfig(**data['discord'])
            
            # Convert datetime strings
            if 'last_updated' in data:
                data['last_updated'] = datetime.fromisoformat(data['last_updated'])
            
            return Config(**data)
        except Exception as e:
            logger.error(f"Error converting dict to config: {str(e)}")
            return self._create_default_config()
    
    def backup_config(self) -> bool:
        """Create a backup of the current configuration."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_dir / f"config_backup_{timestamp}.json"
            
            with open(backup_path, 'w') as f:
                json.dump(asdict(self.config), f, indent=4, default=str)
            
            return True
        except Exception as e:
            logger.error(f"Error backing up config: {str(e)}")
            return False
    
    def restore_config(self, backup_file: str) -> bool:
        """Restore configuration from backup."""
        try:
            backup_path = self.backup_dir / backup_file
            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_file}")
                return False
            
            with open(backup_path, 'r') as f:
                config_data = json.load(f)
                self.config = self._dict_to_config(config_data)
            
            self._save_config()
            return True
        except Exception as e:
            logger.error(f"Error restoring config: {str(e)}")
            return False
    
    def update_config(self, section: str, key: str, value: Any) -> bool:
        """Update configuration value."""
        try:
            if not hasattr(self.config, section):
                logger.error(f"Invalid config section: {section}")
                return False
            
            section_obj = getattr(self.config, section)
            if not hasattr(section_obj, key):
                logger.error(f"Invalid config key: {key}")
                return False
            
            setattr(section_obj, key, value)
            self.config.last_updated = datetime.now(pytz.UTC)
            self._save_config()
            return True
        except Exception as e:
            logger.error(f"Error updating config: {str(e)}")
            return False
    
    def get_config(self, section: Optional[str] = None, key: Optional[str] = None) -> Any:
        """Get configuration value."""
        try:
            if section is None:
                return asdict(self.config)
            
            if not hasattr(self.config, section):
                logger.error(f"Invalid config section: {section}")
                return None
            
            section_obj = getattr(self.config, section)
            if key is None:
                return asdict(section_obj)
            
            if not hasattr(section_obj, key):
                logger.error(f"Invalid config key: {key}")
                return None
            
            return getattr(section_obj, key)
        except Exception as e:
            logger.error(f"Error getting config: {str(e)}")
            return None
    
    def export_config(self, format: str = "json", output_path: Optional[str] = None) -> bool:
        """Export configuration to file."""
        try:
            if not output_path:
                output_path = self.config_dir / f"config_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{format}"
            
            if format == "json":
                with open(output_path, 'w') as f:
                    json.dump(asdict(self.config), f, indent=4, default=str)
            elif format == "yaml":
                with open(output_path, 'w') as f:
                    yaml.dump(asdict(self.config), f, default_flow_style=False)
            else:
                logger.error(f"Unsupported export format: {format}")
                return False
            
            return True
        except Exception as e:
            logger.error(f"Error exporting config: {str(e)}")
            return False
    
    def import_config(self, file_path: str) -> bool:
        """Import configuration from file."""
        try:
            if not os.path.exists(file_path):
                logger.error(f"Config file not found: {file_path}")
                return False
            
            with open(file_path, 'r') as f:
                if file_path.endswith('.json'):
                    config_data = json.load(f)
                elif file_path.endswith('.yaml'):
                    config_data = yaml.safe_load(f)
                else:
                    logger.error(f"Unsupported config format: {file_path}")
                    return False
            
            self.config = self._dict_to_config(config_data)
            self._save_config()
            return True
        except Exception as e:
            logger.error(f"Error importing config: {str(e)}")
            return False
    
    def create_scan_profile(self, name: str, config: Dict[str, Any]) -> bool:
        """Create a new scan profile."""
        try:
            profile_path = self.profiles_dir / f"{name}.json"
            if profile_path.exists():
                logger.error(f"Profile already exists: {name}")
                return False
            
            with open(profile_path, 'w') as f:
                json.dump(config, f, indent=4)
            
            return True
        except Exception as e:
            logger.error(f"Error creating scan profile: {str(e)}")
            return False
    
    def load_scan_profile(self, name: str) -> Optional[Dict[str, Any]]:
        """Load a scan profile."""
        try:
            profile_path = self.profiles_dir / f"{name}.json"
            if not profile_path.exists():
                logger.error(f"Profile not found: {name}")
                return None
            
            with open(profile_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading scan profile: {str(e)}")
            return None
    
    def list_scan_profiles(self) -> List[str]:
        """List available scan profiles."""
        try:
            return [f.stem for f in self.profiles_dir.glob("*.json")]
        except Exception as e:
            logger.error(f"Error listing scan profiles: {str(e)}")
            return []
    
    def delete_scan_profile(self, name: str) -> bool:
        """Delete a scan profile."""
        try:
            profile_path = self.profiles_dir / f"{name}.json"
            if not profile_path.exists():
                logger.error(f"Profile not found: {name}")
                return False
            
            profile_path.unlink()
            return True
        except Exception as e:
            logger.error(f"Error deleting scan profile: {str(e)}")
            return False
    
    def display_config(self, section: Optional[str] = None) -> None:
        """Display configuration in a formatted way."""
        try:
            if section:
                config_data = self.get_config(section)
                if config_data is None:
                    return
                
                # Create table for section
                table = Table(title=f"{section.title()} Configuration")
                for key, value in config_data.items():
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, indent=2)
                    table.add_row(key, str(value))
                
                console.print(table)
            else:
                # Create table for all sections
                table = Table(title="Configuration Overview")
                table.add_column("Section", style="cyan")
                table.add_column("Last Updated", style="green")
                table.add_column("Version", style="yellow")
                
                for section in ['network', 'web', 'privacy', 'scan', 'discord']:
                    config_data = self.get_config(section)
                    if config_data:
                        table.add_row(
                            section,
                            self.config.last_updated.strftime("%Y-%m-%d %H:%M:%S"),
                            self.config.version
                        )
                
                console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying config: {str(e)}")
            console.print(f"[red]Error displaying config: {str(e)}[/]")

# Create global instance
config_manager = ConfigManager() 