"""
Scan Configurator for E502 OSINT Terminal
Provides comprehensive scan configuration management capabilities.
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
import yaml
import shutil
import hashlib
from dataclasses import dataclass, asdict

logger = logging.getLogger("E502OSINT.ScanConfigurator")
console = Console()

@dataclass
class ScanConfig:
    """Scan configuration."""
    name: str
    description: str
    scan_type: str
    target: str
    options: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    author: str
    version: str
    tags: List[str]
    enabled: bool
    schedule: Optional[Dict[str, Any]]
    notifications: Optional[Dict[str, Any]]

class ScanConfigurator:
    def __init__(self):
        self.scan_dir = Path("scans")
        self.config_dir = self.scan_dir / "configs"
        self._ensure_dirs()
        
        # Initialize configurations
        self.configs = {}
        self._load_configs()
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.scan_dir.mkdir(parents=True, exist_ok=True)
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_configs(self) -> None:
        """Load configurations."""
        try:
            # Clear existing configurations
            self.configs.clear()
            
            # Load configurations from files
            for file_path in self.config_dir.glob("*.json"):
                try:
                    with open(file_path, "r") as f:
                        data = json.load(f)
                    
                    # Create configuration
                    config = ScanConfig(
                        name=data["name"],
                        description=data["description"],
                        scan_type=data["scan_type"],
                        target=data["target"],
                        options=data["options"],
                        created_at=datetime.fromisoformat(data["created_at"]),
                        updated_at=datetime.fromisoformat(data["updated_at"]),
                        author=data["author"],
                        version=data["version"],
                        tags=data["tags"],
                        enabled=data["enabled"],
                        schedule=data.get("schedule"),
                        notifications=data.get("notifications")
                    )
                    
                    # Add configuration
                    self.configs[config.name] = config
                    
                except Exception as e:
                    logger.error(f"Error loading configuration {file_path}: {str(e)}")
            
            logger.info(f"Loaded {len(self.configs)} configurations")
            
        except Exception as e:
            logger.error(f"Error loading configurations: {str(e)}")
    
    def _save_configs(self) -> None:
        """Save configurations."""
        try:
            # Save each configuration
            for config in self.configs.values():
                try:
                    # Convert to dict
                    data = asdict(config)
                    
                    # Convert datetime to string
                    data["created_at"] = data["created_at"].isoformat()
                    data["updated_at"] = data["updated_at"].isoformat()
                    
                    # Save to file
                    file_path = self.config_dir / f"{config.name}.json"
                    with open(file_path, "w") as f:
                        json.dump(data, f, indent=4)
                    
                except Exception as e:
                    logger.error(f"Error saving configuration {config.name}: {str(e)}")
            
            logger.info(f"Saved {len(self.configs)} configurations")
            
        except Exception as e:
            logger.error(f"Error saving configurations: {str(e)}")
    
    def add_config(self, config: ScanConfig) -> bool:
        """Add a configuration."""
        try:
            # Check if configuration exists
            if config.name in self.configs:
                logger.error(f"Configuration {config.name} already exists")
                return False
            
            # Add configuration
            self.configs[config.name] = config
            
            # Save configurations
            self._save_configs()
            
            logger.info(f"Added configuration: {config.name}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding configuration: {str(e)}")
            return False
    
    def update_config(self, config: ScanConfig) -> bool:
        """Update a configuration."""
        try:
            # Check if configuration exists
            if config.name not in self.configs:
                logger.error(f"Configuration {config.name} does not exist")
                return False
            
            # Update configuration
            self.configs[config.name] = config
            
            # Save configurations
            self._save_configs()
            
            logger.info(f"Updated configuration: {config.name}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating configuration: {str(e)}")
            return False
    
    def delete_config(self, name: str) -> bool:
        """Delete a configuration."""
        try:
            # Check if configuration exists
            if name not in self.configs:
                logger.error(f"Configuration {name} does not exist")
                return False
            
            # Delete configuration
            del self.configs[name]
            
            # Delete configuration file
            file_path = self.config_dir / f"{name}.json"
            if file_path.exists():
                file_path.unlink()
            
            # Save configurations
            self._save_configs()
            
            logger.info(f"Deleted configuration: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting configuration: {str(e)}")
            return False
    
    def get_config(self, name: str) -> Optional[ScanConfig]:
        """Get a configuration."""
        try:
            return self.configs.get(name)
            
        except Exception as e:
            logger.error(f"Error getting configuration: {str(e)}")
            return None
    
    def get_configs_by_type(self, scan_type: str) -> List[ScanConfig]:
        """Get configurations by scan type."""
        try:
            return [
                config for config in self.configs.values()
                if config.scan_type == scan_type
            ]
            
        except Exception as e:
            logger.error(f"Error getting configurations by type: {str(e)}")
            return []
    
    def get_configs_by_tag(self, tag: str) -> List[ScanConfig]:
        """Get configurations by tag."""
        try:
            return [
                config for config in self.configs.values()
                if tag in config.tags
            ]
            
        except Exception as e:
            logger.error(f"Error getting configurations by tag: {str(e)}")
            return []
    
    def get_enabled_configs(self) -> List[ScanConfig]:
        """Get enabled configurations."""
        try:
            return [
                config for config in self.configs.values()
                if config.enabled
            ]
            
        except Exception as e:
            logger.error(f"Error getting enabled configurations: {str(e)}")
            return []
    
    def get_scheduled_configs(self) -> List[ScanConfig]:
        """Get scheduled configurations."""
        try:
            return [
                config for config in self.configs.values()
                if config.schedule is not None
            ]
            
        except Exception as e:
            logger.error(f"Error getting scheduled configurations: {str(e)}")
            return []
    
    def backup_configs(self) -> bool:
        """Backup configurations."""
        try:
            # Create backup directory
            backup_dir = self.config_dir / "backup"
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            # Create backup timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Create backup directory
            backup_path = backup_dir / timestamp
            backup_path.mkdir(parents=True, exist_ok=True)
            
            # Copy configuration files
            for file_path in self.config_dir.glob("*.json"):
                if file_path.parent != backup_path:
                    shutil.copy2(file_path, backup_path)
            
            logger.info(f"Backed up configurations to: {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error backing up configurations: {str(e)}")
            return False
    
    def restore_configs(self, timestamp: str) -> bool:
        """Restore configurations."""
        try:
            # Check backup directory
            backup_dir = self.config_dir / "backup"
            if not backup_dir.exists():
                logger.error("Backup directory does not exist")
                return False
            
            # Check backup timestamp
            backup_path = backup_dir / timestamp
            if not backup_path.exists():
                logger.error(f"Backup {timestamp} does not exist")
                return False
            
            # Clear existing configurations
            self.configs.clear()
            
            # Copy configuration files
            for file_path in backup_path.glob("*.json"):
                shutil.copy2(file_path, self.config_dir)
            
            # Load configurations
            self._load_configs()
            
            logger.info(f"Restored configurations from: {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error restoring configurations: {str(e)}")
            return False
    
    def export_config(self, name: str, format: str = "json") -> Optional[str]:
        """Export a configuration."""
        try:
            # Get configuration
            config = self.get_config(name)
            if not config:
                logger.error(f"Configuration {name} does not exist")
                return None
            
            # Convert to dict
            data = asdict(config)
            
            # Convert datetime to string
            data["created_at"] = data["created_at"].isoformat()
            data["updated_at"] = data["updated_at"].isoformat()
            
            # Export based on format
            if format == "json":
                # Save to file
                file_path = self.config_dir / f"{name}_export.json"
                with open(file_path, "w") as f:
                    json.dump(data, f, indent=4)
            
            elif format == "yaml":
                # Save to file
                file_path = self.config_dir / f"{name}_export.yaml"
                with open(file_path, "w") as f:
                    yaml.dump(data, f, default_flow_style=False)
            
            else:
                logger.error(f"Unsupported format: {format}")
                return None
            
            logger.info(f"Exported configuration {name} to: {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Error exporting configuration: {str(e)}")
            return None
    
    def import_config(self, file_path: str) -> bool:
        """Import a configuration."""
        try:
            # Check if file exists
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return False
            
            # Get file format
            format = file_path.split(".")[-1].lower()
            
            # Import data
            if format == "json":
                with open(file_path, "r") as f:
                    data = json.load(f)
            
            elif format == "yaml":
                with open(file_path, "r") as f:
                    data = yaml.safe_load(f)
            
            else:
                logger.error(f"Unsupported format: {format}")
                return False
            
            # Create configuration
            config = ScanConfig(
                name=data["name"],
                description=data["description"],
                scan_type=data["scan_type"],
                target=data["target"],
                options=data["options"],
                created_at=datetime.fromisoformat(data["created_at"]),
                updated_at=datetime.fromisoformat(data["updated_at"]),
                author=data["author"],
                version=data["version"],
                tags=data["tags"],
                enabled=data["enabled"],
                schedule=data.get("schedule"),
                notifications=data.get("notifications")
            )
            
            # Add configuration
            return self.add_config(config)
            
        except Exception as e:
            logger.error(f"Error importing configuration: {str(e)}")
            return False
    
    def display_configs(self) -> None:
        """Display configurations."""
        try:
            # Get configurations
            configs = list(self.configs.values())
            
            if not configs:
                console.print("[yellow]No configurations available[/yellow]")
                return
            
            # Create table
            table = Table(title="Scan Configurations")
            
            # Add columns
            table.add_column("Name", style="cyan")
            table.add_column("Type", style="magenta")
            table.add_column("Target", style="green")
            table.add_column("Version", style="blue")
            table.add_column("Tags", style="yellow")
            table.add_column("Enabled", style="red")
            
            # Add rows
            for config in configs:
                table.add_row(
                    config.name,
                    config.scan_type,
                    config.target,
                    config.version,
                    ", ".join(config.tags),
                    str(config.enabled)
                )
            
            # Display table
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying configurations: {str(e)}")
            console.print(f"[red]Error displaying configurations: {str(e)}[/red]")
    
    def display_config(self, name: str) -> None:
        """Display a configuration."""
        try:
            # Get configuration
            config = self.get_config(name)
            
            if not config:
                console.print(f"[red]Configuration {name} does not exist[/red]")
                return
            
            # Create table
            table = Table(title=f"Configuration: {name}")
            
            # Add rows
            table.add_row("Name", config.name)
            table.add_row("Description", config.description)
            table.add_row("Type", config.scan_type)
            table.add_row("Target", config.target)
            table.add_row("Version", config.version)
            table.add_row("Author", config.author)
            table.add_row("Tags", ", ".join(config.tags))
            table.add_row("Enabled", str(config.enabled))
            table.add_row("Created", config.created_at.isoformat())
            table.add_row("Updated", config.updated_at.isoformat())
            
            if config.schedule:
                table.add_row("Schedule", json.dumps(config.schedule, indent=2))
            
            if config.notifications:
                table.add_row("Notifications", json.dumps(config.notifications, indent=2))
            
            table.add_row("Options", json.dumps(config.options, indent=2))
            
            # Display table
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying configuration: {str(e)}")
            console.print(f"[red]Error displaying configuration: {str(e)}[/red]")

# Create global instance
scan_configurator = ScanConfigurator() 