"""
Notification Manager for E502 OSINT Terminal
Provides comprehensive notification management capabilities.
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
import aiohttp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
import yaml

logger = logging.getLogger("E502OSINT.NotificationManager")
console = Console()

@dataclass
class NotificationConfig:
    """Notification configuration data class."""
    type: str
    enabled: bool
    config: Dict[str, Any]
    created_at: datetime
    updated_at: datetime
    last_used: Optional[datetime] = None
    error_count: int = 0
    last_error: Optional[str] = None

@dataclass
class Notification:
    """Notification data class."""
    notification_id: str
    type: str
    title: str
    message: str
    level: str
    timestamp: datetime
    status: str
    error: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class NotificationManager:
    def __init__(self):
        self.notification_dir = Path("notifications")
        self.backup_dir = self.notification_dir / "backups"
        self.config_file = self.notification_dir / "config.json"
        self.history_file = self.notification_dir / "history.json"
        self._ensure_dirs()
        self._load_config()
        self._load_history()
    
    def _ensure_dirs(self) -> None:
        """Ensure required directories exist."""
        self.notification_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_config(self) -> None:
        """Load notification configuration."""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                    self.configs = [NotificationConfig(**config) for config in config_data]
            else:
                self.configs = []
                self._create_default_configs()
        except Exception as e:
            logger.error(f"Error loading config: {str(e)}")
            self.configs = []
    
    def _load_history(self) -> None:
        """Load notification history."""
        try:
            if self.history_file.exists():
                with open(self.history_file, 'r') as f:
                    history_data = json.load(f)
                    self.history = [Notification(**notification) for notification in history_data]
            else:
                self.history = []
        except Exception as e:
            logger.error(f"Error loading history: {str(e)}")
            self.history = []
    
    def _save_config(self) -> None:
        """Save notification configuration."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump([asdict(config) for config in self.configs], f, indent=4, default=str)
        except Exception as e:
            logger.error(f"Error saving config: {str(e)}")
    
    def _save_history(self) -> None:
        """Save notification history."""
        try:
            with open(self.history_file, 'w') as f:
                json.dump([asdict(notification) for notification in self.history], f, indent=4, default=str)
        except Exception as e:
            logger.error(f"Error saving history: {str(e)}")
    
    def _create_default_configs(self) -> None:
        """Create default notification configurations."""
        try:
            # Create Discord config
            discord_config = NotificationConfig(
                type="discord",
                enabled=True,
                config={
                    "webhook_url": "",
                    "username": "E502 OSINT Terminal",
                    "avatar_url": "",
                    "color_scheme": {
                        "info": 0x3498db,
                        "success": 0x2ecc71,
                        "warning": 0xf1c40f,
                        "error": 0xe74c3c
                    }
                },
                created_at=datetime.now(pytz.UTC),
                updated_at=datetime.now(pytz.UTC)
            )
            
            # Create email config
            email_config = NotificationConfig(
                type="email",
                enabled=False,
                config={
                    "smtp_server": "",
                    "smtp_port": 587,
                    "username": "",
                    "password": "",
                    "from_address": "",
                    "to_addresses": [],
                    "use_tls": True
                },
                created_at=datetime.now(pytz.UTC),
                updated_at=datetime.now(pytz.UTC)
            )
            
            # Create webhook config
            webhook_config = NotificationConfig(
                type="webhook",
                enabled=False,
                config={
                    "webhook_url": "",
                    "method": "POST",
                    "headers": {},
                    "timeout": 30,
                    "retry_count": 3
                },
                created_at=datetime.now(pytz.UTC),
                updated_at=datetime.now(pytz.UTC)
            )
            
            # Add configs
            self.configs = [
                discord_config,
                email_config,
                webhook_config
            ]
            
            self._save_config()
            
        except Exception as e:
            logger.error(f"Error creating default configs: {str(e)}")
    
    def add_config(self, config: NotificationConfig) -> bool:
        """Add a new notification configuration."""
        try:
            # Check if config with same type exists
            for existing_config in self.configs:
                if existing_config.type == config.type:
                    logger.error(f"Config with type '{config.type}' already exists")
                    return False
            
            # Add config
            self.configs.append(config)
            self._save_config()
            return True
        except Exception as e:
            logger.error(f"Error adding config: {str(e)}")
            return False
    
    def get_config(self, type: str) -> Optional[NotificationConfig]:
        """Get a notification configuration by type."""
        try:
            for config in self.configs:
                if config.type == type:
                    return config
            return None
        except Exception as e:
            logger.error(f"Error getting config: {str(e)}")
            return None
    
    def update_config(self, type: str, updates: Dict[str, Any]) -> bool:
        """Update a notification configuration."""
        try:
            for config in self.configs:
                if config.type == type:
                    for key, value in updates.items():
                        if hasattr(config, key):
                            setattr(config, key, value)
                    config.updated_at = datetime.now(pytz.UTC)
                    self._save_config()
                    return True
            return False
        except Exception as e:
            logger.error(f"Error updating config: {str(e)}")
            return False
    
    def delete_config(self, type: str) -> bool:
        """Delete a notification configuration."""
        try:
            for i, config in enumerate(self.configs):
                if config.type == type:
                    # Remove config
                    del self.configs[i]
                    self._save_config()
                    return True
            return False
        except Exception as e:
            logger.error(f"Error deleting config: {str(e)}")
            return False
    
    async def send_notification(self, type: str, title: str, message: str, level: str = "info", metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Send a notification."""
        try:
            # Get config
            config = self.get_config(type)
            if not config or not config.enabled:
                logger.error(f"Notification type '{type}' not configured or disabled")
                return False
            
            # Create notification
            notification = Notification(
                notification_id=hashlib.md5(f"{title}{message}{datetime.now().isoformat()}".encode()).hexdigest(),
                type=type,
                title=title,
                message=message,
                level=level,
                timestamp=datetime.now(pytz.UTC),
                status="pending",
                metadata=metadata
            )
            
            # Send notification based on type
            if type == "discord":
                success = await self._send_discord_notification(config, notification)
            elif type == "email":
                success = await self._send_email_notification(config, notification)
            elif type == "webhook":
                success = await self._send_webhook_notification(config, notification)
            else:
                logger.error(f"Unsupported notification type: {type}")
                return False
            
            # Update notification status
            if success:
                notification.status = "sent"
                config.last_used = datetime.now(pytz.UTC)
                config.error_count = 0
                config.last_error = None
            else:
                notification.status = "failed"
                config.error_count += 1
                config.last_error = notification.error
            
            # Update config
            config.updated_at = datetime.now(pytz.UTC)
            self._save_config()
            
            # Add to history
            self.history.append(notification)
            self._save_history()
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending notification: {str(e)}")
            return False
    
    async def _send_discord_notification(self, config: NotificationConfig, notification: Notification) -> bool:
        """Send a Discord notification."""
        try:
            if not config.config.get("webhook_url"):
                notification.error = "Webhook URL not configured"
                return False
            
            # Create embed
            embed = {
                "title": notification.title,
                "description": notification.message,
                "color": config.config["color_scheme"].get(notification.level, 0x3498db),
                "timestamp": notification.timestamp.isoformat()
            }
            
            # Add metadata if available
            if notification.metadata:
                for key, value in notification.metadata.items():
                    embed[key] = value
            
            # Create payload
            payload = {
                "username": config.config.get("username", "E502 OSINT Terminal"),
                "embeds": [embed]
            }
            
            # Add avatar if configured
            if config.config.get("avatar_url"):
                payload["avatar_url"] = config.config["avatar_url"]
            
            # Send request
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    config.config["webhook_url"],
                    json=payload,
                    timeout=30
                ) as response:
                    if response.status == 204:
                        return True
                    else:
                        notification.error = f"Discord API error: {response.status}"
                        return False
            
        except Exception as e:
            notification.error = str(e)
            return False
    
    async def _send_email_notification(self, config: NotificationConfig, notification: Notification) -> bool:
        """Send an email notification."""
        try:
            if not all([
                config.config.get("smtp_server"),
                config.config.get("smtp_port"),
                config.config.get("username"),
                config.config.get("password"),
                config.config.get("from_address"),
                config.config.get("to_addresses")
            ]):
                notification.error = "Email configuration incomplete"
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg["From"] = config.config["from_address"]
            msg["To"] = ", ".join(config.config["to_addresses"])
            msg["Subject"] = notification.title
            
            # Add body
            msg.attach(MIMEText(notification.message, "plain"))
            
            # Add metadata if available
            if notification.metadata:
                metadata_text = "\n\nMetadata:\n"
                for key, value in notification.metadata.items():
                    metadata_text += f"{key}: {value}\n"
                msg.attach(MIMEText(metadata_text, "plain"))
            
            # Send email
            with smtplib.SMTP(config.config["smtp_server"], config.config["smtp_port"]) as server:
                if config.config["use_tls"]:
                    server.starttls()
                server.login(config.config["username"], config.config["password"])
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            notification.error = str(e)
            return False
    
    async def _send_webhook_notification(self, config: NotificationConfig, notification: Notification) -> bool:
        """Send a webhook notification."""
        try:
            if not config.config.get("webhook_url"):
                notification.error = "Webhook URL not configured"
                return False
            
            # Create payload
            payload = {
                "title": notification.title,
                "message": notification.message,
                "level": notification.level,
                "timestamp": notification.timestamp.isoformat()
            }
            
            # Add metadata if available
            if notification.metadata:
                payload["metadata"] = notification.metadata
            
            # Send request
            async with aiohttp.ClientSession() as session:
                for attempt in range(config.config.get("retry_count", 3)):
                    try:
                        async with session.request(
                            config.config.get("method", "POST"),
                            config.config["webhook_url"],
                            json=payload,
                            headers=config.config.get("headers", {}),
                            timeout=config.config.get("timeout", 30)
                        ) as response:
                            if response.status in [200, 201, 202, 204]:
                                return True
                            else:
                                notification.error = f"Webhook error: {response.status}"
                    except Exception as e:
                        if attempt == config.config.get("retry_count", 3) - 1:
                            notification.error = str(e)
                            return False
                        continue
            
            return False
            
        except Exception as e:
            notification.error = str(e)
            return False
    
    def get_notification(self, notification_id: str) -> Optional[Notification]:
        """Get a notification by ID."""
        try:
            for notification in self.history:
                if notification.notification_id == notification_id:
                    return notification
            return None
        except Exception as e:
            logger.error(f"Error getting notification: {str(e)}")
            return None
    
    def get_notifications_by_type(self, type: str) -> List[Notification]:
        """Get all notifications of a specific type."""
        try:
            return [notification for notification in self.history if notification.type == type]
        except Exception as e:
            logger.error(f"Error getting notifications by type: {str(e)}")
            return []
    
    def get_notifications_by_level(self, level: str) -> List[Notification]:
        """Get all notifications of a specific level."""
        try:
            return [notification for notification in self.history if notification.level == level]
        except Exception as e:
            logger.error(f"Error getting notifications by level: {str(e)}")
            return []
    
    def get_notifications_by_status(self, status: str) -> List[Notification]:
        """Get all notifications with a specific status."""
        try:
            return [notification for notification in self.history if notification.status == status]
        except Exception as e:
            logger.error(f"Error getting notifications by status: {str(e)}")
            return []
    
    def backup_config(self) -> bool:
        """Create a backup of notification configuration."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.backup_dir / f"config_backup_{timestamp}.json"
            
            with open(backup_path, 'w') as f:
                json.dump([asdict(config) for config in self.configs], f, indent=4, default=str)
            
            return True
        except Exception as e:
            logger.error(f"Error backing up config: {str(e)}")
            return False
    
    def restore_config(self, backup_file: str) -> bool:
        """Restore notification configuration from backup."""
        try:
            backup_path = self.backup_dir / backup_file
            if not backup_path.exists():
                logger.error(f"Backup file not found: {backup_file}")
                return False
            
            with open(backup_path, 'r') as f:
                config_data = json.load(f)
                self.configs = [NotificationConfig(**config) for config in config_data]
            
            self._save_config()
            return True
        except Exception as e:
            logger.error(f"Error restoring config: {str(e)}")
            return False
    
    def display_configs(self) -> None:
        """Display notification configurations in a formatted way."""
        try:
            # Create table
            table = Table(title="Notification Configurations")
            table.add_column("Type", style="cyan")
            table.add_column("Enabled", style="green")
            table.add_column("Last Used", style="yellow")
            table.add_column("Error Count", style="magenta")
            table.add_column("Last Error", style="red")
            
            # Add rows
            for config in self.configs:
                table.add_row(
                    config.type,
                    str(config.enabled),
                    config.last_used.strftime("%Y-%m-%d %H:%M:%S") if config.last_used else "Never",
                    str(config.error_count),
                    config.last_error or "None"
                )
            
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying configs: {str(e)}")
            console.print(f"[red]Error displaying configs: {str(e)}[/]")
    
    def display_history(self, filters: Optional[Dict[str, Any]] = None) -> None:
        """Display notification history in a formatted way."""
        try:
            # Filter history if needed
            filtered_history = self.history
            if filters:
                if "type" in filters:
                    filtered_history = [n for n in filtered_history if n.type == filters["type"]]
                if "level" in filters:
                    filtered_history = [n for n in filtered_history if n.level == filters["level"]]
                if "status" in filters:
                    filtered_history = [n for n in filtered_history if n.status == filters["status"]]
            
            # Create table
            table = Table(title="Notification History")
            table.add_column("ID", style="cyan")
            table.add_column("Type", style="green")
            table.add_column("Title", style="yellow")
            table.add_column("Level", style="magenta")
            table.add_column("Status", style="blue")
            table.add_column("Timestamp", style="red")
            
            # Add rows
            for notification in filtered_history:
                table.add_row(
                    notification.notification_id[:8],
                    notification.type,
                    notification.title,
                    notification.level,
                    notification.status,
                    notification.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                )
            
            console.print(table)
            
        except Exception as e:
            logger.error(f"Error displaying history: {str(e)}")
            console.print(f"[red]Error displaying history: {str(e)}[/]")

# Create global instance
notification_manager = NotificationManager() 