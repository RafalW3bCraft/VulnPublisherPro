"""
Configuration Manager for GitHub Automation Suite
Handles JSON-based configuration with backward compatibility
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

class ConfigManager:
    """Manages configuration for GitHub automation features"""
    
    def __init__(self, config_dir: str = "data"):
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / "config.json"
        
        # Ensure config directory exists
        self.config_dir.mkdir(exist_ok=True)
        
        # Default configuration
        self.default_config = {
            "USERNAME": None,
            "TOKEN": None,
            "PROMOTION": {
                "enabled": False,
                "days_period": 7,
                "count_promotion_users": 50,
                "min_followers": 0,
                "filter_verified": False
            },
            "RETRY": {
                "enabled": True,
                "max_retries": 10,
                "delay": 1,
                "exponential_backoff": True
            },
            "AUTO_SYNC": {
                "enabled": False,
                "check_interval": 3600,
                "follow_back": True,
                "unfollow_non_followers": True
            },
            "RATE_LIMITING": {
                "requests_per_hour": 5000,
                "follow_delay": 0.3,
                "unfollow_delay": 0.3
            },
            "LOGGING": {
                "level": "INFO",
                "file": "logs/github_automation.log"
            }
        }
        
        # Load or create config
        self.config = self._load_or_create_config()
    
    def _load_or_create_config(self) -> Dict[str, Any]:
        """Load existing config or create default one"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as file:
                    config = json.load(file)
                
                # Merge with defaults to ensure all keys exist
                merged_config = self._deep_merge(self.default_config.copy(), config)
                
                # Save merged config back to file
                self._save_config(merged_config)
                
                return merged_config
            except (json.JSONDecodeError, Exception) as e:
                logging.warning(f"Error loading config file: {e}. Using defaults.")
                return self._create_default_config()
        else:
            return self._create_default_config()
    
    def _create_default_config(self) -> Dict[str, Any]:
        """Create default configuration file"""
        config = self.default_config.copy()
        
        # Try to get GitHub token from environment
        config["TOKEN"] = os.getenv("GITHUB_TOKEN")
        config["USERNAME"] = os.getenv("GITHUB_USERNAME")
        
        self._save_config(config)
        return config
    
    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries"""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to file"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as file:
                json.dump(config, file, indent=4)
        except Exception as e:
            logging.error(f"Error saving config file: {e}")
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            key_path: Dot-separated key path (e.g., 'PROMOTION.enabled')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any) -> None:
        """
        Set configuration value using dot notation
        
        Args:
            key_path: Dot-separated key path (e.g., 'PROMOTION.enabled')
            value: Value to set
        """
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to parent key
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the final value
        config[keys[-1]] = value
        
        # Save updated config
        self._save_config(self.config)
    
    def update_promotion_config(self, **kwargs) -> None:
        """Update promotion configuration"""
        for key, value in kwargs.items():
            self.set(f"PROMOTION.{key}", value)
    
    def update_retry_config(self, **kwargs) -> None:
        """Update retry configuration"""
        for key, value in kwargs.items():
            self.set(f"RETRY.{key}", value)
    
    def update_auto_sync_config(self, **kwargs) -> None:
        """Update auto-sync configuration"""
        for key, value in kwargs.items():
            self.set(f"AUTO_SYNC.{key}", value)
    
    def get_github_credentials(self) -> tuple[Optional[str], Optional[str]]:
        """Get GitHub username and token"""
        username = self.get("USERNAME") or os.getenv("GITHUB_USERNAME")
        token = self.get("TOKEN") or os.getenv("GITHUB_TOKEN")
        
        return username, token
    
    def set_github_credentials(self, username: str, token: str) -> None:
        """Set GitHub credentials"""
        self.set("USERNAME", username)
        self.set("TOKEN", token)
    
    def is_promotion_enabled(self) -> bool:
        """Check if promotion system is enabled"""
        return self.get("PROMOTION.enabled", False)
    
    def is_auto_sync_enabled(self) -> bool:
        """Check if auto-sync mode is enabled"""
        return self.get("AUTO_SYNC.enabled", False)
    
    def get_rate_limits(self) -> Dict[str, float]:
        """Get rate limiting configuration"""
        return {
            "follow_delay": self.get("RATE_LIMITING.follow_delay", 0.3),
            "unfollow_delay": self.get("RATE_LIMITING.unfollow_delay", 0.3),
            "requests_per_hour": self.get("RATE_LIMITING.requests_per_hour", 5000)
        }
    
    def export_config(self) -> str:
        """Export current configuration as JSON string"""
        return json.dumps(self.config, indent=4)
    
    def import_config(self, config_json: str) -> bool:
        """
        Import configuration from JSON string
        
        Args:
            config_json: JSON string containing configuration
            
        Returns:
            True if successful, False otherwise
        """
        try:
            new_config = json.loads(config_json)
            self.config = self._deep_merge(self.default_config.copy(), new_config)
            self._save_config(self.config)
            return True
        except (json.JSONDecodeError, Exception) as e:
            logging.error(f"Error importing config: {e}")
            return False