"""
Configuration management for VulnPublisherPro
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

@dataclass
class DatabaseConfig:
    url: Optional[str] = None  # PostgreSQL URL from DATABASE_URL secret
    path: str = "vulnpublisher.db"  # Fallback SQLite path
    backup_enabled: bool = True
    backup_interval: int = 86400  # 24 hours

@dataclass
class ScrapingConfig:
    default_limit: int = 100
    rate_limit_delay: float = 1.0
    retry_attempts: int = 3
    timeout: int = 30
    user_agent: str = "VulnPublisherPro/1.0"

@dataclass
class PublishingConfig:
    default_platforms: Optional[list] = None
    content_templates: Optional[Dict[str, str]] = None
    rate_limit_delay: float = 2.0
    retry_attempts: int = 3

@dataclass
class SchedulingConfig:
    enabled: bool = False
    scrape_interval: int = 3600  # 1 hour
    publish_interval: int = 7200  # 2 hours
    cleanup_interval: int = 86400  # 24 hours

class Config:
    """Configuration manager for VulnPublisherPro"""
    
    def __init__(self, config_path: Optional[str] = None):
        # Load environment variables
        load_dotenv()
        
        # Set default config path
        if not config_path:
            config_path = os.getenv('VULNPUB_CONFIG', 'config.json')
        
        self.config_path = config_path
        self._config = {}
        
        # Initialize default configuration
        self._set_defaults()
        
        # Load configuration file if it exists
        if Path(config_path).exists():
            self._load_config_file()
        
        # Override with environment variables
        self._load_env_vars()
    
    def _set_defaults(self):
        """Set default configuration values"""
        self._config = {
            'database': asdict(DatabaseConfig()),
            'scraping': asdict(ScrapingConfig()),
            'publishing': asdict(PublishingConfig(
                default_platforms=['twitter', 'linkedin', 'telegram'],
                content_templates={
                    'summary': "🚨 New {severity} vulnerability: {cve_id}\n{description}\nCVSS: {cvss_score}\nSource: {source}",
                    'detailed': "🔍 Vulnerability Alert: {cve_id}\n\nSeverity: {severity}\nCVSS Score: {cvss_score}\n\nDescription:\n{description}\n\nAffected Products:\n{affected_products}\n\nSource: {source}\nPublished: {published_date}",
                    'alert': "⚠️ CRITICAL: {cve_id} - {severity}\n{description}\nImmediate action required!",
                    'thread': "🧵 Thread: Deep dive into {cve_id}\n\n1/ Overview: {description}\n\n2/ Technical Details: {technical_details}\n\n3/ Impact Assessment: {impact}\n\n4/ Mitigation: {mitigation}"
                }
            )),
            'scheduling': asdict(SchedulingConfig()),
            'logging': {
                'level': 'INFO',
                'file': 'vulnpublisher.log',
                'max_size': 10485760,  # 10MB
                'backup_count': 5
            }
        }
    
    def _load_config_file(self):
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r') as f:
                file_config = json.load(f)
                self._merge_config(file_config)
            logger.info(f"Loaded configuration from {self.config_path}")
        except Exception as e:
            logger.error(f"Error loading config file {self.config_path}: {e}")
    
    def _load_env_vars(self):
        """Load configuration from environment variables"""
        # Database configuration
        self.database_url = os.getenv('DATABASE_URL')
        
        # API Keys
        self.openai_api_key = os.getenv('OPENAI_API_KEY')
        
        # Vulnerability source API keys
        self.nvd_api_key = os.getenv('NVD_API_KEY')
        self.github_token = os.getenv('GITHUB_TOKEN')
        self.hackerone_username = os.getenv('HACKERONE_USERNAME')
        self.hackerone_token = os.getenv('HACKERONE_TOKEN')
        self.bugcrowd_token = os.getenv('BUGCROWD_TOKEN')
        self.intigriti_token = os.getenv('INTIGRITI_TOKEN')
        self.vulncheck_token = os.getenv('VULNCHECK_TOKEN')
        self.cve_details_token = os.getenv('CVE_DETAILS_TOKEN')
        self.vulndb_token = os.getenv('VULNDB_TOKEN')
        
        # Social media API keys
        self.twitter_api_key = os.getenv('TWITTER_API_KEY')
        self.twitter_api_secret = os.getenv('TWITTER_API_SECRET')
        self.twitter_access_token = os.getenv('TWITTER_ACCESS_TOKEN')
        self.twitter_access_token_secret = os.getenv('TWITTER_ACCESS_TOKEN_SECRET')
        
        self.linkedin_access_token = os.getenv('LINKEDIN_ACCESS_TOKEN')
        self.linkedin_person_id = os.getenv('LINKEDIN_PERSON_ID')
        
        self.telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
        self.telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')
        
        self.discord_bot_token = os.getenv('DISCORD_BOT_TOKEN')
        self.discord_channel_id = os.getenv('DISCORD_CHANNEL_ID')
        
        self.reddit_client_id = os.getenv('REDDIT_CLIENT_ID')
        self.reddit_client_secret = os.getenv('REDDIT_CLIENT_SECRET')
        self.reddit_username = os.getenv('REDDIT_USERNAME')
        self.reddit_password = os.getenv('REDDIT_PASSWORD')
        
        self.medium_token = os.getenv('MEDIUM_TOKEN')
        self.facebook_access_token = os.getenv('FACEBOOK_ACCESS_TOKEN')
        self.instagram_access_token = os.getenv('INSTAGRAM_ACCESS_TOKEN')
        self.youtube_api_key = os.getenv('YOUTUBE_API_KEY')
        self.tiktok_access_token = os.getenv('TIKTOK_ACCESS_TOKEN')
        self.mastodon_access_token = os.getenv('MASTODON_ACCESS_TOKEN')
        self.mastodon_instance_url = os.getenv('MASTODON_INSTANCE_URL', 'https://mastodon.social')
        self.slack_token = os.getenv('SLACK_TOKEN')
        self.slack_channel = os.getenv('SLACK_CHANNEL')
        self.teams_webhook_url = os.getenv('TEAMS_WEBHOOK_URL')
        
        # Override config with environment variables
        env_overrides = {
            'database.path': os.getenv('DATABASE_PATH'),
            'scraping.default_limit': int(os.getenv('SCRAPING_DEFAULT_LIMIT', '0')) or None,
            'scraping.rate_limit_delay': float(os.getenv('SCRAPING_RATE_LIMIT', '0')) or None,
            'publishing.rate_limit_delay': float(os.getenv('PUBLISHING_RATE_LIMIT', '0')) or None,
            'scheduling.enabled': os.getenv('SCHEDULING_ENABLED', 'false').lower() == 'true',
            'scheduling.scrape_interval': int(os.getenv('SCRAPE_INTERVAL', '0')) or None,
            'scheduling.publish_interval': int(os.getenv('PUBLISH_INTERVAL', '0')) or None
        }
        
        for key, value in env_overrides.items():
            if value is not None:
                self._set_nested_value(key, value)
    
    def _merge_config(self, new_config: Dict[str, Any]):
        """Merge new configuration with existing"""
        def merge_dict(base: Dict, overlay: Dict):
            for key, value in overlay.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    merge_dict(base[key], value)
                else:
                    base[key] = value
        
        merge_dict(self._config, new_config)
    
    def _set_nested_value(self, key_path: str, value: Any):
        """Set a nested configuration value using dot notation"""
        keys = key_path.split('.')
        current = self._config
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get a configuration value using dot notation"""
        keys = key_path.split('.')
        current = self._config
        
        try:
            for key in keys:
                current = current[key]
            return current
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any):
        """Set a configuration value using dot notation"""
        self._set_nested_value(key_path, value)
    
    def save(self, path: Optional[str] = None):
        """Save configuration to file"""
        save_path = path or self.config_path
        
        try:
            with open(save_path, 'w') as f:
                json.dump(self._config, f, indent=2)
            logger.info(f"Configuration saved to {save_path}")
        except Exception as e:
            logger.error(f"Error saving configuration to {save_path}: {e}")
    
    @property
    def database_path(self) -> str:
        return self.get('database.path', 'vulnpublisher.db')
    
    @property
    def database_url(self) -> Optional[str]:
        return getattr(self, '_database_url', None)
    
    @database_url.setter
    def database_url(self, value: Optional[str]):
        self._database_url = value
    
    @property
    def scraping_config(self) -> ScrapingConfig:
        return ScrapingConfig(**self.get('scraping', {}))
    
    @property
    def publishing_config(self) -> PublishingConfig:
        config_dict = self.get('publishing', {})
        # Ensure default_platforms is a list
        if config_dict.get('default_platforms') is None:
            config_dict['default_platforms'] = ['twitter', 'linkedin', 'telegram']
        if config_dict.get('content_templates') is None:
            config_dict['content_templates'] = self._config['publishing']['content_templates']
        return PublishingConfig(**config_dict)
    
    @property
    def scheduling_config(self) -> SchedulingConfig:
        return SchedulingConfig(**self.get('scheduling', {}))
    
    def validate(self) -> bool:
        """Validate configuration"""
        errors = []
        
        # Check required API keys
        if not self.openai_api_key:
            errors.append("OpenAI API key is required (OPENAI_API_KEY)")
        
        # Check database path is writable
        db_path = Path(self.database_path)
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            if not os.access(db_path.parent, os.W_OK):
                errors.append(f"Database directory is not writable: {db_path.parent}")
        except Exception as e:
            errors.append(f"Error checking database path: {e}")
        
        # Validate platform configurations
        publishing_config = self.publishing_config
        if not publishing_config.default_platforms:
            errors.append("At least one default publishing platform must be configured")
        
        # Log validation results
        if errors:
            for error in errors:
                logger.error(f"Configuration error: {error}")
            return False
        
        logger.info("Configuration validation passed")
        return True
    
    def get_platform_config(self, platform: str) -> Dict[str, Any]:
        """Get platform-specific configuration"""
        platform_configs = {
            'twitter': {
                'api_key': self.twitter_api_key,
                'api_secret': self.twitter_api_secret,
                'access_token': self.twitter_access_token,
                'access_token_secret': self.twitter_access_token_secret
            },
            'linkedin': {
                'access_token': self.linkedin_access_token,
                'person_id': self.linkedin_person_id
            },
            'telegram': {
                'bot_token': self.telegram_bot_token,
                'chat_id': self.telegram_chat_id
            },
            'discord': {
                'bot_token': self.discord_bot_token,
                'channel_id': self.discord_channel_id
            },
            'reddit': {
                'client_id': self.reddit_client_id,
                'client_secret': self.reddit_client_secret,
                'username': self.reddit_username,
                'password': self.reddit_password
            },
            'medium': {
                'token': self.medium_token
            },
            'facebook': {
                'access_token': self.facebook_access_token
            },
            'instagram': {
                'access_token': self.instagram_access_token
            },
            'youtube': {
                'api_key': self.youtube_api_key
            },
            'tiktok': {
                'access_token': self.tiktok_access_token
            },
            'mastodon': {
                'access_token': self.mastodon_access_token,
                'instance_url': self.mastodon_instance_url
            },
            'slack': {
                'token': self.slack_token,
                'channel': self.slack_channel
            },
            'teams': {
                'webhook_url': self.teams_webhook_url
            }
        }
        
        return platform_configs.get(platform, {})
