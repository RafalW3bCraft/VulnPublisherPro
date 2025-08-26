"""
Utility functions for VulnPublisherPro
"""

import logging
import logging.handlers
import os
import json
import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
import asyncio

def setup_logging(level: int = logging.INFO, 
                 log_file: str = "vulnpublisher.log",
                 max_size: int = 10485760,  # 10MB
                 backup_count: int = 5) -> logging.Logger:
    """Setup logging configuration"""
    
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    )
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(simple_formatter)
    logger.addHandler(console_handler)
    
    # File handler with rotation
    if log_file:
        try:
            # Create log directory if it doesn't exist
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_size,
                backupCount=backup_count
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(detailed_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Could not create file handler: {e}")
    
    # Set specific loggers to reduce noise
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('aiohttp').setLevel(logging.WARNING)
    
    logger.info("Logging setup completed")
    return logger

def validate_config(config) -> bool:
    """Validate configuration and required settings"""
    
    logger = logging.getLogger(__name__)
    
    # Check environment variables
    required_env_vars = ['OPENAI_API_KEY']
    missing_vars = []
    
    for var in required_env_vars:
        if not os.getenv(var):
            missing_vars.append(var)
    
    if missing_vars:
        logger.warning(f"Missing environment variables: {', '.join(missing_vars)} - some features may not work")
        # Don't fail validation for missing API keys, just warn
    
    # Check config object if provided
    if hasattr(config, 'config_path') and config.config_path and Path(config.config_path).exists():
        try:
            with open(config.config_path, 'r') as f:
                config_data = json.load(f)
            
            # Validate config structure
            required_sections = ['database', 'scraping', 'publishing', 'scheduling']
            for section in required_sections:
                if section not in config_data:
                    logger.warning(f"Missing config section: {section}")
            
            logger.info("Configuration file validation passed")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            return False
        except Exception as e:
            logger.error(f"Error reading config file: {e}")
            return False
    
    return True

def generate_vulnerability_hash(vulnerability: Dict[str, Any]) -> str:
    """Generate a unique hash for a vulnerability for deduplication"""
    
    # Use key fields to generate a unique hash
    key_data = {
        'cve_id': vulnerability.get('cve_id', ''),
        'title': vulnerability.get('title', ''),
        'description': vulnerability.get('description', ''),
        'source': vulnerability.get('source', '')
    }
    
    # Sort to ensure consistent ordering
    content = json.dumps(key_data, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()

def normalize_severity(severity: str) -> str:
    """Normalize severity to standard levels"""
    if not severity:
        return 'unknown'
    
    severity = severity.lower().strip()
    
    severity_map = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'moderate': 'medium',
        'low': 'low',
        'none': 'low',
        'info': 'low',
        'informational': 'low',
        'important': 'high',
        'severe': 'high'
    }
    
    return severity_map.get(severity, 'unknown')

def parse_cvss_score(score: Any) -> Optional[float]:
    """Parse CVSS score to float"""
    if score is None:
        return None
    
    try:
        if isinstance(score, str):
            # Extract numeric value from string
            match = re.search(r'(\d+\.?\d*)', score)
            if match:
                return float(match.group(1))
        return float(score)
    except (ValueError, TypeError):
        return None

def map_cvss_to_severity(cvss_score: float) -> str:
    """Map CVSS score to severity level"""
    if cvss_score >= 9.0:
        return 'critical'
    elif cvss_score >= 7.0:
        return 'high'
    elif cvss_score >= 4.0:
        return 'medium'
    elif cvss_score > 0:
        return 'low'
    else:
        return 'unknown'

def extract_cve_ids(text: str) -> List[str]:
    """Extract CVE IDs from text"""
    if not text:
        return []
    
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    return re.findall(cve_pattern, text, re.IGNORECASE)

def extract_urls(text: str) -> List[str]:
    """Extract URLs from text"""
    if not text:
        return []
    
    url_pattern = r'https?://[^\s\)\]>]+'
    return re.findall(url_pattern, text)

def clean_html(text: str) -> str:
    """Remove HTML tags from text"""
    if not text:
        return ''
    
    # Remove HTML tags
    clean = re.sub(r'<[^>]+>', '', text)
    
    # Replace HTML entities
    html_entities = {
        '&amp;': '&',
        '&lt;': '<',
        '&gt;': '>',
        '&quot;': '"',
        '&#39;': "'",
        '&nbsp;': ' '
    }
    
    for entity, char in html_entities.items():
        clean = clean.replace(entity, char)
    
    return clean.strip()

def truncate_text(text: str, max_length: int, suffix: str = '...') -> str:
    """Truncate text to specified length"""
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

def format_date_string(date_input: Any) -> Optional[str]:
    """Format various date inputs to ISO format"""
    if not date_input:
        return None
    
    if isinstance(date_input, str):
        # Try to parse various date formats
        from dateutil.parser import parse
        try:
            dt = parse(date_input)
            return dt.isoformat()
        except:
            return date_input
    elif hasattr(date_input, 'isoformat'):
        return date_input.isoformat()
    else:
        return str(date_input)

def validate_email(email: str) -> bool:
    """Validate email address format"""
    if not email:
        return False
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_url(url: str) -> bool:
    """Validate URL format"""
    if not url:
        return False
    
    pattern = r'^https?://[^\s/$.?#].[^\s]*$'
    return bool(re.match(pattern, url, re.IGNORECASE))

def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe filesystem usage"""
    if not filename:
        return 'unnamed'
    
    # Remove or replace invalid characters
    invalid_chars = r'[<>:"/\\|?*]'
    sanitized = re.sub(invalid_chars, '_', filename)
    
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip('. ')
    
    # Limit length
    if len(sanitized) > 255:
        sanitized = sanitized[:255]
    
    return sanitized or 'unnamed'

def merge_dictionaries(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge two dictionaries"""
    result = base.copy()
    
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dictionaries(result[key], value)
        else:
            result[key] = value
    
    return result

def calculate_time_ago(date_str: str) -> str:
    """Calculate human-readable time ago from date string"""
    if not date_str:
        return 'Unknown'
    
    try:
        from dateutil.parser import parse
        date = parse(date_str)
        now = datetime.now(date.tzinfo) if date.tzinfo else datetime.now()
        diff = now - date
        
        if diff.days > 0:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "Just now"
    except:
        return 'Unknown'

def batch_list(items: List[Any], batch_size: int) -> List[List[Any]]:
    """Split a list into batches of specified size"""
    if not items or batch_size <= 0:
        return []
    
    batches = []
    for i in range(0, len(items), batch_size):
        batches.append(items[i:i + batch_size])
    
    return batches

def retry_async(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """Decorator for retrying async functions"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            attempt = 1
            current_delay = delay
            
            while attempt <= max_attempts:
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_attempts:
                        raise e
                    
                    logger = logging.getLogger(func.__module__)
                    logger.warning(f"Attempt {attempt}/{max_attempts} failed for {func.__name__}: {e}")
                    
                    await asyncio.sleep(current_delay)
                    current_delay *= backoff
                    attempt += 1
            
            return None
        return wrapper
    return decorator

def create_rate_limiter(calls_per_second: float):
    """Create a rate limiter for API calls"""
    min_interval = 1.0 / calls_per_second
    last_called = [0.0]
    
    async def rate_limit():
        elapsed = asyncio.get_event_loop().time() - last_called[0]
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        last_called[0] = asyncio.get_event_loop().time()
    
    return rate_limit

def get_file_size(file_path: str) -> int:
    """Get file size in bytes"""
    try:
        return os.path.getsize(file_path)
    except OSError:
        return 0

def ensure_directory(path: str) -> bool:
    """Ensure directory exists, create if necessary"""
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to create directory {path}: {e}")
        return False

def load_json_file(file_path: str) -> Optional[Dict[str, Any]]:
    """Load JSON data from file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to load JSON from {file_path}: {e}")
        return None

def save_json_file(data: Dict[str, Any], file_path: str) -> bool:
    """Save data as JSON file"""
    try:
        # Ensure directory exists
        ensure_directory(str(Path(file_path).parent))
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        return True
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to save JSON to {file_path}: {e}")
        return False

def compress_text(text: str, max_words: int = 100) -> str:
    """Compress text to specified word count"""
    if not text:
        return ''
    
    words = text.split()
    if len(words) <= max_words:
        return text
    
    # Take first and last portions
    first_half = max_words // 2
    second_half = max_words - first_half
    
    compressed = ' '.join(words[:first_half] + ['...'] + words[-second_half:])
    return compressed

def mask_sensitive_data(data: str, mask_char: str = '*', keep_chars: int = 4) -> str:
    """Mask sensitive data like API keys"""
    if not data or len(data) <= keep_chars * 2:
        return mask_char * 8
    
    start = data[:keep_chars]
    end = data[-keep_chars:]
    middle = mask_char * min(len(data) - keep_chars * 2, 8)
    
    return f"{start}{middle}{end}"

class ProgressTracker:
    """Simple progress tracker for long-running operations"""
    
    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = datetime.now()
        self.logger = logging.getLogger(__name__)
    
    def update(self, increment: int = 1):
        """Update progress"""
        self.current += increment
        if self.current > self.total:
            self.current = self.total
        
        percentage = (self.current / self.total) * 100 if self.total > 0 else 0
        elapsed = datetime.now() - self.start_time
        
        if self.current == self.total:
            self.logger.info(f"{self.description} completed: {self.current}/{self.total} (100.0%) in {elapsed}")
        elif self.current % max(1, self.total // 10) == 0:  # Log every 10%
            self.logger.info(f"{self.description}: {self.current}/{self.total} ({percentage:.1f}%)")
    
    def finish(self):
        """Mark as finished"""
        self.current = self.total
        self.update(0)

# Export utility functions
__all__ = [
    'setup_logging',
    'validate_config',
    'generate_vulnerability_hash',
    'normalize_severity',
    'parse_cvss_score',
    'map_cvss_to_severity',
    'extract_cve_ids',
    'extract_urls',
    'clean_html',
    'truncate_text',
    'format_date_string',
    'validate_email',
    'validate_url',
    'sanitize_filename',
    'merge_dictionaries',
    'calculate_time_ago',
    'batch_list',
    'retry_async',
    'create_rate_limiter',
    'get_file_size',
    'ensure_directory',
    'load_json_file',
    'save_json_file',
    'compress_text',
    'mask_sensitive_data',
    'ProgressTracker'
]
