"""
Base publisher class for VulnPublisherPro
"""

import asyncio
import logging
import time
import aiohttp
import requests
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
from datetime import datetime

logger = logging.getLogger(__name__)

class BasePublisher(ABC):
    """Base class for all social media publishers"""
    
    def __init__(self, config, platform_name: str):
        self.config = config
        self.platform_name = platform_name
        self.session = None
        
        # Get publishing configuration
        publishing_config = config.publishing_config
        self.rate_limit_delay = publishing_config.rate_limit_delay
        self.retry_attempts = publishing_config.retry_attempts
        
        # Rate limiting
        self.last_request_time = 0
        
        # Get platform-specific configuration
        self.platform_config = config.get_platform_config(platform_name)
        
        logger.info(f"Initialized {platform_name} publisher")
    
    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create async HTTP session"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=30)
            headers = {
                'User-Agent': 'VulnPublisherPro/1.0',
                'Accept': 'application/json',
            }
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers
            )
        return self.session
    
    async def close_session(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()
            self.session = None
    
    async def rate_limit(self):
        """Apply rate limiting between requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            await asyncio.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    async def make_request(self, url: str, method: str = 'POST',
                          headers: Dict[str, str] = None,
                          params: Dict[str, Any] = None,
                          data: Dict[str, Any] = None,
                          json_data: Dict[str, Any] = None,
                          files: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Make HTTP request with retry logic"""
        session = await self.get_session()
        
        # Apply rate limiting
        await self.rate_limit()
        
        # Merge headers
        request_headers = {}
        if headers:
            request_headers.update(headers)
        
        for attempt in range(self.retry_attempts):
            try:
                # Handle file uploads
                if files:
                    form_data = aiohttp.FormData()
                    if data:
                        for key, value in data.items():
                            form_data.add_field(key, str(value))
                    for key, file_data in files.items():
                        form_data.add_field(key, file_data)
                    data_payload = form_data
                else:
                    data_payload = data
                
                async with session.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    params=params,
                    data=data_payload if not json_data else None,
                    json=json_data if json_data else None
                ) as response:
                    
                    # Check for rate limiting
                    if response.status == 429:
                        retry_after = int(response.headers.get('Retry-After', 60))
                        logger.warning(f"Rate limited by {self.platform_name}, waiting {retry_after} seconds")
                        await asyncio.sleep(retry_after)
                        continue
                    
                    # Get response content
                    try:
                        response_data = await response.json()
                    except:
                        response_data = {'text': await response.text(), 'status': response.status}
                    
                    if response.status >= 400:
                        logger.error(f"HTTP {response.status} error from {self.platform_name}: {response_data}")
                        if attempt < self.retry_attempts - 1:
                            await asyncio.sleep(2 ** attempt)  # Exponential backoff
                            continue
                        else:
                            return {
                                'success': False,
                                'error': f"HTTP {response.status}",
                                'details': response_data
                            }
                    
                    return {
                        'success': True,
                        'data': response_data,
                        'status': response.status
                    }
                        
            except Exception as e:
                logger.warning(f"Request failed (attempt {attempt + 1}/{self.retry_attempts}): {e}")
                if attempt < self.retry_attempts - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    logger.error(f"All retry attempts failed for {self.platform_name}")
                    return {
                        'success': False,
                        'error': str(e)
                    }
        
        return {'success': False, 'error': 'Unknown error'}
    
    @abstractmethod
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to the platform"""
        pass
    
    @abstractmethod
    def validate_config(self) -> bool:
        """Validate platform configuration"""
        pass
    
    def format_content_for_platform(self, content: Dict[str, Any]) -> str:
        """Format content for the specific platform"""
        # Default implementation - can be overridden
        return content.get('content', '')
    
    def add_platform_hashtags(self, content: str, hashtags: list = None) -> str:
        """Add platform-appropriate hashtags"""
        if not hashtags:
            hashtags = ['#cybersecurity', '#infosec', '#vulnerability']
        
        # Check if hashtags already exist
        if not any(tag in content for tag in hashtags):
            content += '\n\n' + ' '.join(hashtags)
        
        return content
    
    def truncate_content(self, content: str, max_length: int) -> str:
        """Truncate content to fit platform limits"""
        if len(content) <= max_length:
            return content
        
        # Truncate and add ellipsis
        return content[:max_length-3] + '...'
    
    def extract_urls(self, content: str) -> list:
        """Extract URLs from content"""
        import re
        url_pattern = r'https?://[^\s\)>]+'
        return re.findall(url_pattern, content)
    
    def create_success_response(self, post_data: Dict[str, Any], 
                               post_id: str = None, post_url: str = None) -> Dict[str, Any]:
        """Create standardized success response"""
        return {
            'success': True,
            'platform': self.platform_name,
            'post_id': post_id,
            'post_url': post_url,
            'published_at': datetime.now().isoformat(),
            'data': post_data
        }
    
    def create_error_response(self, error: str, details: Any = None) -> Dict[str, Any]:
        """Create standardized error response"""
        return {
            'success': False,
            'platform': self.platform_name,
            'error': error,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test platform connection and authentication"""
        try:
            # This should be overridden by each platform
            return {
                'success': True,
                'platform': self.platform_name,
                'message': 'Base test - override in platform class'
            }
        except Exception as e:
            return {
                'success': False,
                'platform': self.platform_name,
                'error': str(e)
            }
    
    async def get_analytics(self, post_id: str) -> Dict[str, Any]:
        """Get analytics for a published post (if supported)"""
        return {
            'success': False,
            'platform': self.platform_name,
            'message': 'Analytics not implemented for this platform'
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close_session()
