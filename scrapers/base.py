"""
Base scraper class for VulnPublisherPro
"""

import asyncio
import logging
import time
import aiohttp
import requests
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod
from datetime import datetime
import json

logger = logging.getLogger(__name__)

class BaseScraper(ABC):
    """Base class for all vulnerability scrapers"""
    
    def __init__(self, config, source_name: str):
        self.config = config
        self.source_name = source_name
        self.session = None
        
        # Get scraping configuration
        scraping_config = config.scraping_config
        self.rate_limit_delay = scraping_config.rate_limit_delay
        self.retry_attempts = scraping_config.retry_attempts
        self.timeout = scraping_config.timeout
        self.user_agent = scraping_config.user_agent
        
        # Rate limiting
        self.last_request_time = 0
        
        logger.info(f"Initialized {source_name} scraper")
    
    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create async HTTP session"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {
                'User-Agent': self.user_agent,
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
    
    async def make_request(self, url: str, method: str = 'GET', 
                          headers: Dict[str, str] = None,
                          params: Dict[str, Any] = None,
                          data: Dict[str, Any] = None,
                          json_data: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
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
                async with session.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    params=params,
                    data=data,
                    json=json_data
                ) as response:
                    
                    # Check for rate limiting
                    if response.status == 429:
                        retry_after = int(response.headers.get('Retry-After', 60))
                        logger.warning(f"Rate limited by {self.source_name}, waiting {retry_after} seconds")
                        await asyncio.sleep(retry_after)
                        continue
                    
                    # Check for successful response
                    response.raise_for_status()
                    
                    # Try to parse JSON, fall back to text
                    try:
                        return await response.json()
                    except:
                        text = await response.text()
                        logger.debug(f"Non-JSON response from {url}: {text[:200]}...")
                        return {'text': text}
                        
            except aiohttp.ClientError as e:
                logger.warning(f"Request failed (attempt {attempt + 1}/{self.retry_attempts}): {e}")
                if attempt < self.retry_attempts - 1:
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                else:
                    logger.error(f"All retry attempts failed for {url}")
                    return None
            except Exception as e:
                logger.error(f"Unexpected error making request to {url}: {e}")
                return None
        
        return None
    
    def make_sync_request(self, url: str, method: str = 'GET',
                         headers: Dict[str, str] = None,
                         params: Dict[str, Any] = None,
                         data: Dict[str, Any] = None,
                         json_data: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Make synchronous HTTP request (for compatibility)"""
        request_headers = {
            'User-Agent': self.user_agent,
            'Accept': 'application/json',
        }
        if headers:
            request_headers.update(headers)
        
        for attempt in range(self.retry_attempts):
            try:
                # Apply rate limiting
                current_time = time.time()
                time_since_last = current_time - self.last_request_time
                if time_since_last < self.rate_limit_delay:
                    time.sleep(self.rate_limit_delay - time_since_last)
                self.last_request_time = time.time()
                
                response = requests.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    params=params,
                    data=data,
                    json=json_data,
                    timeout=self.timeout
                )
                
                # Check for rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get('Retry-After', 60))
                    logger.warning(f"Rate limited by {self.source_name}, waiting {retry_after} seconds")
                    time.sleep(retry_after)
                    continue
                
                response.raise_for_status()
                
                # Try to parse JSON
                try:
                    return response.json()
                except:
                    return {'text': response.text}
                    
            except requests.RequestException as e:
                logger.warning(f"Request failed (attempt {attempt + 1}/{self.retry_attempts}): {e}")
                if attempt < self.retry_attempts - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    logger.error(f"All retry attempts failed for {url}")
                    return None
            except Exception as e:
                logger.error(f"Unexpected error making request to {url}: {e}")
                return None
        
        return None
    
    @abstractmethod
    async def scrape(self, limit: int = None) -> List[Dict[str, Any]]:
        """Scrape vulnerabilities from the source"""
        pass
    
    def normalize_severity(self, severity: str) -> str:
        """Normalize severity to standard levels"""
        if not severity:
            return 'unknown'
        
        severity = severity.lower().strip()
        
        if severity in ['critical', 'high', 'medium', 'low']:
            return severity
        elif severity in ['none', 'informational', 'info']:
            return 'low'
        elif severity in ['moderate']:
            return 'medium'
        elif severity in ['important', 'severe']:
            return 'high'
        else:
            return 'unknown'
    
    def parse_cvss_score(self, score: Any) -> Optional[float]:
        """Parse CVSS score to float"""
        if score is None:
            return None
        
        try:
            if isinstance(score, str):
                # Extract numeric value from string
                import re
                match = re.search(r'(\d+\.?\d*)', score)
                if match:
                    return float(match.group(1))
            return float(score)
        except (ValueError, TypeError):
            return None
    
    def format_date(self, date_input: Any) -> Optional[str]:
        """Format date to ISO format"""
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
    
    def clean_text(self, text: str) -> str:
        """Clean and normalize text content"""
        if not text:
            return ''
        
        # Remove extra whitespace and normalize
        text = ' '.join(text.split())
        
        # Remove HTML tags if present
        import re
        text = re.sub(r'<[^>]+>', '', text)
        
        return text.strip()
    
    def extract_cve_ids(self, text: str) -> List[str]:
        """Extract CVE IDs from text"""
        if not text:
            return []
        
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        return re.findall(cve_pattern, text, re.IGNORECASE)
    
    def create_vulnerability_dict(self, **kwargs) -> Dict[str, Any]:
        """Create a standardized vulnerability dictionary"""
        return {
            'cve_id': kwargs.get('cve_id'),
            'vulnerability_id': kwargs.get('vulnerability_id'),
            'title': self.clean_text(kwargs.get('title', '')),
            'description': self.clean_text(kwargs.get('description', '')),
            'severity': self.normalize_severity(kwargs.get('severity')),
            'cvss_score': self.parse_cvss_score(kwargs.get('cvss_score')),
            'cvss_vector': kwargs.get('cvss_vector'),
            'cwe_id': kwargs.get('cwe_id'),
            'affected_products': kwargs.get('affected_products', []),
            'references': kwargs.get('references', []),
            'technical_details': self.clean_text(kwargs.get('technical_details', '')),
            'impact': self.clean_text(kwargs.get('impact', '')),
            'mitigation': self.clean_text(kwargs.get('mitigation', '')),
            'exploit_available': kwargs.get('exploit_available', False),
            'poc_available': kwargs.get('poc_available', False),
            'source': self.source_name,
            'source_url': kwargs.get('source_url'),
            'published_date': self.format_date(kwargs.get('published_date')),
            'updated_date': self.format_date(kwargs.get('updated_date')),
            'discovered_date': self.format_date(kwargs.get('discovered_date')),
            'disclosure_date': self.format_date(kwargs.get('disclosure_date')),
            'vendor_response': kwargs.get('vendor_response'),
            'tags': kwargs.get('tags', []),
            'raw_data': kwargs.get('raw_data', {})
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close_session()
