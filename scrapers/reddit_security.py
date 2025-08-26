"""
Reddit Security Communities scraper
API Documentation: https://www.reddit.com/dev/api/
"""

import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .base import BaseScraper
import logging
import re

logger = logging.getLogger(__name__)

class RedditSecurityScraper(BaseScraper):
    """Scraper for Reddit security communities"""
    
    def __init__(self, config):
        super().__init__(config, 'reddit_security')
        self.base_url = "https://www.reddit.com"
        self.client_id = config.reddit_client_id
        self.client_secret = config.reddit_client_secret
        self.username = config.reddit_username
        self.password = config.reddit_password
        
        # Reddit API rate limits: 60 requests per minute
        self.rate_limit_delay = 1.0
        
        # Security-related subreddits to monitor
        self.security_subreddits = [
            'netsec',
            'cybersecurity', 
            'AskNetsec',
            'securityCTF',
            'hacking',
            'ReverseEngineering',
            'Malware',
            'computerforensics',
            'pwned',
            'bugbounty'
        ]
    
    async def scrape(self, limit: int = None) -> List[Dict[str, Any]]:
        """Scrape security-related posts from Reddit"""
        if not self.client_id or not self.client_secret:
            logger.warning("Reddit credentials not configured, skipping")
            return []
        
        vulnerabilities = []
        
        try:
            # Get OAuth token
            access_token = await self._get_access_token()
            if not access_token:
                logger.error("Failed to get Reddit access token")
                return []
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'User-Agent': self.user_agent
            }
            
            # Scrape from each security subreddit
            for subreddit in self.security_subreddits:
                try:
                    logger.info(f"Scraping r/{subreddit}")
                    
                    # Get recent posts from subreddit
                    params = {
                        'limit': min(limit or 25, 100),
                        'sort': 'new',
                        't': 'week'  # Past week
                    }
                    
                    response = await self.make_request(
                        url=f"{self.base_url}/r/{subreddit}/new.json",
                        params=params,
                        headers=headers
                    )
                    
                    if not response or 'data' not in response:
                        continue
                    
                    posts = response['data'].get('children', [])
                    
                    for post_data in posts:
                        try:
                            post = post_data.get('data', {})
                            vuln = self._parse_post(post, subreddit)
                            if vuln:
                                vulnerabilities.append(vuln)
                                
                                # Check global limit
                                if limit and len(vulnerabilities) >= limit:
                                    logger.info(f"Reached limit of {limit} vulnerabilities")
                                    return vulnerabilities
                                    
                        except Exception as e:
                            logger.error(f"Error parsing Reddit post: {e}")
                            continue
                    
                except Exception as e:
                    logger.error(f"Error scraping r/{subreddit}: {e}")
                    continue
            
            logger.info(f"Scraped {len(vulnerabilities)} security posts from Reddit")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scraping Reddit security: {e}")
            return []
        finally:
            await self.close_session()
    
    async def _get_access_token(self) -> Optional[str]:
        """Get OAuth access token for Reddit API"""
        try:
            import base64
            
            # Create basic auth header
            auth_string = f"{self.client_id}:{self.client_secret}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            headers = {
                'Authorization': f'Basic {auth_b64}',
                'User-Agent': self.user_agent
            }
            
            data = {
                'grant_type': 'password',
                'username': self.username,
                'password': self.password
            }
            
            response = await self.make_request(
                url='https://www.reddit.com/api/v1/access_token',
                method='POST',
                headers=headers,
                data=data
            )
            
            if response and 'access_token' in response:
                return response['access_token']
            
        except Exception as e:
            logger.error(f"Error getting Reddit access token: {e}")
        
        return None
    
    def _parse_post(self, post: Dict[str, Any], subreddit: str) -> Optional[Dict[str, Any]]:
        """Parse a Reddit post for security content"""
        try:
            title = post.get('title', '')
            selftext = post.get('selftext', '')
            url = post.get('url', '')
            post_id = post.get('id', '')
            author = post.get('author', '')
            score = post.get('score', 0)
            created_utc = post.get('created_utc', 0)
            
            # Filter for security-relevant posts
            if not self._is_security_relevant(title, selftext):
                return None
            
            # Extract CVE IDs if present
            cve_ids = self.extract_cve_ids(title + ' ' + selftext)
            cve_id = cve_ids[0] if cve_ids else None
            
            # Create description
            description = title
            if selftext and selftext != title:
                # Truncate long self text
                if len(selftext) > 500:
                    description += f'\n\n{selftext[:500]}...'
                else:
                    description += f'\n\n{selftext}'
            
            description += f'\n\nPosted by u/{author} in r/{subreddit}'
            description += f'\nScore: {score} points'
            
            # Determine severity based on keywords and score
            severity = self._determine_severity(title, selftext, score)
            
            # Check for exploit/PoC indicators
            exploit_available = self._has_exploit_indicators(title, selftext, url)
            poc_available = self._has_poc_indicators(title, selftext, url)
            
            # Extract affected products/technologies
            affected_products = self._extract_technologies(title, selftext)
            
            # Build references
            references = []
            post_url = f"https://www.reddit.com/r/{subreddit}/comments/{post_id}/"
            references.append(post_url)
            
            if url and url != post_url:
                references.append(url)
            
            # Extract additional URLs from text
            url_pattern = r'https?://[^\s\)>]+'
            urls = re.findall(url_pattern, selftext)
            for found_url in urls[:3]:  # Limit to first 3 URLs
                if found_url not in references:
                    references.append(found_url)
            
            # Build tags
            tags = ['reddit', f'r_{subreddit}', f'author_{author}']
            
            # Add keyword-based tags
            keywords = ['malware', 'ransomware', 'phishing', 'apt', 'zero-day', 'exploit', 'vulnerability']
            for keyword in keywords:
                if keyword in title.lower() or keyword in selftext.lower():
                    tags.append(keyword.replace('-', '_'))
            
            # Convert timestamp
            published_date = datetime.fromtimestamp(created_utc).isoformat() if created_utc else None
            
            return self.create_vulnerability_dict(
                cve_id=cve_id,
                vulnerability_id=f"REDDIT-{subreddit}-{post_id}",
                title=title,
                description=description,
                severity=severity,
                affected_products=affected_products,
                references=references,
                exploit_available=exploit_available,
                poc_available=poc_available,
                published_date=published_date,
                source_url=post_url,
                vendor_response=f'Discussion on r/{subreddit}',
                tags=tags,
                raw_data=post
            )
            
        except Exception as e:
            logger.error(f"Error parsing Reddit post {post.get('id', 'unknown')}: {e}")
            return None
    
    def _is_security_relevant(self, title: str, text: str) -> bool:
        """Check if a post is security-relevant"""
        content = (title + ' ' + text).lower()
        
        # Security keywords that indicate relevance
        security_keywords = [
            'vulnerability', 'exploit', 'cve', 'security', 'hack', 'breach',
            'malware', 'ransomware', 'phishing', 'apt', 'zero-day', 'backdoor',
            'injection', 'xss', 'csrf', 'rce', 'privilege escalation',
            'buffer overflow', 'memory corruption', 'authentication bypass',
            'information disclosure', 'denial of service', 'dos'
        ]
        
        # Check for security keywords
        for keyword in security_keywords:
            if keyword in content:
                return True
        
        # Check for CVE pattern
        if re.search(r'cve-\d{4}-\d{4,}', content):
            return True
        
        # Check for common vulnerability patterns
        vuln_patterns = [
            r'zero[- ]?day',
            r'0[- ]?day',
            r'remote code execution',
            r'arbitrary code execution',
            r'sql injection',
            r'cross[- ]?site scripting'
        ]
        
        for pattern in vuln_patterns:
            if re.search(pattern, content):
                return True
        
        return False
    
    def _determine_severity(self, title: str, text: str, score: int) -> str:
        """Determine severity based on content and community score"""
        content = (title + ' ' + text).lower()
        
        # High severity indicators
        high_severity_keywords = [
            'critical', 'severe', 'zero-day', '0-day', 'remote code execution',
            'rce', 'privilege escalation', 'authentication bypass'
        ]
        
        for keyword in high_severity_keywords:
            if keyword in content:
                return 'high'
        
        # Medium severity indicators
        medium_severity_keywords = [
            'vulnerability', 'exploit', 'injection', 'xss', 'csrf'
        ]
        
        for keyword in medium_severity_keywords:
            if keyword in content:
                # Use score to differentiate
                if score > 100:
                    return 'high'
                else:
                    return 'medium'
        
        # Default based on score
        if score > 500:
            return 'high'
        elif score > 50:
            return 'medium'
        else:
            return 'low'
    
    def _has_exploit_indicators(self, title: str, text: str, url: str) -> bool:
        """Check for exploit availability indicators"""
        content = (title + ' ' + text + ' ' + url).lower()
        
        exploit_indicators = [
            'exploit', 'metasploit', 'exploit-db', 'poc', 'proof of concept',
            'working exploit', 'exploit code', 'demonstration'
        ]
        
        for indicator in exploit_indicators:
            if indicator in content:
                return True
        
        return False
    
    def _has_poc_indicators(self, title: str, text: str, url: str) -> bool:
        """Check for PoC availability indicators"""
        content = (title + ' ' + text + ' ' + url).lower()
        
        poc_indicators = [
            'poc', 'proof of concept', 'demonstration', 'github.com',
            'code sample', 'reproduce', 'steps to reproduce'
        ]
        
        for indicator in poc_indicators:
            if indicator in content:
                return True
        
        return False
    
    def _extract_technologies(self, title: str, text: str) -> List[str]:
        """Extract mentioned technologies/products"""
        content = title + ' ' + text
        technologies = []
        
        # Common technology patterns
        tech_patterns = [
            r'\b(Windows|Linux|macOS|Android|iOS)\b',
            r'\b(Apache|Nginx|IIS|Tomcat)\b',
            r'\b(MySQL|PostgreSQL|MongoDB|Redis)\b',
            r'\b(Chrome|Firefox|Safari|Edge)\b',
            r'\b(WordPress|Drupal|Joomla)\b',
            r'\b(Java|Python|PHP|JavaScript|Node\.js)\b',
            r'\b(VMware|VirtualBox|Docker|Kubernetes)\b'
        ]
        
        for pattern in tech_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match not in technologies:
                    technologies.append(match)
        
        return technologies[:5]  # Limit to first 5 technologies
    
    async def search_subreddit(self, subreddit: str, query: str) -> List[Dict[str, Any]]:
        """Search a specific subreddit for security content"""
        if not self.client_id or not self.client_secret:
            return []
        
        try:
            access_token = await self._get_access_token()
            if not access_token:
                return []
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'User-Agent': self.user_agent
            }
            
            params = {
                'q': query,
                'restrict_sr': 'on',
                'sort': 'relevance',
                'limit': 25
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/r/{subreddit}/search.json",
                params=params,
                headers=headers
            )
            
            if response and 'data' in response:
                vulnerabilities = []
                posts = response['data'].get('children', [])
                
                for post_data in posts:
                    post = post_data.get('data', {})
                    vuln = self._parse_post(post, subreddit)
                    if vuln:
                        vulnerabilities.append(vuln)
                
                return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error searching r/{subreddit}: {e}")
        
        return []
