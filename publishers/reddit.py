"""
Reddit publisher for VulnPublisherPro
API Documentation: https://www.reddit.com/dev/api/
"""

import logging
from typing import Dict, Any
from .base import BasePublisher
import base64

logger = logging.getLogger(__name__)

class RedditPublisher(BasePublisher):
    """Publisher for Reddit platform"""
    
    def __init__(self, config):
        super().__init__(config, 'reddit')
        
        # Reddit API credentials
        self.client_id = self.platform_config.get('client_id')
        self.client_secret = self.platform_config.get('client_secret')
        self.username = self.platform_config.get('username')
        self.password = self.platform_config.get('password')
        
        # Reddit API endpoints
        self.base_url = "https://oauth.reddit.com"
        self.auth_url = "https://www.reddit.com/api/v1/access_token"
        
        # Access token (will be obtained)
        self.access_token = None
    
    def validate_config(self) -> bool:
        """Validate Reddit configuration"""
        required_fields = ['client_id', 'client_secret', 'username', 'password']
        
        for field in required_fields:
            if not self.platform_config.get(field):
                logger.error(f"Reddit {field} not configured")
                return False
        
        return True
    
    async def _get_access_token(self) -> str:
        """Get Reddit OAuth access token"""
        if self.access_token:
            return self.access_token
        
        try:
            # Create basic auth header
            auth_string = f"{self.client_id}:{self.client_secret}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            headers = {
                'Authorization': f'Basic {auth_b64}',
                'User-Agent': 'VulnPublisherPro/1.0'
            }
            
            data = {
                'grant_type': 'password',
                'username': self.username,
                'password': self.password
            }
            
            response = await self.make_request(
                url=self.auth_url,
                method='POST',
                headers=headers,
                data=data
            )
            
            if response['success'] and 'access_token' in response['data']:
                self.access_token = response['data']['access_token']
                return self.access_token
            else:
                logger.error(f"Failed to get Reddit access token: {response}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting Reddit access token: {e}")
            return None
    
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to Reddit"""
        if not self.validate_config():
            return self.create_error_response("Reddit configuration invalid")
        
        try:
            # Get access token
            token = await self._get_access_token()
            if not token:
                return self.create_error_response("Failed to get Reddit access token")
            
            # Determine target subreddit based on content
            subreddit = self._get_target_subreddit(vulnerability)
            
            # Format content for Reddit
            title, text = self._format_for_reddit(content, vulnerability)
            
            # Create post data
            post_data = {
                'sr': subreddit,
                'kind': 'self',  # Text post
                'title': title,
                'text': text,
                'api_type': 'json'
            }
            
            headers = {
                'Authorization': f'Bearer {token}',
                'User-Agent': 'VulnPublisherPro/1.0'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/api/submit",
                method='POST',
                headers=headers,
                data=post_data
            )
            
            if response['success']:
                result_data = response['data']
                
                # Reddit API returns nested data
                if 'json' in result_data and 'data' in result_data['json']:
                    post_info = result_data['json']['data']
                    post_id = post_info.get('name')  # Reddit post ID
                    post_url = post_info.get('url')
                    
                    if post_id:
                        logger.info(f"Successfully posted to Reddit: {post_id}")
                        
                        return self.create_success_response(
                            post_data=post_data,
                            post_id=post_id,
                            post_url=post_url
                        )
                
                return self.create_error_response("Unexpected Reddit API response", result_data)
            else:
                return self.create_error_response("Failed to post to Reddit", response)
                
        except Exception as e:
            logger.error(f"Error publishing to Reddit: {e}")
            return self.create_error_response(str(e))
    
    def _get_target_subreddit(self, vulnerability: Dict[str, Any]) -> str:
        """Determine the best subreddit for the vulnerability"""
        # Default to netsec
        default_subreddit = 'netsec'
        
        # Map vulnerability characteristics to subreddits
        severity = vulnerability.get('severity', '').lower()
        affected_products = [p.lower() for p in vulnerability.get('affected_products', [])]
        tags = [t.lower() for t in vulnerability.get('tags', [])]
        
        # Critical vulnerabilities go to main security subreddits
        if severity == 'critical':
            return 'cybersecurity'
        
        # Check for specific technology subreddits
        if any('windows' in p for p in affected_products):
            return 'sysadmin'
        elif any('linux' in p for p in affected_products):
            return 'linux'
        elif any('web' in p or 'http' in p for p in affected_products):
            return 'websecurity'
        elif 'malware' in tags or 'ransomware' in tags:
            return 'Malware'
        elif 'bug_bounty' in tags:
            return 'bugbounty'
        
        return default_subreddit
    
    def _format_for_reddit(self, content: Dict[str, Any], 
                          vulnerability: Dict[str, Any]) -> tuple:
        """Format content for Reddit post"""
        content_type = content.get('content_type', 'summary')
        
        # Create title
        cve_id = vulnerability.get('cve_id', '')
        severity = vulnerability.get('severity', '').title()
        vuln_title = vulnerability.get('title', 'Security Vulnerability')
        
        if cve_id:
            title = f"[{severity}] {cve_id}: {vuln_title}"
        else:
            title = f"[{severity}] {vuln_title}"
        
        # Truncate title if too long (Reddit limit is 300 characters)
        title = self.truncate_content(title, 300)
        
        # Create post body
        if content_type == 'detailed':
            text = content.get('content', '')
            
            # Add executive summary if available
            if content.get('executive_summary'):
                text = f"**Executive Summary:**\n{content['executive_summary']}\n\n{text}"
            
            # Add vulnerability details
            text += self._add_vulnerability_details(vulnerability)
            
        else:
            # Use regular content
            text = content.get('content', '')
            text += self._add_vulnerability_details(vulnerability)
        
        # Add source attribution
        source_url = vulnerability.get('source_url')
        if source_url:
            text += f"\n\n**Source:** {source_url}"
        
        # Add disclaimer
        text += "\n\n---\n*This post was generated by VulnPublisherPro*"
        
        return title, text
    
    def _add_vulnerability_details(self, vulnerability: Dict[str, Any]) -> str:
        """Add structured vulnerability details"""
        details = "\n\n## Vulnerability Details\n\n"
        
        # Basic info
        cve_id = vulnerability.get('cve_id')
        if cve_id:
            details += f"**CVE ID:** {cve_id}\n\n"
        
        severity = vulnerability.get('severity')
        if severity:
            details += f"**Severity:** {severity.title()}\n\n"
        
        cvss_score = vulnerability.get('cvss_score')
        if cvss_score:
            details += f"**CVSS Score:** {cvss_score}\n\n"
        
        # Affected products
        affected_products = vulnerability.get('affected_products', [])
        if affected_products:
            details += "**Affected Products:**\n"
            for product in affected_products[:10]:  # Limit to 10
                details += f"- {product}\n"
            details += "\n"
        
        # Exploit status
        if vulnerability.get('exploit_available'):
            details += "⚠️ **Exploit Available**\n\n"
        
        if vulnerability.get('poc_available'):
            details += "🔬 **Proof of Concept Available**\n\n"
        
        # References
        references = vulnerability.get('references', [])
        if references:
            details += "**References:**\n"
            for ref in references[:5]:  # Limit to 5
                details += f"- {ref}\n"
            details += "\n"
        
        return details
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test Reddit API connection"""
        if not self.validate_config():
            return {
                'success': False,
                'platform': self.platform_name,
                'error': 'Reddit configuration invalid'
            }
        
        try:
            token = await self._get_access_token()
            if not token:
                return {
                    'success': False,
                    'platform': self.platform_name,
                    'error': 'Failed to get access token'
                }
            
            headers = {
                'Authorization': f'Bearer {token}',
                'User-Agent': 'VulnPublisherPro/1.0'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/api/v1/me",
                method='GET',
                headers=headers
            )
            
            if response['success']:
                user_data = response['data']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Connected as u/{user_data.get("name")}',
                    'user_data': {
                        'name': user_data.get('name'),
                        'id': user_data.get('id'),
                        'link_karma': user_data.get('link_karma'),
                        'comment_karma': user_data.get('comment_karma'),
                        'created': user_data.get('created')
                    }
                }
            else:
                return {
                    'success': False,
                    'platform': self.platform_name,
                    'error': 'Failed to get user data',
                    'details': response
                }
                
        except Exception as e:
            return {
                'success': False,
                'platform': self.platform_name,
                'error': str(e)
            }
    
    async def get_subreddit_info(self, subreddit: str) -> Dict[str, Any]:
        """Get information about a subreddit"""
        if not self.validate_config():
            return self.create_error_response("Reddit configuration invalid")
        
        try:
            token = await self._get_access_token()
            if not token:
                return self.create_error_response("Failed to get access token")
            
            headers = {
                'Authorization': f'Bearer {token}',
                'User-Agent': 'VulnPublisherPro/1.0'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/r/{subreddit}/about",
                method='GET',
                headers=headers
            )
            
            if response['success'] and 'data' in response['data']:
                sub_data = response['data']['data']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'subreddit_info': {
                        'name': sub_data.get('display_name'),
                        'title': sub_data.get('title'),
                        'description': sub_data.get('public_description'),
                        'subscribers': sub_data.get('subscribers'),
                        'active_users': sub_data.get('accounts_active'),
                        'created': sub_data.get('created'),
                        'over18': sub_data.get('over18'),
                        'allow_images': sub_data.get('allow_images'),
                        'submission_type': sub_data.get('submission_type')
                    }
                }
            else:
                return self.create_error_response("Failed to get subreddit info", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def get_analytics(self, post_id: str) -> Dict[str, Any]:
        """Get Reddit analytics for a post"""
        if not self.validate_config():
            return self.create_error_response("Reddit configuration invalid")
        
        try:
            token = await self._get_access_token()
            if not token:
                return self.create_error_response("Failed to get access token")
            
            headers = {
                'Authorization': f'Bearer {token}',
                'User-Agent': 'VulnPublisherPro/1.0'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/api/info",
                method='GET',
                headers=headers,
                params={'id': post_id}
            )
            
            if response['success'] and 'data' in response['data']:
                children = response['data']['data'].get('children', [])
                if children:
                    post_data = children[0]['data']
                    return {
                        'success': True,
                        'platform': self.platform_name,
                        'post_id': post_id,
                        'analytics': {
                            'score': post_data.get('score', 0),
                            'upvote_ratio': post_data.get('upvote_ratio', 0),
                            'num_comments': post_data.get('num_comments', 0),
                            'created': post_data.get('created'),
                            'gilded': post_data.get('gilded', 0),
                            'total_awards_received': post_data.get('total_awards_received', 0),
                            'subreddit': post_data.get('subreddit'),
                            'permalink': post_data.get('permalink')
                        }
                    }
            
            return self.create_error_response("Post not found", response)
                
        except Exception as e:
            return self.create_error_response(str(e), post_id)
