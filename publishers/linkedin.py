"""
LinkedIn publisher for VulnPublisherPro
API Documentation: https://docs.microsoft.com/en-us/linkedin/
"""

import logging
from typing import Dict, Any
from .base import BasePublisher

logger = logging.getLogger(__name__)

class LinkedInPublisher(BasePublisher):
    """Publisher for LinkedIn platform"""
    
    def __init__(self, config):
        super().__init__(config, 'linkedin')
        
        # LinkedIn API credentials
        self.access_token = self.platform_config.get('access_token')
        self.person_id = self.platform_config.get('person_id')
        
        # LinkedIn API endpoints
        self.base_url = "https://api.linkedin.com/v2"
    
    def validate_config(self) -> bool:
        """Validate LinkedIn configuration"""
        required_fields = ['access_token', 'person_id']
        
        for field in required_fields:
            if not self.platform_config.get(field):
                logger.error(f"LinkedIn {field} not configured")
                return False
        
        return True
    
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to LinkedIn"""
        if not self.validate_config():
            return self.create_error_response("LinkedIn configuration invalid")
        
        try:
            # Format content for LinkedIn
            post_content = self.format_content_for_platform(content)
            
            # Prepare LinkedIn post data
            post_data = {
                "author": f"urn:li:person:{self.person_id}",
                "lifecycleState": "PUBLISHED",
                "specificContent": {
                    "com.linkedin.ugc.ShareContent": {
                        "shareCommentary": {
                            "text": post_content
                        },
                        "shareMediaCategory": "NONE"
                    }
                },
                "visibility": {
                    "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
                }
            }
            
            # Add article link if present
            urls = self.extract_urls(post_content)
            if urls:
                post_data["specificContent"]["com.linkedin.ugc.ShareContent"]["shareMediaCategory"] = "ARTICLE"
                post_data["specificContent"]["com.linkedin.ugc.ShareContent"]["media"] = [{
                    "status": "READY",
                    "description": {
                        "text": "Security vulnerability information"
                    },
                    "originalUrl": urls[0],
                    "title": {
                        "text": vulnerability.get('title', 'Security Vulnerability')
                    }
                }]
            
            # Make API request
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json',
                'X-Restli-Protocol-Version': '2.0.0'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/ugcPosts",
                method='POST',
                headers=headers,
                json_data=post_data
            )
            
            if response['success']:
                post_id = response['data'].get('id')
                
                logger.info(f"Successfully posted to LinkedIn: {post_id}")
                
                return self.create_success_response(
                    post_data=post_data,
                    post_id=post_id,
                    post_url=f"https://www.linkedin.com/feed/update/{post_id}/" if post_id else None
                )
            else:
                return self.create_error_response("Failed to post to LinkedIn", response)
                
        except Exception as e:
            logger.error(f"Error publishing to LinkedIn: {e}")
            return self.create_error_response(str(e))
    
    def format_content_for_platform(self, content: Dict[str, Any]) -> str:
        """Format content for LinkedIn"""
        if content.get('content_type') == 'detailed':
            # Use detailed content for LinkedIn
            detailed_content = content.get('content', '')
            
            # Add professional formatting
            if content.get('executive_summary'):
                formatted_content = f"🔒 SECURITY ADVISORY\n\n"
                formatted_content += f"{content['executive_summary']}\n\n"
                formatted_content += detailed_content
            else:
                formatted_content = detailed_content
            
            # Add hashtags
            hashtags = content.get('tags', [])
            professional_hashtags = ['#cybersecurity', '#infosec', '#security', '#vulnerability']
            
            for tag in professional_hashtags:
                if tag not in hashtags:
                    hashtags.append(tag)
            
            formatted_content = self.add_platform_hashtags(formatted_content, hashtags)
            
            # LinkedIn allows up to 3000 characters
            return self.truncate_content(formatted_content, 3000)
        else:
            # Use regular content
            linkedin_content = content.get('platform_variants', {}).get('linkedin', content.get('content', ''))
            hashtags = content.get('hashtags', ['#cybersecurity', '#infosec'])
            return self.add_platform_hashtags(linkedin_content, hashtags)
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test LinkedIn API connection"""
        if not self.validate_config():
            return {
                'success': False,
                'platform': self.platform_name,
                'error': 'LinkedIn configuration invalid'
            }
        
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}',
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/people/(id:{self.person_id})",
                method='GET',
                headers=headers
            )
            
            if response['success']:
                profile_data = response['data']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Connected to LinkedIn profile',
                    'profile_data': {
                        'id': profile_data.get('id'),
                        'first_name': profile_data.get('localizedFirstName'),
                        'last_name': profile_data.get('localizedLastName')
                    }
                }
            else:
                return {
                    'success': False,
                    'platform': self.platform_name,
                    'error': 'Failed to get profile data',
                    'details': response
                }
                
        except Exception as e:
            return {
                'success': False,
                'platform': self.platform_name,
                'error': str(e)
            }
    
    async def get_analytics(self, post_id: str) -> Dict[str, Any]:
        """Get LinkedIn analytics for a post"""
        if not self.validate_config():
            return self.create_error_response("LinkedIn configuration invalid")
        
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}',
            }
            
            # Get post statistics
            response = await self.make_request(
                url=f"{self.base_url}/socialActions/{post_id}",
                method='GET',
                headers=headers
            )
            
            if response['success']:
                social_data = response['data']
                
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'post_id': post_id,
                    'analytics': {
                        'likes': social_data.get('likesSummary', {}).get('totalLikes', 0),
                        'comments': social_data.get('commentsSummary', {}).get('totalComments', 0),
                        'shares': social_data.get('sharesSummary', {}).get('totalShares', 0),
                        'clicks': social_data.get('clicksSummary', {}).get('totalClicks', 0)
                    }
                }
            else:
                return self.create_error_response("Failed to get analytics", response)
                
        except Exception as e:
            return self.create_error_response(str(e), post_id)
    
    async def publish_article(self, content: Dict[str, Any], 
                             vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish a LinkedIn article (if detailed content)"""
        if not self.validate_config():
            return self.create_error_response("LinkedIn configuration invalid")
        
        try:
            # Prepare article data
            article_data = {
                "author": f"urn:li:person:{self.person_id}",
                "lifecycleState": "PUBLISHED",
                "specificContent": {
                    "com.linkedin.ugc.ShareContent": {
                        "shareCommentary": {
                            "text": content.get('title', 'Security Vulnerability Report')
                        },
                        "shareMediaCategory": "ARTICLE",
                        "media": [{
                            "status": "READY",
                            "description": {
                                "text": content.get('executive_summary', '')
                            },
                            "originalUrl": vulnerability.get('source_url', ''),
                            "title": {
                                "text": content.get('title', 'Security Vulnerability Report')
                            }
                        }]
                    }
                },
                "visibility": {
                    "com.linkedin.ugc.MemberNetworkVisibility": "PUBLIC"
                }
            }
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json',
                'X-Restli-Protocol-Version': '2.0.0'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/ugcPosts",
                method='POST',
                headers=headers,
                json_data=article_data
            )
            
            if response['success']:
                post_id = response['data'].get('id')
                
                return self.create_success_response(
                    post_data=article_data,
                    post_id=post_id,
                    post_url=f"https://www.linkedin.com/feed/update/{post_id}/"
                )
            else:
                return self.create_error_response("Failed to publish article", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
