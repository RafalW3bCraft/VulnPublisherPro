"""
Facebook publisher for VulnPublisherPro
API Documentation: https://developers.facebook.com/docs/graph-api
"""

import logging
from typing import Dict, Any
from .base import BasePublisher

logger = logging.getLogger(__name__)

class FacebookPublisher(BasePublisher):
    """Publisher for Facebook platform"""
    
    def __init__(self, config):
        super().__init__(config, 'facebook')
        
        # Facebook API credentials
        self.access_token = self.platform_config.get('access_token')
        
        # Facebook Graph API base URL
        self.base_url = "https://graph.facebook.com/v18.0"
    
    def validate_config(self) -> bool:
        """Validate Facebook configuration"""
        if not self.access_token:
            logger.error("Facebook access token not configured")
            return False
        
        return True
    
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to Facebook"""
        if not self.validate_config():
            return self.create_error_response("Facebook configuration invalid")
        
        try:
            # Format content for Facebook
            message = self.format_content_for_platform(content)
            
            # Create post data
            post_data = {
                'message': message,
                'access_token': self.access_token
            }
            
            # Add link if available
            source_url = vulnerability.get('source_url')
            if source_url:
                post_data['link'] = source_url
            
            response = await self.make_request(
                url=f"{self.base_url}/me/feed",
                method='POST',
                data=post_data
            )
            
            if response['success'] and 'id' in response['data']:
                post_id = response['data']['id']
                post_url = f"https://www.facebook.com/{post_id.replace('_', '/posts/')}"
                
                logger.info(f"Successfully posted to Facebook: {post_id}")
                
                return self.create_success_response(
                    post_data=post_data,
                    post_id=post_id,
                    post_url=post_url
                )
            else:
                return self.create_error_response("Failed to post to Facebook", response)
                
        except Exception as e:
            logger.error(f"Error publishing to Facebook: {e}")
            return self.create_error_response(str(e))
    
    def format_content_for_platform(self, content: Dict[str, Any]) -> str:
        """Format content for Facebook"""
        # Facebook allows longer posts, so use detailed content if available
        facebook_content = content.get('platform_variants', {}).get('facebook', content.get('content', ''))
        
        # Add hashtags
        hashtags = content.get('hashtags', ['#cybersecurity', '#security'])
        facebook_content = self.add_platform_hashtags(facebook_content, hashtags)
        
        # Facebook has a 63,206 character limit
        return self.truncate_content(facebook_content, 60000)
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test Facebook API connection"""
        if not self.validate_config():
            return {
                'success': False,
                'platform': self.platform_name,
                'error': 'Facebook configuration invalid'
            }
        
        try:
            params = {
                'access_token': self.access_token,
                'fields': 'id,name,email'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/me",
                method='GET',
                params=params
            )
            
            if response['success']:
                user_data = response['data']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Connected as {user_data.get("name")}',
                    'user_data': {
                        'id': user_data.get('id'),
                        'name': user_data.get('name'),
                        'email': user_data.get('email')
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
    
    async def get_analytics(self, post_id: str) -> Dict[str, Any]:
        """Get Facebook analytics for a post"""
        if not self.validate_config():
            return self.create_error_response("Facebook configuration invalid")
        
        try:
            params = {
                'access_token': self.access_token,
                'fields': 'reactions.limit(0).summary(1),comments.limit(0).summary(1),shares'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/{post_id}",
                method='GET',
                params=params
            )
            
            if response['success']:
                post_data = response['data']
                reactions_summary = post_data.get('reactions', {}).get('summary', {})
                comments_summary = post_data.get('comments', {}).get('summary', {})
                shares_data = post_data.get('shares', {})
                
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'post_id': post_id,
                    'analytics': {
                        'reactions': reactions_summary.get('total_count', 0),
                        'comments': comments_summary.get('total_count', 0),
                        'shares': shares_data.get('count', 0)
                    }
                }
            else:
                return self.create_error_response("Failed to get analytics", response)
                
        except Exception as e:
            return self.create_error_response(str(e), post_id)
