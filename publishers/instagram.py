"""
Instagram publisher for VulnPublisherPro
API Documentation: https://developers.facebook.com/docs/instagram-api
"""

import logging
from typing import Dict, Any
from .base import BasePublisher

logger = logging.getLogger(__name__)

class InstagramPublisher(BasePublisher):
    """Publisher for Instagram platform"""
    
    def __init__(self, config):
        super().__init__(config, 'instagram')
        
        # Instagram API credentials (uses Facebook Graph API)
        self.access_token = self.platform_config.get('access_token')
        
        # Instagram Graph API base URL
        self.base_url = "https://graph.facebook.com/v18.0"
        
        # Instagram account ID (will be obtained)
        self.instagram_account_id = None
    
    def validate_config(self) -> bool:
        """Validate Instagram configuration"""
        if not self.access_token:
            logger.error("Instagram access token not configured")
            return False
        
        return True
    
    async def _get_instagram_account_id(self) -> str:
        """Get Instagram Business Account ID"""
        if self.instagram_account_id:
            return self.instagram_account_id
        
        try:
            params = {
                'access_token': self.access_token,
                'fields': 'instagram_business_account'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/me/accounts",
                method='GET',
                params=params
            )
            
            if response['success'] and 'data' in response['data']:
                accounts = response['data']['data']
                for account in accounts:
                    ig_account = account.get('instagram_business_account')
                    if ig_account:
                        self.instagram_account_id = ig_account['id']
                        return self.instagram_account_id
            
            logger.error("No Instagram Business Account found")
            return None
                
        except Exception as e:
            logger.error(f"Error getting Instagram account ID: {e}")
            return None
    
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to Instagram"""
        if not self.validate_config():
            return self.create_error_response("Instagram configuration invalid")
        
        # Instagram requires images for posts, so we'll create a text-based story instead
        # or post as a carousel with text overlay
        return await self._publish_story(content, vulnerability)
    
    async def _publish_story(self, content: Dict[str, Any], 
                            vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content as Instagram Story"""
        try:
            account_id = await self._get_instagram_account_id()
            if not account_id:
                return self.create_error_response("Failed to get Instagram account ID")
            
            # Format content for Instagram Story
            story_content = self._format_for_story(content, vulnerability)
            
            # Instagram Stories require media, so we'll create a simple text image
            # For now, we'll simulate this process
            media_url = await self._create_text_image(story_content)
            
            if not media_url:
                return self.create_error_response("Failed to create story media")
            
            # Create story media object
            story_data = {
                'image_url': media_url,
                'access_token': self.access_token
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/{account_id}/media",
                method='POST',
                data=story_data
            )
            
            if response['success'] and 'id' in response['data']:
                media_id = response['data']['id']
                
                # Publish the story
                publish_data = {
                    'creation_id': media_id,
                    'access_token': self.access_token
                }
                
                publish_response = await self.make_request(
                    url=f"{self.base_url}/{account_id}/media_publish",
                    method='POST',
                    data=publish_data
                )
                
                if publish_response['success'] and 'id' in publish_response['data']:
                    story_id = publish_response['data']['id']
                    
                    logger.info(f"Successfully posted Instagram story: {story_id}")
                    
                    return self.create_success_response(
                        post_data=story_data,
                        post_id=story_id,
                        post_url=f"https://www.instagram.com/stories/{account_id}/"
                    )
                else:
                    return self.create_error_response("Failed to publish story", publish_response)
            else:
                return self.create_error_response("Failed to create story media", response)
                
        except Exception as e:
            logger.error(f"Error publishing Instagram story: {e}")
            return self.create_error_response(str(e))
    
    def _format_for_story(self, content: Dict[str, Any], vulnerability: Dict[str, Any]) -> str:
        """Format content for Instagram Story"""
        # Instagram Stories have limited text space
        cve_id = vulnerability.get('cve_id', '')
        severity = vulnerability.get('severity', '').title()
        
        story_text = f"🚨 SECURITY ALERT\n\n"
        
        if cve_id:
            story_text += f"{cve_id}\n"
        
        story_text += f"Severity: {severity}\n\n"
        
        # Add brief description
        description = vulnerability.get('description', '')
        if description:
            # Truncate for story
            brief_desc = description[:100] + '...' if len(description) > 100 else description
            story_text += f"{brief_desc}\n\n"
        
        story_text += "Swipe up for details\n#CyberSecurity #InfoSec"
        
        return story_text
    
    async def _create_text_image(self, text: str) -> str:
        """Create a text-based image for Instagram (placeholder implementation)"""
        # In a real implementation, this would:
        # 1. Create an image with the text overlay
        # 2. Upload it to a hosting service
        # 3. Return the URL
        
        # For now, we'll return a placeholder
        # This should be replaced with actual image generation logic
        logger.info("Creating text image for Instagram story (placeholder)")
        return "https://via.placeholder.com/1080x1920/000000/FFFFFF?text=Security+Alert"
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test Instagram API connection"""
        if not self.validate_config():
            return {
                'success': False,
                'platform': self.platform_name,
                'error': 'Instagram configuration invalid'
            }
        
        try:
            account_id = await self._get_instagram_account_id()
            if not account_id:
                return {
                    'success': False,
                    'platform': self.platform_name,
                    'error': 'Failed to get Instagram account ID'
                }
            
            params = {
                'access_token': self.access_token,
                'fields': 'id,username,name,profile_picture_url,followers_count'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/{account_id}",
                method='GET',
                params=params
            )
            
            if response['success']:
                account_data = response['data']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Connected as @{account_data.get("username")}',
                    'account_data': {
                        'id': account_data.get('id'),
                        'username': account_data.get('username'),
                        'name': account_data.get('name'),
                        'followers_count': account_data.get('followers_count'),
                        'profile_picture_url': account_data.get('profile_picture_url')
                    }
                }
            else:
                return {
                    'success': False,
                    'platform': self.platform_name,
                    'error': 'Failed to get account data',
                    'details': response
                }
                
        except Exception as e:
            return {
                'success': False,
                'platform': self.platform_name,
                'error': str(e)
            }
    
    async def get_analytics(self, post_id: str) -> Dict[str, Any]:
        """Get Instagram analytics for a post"""
        if not self.validate_config():
            return self.create_error_response("Instagram configuration invalid")
        
        try:
            params = {
                'access_token': self.access_token,
                'metric': 'impressions,reach,likes,comments,saves,shares'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/{post_id}/insights",
                method='GET',
                params=params
            )
            
            if response['success'] and 'data' in response['data']:
                insights = response['data']['data']
                metrics = {}
                
                for insight in insights:
                    metric_name = insight.get('name')
                    metric_values = insight.get('values', [])
                    if metric_values:
                        metrics[metric_name] = metric_values[0].get('value', 0)
                
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'post_id': post_id,
                    'analytics': metrics
                }
            else:
                return self.create_error_response("Failed to get analytics", response)
                
        except Exception as e:
            return self.create_error_response(str(e), post_id)
