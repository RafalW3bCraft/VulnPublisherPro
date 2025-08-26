"""
TikTok publisher for VulnPublisherPro
API Documentation: https://developers.tiktok.com/
"""

import logging
from typing import Dict, Any
from .base import BasePublisher

logger = logging.getLogger(__name__)

class TikTokPublisher(BasePublisher):
    """Publisher for TikTok platform"""
    
    def __init__(self, config):
        super().__init__(config, 'tiktok')
        
        # TikTok API credentials
        self.access_token = self.platform_config.get('access_token')
        
        # TikTok API base URL
        self.base_url = "https://open-api.tiktok.com"
    
    def validate_config(self) -> bool:
        """Validate TikTok configuration"""
        if not self.access_token:
            logger.error("TikTok access token not configured")
            return False
        
        return True
    
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to TikTok"""
        if not self.validate_config():
            return self.create_error_response("TikTok configuration invalid")
        
        # TikTok requires video content, so we'll create a text-based video placeholder
        # In a real implementation, this would generate or use pre-made video templates
        return await self._create_text_video_post(content, vulnerability)
    
    async def _create_text_video_post(self, content: Dict[str, Any], 
                                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Create a text-based video post for TikTok"""
        try:
            # Format content for TikTok
            caption = self._format_for_tiktok(content, vulnerability)
            
            # In a real implementation, this would:
            # 1. Generate a video with text overlay
            # 2. Upload the video to TikTok
            # 3. Create a post with the caption
            
            # For now, we'll create a placeholder implementation
            video_url = await self._create_text_video(content, vulnerability)
            
            if not video_url:
                return self.create_error_response("Failed to create video content")
            
            # Upload video and create post
            post_data = {
                'video': {
                    'video_url': video_url
                },
                'text': caption,
                'privacy_level': 'PUBLIC_TO_EVERYONE',
                'disable_duet': False,
                'disable_comment': False,
                'disable_stitch': False,
                'brand_content_toggle': False
            }
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/v2/post/publish/video/init/",
                method='POST',
                headers=headers,
                json_data=post_data
            )
            
            if response['success']:
                post_info = response['data']
                publish_id = post_info.get('publish_id')
                
                # Check publish status
                status_response = await self._check_publish_status(publish_id)
                
                if status_response['success']:
                    logger.info(f"Successfully posted to TikTok: {publish_id}")
                    
                    return self.create_success_response(
                        post_data=post_data,
                        post_id=publish_id,
                        post_url=f"https://www.tiktok.com/@user/video/{publish_id}"
                    )
                else:
                    return self.create_error_response("Failed to publish video", status_response)
            else:
                return self.create_error_response("Failed to upload video", response)
                
        except Exception as e:
            logger.error(f"Error publishing to TikTok: {e}")
            return self.create_error_response(str(e))
    
    def _format_for_tiktok(self, content: Dict[str, Any], vulnerability: Dict[str, Any]) -> str:
        """Format content for TikTok caption"""
        # TikTok captions support up to 2200 characters
        cve_id = vulnerability.get('cve_id', '')
        severity = vulnerability.get('severity', '').title()
        
        caption = f"🚨 SECURITY ALERT: {severity} Vulnerability!\n\n"
        
        if cve_id:
            caption += f"🆔 {cve_id}\n"
        
        # Add brief description
        description = vulnerability.get('description', '')
        if description:
            # Keep it short for TikTok
            brief_desc = description[:150] + '...' if len(description) > 150 else description
            caption += f"📝 {brief_desc}\n\n"
        
        # Add affected products (limited)
        affected_products = vulnerability.get('affected_products', [])
        if affected_products:
            caption += f"🎯 Affects: {', '.join(affected_products[:2])}\n"
            if len(affected_products) > 2:
                caption += f"...and {len(affected_products) - 2} more\n"
        
        # Add exploit warning
        if vulnerability.get('exploit_available'):
            caption += "\n⚠️ EXPLOIT AVAILABLE - Update ASAP!\n"
        
        # Add hashtags (TikTok loves hashtags)
        hashtags = [
            '#cybersecurity', '#infosec', '#security', '#hacking', 
            '#tech', '#vulnerability', '#cyberthreat', '#datasecurity',
            '#cybersafety', '#infosecurity'
        ]
        
        caption += f"\n{' '.join(hashtags[:8])}"  # Limit hashtags
        
        return self.truncate_content(caption, 2200)
    
    async def _create_text_video(self, content: Dict[str, Any], 
                                vulnerability: Dict[str, Any]) -> str:
        """Create a text-based video (placeholder implementation)"""
        # In a real implementation, this would:
        # 1. Use a video generation library to create a video with text overlay
        # 2. Add animations, transitions, and effects
        # 3. Upload to a temporary hosting service
        # 4. Return the video URL
        
        logger.info("Creating text video for TikTok (placeholder implementation)")
        return "https://example.com/placeholder_video.mp4"
    
    async def _check_publish_status(self, publish_id: str) -> Dict[str, Any]:
        """Check the status of a video publish"""
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}'
            }
            
            params = {
                'publish_id': publish_id
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/v2/post/publish/status/fetch/",
                method='POST',
                headers=headers,
                params=params
            )
            
            return response
            
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test TikTok API connection"""
        if not self.validate_config():
            return {
                'success': False,
                'platform': self.platform_name,
                'error': 'TikTok configuration invalid'
            }
        
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/v2/user/info/",
                method='POST',
                headers=headers
            )
            
            if response['success'] and 'data' in response['data']:
                user_data = response['data']['data']['user']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Connected as @{user_data.get("username")}',
                    'user_data': {
                        'open_id': user_data.get('open_id'),
                        'username': user_data.get('username'),
                        'display_name': user_data.get('display_name'),
                        'avatar_url': user_data.get('avatar_url'),
                        'follower_count': user_data.get('follower_count'),
                        'following_count': user_data.get('following_count')
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
        """Get TikTok analytics for a video"""
        if not self.validate_config():
            return self.create_error_response("TikTok configuration invalid")
        
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}'
            }
            
            data = {
                'fields': ['view_count', 'like_count', 'comment_count', 'share_count']
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/v2/video/data/",
                method='POST',
                headers=headers,
                json_data=data
            )
            
            if response['success'] and 'data' in response['data']:
                videos = response['data']['data']['videos']
                if videos:
                    video_data = videos[0]
                    return {
                        'success': True,
                        'platform': self.platform_name,
                        'post_id': post_id,
                        'analytics': {
                            'views': video_data.get('view_count', 0),
                            'likes': video_data.get('like_count', 0),
                            'comments': video_data.get('comment_count', 0),
                            'shares': video_data.get('share_count', 0),
                            'create_time': video_data.get('create_time')
                        }
                    }
            
            return self.create_error_response("Video not found", response)
                
        except Exception as e:
            return self.create_error_response(str(e), post_id)
    
    async def get_user_videos(self) -> Dict[str, Any]:
        """Get user's TikTok videos"""
        if not self.validate_config():
            return self.create_error_response("TikTok configuration invalid")
        
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}'
            }
            
            data = {
                'max_count': 20,
                'fields': ['id', 'create_time', 'cover_image_url', 'video_description', 'duration', 'height', 'width']
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/v2/video/list/",
                method='POST',
                headers=headers,
                json_data=data
            )
            
            if response['success'] and 'data' in response['data']:
                videos_data = response['data']['data']
                videos = videos_data.get('videos', [])
                
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'videos': [{
                        'id': video.get('id'),
                        'title': video.get('video_description', ''),
                        'create_time': video.get('create_time'),
                        'cover_image_url': video.get('cover_image_url'),
                        'duration': video.get('duration'),
                        'dimensions': f"{video.get('width')}x{video.get('height')}"
                    } for video in videos],
                    'has_more': videos_data.get('has_more', False),
                    'cursor': videos_data.get('cursor')
                }
            else:
                return self.create_error_response("Failed to get videos", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
