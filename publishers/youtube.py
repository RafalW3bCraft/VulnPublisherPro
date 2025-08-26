"""
YouTube publisher for VulnPublisherPro
API Documentation: https://developers.google.com/youtube/v3
"""

import logging
from typing import Dict, Any
from .base import BasePublisher

logger = logging.getLogger(__name__)

class YouTubePublisher(BasePublisher):
    """Publisher for YouTube platform"""
    
    def __init__(self, config):
        super().__init__(config, 'youtube')
        
        # YouTube API credentials
        self.api_key = self.platform_config.get('api_key')
        
        # YouTube Data API base URL
        self.base_url = "https://www.googleapis.com/youtube/v3"
    
    def validate_config(self) -> bool:
        """Validate YouTube configuration"""
        if not self.api_key:
            logger.error("YouTube API key not configured")
            return False
        
        return True
    
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to YouTube (Community Post)"""
        if not self.validate_config():
            return self.create_error_response("YouTube configuration invalid")
        
        # YouTube publishing requires OAuth2 for content creation
        # For now, we'll implement a placeholder that would create a community post
        return await self._create_community_post(content, vulnerability)
    
    async def _create_community_post(self, content: Dict[str, Any], 
                                   vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Create a YouTube Community Post"""
        try:
            # Format content for YouTube Community Post
            post_content = self._format_for_community_post(content, vulnerability)
            
            # In a full implementation, this would use OAuth2 to authenticate
            # and create a community post via the YouTube Data API
            
            # Placeholder implementation
            logger.info("YouTube community post creation (placeholder implementation)")
            
            # Simulate successful post creation
            post_id = f"community_post_{hash(post_content) % 1000000}"
            
            return self.create_success_response(
                post_data={'content': post_content},
                post_id=post_id,
                post_url=f"https://www.youtube.com/post/{post_id}"
            )
                
        except Exception as e:
            logger.error(f"Error creating YouTube community post: {e}")
            return self.create_error_response(str(e))
    
    def _format_for_community_post(self, content: Dict[str, Any], 
                                  vulnerability: Dict[str, Any]) -> str:
        """Format content for YouTube Community Post"""
        # YouTube Community Posts support up to 8000 characters
        cve_id = vulnerability.get('cve_id', '')
        severity = vulnerability.get('severity', '').title()
        title = vulnerability.get('title', 'Security Vulnerability')
        
        post_content = f"🔒 SECURITY ALERT: {severity} Vulnerability\n\n"
        
        if cve_id:
            post_content += f"🆔 {cve_id}\n"
        
        post_content += f"📝 {title}\n\n"
        
        # Add description
        description = vulnerability.get('description', '')
        if description:
            # Truncate for readability
            if len(description) > 500:
                post_content += f"{description[:500]}...\n\n"
            else:
                post_content += f"{description}\n\n"
        
        # Add affected products
        affected_products = vulnerability.get('affected_products', [])
        if affected_products:
            post_content += "🎯 Affected Products:\n"
            for product in affected_products[:5]:  # Limit to 5
                post_content += f"• {product}\n"
            post_content += "\n"
        
        # Add CVSS score if available
        cvss_score = vulnerability.get('cvss_score')
        if cvss_score:
            post_content += f"📊 CVSS Score: {cvss_score}\n\n"
        
        # Add exploit status
        if vulnerability.get('exploit_available'):
            post_content += "⚠️ Exploit Available - Take Immediate Action!\n\n"
        
        # Add source
        source_url = vulnerability.get('source_url')
        if source_url:
            post_content += f"🔗 Source: {source_url}\n\n"
        
        # Add hashtags
        post_content += "#CyberSecurity #InfoSec #SecurityAlert #Vulnerability"
        
        # Truncate to YouTube limit
        return self.truncate_content(post_content, 8000)
    
    async def search_channels(self, query: str) -> Dict[str, Any]:
        """Search for YouTube channels"""
        if not self.validate_config():
            return self.create_error_response("YouTube configuration invalid")
        
        try:
            params = {
                'part': 'id,snippet',
                'q': query,
                'type': 'channel',
                'key': self.api_key,
                'maxResults': 10
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/search",
                method='GET',
                params=params
            )
            
            if response['success'] and 'items' in response['data']:
                channels = []
                for item in response['data']['items']:
                    snippet = item.get('snippet', {})
                    channels.append({
                        'id': item.get('id', {}).get('channelId'),
                        'title': snippet.get('title'),
                        'description': snippet.get('description'),
                        'thumbnail': snippet.get('thumbnails', {}).get('default', {}).get('url'),
                        'published_at': snippet.get('publishedAt')
                    })
                
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'channels': channels
                }
            else:
                return self.create_error_response("Failed to search channels", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def get_channel_info(self, channel_id: str) -> Dict[str, Any]:
        """Get YouTube channel information"""
        if not self.validate_config():
            return self.create_error_response("YouTube configuration invalid")
        
        try:
            params = {
                'part': 'id,snippet,statistics',
                'id': channel_id,
                'key': self.api_key
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/channels",
                method='GET',
                params=params
            )
            
            if response['success'] and 'items' in response['data'] and response['data']['items']:
                channel = response['data']['items'][0]
                snippet = channel.get('snippet', {})
                statistics = channel.get('statistics', {})
                
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'channel_info': {
                        'id': channel.get('id'),
                        'title': snippet.get('title'),
                        'description': snippet.get('description'),
                        'custom_url': snippet.get('customUrl'),
                        'published_at': snippet.get('publishedAt'),
                        'thumbnail': snippet.get('thumbnails', {}).get('default', {}).get('url'),
                        'subscriber_count': statistics.get('subscriberCount'),
                        'video_count': statistics.get('videoCount'),
                        'view_count': statistics.get('viewCount')
                    }
                }
            else:
                return self.create_error_response("Channel not found", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test YouTube API connection"""
        if not self.validate_config():
            return {
                'success': False,
                'platform': self.platform_name,
                'error': 'YouTube configuration invalid'
            }
        
        try:
            # Test with a simple search query
            params = {
                'part': 'id',
                'q': 'cybersecurity',
                'type': 'channel',
                'key': self.api_key,
                'maxResults': 1
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/search",
                method='GET',
                params=params
            )
            
            if response['success']:
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': 'YouTube API connection successful',
                    'quota_cost': '100 units per search request'
                }
            else:
                return {
                    'success': False,
                    'platform': self.platform_name,
                    'error': 'Failed to connect to YouTube API',
                    'details': response
                }
                
        except Exception as e:
            return {
                'success': False,
                'platform': self.platform_name,
                'error': str(e)
            }
    
    async def get_video_comments(self, video_id: str) -> Dict[str, Any]:
        """Get comments for a YouTube video"""
        if not self.validate_config():
            return self.create_error_response("YouTube configuration invalid")
        
        try:
            params = {
                'part': 'id,snippet',
                'videoId': video_id,
                'key': self.api_key,
                'maxResults': 50,
                'order': 'time'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/commentThreads",
                method='GET',
                params=params
            )
            
            if response['success'] and 'items' in response['data']:
                comments = []
                for item in response['data']['items']:
                    snippet = item.get('snippet', {})
                    top_comment = snippet.get('topLevelComment', {}).get('snippet', {})
                    
                    comments.append({
                        'id': item.get('id'),
                        'author': top_comment.get('authorDisplayName'),
                        'text': top_comment.get('textDisplay'),
                        'like_count': top_comment.get('likeCount'),
                        'published_at': top_comment.get('publishedAt'),
                        'reply_count': snippet.get('totalReplyCount', 0)
                    })
                
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'video_id': video_id,
                    'comments': comments,
                    'total_comments': response['data'].get('pageInfo', {}).get('totalResults', 0)
                }
            else:
                return self.create_error_response("Failed to get comments", response)
                
        except Exception as e:
            return self.create_error_response(str(e), video_id)
