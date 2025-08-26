"""
Mastodon publisher for VulnPublisherPro
API Documentation: https://docs.joinmastodon.org/api/
"""

import logging
from typing import Dict, Any
from .base import BasePublisher

logger = logging.getLogger(__name__)

class MastodonPublisher(BasePublisher):
    """Publisher for Mastodon platform"""
    
    def __init__(self, config):
        super().__init__(config, 'mastodon')
        
        # Mastodon API credentials
        self.access_token = self.platform_config.get('access_token')
        self.instance_url = self.platform_config.get('instance_url', 'https://mastodon.social')
        
        # Clean up instance URL
        self.instance_url = self.instance_url.rstrip('/')
    
    def validate_config(self) -> bool:
        """Validate Mastodon configuration"""
        if not self.access_token:
            logger.error("Mastodon access token not configured")
            return False
        
        if not self.instance_url:
            logger.error("Mastodon instance URL not configured")
            return False
        
        return True
    
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to Mastodon"""
        if not self.validate_config():
            return self.create_error_response("Mastodon configuration invalid")
        
        try:
            # Check if content should be posted as a thread
            content_type = content.get('content_type', 'summary')
            
            if content_type == 'thread' and content.get('tweets'):
                return await self._publish_thread(content, vulnerability)
            else:
                return await self._publish_single_toot(content, vulnerability)
                
        except Exception as e:
            logger.error(f"Error publishing to Mastodon: {e}")
            return self.create_error_response(str(e))
    
    async def _publish_single_toot(self, content: Dict[str, Any], 
                                  vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish a single toot to Mastodon"""
        try:
            # Format content for Mastodon
            toot_content = self.format_content_for_platform(content)
            
            # Prepare toot data
            toot_data = {
                'status': toot_content,
                'visibility': 'public',
                'sensitive': False,
                'spoiler_text': ''
            }
            
            # Add content warning for critical vulnerabilities
            severity = vulnerability.get('severity', '').lower()
            if severity in ['critical', 'high']:
                toot_data['sensitive'] = True
                toot_data['spoiler_text'] = f'{severity.title()} Security Vulnerability Alert'
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json'
            }
            
            response = await self.make_request(
                url=f"{self.instance_url}/api/v1/statuses",
                method='POST',
                headers=headers,
                json_data=toot_data
            )
            
            if response['success']:
                toot_data_resp = response['data']
                toot_id = toot_data_resp.get('id')
                toot_url = toot_data_resp.get('url')
                
                logger.info(f"Successfully posted to Mastodon: {toot_id}")
                
                return self.create_success_response(
                    post_data=toot_data,
                    post_id=toot_id,
                    post_url=toot_url
                )
            else:
                return self.create_error_response("Failed to post to Mastodon", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def _publish_thread(self, content: Dict[str, Any], 
                             vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish a thread to Mastodon"""
        try:
            toots = content.get('tweets', [])  # Reuse tweet content for toots
            if not toots:
                return self.create_error_response("No toots in thread content")
            
            thread_ids = []
            reply_to_id = None
            
            for i, toot_text in enumerate(toots):
                # Mastodon allows 500 characters per toot
                toot_text = self.truncate_content(toot_text, 500)
                
                toot_data = {
                    'status': toot_text,
                    'visibility': 'public',
                    'sensitive': False
                }
                
                # Add content warning to first toot for critical vulnerabilities
                if i == 0:
                    severity = vulnerability.get('severity', '').lower()
                    if severity in ['critical', 'high']:
                        toot_data['sensitive'] = True
                        toot_data['spoiler_text'] = f'{severity.title()} Security Vulnerability Thread'
                
                # Add reply reference for thread
                if reply_to_id:
                    toot_data['in_reply_to_id'] = reply_to_id
                
                headers = {
                    'Authorization': f'Bearer {self.access_token}',
                    'Content-Type': 'application/json'
                }
                
                try:
                    response = await self.make_request(
                        url=f"{self.instance_url}/api/v1/statuses",
                        method='POST',
                        headers=headers,
                        json_data=toot_data
                    )
                    
                    if response['success']:
                        toot_resp = response['data']
                        toot_id = toot_resp.get('id')
                        thread_ids.append(toot_id)
                        reply_to_id = toot_id
                        
                        logger.info(f"Posted thread toot {i+1}/{len(toots)}: {toot_id}")
                        
                        # Rate limiting between toots
                        if i < len(toots) - 1:
                            await self.rate_limit()
                    else:
                        logger.error(f"Failed to post thread toot {i+1}: {response}")
                        break
                        
                except Exception as e:
                    logger.error(f"Error posting thread toot {i+1}: {e}")
                    break
            
            if thread_ids:
                first_toot_url = f"{self.instance_url}/@user/{thread_ids[0]}"
                
                return self.create_success_response(
                    post_data={
                        'thread_ids': thread_ids,
                        'total_toots': len(thread_ids),
                        'toots': toots[:len(thread_ids)]
                    },
                    post_id=thread_ids[0],
                    post_url=first_toot_url
                )
            else:
                return self.create_error_response("Failed to post any toots in thread")
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    def format_content_for_platform(self, content: Dict[str, Any]) -> str:
        """Format content for Mastodon"""
        # Use platform variant if available
        platform_variants = content.get('platform_variants', {})
        if 'mastodon' in platform_variants:
            toot_content = platform_variants['mastodon']
        else:
            toot_content = content.get('content', '')
        
        # Add hashtags
        hashtags = content.get('hashtags', ['#cybersecurity', '#infosec', '#security'])
        toot_content = self.add_platform_hashtags(toot_content, hashtags)
        
        # Mastodon allows 500 characters
        return self.truncate_content(toot_content, 500)
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test Mastodon API connection"""
        if not self.validate_config():
            return {
                'success': False,
                'platform': self.platform_name,
                'error': 'Mastodon configuration invalid'
            }
        
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}'
            }
            
            response = await self.make_request(
                url=f"{self.instance_url}/api/v1/accounts/verify_credentials",
                method='GET',
                headers=headers
            )
            
            if response['success']:
                account_data = response['data']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Connected as @{account_data.get("username")}@{self.instance_url.split("//")[1]}',
                    'account_data': {
                        'id': account_data.get('id'),
                        'username': account_data.get('username'),
                        'display_name': account_data.get('display_name'),
                        'url': account_data.get('url'),
                        'followers_count': account_data.get('followers_count'),
                        'following_count': account_data.get('following_count'),
                        'statuses_count': account_data.get('statuses_count'),
                        'created_at': account_data.get('created_at')
                    }
                }
            else:
                return {
                    'success': False,
                    'platform': self.platform_name,
                    'error': 'Failed to verify credentials',
                    'details': response
                }
                
        except Exception as e:
            return {
                'success': False,
                'platform': self.platform_name,
                'error': str(e)
            }
    
    async def get_analytics(self, post_id: str) -> Dict[str, Any]:
        """Get Mastodon analytics for a toot"""
        if not self.validate_config():
            return self.create_error_response("Mastodon configuration invalid")
        
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}'
            }
            
            response = await self.make_request(
                url=f"{self.instance_url}/api/v1/statuses/{post_id}",
                method='GET',
                headers=headers
            )
            
            if response['success']:
                toot_data = response['data']
                
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'post_id': post_id,
                    'analytics': {
                        'favourites': toot_data.get('favourites_count', 0),
                        'reblogs': toot_data.get('reblogs_count', 0),
                        'replies': toot_data.get('replies_count', 0),
                        'created_at': toot_data.get('created_at'),
                        'url': toot_data.get('url'),
                        'visibility': toot_data.get('visibility'),
                        'sensitive': toot_data.get('sensitive', False)
                    }
                }
            else:
                return self.create_error_response("Toot not found", response)
                
        except Exception as e:
            return self.create_error_response(str(e), post_id)
    
    async def get_instance_info(self) -> Dict[str, Any]:
        """Get information about the Mastodon instance"""
        try:
            response = await self.make_request(
                url=f"{self.instance_url}/api/v1/instance",
                method='GET'
            )
            
            if response['success']:
                instance_data = response['data']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'instance_info': {
                        'title': instance_data.get('title'),
                        'description': instance_data.get('description'),
                        'short_description': instance_data.get('short_description'),
                        'email': instance_data.get('email'),
                        'version': instance_data.get('version'),
                        'languages': instance_data.get('languages'),
                        'registrations': instance_data.get('registrations'),
                        'approval_required': instance_data.get('approval_required'),
                        'invites_enabled': instance_data.get('invites_enabled'),
                        'uri': instance_data.get('uri'),
                        'stats': instance_data.get('stats')
                    }
                }
            else:
                return self.create_error_response("Failed to get instance info", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def boost_toot(self, post_id: str) -> Dict[str, Any]:
        """Boost (reblog) a toot"""
        if not self.validate_config():
            return self.create_error_response("Mastodon configuration invalid")
        
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}'
            }
            
            response = await self.make_request(
                url=f"{self.instance_url}/api/v1/statuses/{post_id}/reblog",
                method='POST',
                headers=headers
            )
            
            if response['success']:
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Successfully boosted toot {post_id}',
                    'post_id': post_id
                }
            else:
                return self.create_error_response("Failed to boost toot", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def favourite_toot(self, post_id: str) -> Dict[str, Any]:
        """Favourite a toot"""
        if not self.validate_config():
            return self.create_error_response("Mastodon configuration invalid")
        
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}'
            }
            
            response = await self.make_request(
                url=f"{self.instance_url}/api/v1/statuses/{post_id}/favourite",
                method='POST',
                headers=headers
            )
            
            if response['success']:
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Successfully favourited toot {post_id}',
                    'post_id': post_id
                }
            else:
                return self.create_error_response("Failed to favourite toot", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
