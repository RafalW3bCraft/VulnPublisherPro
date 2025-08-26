"""
Discord publisher for VulnPublisherPro
API Documentation: https://discord.com/developers/docs/intro
"""

import logging
from typing import Dict, Any
from .base import BasePublisher

logger = logging.getLogger(__name__)

class DiscordPublisher(BasePublisher):
    """Publisher for Discord platform"""
    
    def __init__(self, config):
        super().__init__(config, 'discord')
        
        # Discord Bot API credentials
        self.bot_token = self.platform_config.get('bot_token')
        self.channel_id = self.platform_config.get('channel_id')
        
        # Discord API base URL
        self.base_url = "https://discord.com/api/v10"
    
    def validate_config(self) -> bool:
        """Validate Discord configuration"""
        required_fields = ['bot_token', 'channel_id']
        
        for field in required_fields:
            if not self.platform_config.get(field):
                logger.error(f"Discord {field} not configured")
                return False
        
        return True
    
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to Discord"""
        if not self.validate_config():
            return self.create_error_response("Discord configuration invalid")
        
        try:
            # Determine if we should send an embed or plain message
            if content.get('content_type') in ['detailed', 'alert']:
                return await self._send_embed_message(content, vulnerability)
            else:
                return await self._send_text_message(content, vulnerability)
                
        except Exception as e:
            logger.error(f"Error publishing to Discord: {e}")
            return self.create_error_response(str(e))
    
    async def _send_text_message(self, content: Dict[str, Any], 
                                vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Send a text message to Discord"""
        try:
            message_content = self.format_content_for_platform(content)
            
            # Discord allows up to 2000 characters
            message_content = self.truncate_content(message_content, 2000)
            
            message_data = {
                'content': message_content
            }
            
            headers = {
                'Authorization': f'Bot {self.bot_token}',
                'Content-Type': 'application/json'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/channels/{self.channel_id}/messages",
                method='POST',
                headers=headers,
                json_data=message_data
            )
            
            if response['success']:
                message_data = response['data']
                message_id = message_data.get('id')
                
                logger.info(f"Successfully sent Discord message: {message_id}")
                
                return self.create_success_response(
                    post_data={'content': message_content},
                    post_id=message_id,
                    post_url=f"https://discord.com/channels/{message_data.get('guild_id', '@me')}/{self.channel_id}/{message_id}"
                )
            else:
                return self.create_error_response("Failed to send Discord message", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def _send_embed_message(self, content: Dict[str, Any], 
                                 vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Send an embed message to Discord"""
        try:
            embed = self._create_embed(content, vulnerability)
            
            message_data = {
                'embeds': [embed]
            }
            
            # Add content if it fits
            plain_content = content.get('content', '')[:500] if content.get('content') else None
            if plain_content:
                message_data['content'] = plain_content
            
            headers = {
                'Authorization': f'Bot {self.bot_token}',
                'Content-Type': 'application/json'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/channels/{self.channel_id}/messages",
                method='POST',
                headers=headers,
                json_data=message_data
            )
            
            if response['success']:
                message_data_resp = response['data']
                message_id = message_data_resp.get('id')
                
                logger.info(f"Successfully sent Discord embed: {message_id}")
                
                return self.create_success_response(
                    post_data=message_data,
                    post_id=message_id,
                    post_url=f"https://discord.com/channels/{message_data_resp.get('guild_id', '@me')}/{self.channel_id}/{message_id}"
                )
            else:
                return self.create_error_response("Failed to send Discord embed", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    def _create_embed(self, content: Dict[str, Any], vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Create Discord embed for vulnerability"""
        # Determine color based on severity
        severity = vulnerability.get('severity', 'unknown').lower()
        color_map = {
            'critical': 0xFF0000,  # Red
            'high': 0xFF6600,      # Orange
            'medium': 0xFFFF00,    # Yellow
            'low': 0x00FF00,       # Green
            'unknown': 0x808080    # Gray
        }
        
        embed_color = color_map.get(severity, 0x808080)
        
        # Create embed
        embed = {
            'title': vulnerability.get('title', 'Security Vulnerability')[:256],
            'color': embed_color,
            'timestamp': vulnerability.get('published_date') or vulnerability.get('created_at'),
            'fields': [],
            'footer': {
                'text': f"Source: {vulnerability.get('source', 'VulnPublisherPro')}"
            }
        }
        
        # Add CVE ID if available
        cve_id = vulnerability.get('cve_id')
        if cve_id:
            embed['title'] = f"{cve_id}: {embed['title']}"
        
        # Add description
        description = vulnerability.get('description', '')
        if description:
            embed['description'] = description[:4096]  # Discord limit
        
        # Add severity field
        if severity != 'unknown':
            embed['fields'].append({
                'name': '🚨 Severity',
                'value': severity.title(),
                'inline': True
            })
        
        # Add CVSS score if available
        cvss_score = vulnerability.get('cvss_score')
        if cvss_score:
            embed['fields'].append({
                'name': '📊 CVSS Score',
                'value': str(cvss_score),
                'inline': True
            })
        
        # Add affected products
        affected_products = vulnerability.get('affected_products', [])
        if affected_products:
            products_text = '\n'.join(affected_products[:5])  # Limit to 5
            if len(affected_products) > 5:
                products_text += f"\n...and {len(affected_products) - 5} more"
            
            embed['fields'].append({
                'name': '🎯 Affected Products',
                'value': products_text[:1024],  # Discord field limit
                'inline': False
            })
        
        # Add exploit availability
        if vulnerability.get('exploit_available'):
            embed['fields'].append({
                'name': '⚠️ Status',
                'value': 'Exploit Available',
                'inline': True
            })
        
        # Add source URL
        source_url = vulnerability.get('source_url')
        if source_url:
            embed['url'] = source_url
        
        # Add thumbnail for critical vulnerabilities
        if severity == 'critical':
            embed['thumbnail'] = {
                'url': 'https://cdn.discordapp.com/emojis/856164602094518302.png'  # Warning emoji
            }
        
        return embed
    
    def format_content_for_platform(self, content: Dict[str, Any]) -> str:
        """Format content for Discord"""
        content_type = content.get('content_type', 'summary')
        
        if content_type == 'alert':
            # Format alert content with Discord formatting
            alert_content = content.get('content', '')
            
            # Convert to Discord markdown
            formatted_content = alert_content.replace('🚨', '🚨 ')
            formatted_content = formatted_content.replace('✅', '• ')
            
            # Add mention for critical alerts
            action_items = content.get('action_items', [])
            if action_items:
                formatted_content += "\n\n**IMMEDIATE ACTIONS:**\n"
                for item in action_items:
                    formatted_content += f"• {item}\n"
            
            return formatted_content
        else:
            # Regular content
            discord_content = content.get('platform_variants', {}).get('discord', content.get('content', ''))
            
            # Add hashtags as tags
            hashtags = content.get('hashtags', [])
            if hashtags:
                tags = ' '.join([tag.replace('#', '') for tag in hashtags])
                discord_content += f"\n\n`{tags}`"
            
            return discord_content
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test Discord Bot API connection"""
        if not self.validate_config():
            return {
                'success': False,
                'platform': self.platform_name,
                'error': 'Discord configuration invalid'
            }
        
        try:
            headers = {
                'Authorization': f'Bot {self.bot_token}'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/users/@me",
                method='GET',
                headers=headers
            )
            
            if response['success']:
                bot_info = response['data']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Connected as {bot_info.get("username")}#{bot_info.get("discriminator")}',
                    'bot_data': {
                        'id': bot_info.get('id'),
                        'username': bot_info.get('username'),
                        'discriminator': bot_info.get('discriminator'),
                        'bot': bot_info.get('bot'),
                        'verified': bot_info.get('verified')
                    }
                }
            else:
                return {
                    'success': False,
                    'platform': self.platform_name,
                    'error': 'Failed to get bot data',
                    'details': response
                }
                
        except Exception as e:
            return {
                'success': False,
                'platform': self.platform_name,
                'error': str(e)
            }
    
    async def get_channel_info(self) -> Dict[str, Any]:
        """Get information about the target channel"""
        if not self.validate_config():
            return self.create_error_response("Discord configuration invalid")
        
        try:
            headers = {
                'Authorization': f'Bot {self.bot_token}'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/channels/{self.channel_id}",
                method='GET',
                headers=headers
            )
            
            if response['success']:
                channel_info = response['data']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'channel_info': {
                        'id': channel_info.get('id'),
                        'name': channel_info.get('name'),
                        'type': channel_info.get('type'),
                        'guild_id': channel_info.get('guild_id'),
                        'position': channel_info.get('position'),
                        'topic': channel_info.get('topic')
                    }
                }
            else:
                return self.create_error_response("Failed to get channel info", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def add_reaction(self, message_id: str, emoji: str) -> Dict[str, Any]:
        """Add a reaction to a message"""
        if not self.validate_config():
            return self.create_error_response("Discord configuration invalid")
        
        try:
            headers = {
                'Authorization': f'Bot {self.bot_token}'
            }
            
            # URL encode the emoji
            import urllib.parse
            encoded_emoji = urllib.parse.quote(emoji)
            
            response = await self.make_request(
                url=f"{self.base_url}/channels/{self.channel_id}/messages/{message_id}/reactions/{encoded_emoji}/@me",
                method='PUT',
                headers=headers
            )
            
            if response['success']:
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Added reaction {emoji} to message {message_id}'
                }
            else:
                return self.create_error_response("Failed to add reaction", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
