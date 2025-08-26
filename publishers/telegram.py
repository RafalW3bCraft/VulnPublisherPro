"""
Telegram publisher for VulnPublisherPro
API Documentation: https://core.telegram.org/bots/api
"""

import logging
from typing import Dict, Any
from .base import BasePublisher

logger = logging.getLogger(__name__)

class TelegramPublisher(BasePublisher):
    """Publisher for Telegram Bot API"""
    
    def __init__(self, config):
        super().__init__(config, 'telegram')
        
        # Telegram Bot API credentials
        self.bot_token = self.platform_config.get('bot_token')
        self.chat_id = self.platform_config.get('chat_id')
        
        # Telegram API base URL
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}" if self.bot_token else None
    
    def validate_config(self) -> bool:
        """Validate Telegram configuration"""
        required_fields = ['bot_token', 'chat_id']
        
        for field in required_fields:
            if not self.platform_config.get(field):
                logger.error(f"Telegram {field} not configured")
                return False
        
        return True
    
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to Telegram"""
        if not self.validate_config():
            return self.create_error_response("Telegram configuration invalid")
        
        try:
            # Format content for Telegram
            message_text = self.format_content_for_platform(content)
            
            # Prepare Telegram message data
            message_data = {
                'chat_id': self.chat_id,
                'text': message_text,
                'parse_mode': 'Markdown',
                'disable_web_page_preview': False
            }
            
            # Make API request
            response = await self.make_request(
                url=f"{self.base_url}/sendMessage",
                method='POST',
                json_data=message_data
            )
            
            if response['success'] and response['data'].get('ok'):
                result = response['data']['result']
                message_id = result['message_id']
                
                logger.info(f"Successfully sent Telegram message: {message_id}")
                
                return self.create_success_response(
                    post_data=message_data,
                    post_id=str(message_id),
                    post_url=f"https://t.me/{self.chat_id.replace('@', '')}/{message_id}" if isinstance(self.chat_id, str) and self.chat_id.startswith('@') else None
                )
            else:
                error_msg = response.get('data', {}).get('description', 'Unknown error')
                return self.create_error_response(f"Telegram API error: {error_msg}", response)
                
        except Exception as e:
            logger.error(f"Error publishing to Telegram: {e}")
            return self.create_error_response(str(e))
    
    def format_content_for_platform(self, content: Dict[str, Any]) -> str:
        """Format content for Telegram with Markdown"""
        content_type = content.get('content_type', 'summary')
        
        if content_type == 'alert':
            # Format alert with urgent styling
            alert_content = content.get('content', '')
            
            # Convert to Markdown
            formatted_content = f"🚨 **SECURITY ALERT** 🚨\n\n"
            formatted_content += alert_content.replace('✅', '• ')
            
            # Add action items if present
            action_items = content.get('action_items', [])
            if action_items:
                formatted_content += "\n\n**IMMEDIATE ACTIONS:**\n"
                for item in action_items:
                    formatted_content += f"• {item}\n"
            
            return formatted_content
            
        elif content_type == 'detailed':
            # Format detailed report
            title = content.get('title', 'Security Report')
            detailed_content = content.get('content', '')
            
            formatted_content = f"**{title}**\n\n"
            
            # Add executive summary if present
            if content.get('executive_summary'):
                formatted_content += f"**Executive Summary:**\n{content['executive_summary']}\n\n"
            
            # Add main content (convert basic formatting to Markdown)
            formatted_content += detailed_content
            
            # Convert basic formatting
            formatted_content = formatted_content.replace('# ', '**').replace('\n# ', '\n**')
            formatted_content = formatted_content.replace('## ', '**').replace('\n## ', '\n**')
            
            return self.truncate_content(formatted_content, 4096)  # Telegram limit
        
        else:
            # Regular content
            telegram_content = content.get('platform_variants', {}).get('telegram', content.get('content', ''))
            
            # Add hashtags
            hashtags = content.get('hashtags', [])
            if hashtags:
                telegram_content += f"\n\n{' '.join(hashtags)}"
            
            return self.truncate_content(telegram_content, 4096)
    
    async def send_document(self, file_path: str, caption: str = None) -> Dict[str, Any]:
        """Send a document to Telegram channel"""
        if not self.validate_config():
            return self.create_error_response("Telegram configuration invalid")
        
        try:
            data = {
                'chat_id': self.chat_id,
                'caption': caption or "Vulnerability Report",
                'parse_mode': 'Markdown'
            }
            
            with open(file_path, 'rb') as document:
                files = {'document': document}
                
                response = await self.make_request(
                    url=f"{self.base_url}/sendDocument",
                    method='POST',
                    data=data,
                    files=files
                )
            
            if response['success'] and response['data'].get('ok'):
                result = response['data']['result']
                message_id = result['message_id']
                
                return self.create_success_response(
                    post_data={'file_path': file_path, 'caption': caption},
                    post_id=str(message_id)
                )
            else:
                error_msg = response.get('data', {}).get('description', 'Unknown error')
                return self.create_error_response(f"Failed to send document: {error_msg}", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test Telegram Bot API connection"""
        if not self.validate_config():
            return {
                'success': False,
                'platform': self.platform_name,
                'error': 'Telegram configuration invalid'
            }
        
        try:
            response = await self.make_request(
                url=f"{self.base_url}/getMe",
                method='GET'
            )
            
            if response['success'] and response['data'].get('ok'):
                bot_info = response['data']['result']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Connected as @{bot_info.get("username")}',
                    'bot_data': {
                        'id': bot_info.get('id'),
                        'username': bot_info.get('username'),
                        'first_name': bot_info.get('first_name'),
                        'can_join_groups': bot_info.get('can_join_groups'),
                        'can_read_all_group_messages': bot_info.get('can_read_all_group_messages')
                    }
                }
            else:
                error_msg = response.get('data', {}).get('description', 'Unknown error')
                return {
                    'success': False,
                    'platform': self.platform_name,
                    'error': f'Telegram API error: {error_msg}'
                }
                
        except Exception as e:
            return {
                'success': False,
                'platform': self.platform_name,
                'error': str(e)
            }
    
    async def get_chat_info(self) -> Dict[str, Any]:
        """Get information about the target chat"""
        if not self.validate_config():
            return self.create_error_response("Telegram configuration invalid")
        
        try:
            response = await self.make_request(
                url=f"{self.base_url}/getChat",
                method='GET',
                params={'chat_id': self.chat_id}
            )
            
            if response['success'] and response['data'].get('ok'):
                chat_info = response['data']['result']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'chat_info': {
                        'id': chat_info.get('id'),
                        'type': chat_info.get('type'),
                        'title': chat_info.get('title'),
                        'username': chat_info.get('username'),
                        'member_count': chat_info.get('member_count')
                    }
                }
            else:
                error_msg = response.get('data', {}).get('description', 'Unknown error')
                return self.create_error_response(f"Failed to get chat info: {error_msg}", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def edit_message(self, message_id: str, new_content: Dict[str, Any]) -> Dict[str, Any]:
        """Edit a previously sent message"""
        if not self.validate_config():
            return self.create_error_response("Telegram configuration invalid")
        
        try:
            new_text = self.format_content_for_platform(new_content)
            
            data = {
                'chat_id': self.chat_id,
                'message_id': int(message_id),
                'text': new_text,
                'parse_mode': 'Markdown'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/editMessageText",
                method='POST',
                json_data=data
            )
            
            if response['success'] and response['data'].get('ok'):
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': 'Message edited successfully',
                    'message_id': message_id
                }
            else:
                error_msg = response.get('data', {}).get('description', 'Unknown error')
                return self.create_error_response(f"Failed to edit message: {error_msg}", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def pin_message(self, message_id: str) -> Dict[str, Any]:
        """Pin a message in the chat"""
        if not self.validate_config():
            return self.create_error_response("Telegram configuration invalid")
        
        try:
            data = {
                'chat_id': self.chat_id,
                'message_id': int(message_id),
                'disable_notification': False
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/pinChatMessage",
                method='POST',
                json_data=data
            )
            
            if response['success'] and response['data'].get('ok'):
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': 'Message pinned successfully',
                    'message_id': message_id
                }
            else:
                error_msg = response.get('data', {}).get('description', 'Unknown error')
                return self.create_error_response(f"Failed to pin message: {error_msg}", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
