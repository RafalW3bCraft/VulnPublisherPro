"""
Slack publisher for VulnPublisherPro
API Documentation: https://api.slack.com/
"""

import logging
from typing import Dict, Any
from .base import BasePublisher

logger = logging.getLogger(__name__)

class SlackPublisher(BasePublisher):
    """Publisher for Slack platform"""
    
    def __init__(self, config):
        super().__init__(config, 'slack')
        
        # Slack API credentials
        self.token = self.platform_config.get('token')
        self.channel = self.platform_config.get('channel', '#general')
        
        # Slack Web API base URL
        self.base_url = "https://slack.com/api"
    
    def validate_config(self) -> bool:
        """Validate Slack configuration"""
        if not self.token:
            logger.error("Slack token not configured")
            return False
        
        if not self.channel:
            logger.error("Slack channel not configured")
            return False
        
        return True
    
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to Slack"""
        if not self.validate_config():
            return self.create_error_response("Slack configuration invalid")
        
        try:
            # Determine message format based on content type
            content_type = content.get('content_type', 'summary')
            
            if content_type == 'alert':
                return await self._send_alert_message(content, vulnerability)
            elif content_type == 'detailed':
                return await self._send_detailed_message(content, vulnerability)
            else:
                return await self._send_simple_message(content, vulnerability)
                
        except Exception as e:
            logger.error(f"Error publishing to Slack: {e}")
            return self.create_error_response(str(e))
    
    async def _send_simple_message(self, content: Dict[str, Any], 
                                  vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Send a simple text message to Slack"""
        try:
            message_text = self.format_content_for_platform(content)
            
            message_data = {
                'channel': self.channel,
                'text': message_text,
                'unfurl_links': True,
                'unfurl_media': True
            }
            
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/chat.postMessage",
                method='POST',
                headers=headers,
                json_data=message_data
            )
            
            if response['success'] and response['data'].get('ok'):
                message_info = response['data']
                message_ts = message_info.get('ts')
                channel_id = message_info.get('channel')
                
                logger.info(f"Successfully posted to Slack: {message_ts}")
                
                return self.create_success_response(
                    post_data=message_data,
                    post_id=message_ts,
                    post_url=f"https://app.slack.com/client/{channel_id}/{message_ts}"
                )
            else:
                error_msg = response.get('data', {}).get('error', 'Unknown error')
                return self.create_error_response(f"Slack API error: {error_msg}", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def _send_alert_message(self, content: Dict[str, Any], 
                                 vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Send an alert message with rich formatting"""
        try:
            # Create rich message blocks
            blocks = self._create_alert_blocks(content, vulnerability)
            
            message_data = {
                'channel': self.channel,
                'text': f"🚨 Security Alert: {vulnerability.get('cve_id', 'Vulnerability')}",
                'blocks': blocks,
                'unfurl_links': False
            }
            
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/chat.postMessage",
                method='POST',
                headers=headers,
                json_data=message_data
            )
            
            if response['success'] and response['data'].get('ok'):
                message_info = response['data']
                message_ts = message_info.get('ts')
                
                return self.create_success_response(
                    post_data=message_data,
                    post_id=message_ts
                )
            else:
                error_msg = response.get('data', {}).get('error', 'Unknown error')
                return self.create_error_response(f"Slack API error: {error_msg}", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def _send_detailed_message(self, content: Dict[str, Any], 
                                   vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Send a detailed message with attachment"""
        try:
            # Create message with attachment
            attachment = self._create_detailed_attachment(content, vulnerability)
            
            message_data = {
                'channel': self.channel,
                'text': f"Security Vulnerability Report: {vulnerability.get('cve_id', 'N/A')}",
                'attachments': [attachment]
            }
            
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/chat.postMessage",
                method='POST',
                headers=headers,
                json_data=message_data
            )
            
            if response['success'] and response['data'].get('ok'):
                message_info = response['data']
                message_ts = message_info.get('ts')
                
                return self.create_success_response(
                    post_data=message_data,
                    post_id=message_ts
                )
            else:
                error_msg = response.get('data', {}).get('error', 'Unknown error')
                return self.create_error_response(f"Slack API error: {error_msg}", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    def _create_alert_blocks(self, content: Dict[str, Any], vulnerability: Dict[str, Any]) -> list:
        """Create Slack blocks for alert message"""
        severity = vulnerability.get('severity', 'unknown').lower()
        cve_id = vulnerability.get('cve_id', 'N/A')
        
        # Determine color based on severity
        color_map = {
            'critical': '#FF0000',
            'high': '#FF6600',
            'medium': '#FFFF00',
            'low': '#00FF00',
            'unknown': '#808080'
        }
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 {severity.title()} Security Alert"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*CVE ID:*\n{cve_id}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{severity.title()}"
                    }
                ]
            }
        ]
        
        # Add CVSS score if available
        cvss_score = vulnerability.get('cvss_score')
        if cvss_score:
            blocks.append({
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*CVSS Score:*\n{cvss_score}"
                    }
                ]
            })
        
        # Add description
        description = vulnerability.get('description', '')
        if description:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{description[:500]}{'...' if len(description) > 500 else ''}"
                }
            })
        
        # Add affected products
        affected_products = vulnerability.get('affected_products', [])
        if affected_products:
            products_text = '\n'.join([f"• {product}" for product in affected_products[:5]])
            if len(affected_products) > 5:
                products_text += f"\n• ...and {len(affected_products) - 5} more"
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Affected Products:*\n{products_text}"
                }
            })
        
        # Add action items if available
        action_items = content.get('action_items', [])
        if action_items:
            actions_text = '\n'.join([f"• {item}" for item in action_items])
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Immediate Actions:*\n{actions_text}"
                }
            })
        
        # Add source link if available
        source_url = vulnerability.get('source_url')
        if source_url:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"<{source_url}|View Full Details>"
                }
            })
        
        return blocks
    
    def _create_detailed_attachment(self, content: Dict[str, Any], vulnerability: Dict[str, Any]) -> dict:
        """Create Slack attachment for detailed message"""
        severity = vulnerability.get('severity', 'unknown').lower()
        
        # Determine color based on severity
        color_map = {
            'critical': 'danger',
            'high': 'warning',
            'medium': '#FFFF00',
            'low': 'good',
            'unknown': '#808080'
        }
        
        attachment = {
            "color": color_map.get(severity, '#808080'),
            "title": vulnerability.get('title', 'Security Vulnerability'),
            "title_link": vulnerability.get('source_url'),
            "text": content.get('executive_summary', vulnerability.get('description', '')),
            "fields": []
        }
        
        # Add fields
        fields_data = [
            ("CVE ID", vulnerability.get('cve_id')),
            ("Severity", severity.title()),
            ("CVSS Score", vulnerability.get('cvss_score')),
            ("Source", vulnerability.get('source', '').title()),
            ("Published", vulnerability.get('published_date', '').split('T')[0] if vulnerability.get('published_date') else None)
        ]
        
        for title, value in fields_data:
            if value:
                attachment["fields"].append({
                    "title": title,
                    "value": str(value),
                    "short": True
                })
        
        # Add footer
        attachment["footer"] = "VulnPublisherPro"
        attachment["ts"] = int(vulnerability.get('created_at', vulnerability.get('published_date', '1970-01-01')).split('T')[0].replace('-', ''))
        
        return attachment
    
    def format_content_for_platform(self, content: Dict[str, Any]) -> str:
        """Format content for Slack"""
        slack_content = content.get('platform_variants', {}).get('slack', content.get('content', ''))
        
        # Convert basic markdown to Slack format
        slack_content = slack_content.replace('**', '*')  # Bold
        slack_content = slack_content.replace('# ', '*')   # Headers to bold
        slack_content = slack_content.replace('## ', '*')  # Headers to bold
        
        return slack_content
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test Slack API connection"""
        if not self.validate_config():
            return {
                'success': False,
                'platform': self.platform_name,
                'error': 'Slack configuration invalid'
            }
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/auth.test",
                method='POST',
                headers=headers
            )
            
            if response['success'] and response['data'].get('ok'):
                auth_data = response['data']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Connected to {auth_data.get("team")} as {auth_data.get("user")}',
                    'auth_data': {
                        'user': auth_data.get('user'),
                        'user_id': auth_data.get('user_id'),
                        'team': auth_data.get('team'),
                        'team_id': auth_data.get('team_id'),
                        'url': auth_data.get('url')
                    }
                }
            else:
                error_msg = response.get('data', {}).get('error', 'Unknown error')
                return {
                    'success': False,
                    'platform': self.platform_name,
                    'error': f'Slack API error: {error_msg}'
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
            return self.create_error_response("Slack configuration invalid")
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}'
            }
            
            params = {
                'channel': self.channel
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/conversations.info",
                method='GET',
                headers=headers,
                params=params
            )
            
            if response['success'] and response['data'].get('ok'):
                channel_data = response['data']['channel']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'channel_info': {
                        'id': channel_data.get('id'),
                        'name': channel_data.get('name'),
                        'is_channel': channel_data.get('is_channel'),
                        'is_group': channel_data.get('is_group'),
                        'is_im': channel_data.get('is_im'),
                        'is_private': channel_data.get('is_private'),
                        'is_archived': channel_data.get('is_archived'),
                        'topic': channel_data.get('topic', {}).get('value'),
                        'purpose': channel_data.get('purpose', {}).get('value'),
                        'num_members': channel_data.get('num_members')
                    }
                }
            else:
                error_msg = response.get('data', {}).get('error', 'Unknown error')
                return self.create_error_response(f"Slack API error: {error_msg}", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def add_reaction(self, message_ts: str, emoji: str) -> Dict[str, Any]:
        """Add a reaction to a message"""
        if not self.validate_config():
            return self.create_error_response("Slack configuration invalid")
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}'
            }
            
            data = {
                'channel': self.channel,
                'timestamp': message_ts,
                'name': emoji.replace(':', '')  # Remove colons if present
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/reactions.add",
                method='POST',
                headers=headers,
                json_data=data
            )
            
            if response['success'] and response['data'].get('ok'):
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Added reaction :{emoji}: to message {message_ts}'
                }
            else:
                error_msg = response.get('data', {}).get('error', 'Unknown error')
                return self.create_error_response(f"Failed to add reaction: {error_msg}", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
