"""
Microsoft Teams publisher for VulnPublisherPro
API Documentation: https://docs.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/
"""

import logging
from typing import Dict, Any
from .base import BasePublisher

logger = logging.getLogger(__name__)

class TeamsPublisher(BasePublisher):
    """Publisher for Microsoft Teams platform"""
    
    def __init__(self, config):
        super().__init__(config, 'teams')
        
        # Teams webhook URL
        self.webhook_url = self.platform_config.get('webhook_url')
    
    def validate_config(self) -> bool:
        """Validate Teams configuration"""
        if not self.webhook_url:
            logger.error("Teams webhook URL not configured")
            return False
        
        return True
    
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to Microsoft Teams"""
        if not self.validate_config():
            return self.create_error_response("Teams configuration invalid")
        
        try:
            # Determine message format based on content type
            content_type = content.get('content_type', 'summary')
            
            if content_type == 'alert':
                return await self._send_alert_card(content, vulnerability)
            elif content_type == 'detailed':
                return await self._send_detailed_card(content, vulnerability)
            else:
                return await self._send_simple_card(content, vulnerability)
                
        except Exception as e:
            logger.error(f"Error publishing to Teams: {e}")
            return self.create_error_response(str(e))
    
    async def _send_simple_card(self, content: Dict[str, Any], 
                               vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Send a simple adaptive card to Teams"""
        try:
            card = self._create_simple_card(content, vulnerability)
            
            message_data = {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": card
                    }
                ]
            }
            
            response = await self.make_request(
                url=self.webhook_url,
                method='POST',
                json_data=message_data
            )
            
            if response['success']:
                logger.info("Successfully posted to Teams")
                
                return self.create_success_response(
                    post_data=message_data,
                    post_id="teams_message",  # Teams doesn't return message ID
                    post_url=None
                )
            else:
                return self.create_error_response("Failed to post to Teams", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def _send_alert_card(self, content: Dict[str, Any], 
                              vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Send an alert adaptive card to Teams"""
        try:
            card = self._create_alert_card(content, vulnerability)
            
            message_data = {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": card
                    }
                ]
            }
            
            response = await self.make_request(
                url=self.webhook_url,
                method='POST',
                json_data=message_data
            )
            
            if response['success']:
                return self.create_success_response(
                    post_data=message_data,
                    post_id="teams_alert"
                )
            else:
                return self.create_error_response("Failed to post alert to Teams", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def _send_detailed_card(self, content: Dict[str, Any], 
                                 vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Send a detailed adaptive card to Teams"""
        try:
            card = self._create_detailed_card(content, vulnerability)
            
            message_data = {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": card
                    }
                ]
            }
            
            response = await self.make_request(
                url=self.webhook_url,
                method='POST',
                json_data=message_data
            )
            
            if response['success']:
                return self.create_success_response(
                    post_data=message_data,
                    post_id="teams_detailed"
                )
            else:
                return self.create_error_response("Failed to post detailed card to Teams", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    def _create_simple_card(self, content: Dict[str, Any], vulnerability: Dict[str, Any]) -> dict:
        """Create a simple adaptive card"""
        severity = vulnerability.get('severity', 'unknown').lower()
        cve_id = vulnerability.get('cve_id', 'N/A')
        
        # Determine color based on severity
        color_map = {
            'critical': 'attention',
            'high': 'warning',
            'medium': 'accent',
            'low': 'good',
            'unknown': 'default'
        }
        
        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                {
                    "type": "TextBlock",
                    "text": f"🚨 Security Vulnerability: {cve_id}",
                    "weight": "Bolder",
                    "size": "Large",
                    "color": color_map.get(severity, 'default')
                },
                {
                    "type": "FactSet",
                    "facts": [
                        {
                            "title": "Severity:",
                            "value": severity.title()
                        }
                    ]
                }
            ]
        }
        
        # Add CVSS score if available
        cvss_score = vulnerability.get('cvss_score')
        if cvss_score:
            card["body"][1]["facts"].append({
                "title": "CVSS Score:",
                "value": str(cvss_score)
            })
        
        # Add description
        description = vulnerability.get('description', '')
        if description:
            card["body"].append({
                "type": "TextBlock",
                "text": description[:300] + ('...' if len(description) > 300 else ''),
                "wrap": True
            })
        
        # Add source link if available
        source_url = vulnerability.get('source_url')
        if source_url:
            card["actions"] = [
                {
                    "type": "Action.OpenUrl",
                    "title": "View Details",
                    "url": source_url
                }
            ]
        
        return card
    
    def _create_alert_card(self, content: Dict[str, Any], vulnerability: Dict[str, Any]) -> dict:
        """Create an alert adaptive card"""
        severity = vulnerability.get('severity', 'unknown').lower()
        cve_id = vulnerability.get('cve_id', 'N/A')
        
        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                {
                    "type": "Container",
                    "style": "attention" if severity in ['critical', 'high'] else "warning",
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": f"🚨 {severity.upper()} SECURITY ALERT",
                            "weight": "Bolder",
                            "size": "Large",
                            "color": "attention"
                        },
                        {
                            "type": "TextBlock",
                            "text": f"CVE ID: {cve_id}",
                            "weight": "Bolder",
                            "size": "Medium"
                        }
                    ]
                }
            ]
        }
        
        # Add vulnerability details
        facts = []
        
        details_data = [
            ("Severity", severity.title()),
            ("CVSS Score", vulnerability.get('cvss_score')),
            ("Source", vulnerability.get('source', '').title()),
            ("Published", vulnerability.get('published_date', '').split('T')[0] if vulnerability.get('published_date') else None)
        ]
        
        for title, value in details_data:
            if value:
                facts.append({
                    "title": f"{title}:",
                    "value": str(value)
                })
        
        if facts:
            card["body"].append({
                "type": "FactSet",
                "facts": facts
            })
        
        # Add description
        description = vulnerability.get('description', '')
        if description:
            card["body"].append({
                "type": "TextBlock",
                "text": description,
                "wrap": True
            })
        
        # Add affected products
        affected_products = vulnerability.get('affected_products', [])
        if affected_products:
            products_text = "\n".join([f"• {product}" for product in affected_products[:5]])
            if len(affected_products) > 5:
                products_text += f"\n• ...and {len(affected_products) - 5} more"
            
            card["body"].append({
                "type": "TextBlock",
                "text": f"**Affected Products:**\n{products_text}",
                "wrap": True
            })
        
        # Add action items if available
        action_items = content.get('action_items', [])
        if action_items:
            actions_text = "\n".join([f"• {item}" for item in action_items])
            card["body"].append({
                "type": "TextBlock",
                "text": f"**Immediate Actions Required:**\n{actions_text}",
                "wrap": True,
                "color": "attention"
            })
        
        # Add actions
        actions = []
        
        source_url = vulnerability.get('source_url')
        if source_url:
            actions.append({
                "type": "Action.OpenUrl",
                "title": "View Full Details",
                "url": source_url
            })
        
        if actions:
            card["actions"] = actions
        
        return card
    
    def _create_detailed_card(self, content: Dict[str, Any], vulnerability: Dict[str, Any]) -> dict:
        """Create a detailed adaptive card"""
        severity = vulnerability.get('severity', 'unknown').lower()
        cve_id = vulnerability.get('cve_id', 'N/A')
        title = vulnerability.get('title', 'Security Vulnerability')
        
        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                {
                    "type": "TextBlock",
                    "text": f"Security Vulnerability Report",
                    "weight": "Bolder",
                    "size": "Large"
                },
                {
                    "type": "TextBlock",
                    "text": title,
                    "weight": "Bolder",
                    "size": "Medium",
                    "color": "accent"
                }
            ]
        }
        
        # Add executive summary if available
        if content.get('executive_summary'):
            card["body"].append({
                "type": "TextBlock",
                "text": f"**Executive Summary:**\n{content['executive_summary']}",
                "wrap": True
            })
        
        # Add vulnerability details in columns
        column_facts = []
        
        # Left column facts
        left_facts = [
            ("CVE ID", cve_id),
            ("Severity", severity.title()),
            ("CVSS Score", vulnerability.get('cvss_score'))
        ]
        
        # Right column facts
        right_facts = [
            ("CWE ID", vulnerability.get('cwe_id')),
            ("Source", vulnerability.get('source', '').title()),
            ("Published", vulnerability.get('published_date', '').split('T')[0] if vulnerability.get('published_date') else None)
        ]
        
        # Create column sets
        columns = []
        
        # Left column
        left_column_facts = [{"title": f"{title}:", "value": str(value)} for title, value in left_facts if value]
        if left_column_facts:
            columns.append({
                "type": "Column",
                "width": "stretch",
                "items": [
                    {
                        "type": "FactSet",
                        "facts": left_column_facts
                    }
                ]
            })
        
        # Right column
        right_column_facts = [{"title": f"{title}:", "value": str(value)} for title, value in right_facts if value]
        if right_column_facts:
            columns.append({
                "type": "Column",
                "width": "stretch",
                "items": [
                    {
                        "type": "FactSet",
                        "facts": right_column_facts
                    }
                ]
            })
        
        if columns:
            card["body"].append({
                "type": "ColumnSet",
                "columns": columns
            })
        
        # Add description
        description = vulnerability.get('description', '')
        if description:
            card["body"].append({
                "type": "TextBlock",
                "text": f"**Description:**\n{description}",
                "wrap": True
            })
        
        # Add affected products
        affected_products = vulnerability.get('affected_products', [])
        if affected_products:
            products_text = "\n".join([f"• {product}" for product in affected_products])
            card["body"].append({
                "type": "TextBlock",
                "text": f"**Affected Products:**\n{products_text}",
                "wrap": True
            })
        
        # Add recommendations if available
        recommendations = content.get('recommendations', [])
        if recommendations:
            rec_text = "\n".join([f"• {rec}" for rec in recommendations])
            card["body"].append({
                "type": "TextBlock",
                "text": f"**Recommendations:**\n{rec_text}",
                "wrap": True
            })
        
        # Add actions
        actions = []
        
        source_url = vulnerability.get('source_url')
        if source_url:
            actions.append({
                "type": "Action.OpenUrl",
                "title": "View Original Source",
                "url": source_url
            })
        
        # Add references
        references = vulnerability.get('references', [])
        if references and references[0]:
            actions.append({
                "type": "Action.OpenUrl",
                "title": "Additional References",
                "url": references[0]
            })
        
        if actions:
            card["actions"] = actions
        
        return card
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test Teams webhook connection"""
        if not self.validate_config():
            return {
                'success': False,
                'platform': self.platform_name,
                'error': 'Teams configuration invalid'
            }
        
        try:
            # Send a simple test message
            test_card = {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "TextBlock",
                        "text": "VulnPublisherPro Connection Test",
                        "weight": "Bolder",
                        "size": "Medium"
                    },
                    {
                        "type": "TextBlock",
                        "text": "This is a test message to verify the Teams webhook connection is working properly.",
                        "wrap": True
                    }
                ]
            }
            
            test_message = {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": test_card
                    }
                ]
            }
            
            response = await self.make_request(
                url=self.webhook_url,
                method='POST',
                json_data=test_message
            )
            
            if response['success']:
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': 'Teams webhook connection successful'
                }
            else:
                return {
                    'success': False,
                    'platform': self.platform_name,
                    'error': 'Failed to send test message to Teams',
                    'details': response
                }
                
        except Exception as e:
            return {
                'success': False,
                'platform': self.platform_name,
                'error': str(e)
            }

    def format_content_for_platform(self, content: Dict[str, Any]) -> str:
        """Format content for Teams (used for simple text messages)"""
        teams_content = content.get('platform_variants', {}).get('teams', content.get('content', ''))
        
        # Convert markdown to Teams-compatible format
        teams_content = teams_content.replace('**', '**')  # Teams supports bold
        teams_content = teams_content.replace('# ', '**')   # Headers to bold
        teams_content = teams_content.replace('## ', '**')  # Headers to bold
        
        return teams_content
