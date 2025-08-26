"""
Medium publisher for VulnPublisherPro
API Documentation: https://github.com/Medium/medium-api-docs
"""

import logging
from typing import Dict, Any
from .base import BasePublisher

logger = logging.getLogger(__name__)

class MediumPublisher(BasePublisher):
    """Publisher for Medium platform"""
    
    def __init__(self, config):
        super().__init__(config, 'medium')
        
        # Medium API credentials
        self.access_token = self.platform_config.get('token')
        
        # Medium API base URL
        self.base_url = "https://api.medium.com/v1"
        
        # User ID (will be obtained)
        self.user_id = None
    
    def validate_config(self) -> bool:
        """Validate Medium configuration"""
        if not self.access_token:
            logger.error("Medium access token not configured")
            return False
        
        return True
    
    async def _get_user_id(self) -> str:
        """Get Medium user ID"""
        if self.user_id:
            return self.user_id
        
        try:
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Accept': 'application/json'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/me",
                method='GET',
                headers=headers
            )
            
            if response['success'] and 'data' in response['data']:
                user_data = response['data']['data']
                self.user_id = user_data['id']
                return self.user_id
            else:
                logger.error(f"Failed to get Medium user ID: {response}")
                return None
                
        except Exception as e:
            logger.error(f"Error getting Medium user ID: {e}")
            return None
    
    async def publish(self, content: Dict[str, Any], 
                     vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Publish content to Medium"""
        if not self.validate_config():
            return self.create_error_response("Medium configuration invalid")
        
        try:
            # Get user ID
            user_id = await self._get_user_id()
            if not user_id:
                return self.create_error_response("Failed to get Medium user ID")
            
            # Format content for Medium
            title, content_html = self._format_for_medium(content, vulnerability)
            
            # Create post data
            post_data = {
                'title': title,
                'contentFormat': 'html',
                'content': content_html,
                'publishStatus': 'public',
                'tags': self._get_medium_tags(vulnerability, content)
            }
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/users/{user_id}/posts",
                method='POST',
                headers=headers,
                json_data=post_data
            )
            
            if response['success'] and 'data' in response['data']:
                post_info = response['data']['data']
                post_id = post_info.get('id')
                post_url = post_info.get('url')
                
                logger.info(f"Successfully published to Medium: {post_id}")
                
                return self.create_success_response(
                    post_data=post_data,
                    post_id=post_id,
                    post_url=post_url
                )
            else:
                return self.create_error_response("Failed to publish to Medium", response)
                
        except Exception as e:
            logger.error(f"Error publishing to Medium: {e}")
            return self.create_error_response(str(e))
    
    def _format_for_medium(self, content: Dict[str, Any], 
                          vulnerability: Dict[str, Any]) -> tuple:
        """Format content for Medium article"""
        # Create title
        cve_id = vulnerability.get('cve_id', '')
        severity = vulnerability.get('severity', '').title()
        vuln_title = vulnerability.get('title', 'Security Vulnerability')
        
        if cve_id:
            title = f"Security Alert: {cve_id} - {severity} Vulnerability"
        else:
            title = f"Security Alert: {vuln_title} [{severity}]"
        
        # Create HTML content
        html_content = ""
        
        # Add header image placeholder
        html_content += '<p><em>🔒 Security Vulnerability Alert</em></p>'
        
        # Add executive summary
        if content.get('executive_summary'):
            html_content += f"<h2>Executive Summary</h2>"
            html_content += f"<p>{content['executive_summary']}</p>"
        
        # Add main content
        main_content = content.get('content', '')
        if main_content:
            # Convert markdown-like formatting to HTML
            html_content += self._markdown_to_html(main_content)
        
        # Add vulnerability details section
        html_content += self._create_vulnerability_details_html(vulnerability)
        
        # Add recommendations
        recommendations = content.get('recommendations', [])
        if recommendations:
            html_content += "<h2>Recommendations</h2><ul>"
            for rec in recommendations:
                html_content += f"<li>{rec}</li>"
            html_content += "</ul>"
        
        # Add footer
        html_content += self._create_footer_html(vulnerability)
        
        return title, html_content
    
    def _markdown_to_html(self, text: str) -> str:
        """Convert basic markdown to HTML"""
        # Convert headers
        text = text.replace('# ', '<h1>').replace('\n# ', '</h1>\n<h1>') + '</h1>' if '# ' in text else text
        text = text.replace('## ', '<h2>').replace('\n## ', '</h2>\n<h2>') + '</h2>' if '## ' in text else text
        text = text.replace('### ', '<h3>').replace('\n### ', '</h3>\n<h3>') + '</h3>' if '### ' in text else text
        
        # Convert bold and italic
        text = text.replace('**', '<strong>').replace('**', '</strong>')
        text = text.replace('*', '<em>').replace('*', '</em>')
        
        # Convert paragraphs
        paragraphs = text.split('\n\n')
        html_paragraphs = []
        for para in paragraphs:
            if para.strip():
                if not para.startswith('<'):
                    html_paragraphs.append(f'<p>{para.strip()}</p>')
                else:
                    html_paragraphs.append(para.strip())
        
        return '\n'.join(html_paragraphs)
    
    def _create_vulnerability_details_html(self, vulnerability: Dict[str, Any]) -> str:
        """Create HTML for vulnerability details"""
        html = "<h2>Vulnerability Details</h2>"
        
        # Create details table
        html += '<table border="1" style="border-collapse: collapse; width: 100%;">'
        
        details = [
            ('CVE ID', vulnerability.get('cve_id')),
            ('Severity', vulnerability.get('severity', '').title()),
            ('CVSS Score', vulnerability.get('cvss_score')),
            ('CWE ID', vulnerability.get('cwe_id')),
            ('Source', vulnerability.get('source', '').title()),
            ('Published Date', vulnerability.get('published_date', '').split('T')[0] if vulnerability.get('published_date') else None)
        ]
        
        for label, value in details:
            if value:
                html += f'<tr><td><strong>{label}</strong></td><td>{value}</td></tr>'
        
        html += '</table>'
        
        # Add affected products
        affected_products = vulnerability.get('affected_products', [])
        if affected_products:
            html += "<h3>Affected Products</h3><ul>"
            for product in affected_products:
                html += f"<li>{product}</li>"
            html += "</ul>"
        
        # Add status indicators
        status_items = []
        if vulnerability.get('exploit_available'):
            status_items.append("⚠️ Exploit Available")
        if vulnerability.get('poc_available'):
            status_items.append("🔬 Proof of Concept Available")
        
        if status_items:
            html += "<h3>Status</h3><ul>"
            for item in status_items:
                html += f"<li>{item}</li>"
            html += "</ul>"
        
        return html
    
    def _create_footer_html(self, vulnerability: Dict[str, Any]) -> str:
        """Create HTML footer"""
        html = "<hr>"
        
        # Add references
        references = vulnerability.get('references', [])
        if references:
            html += "<h3>References</h3><ul>"
            for ref in references[:5]:  # Limit to 5 references
                html += f'<li><a href="{ref}" target="_blank">{ref}</a></li>'
            html += "</ul>"
        
        # Add source attribution
        source_url = vulnerability.get('source_url')
        if source_url:
            html += f'<p><strong>Original Source:</strong> <a href="{source_url}" target="_blank">{source_url}</a></p>'
        
        # Add disclaimer
        html += "<p><em>This article was generated by VulnPublisherPro. "
        html += "Please verify all information independently and consult official sources.</em></p>"
        
        return html
    
    def _get_medium_tags(self, vulnerability: Dict[str, Any], 
                        content: Dict[str, Any]) -> list:
        """Get appropriate tags for Medium"""
        tags = ['cybersecurity', 'security', 'vulnerability']
        
        # Add severity-based tags
        severity = vulnerability.get('severity', '').lower()
        if severity in ['critical', 'high']:
            tags.append('security-alert')
        
        # Add technology-based tags
        affected_products = vulnerability.get('affected_products', [])
        for product in affected_products[:2]:  # Limit to 2 product tags
            product_lower = product.lower()
            if 'windows' in product_lower:
                tags.append('windows')
            elif 'linux' in product_lower:
                tags.append('linux')
            elif 'web' in product_lower:
                tags.append('web-security')
            elif 'android' in product_lower:
                tags.append('android')
            elif 'ios' in product_lower:
                tags.append('ios')
        
        # Add content-based tags
        vuln_tags = vulnerability.get('tags', [])
        for tag in vuln_tags:
            if tag in ['malware', 'ransomware', 'phishing']:
                tags.append(tag)
        
        # Medium allows up to 5 tags
        return tags[:5]
    
    async def test_connection(self) -> Dict[str, Any]:
        """Test Medium API connection"""
        if not self.validate_config():
            return {
                'success': False,
                'platform': self.platform_name,
                'error': 'Medium configuration invalid'
            }
        
        try:
            user_id = await self._get_user_id()
            if not user_id:
                return {
                    'success': False,
                    'platform': self.platform_name,
                    'error': 'Failed to get user ID'
                }
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Accept': 'application/json'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/me",
                method='GET',
                headers=headers
            )
            
            if response['success'] and 'data' in response['data']:
                user_data = response['data']['data']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'message': f'Connected as @{user_data.get("username")}',
                    'user_data': {
                        'id': user_data.get('id'),
                        'username': user_data.get('username'),
                        'name': user_data.get('name'),
                        'url': user_data.get('url'),
                        'image_url': user_data.get('imageUrl')
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
    
    async def get_publications(self) -> Dict[str, Any]:
        """Get user's publications on Medium"""
        if not self.validate_config():
            return self.create_error_response("Medium configuration invalid")
        
        try:
            user_id = await self._get_user_id()
            if not user_id:
                return self.create_error_response("Failed to get user ID")
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Accept': 'application/json'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/users/{user_id}/publications",
                method='GET',
                headers=headers
            )
            
            if response['success'] and 'data' in response['data']:
                publications = response['data']['data']
                return {
                    'success': True,
                    'platform': self.platform_name,
                    'publications': [{
                        'id': pub.get('id'),
                        'name': pub.get('name'),
                        'description': pub.get('description'),
                        'url': pub.get('url'),
                        'image_url': pub.get('imageUrl')
                    } for pub in publications]
                }
            else:
                return self.create_error_response("Failed to get publications", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
    
    async def publish_to_publication(self, content: Dict[str, Any], 
                                   vulnerability: Dict[str, Any], 
                                   publication_id: str) -> Dict[str, Any]:
        """Publish to a specific Medium publication"""
        if not self.validate_config():
            return self.create_error_response("Medium configuration invalid")
        
        try:
            # Format content for Medium
            title, content_html = self._format_for_medium(content, vulnerability)
            
            # Create post data
            post_data = {
                'title': title,
                'contentFormat': 'html',
                'content': content_html,
                'publishStatus': 'public',
                'tags': self._get_medium_tags(vulnerability, content)
            }
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/publications/{publication_id}/posts",
                method='POST',
                headers=headers,
                json_data=post_data
            )
            
            if response['success'] and 'data' in response['data']:
                post_info = response['data']['data']
                return self.create_success_response(
                    post_data=post_data,
                    post_id=post_info.get('id'),
                    post_url=post_info.get('url')
                )
            else:
                return self.create_error_response("Failed to publish to publication", response)
                
        except Exception as e:
            return self.create_error_response(str(e))
