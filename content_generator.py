"""
AI-powered content generation for VulnPublisherPro
Uses OpenAI GPT-5 for intelligent vulnerability content creation
"""

import json
import os
import logging
from typing import Dict, Any, List, Optional
from openai import OpenAI

logger = logging.getLogger(__name__)

class ContentGenerator:
    """AI-powered content generator for vulnerability reports"""
    
    def __init__(self, api_key: str):
        # the newest OpenAI model is "gpt-5" which was released August 7, 2025.
        # do not change this unless explicitly requested by the user
        self.client = OpenAI(api_key=api_key)
        self.model = "gpt-5"
    
    async def generate_content(self, vulnerability: Dict[str, Any], 
                             content_type: str = 'summary') -> Dict[str, Any]:
        """Generate content for a vulnerability based on type"""
        
        if content_type == 'summary':
            return await self._generate_summary(vulnerability)
        elif content_type == 'detailed':
            return await self._generate_detailed_report(vulnerability)
        elif content_type == 'alert':
            return await self._generate_alert(vulnerability)
        elif content_type == 'thread':
            return await self._generate_thread(vulnerability)
        else:
            raise ValueError(f"Unknown content type: {content_type}")
    
    async def _generate_summary(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a concise summary for social media"""
        
        prompt = f"""
        Create a concise, engaging social media post about this vulnerability.
        
        Vulnerability Details:
        - CVE ID: {vulnerability.get('cve_id', 'N/A')}
        - Title: {vulnerability.get('title', '')}
        - Severity: {vulnerability.get('severity', 'Unknown')}
        - CVSS Score: {vulnerability.get('cvss_score', 'N/A')}
        - Description: {vulnerability.get('description', '')}
        - Affected Products: {', '.join(vulnerability.get('affected_products', []))}
        - Exploit Available: {vulnerability.get('exploit_available', False)}
        - Source: {vulnerability.get('source', '')}
        
        Requirements:
        - Keep under 280 characters for Twitter compatibility
        - Include relevant emojis
        - Mention severity level
        - Include CVE ID if available
        - Make it engaging but professional
        - Include appropriate hashtags
        
        Response format: JSON with 'content', 'hashtags', and 'platform_variants' fields.
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert creating social media content about vulnerabilities. Always respond in JSON format."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                max_tokens=500
            )
            
            content = json.loads(response.choices[0].message.content or '{}')
            
            # Add metadata
            content['content_type'] = 'summary'
            content['character_count'] = len(content.get('content', ''))
            
            return content
            
        except Exception as e:
            logger.error(f"Error generating summary content: {e}")
            return self._create_fallback_summary(vulnerability)
    
    async def _generate_detailed_report(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a detailed vulnerability report"""
        
        prompt = f"""
        Create a comprehensive, professional vulnerability report.
        
        Vulnerability Details:
        - CVE ID: {vulnerability.get('cve_id', 'N/A')}
        - Title: {vulnerability.get('title', '')}
        - Severity: {vulnerability.get('severity', 'Unknown')}
        - CVSS Score: {vulnerability.get('cvss_score', 'N/A')}
        - CVSS Vector: {vulnerability.get('cvss_vector', 'N/A')}
        - CWE ID: {vulnerability.get('cwe_id', 'N/A')}
        - Description: {vulnerability.get('description', '')}
        - Technical Details: {vulnerability.get('technical_details', '')}
        - Impact: {vulnerability.get('impact', '')}
        - Mitigation: {vulnerability.get('mitigation', '')}
        - Affected Products: {', '.join(vulnerability.get('affected_products', []))}
        - Exploit Available: {vulnerability.get('exploit_available', False)}
        - PoC Available: {vulnerability.get('poc_available', False)}
        - Source: {vulnerability.get('source', '')}
        - Published Date: {vulnerability.get('published_date', '')}
        
        Create a structured report with:
        1. Executive Summary
        2. Technical Analysis
        3. Impact Assessment
        4. Affected Systems
        5. Recommendations
        6. Timeline
        
        Make it professional and suitable for LinkedIn, Medium, or technical blogs.
        Response format: JSON with 'title', 'content', 'executive_summary', 'recommendations', and 'tags' fields.
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a senior cybersecurity analyst writing professional vulnerability reports. Always respond in JSON format."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                max_tokens=1500
            )
            
            content = json.loads(response.choices[0].message.content or '{}')
            
            # Add metadata
            content['content_type'] = 'detailed'
            content['word_count'] = len(content.get('content', '').split())
            
            return content
            
        except Exception as e:
            logger.error(f"Error generating detailed report: {e}")
            return self._create_fallback_detailed(vulnerability)
    
    async def _generate_alert(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate an urgent security alert"""
        
        prompt = f"""
        Create an urgent security alert for this critical vulnerability.
        
        Vulnerability Details:
        - CVE ID: {vulnerability.get('cve_id', 'N/A')}
        - Title: {vulnerability.get('title', '')}
        - Severity: {vulnerability.get('severity', 'Unknown')}
        - CVSS Score: {vulnerability.get('cvss_score', 'N/A')}
        - Description: {vulnerability.get('description', '')}
        - Affected Products: {', '.join(vulnerability.get('affected_products', []))}
        - Exploit Available: {vulnerability.get('exploit_available', False)}
        - Mitigation: {vulnerability.get('mitigation', '')}
        
        Requirements:
        - Urgent, attention-grabbing tone
        - Clear call to action
        - Immediate steps to take
        - Suitable for emergency notifications (Slack, Teams, Discord)
        - Include risk level and priority
        
        Response format: JSON with 'content', 'priority', 'action_items', and 'risk_level' fields.
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity incident response expert creating urgent security alerts. Always respond in JSON format."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                max_tokens=800
            )
            
            content = json.loads(response.choices[0].message.content or '{}')
            
            # Add metadata
            content['content_type'] = 'alert'
            content['urgency'] = self._determine_urgency(vulnerability)
            
            return content
            
        except Exception as e:
            logger.error(f"Error generating alert content: {e}")
            return self._create_fallback_alert(vulnerability)
    
    async def _generate_thread(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a Twitter/X thread about the vulnerability"""
        
        prompt = f"""
        Create an engaging Twitter/X thread about this vulnerability.
        
        Vulnerability Details:
        - CVE ID: {vulnerability.get('cve_id', 'N/A')}
        - Title: {vulnerability.get('title', '')}
        - Severity: {vulnerability.get('severity', 'Unknown')}
        - CVSS Score: {vulnerability.get('cvss_score', 'N/A')}
        - Description: {vulnerability.get('description', '')}
        - Technical Details: {vulnerability.get('technical_details', '')}
        - Impact: {vulnerability.get('impact', '')}
        - Affected Products: {', '.join(vulnerability.get('affected_products', []))}
        - Exploit Available: {vulnerability.get('exploit_available', False)}
        
        Create a thread with:
        1. Hook tweet (attention-grabbing intro)
        2. 3-5 informative tweets explaining the vulnerability
        3. Impact and risk assessment
        4. Mitigation recommendations
        5. Call to action/conclusion
        
        Each tweet must be under 280 characters. Use thread numbering (1/6, 2/6, etc.).
        Include relevant emojis and hashtags.
        
        Response format: JSON with 'tweets' array, 'total_tweets', and 'hashtags' fields.
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity influencer creating engaging Twitter threads about vulnerabilities. Always respond in JSON format."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                max_tokens=1200
            )
            
            content = json.loads(response.choices[0].message.content or '{}')
            
            # Add metadata and validate tweet lengths
            content['content_type'] = 'thread'
            content = self._validate_thread_length(content)
            
            return content
            
        except Exception as e:
            logger.error(f"Error generating thread content: {e}")
            return self._create_fallback_thread(vulnerability)
    
    def _determine_urgency(self, vulnerability: Dict[str, Any]) -> str:
        """Determine urgency level based on vulnerability details"""
        severity = vulnerability.get('severity', '').lower()
        cvss_score = vulnerability.get('cvss_score', 0)
        exploit_available = vulnerability.get('exploit_available', False)
        
        try:
            cvss_score = float(cvss_score) if cvss_score else 0
        except (ValueError, TypeError):
            cvss_score = 0
        
        if severity == 'critical' or cvss_score >= 9.0:
            return 'CRITICAL'
        elif (severity == 'high' or cvss_score >= 7.0) and exploit_available:
            return 'HIGH'
        elif severity == 'high' or cvss_score >= 7.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _validate_thread_length(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and fix thread tweet lengths"""
        if 'tweets' not in content:
            return content
        
        validated_tweets = []
        for i, tweet in enumerate(content['tweets']):
            if len(tweet) > 280:
                # Truncate tweet and add ellipsis
                tweet = tweet[:277] + '...'
            validated_tweets.append(tweet)
        
        content['tweets'] = validated_tweets
        content['total_tweets'] = len(validated_tweets)
        
        return content
    
    def _create_fallback_summary(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Create fallback summary content"""
        cve_id = vulnerability.get('cve_id', 'N/A')
        severity = vulnerability.get('severity', 'Unknown').title()
        title = vulnerability.get('title', 'Security Vulnerability')
        
        content = f"🚨 {severity} Vulnerability Alert: {cve_id}\n\n{title[:100]}{'...' if len(title) > 100 else ''}"
        
        return {
            'content_type': 'summary',
            'content': content,
            'hashtags': ['#cybersecurity', '#vulnerability', f'#{severity.lower()}'],
            'character_count': len(content),
            'platform_variants': {
                'twitter': content[:280],
                'linkedin': content,
                'telegram': content
            }
        }
    
    def _create_fallback_detailed(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Create fallback detailed report"""
        cve_id = vulnerability.get('cve_id', 'N/A')
        title = vulnerability.get('title', 'Security Vulnerability')
        description = vulnerability.get('description', 'No description available.')
        severity = vulnerability.get('severity', 'Unknown').title()
        
        content = f"""# Vulnerability Report: {cve_id}

## Executive Summary
A {severity.lower()} severity vulnerability has been identified: {title}

## Description
{description}

## Affected Systems
{', '.join(vulnerability.get('affected_products', ['Unknown']))}

## Recommendations
- Monitor for patches from affected vendors
- Implement compensating controls if available
- Review system configurations
- Monitor for exploitation attempts
"""
        
        return {
            'content_type': 'detailed',
            'title': f"Vulnerability Report: {cve_id}",
            'content': content,
            'executive_summary': f"A {severity.lower()} severity vulnerability has been identified.",
            'recommendations': [
                "Monitor for vendor patches",
                "Implement compensating controls",
                "Review system configurations"
            ],
            'tags': ['cybersecurity', 'vulnerability', 'security'],
            'word_count': len(content.split())
        }
    
    def _create_fallback_alert(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Create fallback alert content"""
        cve_id = vulnerability.get('cve_id', 'N/A')
        severity = vulnerability.get('severity', 'Unknown').title()
        
        content = f"""🚨 SECURITY ALERT 🚨

{severity} vulnerability detected: {cve_id}

IMMEDIATE ACTION REQUIRED:
✅ Check affected systems
✅ Apply patches if available
✅ Monitor for suspicious activity
✅ Report to security team

Risk Level: {severity.upper()}
"""
        
        return {
            'content_type': 'alert',
            'content': content,
            'priority': severity.upper(),
            'action_items': [
                "Check affected systems",
                "Apply patches if available", 
                "Monitor for suspicious activity",
                "Report to security team"
            ],
            'risk_level': severity.upper(),
            'urgency': self._determine_urgency(vulnerability)
        }
    
    def _create_fallback_thread(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Create fallback thread content"""
        cve_id = vulnerability.get('cve_id', 'N/A')
        severity = vulnerability.get('severity', 'Unknown').title()
        title = vulnerability.get('title', 'Security Vulnerability')
        
        tweets = [
            f"🧵 THREAD: {severity} Vulnerability Alert - {cve_id} 1/4",
            f"2/4 📝 Details: {title[:200]}{'...' if len(title) > 200 else ''}",
            f"3/4 ⚠️ Severity: {severity} | Affected: {', '.join(vulnerability.get('affected_products', ['Various systems'])[:2])}",
            "4/4 🛡️ Stay vigilant, apply patches when available, and monitor your systems. #CyberSecurity #InfoSec"
        ]
        
        return {
            'content_type': 'thread',
            'tweets': tweets,
            'total_tweets': len(tweets),
            'hashtags': ['#CyberSecurity', '#InfoSec', '#Vulnerability'],
            'fallback': True
        }
    
    async def customize_for_platform(self, content: Dict[str, Any], 
                                   platform: str) -> Dict[str, Any]:
        """Customize content for specific platform requirements"""
        
        platform_configs = {
            'twitter': {'max_length': 280, 'hashtags': True, 'emojis': True},
            'linkedin': {'max_length': 3000, 'hashtags': True, 'professional': True},
            'telegram': {'max_length': 4096, 'markdown': True, 'emojis': True},
            'discord': {'max_length': 2000, 'markdown': True, 'mentions': True},
            'reddit': {'max_length': 40000, 'markdown': True, 'detailed': True},
            'medium': {'max_length': None, 'html': True, 'detailed': True},
            'slack': {'max_length': 4000, 'mentions': True, 'channels': True}
        }
        
        config = platform_configs.get(platform, {})
        customized_content = content.copy()
        
        # Adjust content length if needed
        if 'max_length' in config and config['max_length']:
            content_text = content.get('content', '')
            if len(content_text) > config['max_length']:
                customized_content['content'] = content_text[:config['max_length']-3] + '...'
        
        # Add platform-specific formatting
        customized_content['platform'] = platform
        customized_content['platform_config'] = config
        
        return customized_content

    async def generate_multiple_variants(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Generate multiple content variants for different platforms"""
        
        variants = {}
        
        # Generate different content types
        content_types = ['summary', 'detailed', 'alert']
        
        for content_type in content_types:
            try:
                variants[content_type] = await self.generate_content(vulnerability, content_type)
            except Exception as e:
                logger.error(f"Error generating {content_type} content: {e}")
                continue
        
        return variants
