"""
AI-Powered Content Generator with Platform Algorithm Optimization
Uses OpenAI GPT-5 to create high-quality vulnerability content optimized for different platforms
"""

import json
import os
import logging
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from openai import OpenAI

# the newest OpenAI model is "gpt-5" which was released August 7, 2025.
# do not change this unless explicitly requested by the user

logger = logging.getLogger(__name__)

@dataclass
class PlatformAlgorithmSpecs:
    """Platform-specific algorithm optimization specs"""
    platform: str
    character_limit: Optional[int]
    optimal_hashtag_count: int
    engagement_keywords: List[str]
    content_structure: str
    posting_frequency: str
    best_times: List[str]
    image_requirements: Optional[Dict[str, Any]]

class AIContentGenerator:
    """AI-powered content generator optimized for platform algorithms"""
    
    def __init__(self):
        self.client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        self.platform_specs = self._initialize_platform_specs()
        
    def _initialize_platform_specs(self) -> Dict[str, PlatformAlgorithmSpecs]:
        """Initialize platform-specific algorithm optimization specs"""
        return {
            'twitter': PlatformAlgorithmSpecs(
                platform='twitter',
                character_limit=280,
                optimal_hashtag_count=3,
                engagement_keywords=['BREAKING', 'ALERT', 'CRITICAL', 'NEW', 'URGENT'],
                content_structure='hook_problem_solution_cta',
                posting_frequency='4-8_times_daily',
                best_times=['9am', '1pm', '3pm', '6pm'],
                image_requirements={'aspect_ratio': '16:9', 'max_size': '5MB'}
            ),
            'linkedin': PlatformAlgorithmSpecs(
                platform='linkedin',
                character_limit=3000,
                optimal_hashtag_count=5,
                engagement_keywords=['Professional', 'Security', 'Enterprise', 'Industry', 'Insights'],
                content_structure='professional_insight_analysis_recommendation',
                posting_frequency='1-2_times_daily',
                best_times=['8am', '12pm', '5pm'],
                image_requirements={'aspect_ratio': '1200x627', 'max_size': '10MB'}
            ),
            'medium': PlatformAlgorithmSpecs(
                platform='medium',
                character_limit=None,
                optimal_hashtag_count=5,
                engagement_keywords=['Deep Dive', 'Technical Analysis', 'Case Study', 'Expert Guide'],
                content_structure='title_subtitle_intro_body_conclusion',
                posting_frequency='2-3_times_weekly',
                best_times=['7am', '7pm'],
                image_requirements={'aspect_ratio': '1400x800', 'max_size': '20MB'}
            ),
            'telegram': PlatformAlgorithmSpecs(
                platform='telegram',
                character_limit=4096,
                optimal_hashtag_count=10,
                engagement_keywords=['🚨', '⚡', '🔥', '💥', 'BREAKING'],
                content_structure='urgent_alert_details_action',
                posting_frequency='multiple_daily',
                best_times=['anytime'],
                image_requirements=None
            ),
            'discord': PlatformAlgorithmSpecs(
                platform='discord',
                character_limit=2000,
                optimal_hashtag_count=0,
                engagement_keywords=['@everyone', '@here', '🚨', 'ALERT'],
                content_structure='mention_alert_technical_discussion',
                posting_frequency='real_time',
                best_times=['anytime'],
                image_requirements=None
            )
        }
    
    async def generate_vulnerability_content(
        self, 
        vulnerability: Dict[str, Any], 
        platform: str, 
        content_type: str = 'summary'
    ) -> Dict[str, Any]:
        """Generate AI-optimized vulnerability content for specific platform"""
        
        platform_spec = self.platform_specs.get(platform.lower())
        if not platform_spec:
            raise ValueError(f"Unsupported platform: {platform}")
        
        try:
            if content_type == 'summary':
                return await self._generate_summary_content(vulnerability, platform_spec)
            elif content_type == 'detailed':
                return await self._generate_detailed_content(vulnerability, platform_spec)
            elif content_type == 'threat_intel':
                return await self._generate_threat_intel_content(vulnerability, platform_spec)
            elif content_type == 'technical_analysis':
                return await self._generate_technical_analysis(vulnerability, platform_spec)
            else:
                raise ValueError(f"Unsupported content type: {content_type}")
                
        except Exception as e:
            logger.error(f"Error generating {content_type} content for {platform}: {e}")
            return self._generate_fallback_content(vulnerability, platform)
    
    async def _generate_summary_content(
        self, 
        vulnerability: Dict[str, Any], 
        spec: PlatformAlgorithmSpecs
    ) -> Dict[str, Any]:
        """Generate algorithm-optimized summary content"""
        
        prompt = f"""
        Create a high-engagement vulnerability alert for {spec.platform} that maximizes algorithmic reach.

        VULNERABILITY DATA:
        - Title: {vulnerability.get('title', 'Unknown')}
        - Severity: {vulnerability.get('severity', 'unknown')}
        - CVE ID: {vulnerability.get('cve_id', 'Pending')}
        - CVSS Score: {vulnerability.get('cvss_score', 'N/A')}
        - Description: {vulnerability.get('description', '')[:500]}
        - Affected Products: {vulnerability.get('affected_products', [])}
        - Published: {vulnerability.get('published_date', 'Recent')}

        PLATFORM OPTIMIZATION REQUIREMENTS:
        - Character limit: {spec.character_limit or 'unlimited'}
        - Optimal hashtag count: {spec.optimal_hashtag_count}
        - Engagement keywords to include: {', '.join(spec.engagement_keywords[:3])}
        - Content structure: {spec.content_structure}
        - Target audience: Cybersecurity professionals and enterprises

        ALGORITHM OPTIMIZATION GOALS:
        - Maximize engagement (likes, shares, comments)
        - Include trending cybersecurity hashtags
        - Use compelling hook in first sentence
        - Create urgency without being alarmist
        - Include clear call-to-action
        - Optimize for {spec.platform} algorithm preferences

        Return JSON with: title, content, hashtags, engagement_score_prediction (1-10), algorithm_factors_used
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-5",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity content strategist specializing in social media algorithm optimization. Create compelling, accurate vulnerability alerts that maximize platform engagement."
                    },
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.7
            )
            
            result = json.loads(response.choices[0].message.content)
            
            # Add metadata
            result.update({
                'platform': spec.platform,
                'content_type': 'summary',
                'generated_at': datetime.now().isoformat(),
                'character_count': len(result.get('content', '')),
                'optimization_level': 'high'
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Error in GPT-5 summary generation: {e}")
            return self._generate_fallback_content(vulnerability, spec.platform)
    
    async def _generate_detailed_content(
        self, 
        vulnerability: Dict[str, Any], 
        spec: PlatformAlgorithmSpecs
    ) -> Dict[str, Any]:
        """Generate detailed technical analysis content"""
        
        prompt = f"""
        Create a comprehensive technical vulnerability analysis for {spec.platform} that demonstrates expertise and builds authority.

        VULNERABILITY DATA:
        - Title: {vulnerability.get('title', 'Unknown')}
        - Severity: {vulnerability.get('severity', 'unknown')}
        - CVE ID: {vulnerability.get('cve_id', 'Pending')}
        - CVSS Score: {vulnerability.get('cvss_score', 'N/A')}
        - Description: {vulnerability.get('description', '')}
        - Affected Products: {vulnerability.get('affected_products', [])}
        - References: {vulnerability.get('references', [])}
        - Tags: {vulnerability.get('tags', [])}

        CONTENT REQUIREMENTS:
        - Platform: {spec.platform}
        - Target length: {"Long-form" if not spec.character_limit else f"{spec.character_limit} characters"}
        - Structure: {spec.content_structure}
        - Professional tone with technical depth
        - Include actionable remediation steps
        - Add business impact assessment
        - Provide timeline and attack vectors

        SECTIONS TO INCLUDE:
        1. Executive Summary
        2. Technical Details
        3. Impact Assessment
        4. Attack Scenarios
        5. Remediation Steps
        6. Detection Methods
        7. References and IOCs

        Return JSON with: title, content, sections, hashtags, technical_depth_score (1-10), business_impact_score (1-10)
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-5",
                messages=[
                    {
                        "role": "system", 
                        "content": "You are a senior cybersecurity analyst creating detailed vulnerability assessments for enterprise security teams."
                    },
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.3
            )
            
            result = json.loads(response.choices[0].message.content)
            
            # Add metadata
            result.update({
                'platform': spec.platform,
                'content_type': 'detailed',
                'generated_at': datetime.now().isoformat(),
                'word_count': len(result.get('content', '').split()),
                'optimization_level': 'expert'
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Error in GPT-5 detailed generation: {e}")
            return self._generate_fallback_content(vulnerability, spec.platform)
    
    async def _generate_threat_intel_content(
        self, 
        vulnerability: Dict[str, Any], 
        spec: PlatformAlgorithmSpecs
    ) -> Dict[str, Any]:
        """Generate threat intelligence content"""
        
        prompt = f"""
        Create threat intelligence content about this vulnerability for cybersecurity teams on {spec.platform}.

        VULNERABILITY DATA:
        - Title: {vulnerability.get('title', 'Unknown')}
        - Severity: {vulnerability.get('severity', 'unknown')}
        - CVE ID: {vulnerability.get('cve_id', 'Pending')}
        - Description: {vulnerability.get('description', '')}
        - Affected Products: {vulnerability.get('affected_products', [])}
        - Tags: {vulnerability.get('tags', [])}

        THREAT INTELLIGENCE FOCUS:
        - Active exploitation status
        - Attribution and threat actors
        - IOCs (Indicators of Compromise)
        - Attack patterns and TTPs
        - Exploit availability and complexity
        - Geographic targeting trends
        - Industry sector impact
        - Mitigation priorities

        CONTENT STYLE:
        - Urgent but professional
        - Intelligence-driven insights
        - Actionable recommendations
        - Risk-based prioritization
        - Clear threat level assessment

        Return JSON with: title, content, threat_level, iocs, ttps, recommendations, hashtags
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-5",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a threat intelligence analyst providing actionable cybersecurity intelligence to security operations teams."
                    },
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.4
            )
            
            result = json.loads(response.choices[0].message.content)
            
            # Add metadata
            result.update({
                'platform': spec.platform,
                'content_type': 'threat_intel',
                'generated_at': datetime.now().isoformat(),
                'intelligence_quality': 'high',
                'actionable_items': len(result.get('recommendations', []))
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Error in GPT-5 threat intel generation: {e}")
            return self._generate_fallback_content(vulnerability, spec.platform)
    
    async def _generate_technical_analysis(
        self, 
        vulnerability: Dict[str, Any], 
        spec: PlatformAlgorithmSpecs
    ) -> Dict[str, Any]:
        """Generate deep technical analysis content"""
        
        prompt = f"""
        Create an in-depth technical analysis of this vulnerability for security researchers and developers on {spec.platform}.

        VULNERABILITY DATA:
        - Title: {vulnerability.get('title', 'Unknown')}
        - Severity: {vulnerability.get('severity', 'unknown')}
        - CVE ID: {vulnerability.get('cve_id', 'Pending')}
        - CVSS Score: {vulnerability.get('cvss_score', 'N/A')}
        - Description: {vulnerability.get('description', '')}
        - Affected Products: {vulnerability.get('affected_products', [])}
        - References: {vulnerability.get('references', [])}

        TECHNICAL ANALYSIS REQUIREMENTS:
        - Root cause analysis
        - Code-level vulnerability details
        - Attack vector breakdown
        - Exploit development complexity
        - Defensive coding practices
        - Security architecture implications
        - Testing and validation methods
        - Patch analysis (if available)

        AUDIENCE: Security engineers, developers, researchers
        DEPTH: Expert level with code examples where relevant
        STYLE: Technical but accessible

        Return JSON with: title, content, technical_sections, code_examples, complexity_score (1-10), research_value (1-10), hashtags
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-5",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a security researcher creating detailed technical vulnerability analysis for the security community."
                    },
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.2
            )
            
            result = json.loads(response.choices[0].message.content)
            
            # Add metadata
            result.update({
                'platform': spec.platform,
                'content_type': 'technical_analysis',
                'generated_at': datetime.now().isoformat(),
                'technical_depth': 'expert',
                'target_audience': 'security_researchers'
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Error in GPT-5 technical analysis generation: {e}")
            return self._generate_fallback_content(vulnerability, spec.platform)
    
    def _generate_fallback_content(self, vulnerability: Dict[str, Any], platform: str) -> Dict[str, Any]:
        """Generate basic fallback content when AI generation fails"""
        
        title = vulnerability.get('title', 'Security Vulnerability Alert')
        severity = vulnerability.get('severity', 'unknown').upper()
        
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }.get(severity, '⚪')
        
        content = f"""{severity_emoji} {severity} Vulnerability Alert

Title: {title}
CVE: {vulnerability.get('cve_id', 'Pending')}
CVSS: {vulnerability.get('cvss_score', 'N/A')}

{vulnerability.get('description', 'Vulnerability details are being analyzed.')[:200]}...

Stay updated on the latest security threats.

#CyberSecurity #Vulnerability #InfoSec #{severity}"""
        
        return {
            'title': f"{severity_emoji} {title[:50]}...",
            'content': content,
            'platform': platform,
            'content_type': 'fallback',
            'hashtags': ['CyberSecurity', 'Vulnerability', 'InfoSec', severity],
            'generated_at': datetime.now().isoformat(),
            'fallback_reason': 'AI_generation_failed'
        }
    
    async def optimize_content_for_engagement(
        self, 
        content: Dict[str, Any], 
        platform: str
    ) -> Dict[str, Any]:
        """Further optimize content for maximum engagement"""
        
        platform_spec = self.platform_specs.get(platform.lower())
        if not platform_spec:
            return content
        
        prompt = f"""
        Optimize this cybersecurity content for maximum engagement on {platform}.

        CURRENT CONTENT:
        {json.dumps(content, indent=2)}

        PLATFORM SPECS:
        - Character limit: {platform_spec.character_limit or 'unlimited'}
        - Best posting times: {', '.join(platform_spec.best_times)}
        - Optimal hashtags: {platform_spec.optimal_hashtag_count}
        - Engagement keywords: {', '.join(platform_spec.engagement_keywords)}

        OPTIMIZATION GOALS:
        1. Increase click-through rates
        2. Boost shares and comments
        3. Improve algorithm visibility
        4. Maintain professional credibility
        5. Drive meaningful engagement

        Return optimized JSON with: title, content, hashtags, posting_strategy, engagement_predictions
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-5",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a social media optimization expert specializing in cybersecurity content that balances engagement with professional authority."
                    },
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.6
            )
            
            optimized = json.loads(response.choices[0].message.content)
            
            # Merge with original content
            optimized.update({
                'original_content': content,
                'optimization_applied': True,
                'optimization_timestamp': datetime.now().isoformat()
            })
            
            return optimized
            
        except Exception as e:
            logger.error(f"Error in content optimization: {e}")
            return content
    
    def get_platform_best_practices(self, platform: str) -> Dict[str, Any]:
        """Get platform-specific best practices and current algorithm insights"""
        
        platform_spec = self.platform_specs.get(platform.lower())
        if not platform_spec:
            return {}
        
        return {
            'character_limit': platform_spec.character_limit,
            'optimal_hashtag_count': platform_spec.optimal_hashtag_count,
            'best_posting_times': platform_spec.best_times,
            'engagement_keywords': platform_spec.engagement_keywords,
            'content_structure': platform_spec.content_structure,
            'posting_frequency': platform_spec.posting_frequency,
            'image_requirements': platform_spec.image_requirements,
            'algorithm_tips': {
                'twitter': 'Use threads for complex topics, engage quickly with replies, include relevant mentions',
                'linkedin': 'Professional tone, industry insights, tag relevant companies/people',
                'medium': 'Long-form with proper formatting, compelling headlines, relevant publications',
                'telegram': 'Quick alerts, use formatting, pin important messages',
                'discord': 'Community-focused, real-time discussion, use channels effectively'
            }.get(platform.lower(), 'Focus on quality content and consistent engagement')
        }