"""
Enhanced Publication System with Algorithm Optimization and User Review
Integrates AI content generation, user review, and platform-specific optimization
"""

import asyncio
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from ai_content_generator import AIContentGenerator
from user_review_system import UserReviewSystem
from publication_formats import UniversalPublicationManager
from scrapers.disclosure_formats import VulnerabilityDisclosure

logger = logging.getLogger(__name__)

class EnhancedPublicationSystem:
    """Complete publication system with AI generation, user review, and optimization"""
    
    def __init__(self):
        self.ai_generator = AIContentGenerator()
        self.review_system = UserReviewSystem()
        self.publication_manager = UniversalPublicationManager()
        
        # Platform-specific algorithm optimization profiles
        self.algorithm_profiles = self._initialize_algorithm_profiles()
        
    def _initialize_algorithm_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Initialize current algorithm optimization profiles for each platform"""
        
        return {
            'twitter': {
                'optimal_length': 250,  # Leave room for engagement
                'hashtag_sweet_spot': 2,  # 1-2 hashtags perform best
                'engagement_triggers': ['BREAKING:', 'THREAD:', '🚨', '⚡'],
                'best_times': ['9:00', '15:00', '21:00'],
                'thread_threshold': 280,
                'retweet_factors': ['question', 'shocking_stat', 'actionable_tip'],
                'algorithm_weights': {
                    'recency': 0.3,
                    'engagement_rate': 0.4,
                    'relevance': 0.2,
                    'user_relationship': 0.1
                }
            },
            'linkedin': {
                'optimal_length': 1300,  # Sweet spot for LinkedIn algorithm
                'hashtag_sweet_spot': 3,
                'engagement_triggers': ['Key insight:', 'Industry update:', 'Breaking:'],
                'best_times': ['8:00', '12:00', '17:00'],
                'professional_keywords': ['enterprise', 'security', 'compliance', 'risk'],
                'algorithm_weights': {
                    'professional_relevance': 0.4,
                    'industry_authority': 0.3,
                    'engagement_quality': 0.2,
                    'network_reach': 0.1
                }
            },
            'medium': {
                'optimal_length': 2500,  # Medium's algorithm favors longer reads
                'read_time_target': '7-10 minutes',
                'engagement_triggers': ['Deep dive:', 'Analysis:', 'Complete guide:'],
                'headline_optimization': ['numbers', 'how_to', 'ultimate_guide'],
                'algorithm_weights': {
                    'read_time': 0.35,
                    'completion_rate': 0.25,
                    'claps_per_view': 0.20,
                    'external_traffic': 0.20
                }
            },
            'telegram': {
                'optimal_length': 1000,
                'hashtag_sweet_spot': 5,
                'engagement_triggers': ['🚨 ALERT:', '⚡ BREAKING:', '🔥 HOT:'],
                'best_times': ['anytime'],  # Telegram is global
                'forward_factors': ['urgency', 'actionable', 'exclusive'],
                'algorithm_weights': {
                    'forward_rate': 0.4,
                    'channel_activity': 0.3,
                    'view_duration': 0.2,
                    'comment_rate': 0.1
                }
            },
            'discord': {
                'optimal_length': 500,
                'engagement_triggers': ['@everyone', '@here', '🚨'],
                'community_factors': ['discussion_starter', 'helpful', 'timely'],
                'algorithm_weights': {
                    'message_reactions': 0.4,
                    'thread_creation': 0.3,
                    'user_mentions': 0.2,
                    'pin_rate': 0.1
                }
            }
        }
    
    async def create_optimized_publication(
        self, 
        vulnerability: Dict[str, Any], 
        platforms: List[str],
        content_types: List[str] = ['summary'],
        enable_user_review: bool = True,
        auto_optimize: bool = True
    ) -> Dict[str, Any]:
        """Create optimized publications for multiple platforms with user review"""
        
        logger.info(f"Creating optimized publications for platforms: {platforms}")
        
        publication_results = {
            'vulnerability_id': vulnerability.get('vulnerability_id'),
            'created_at': datetime.now().isoformat(),
            'platforms': platforms,
            'content_types': content_types,
            'publications': {},
            'user_reviewed': enable_user_review,
            'auto_optimized': auto_optimize,
            'quality_scores': {}
        }
        
        for platform in platforms:
            logger.info(f"Processing platform: {platform}")
            platform_results = {}
            
            for content_type in content_types:
                try:
                    # Step 1: Generate AI-powered content
                    logger.info(f"Generating {content_type} content for {platform}")
                    
                    ai_content = await self.ai_generator.generate_vulnerability_content(
                        vulnerability, platform, content_type
                    )
                    
                    if not ai_content:
                        logger.warning(f"No AI content generated for {platform}/{content_type}")
                        continue
                    
                    # Step 2: Apply algorithm optimization
                    if auto_optimize:
                        logger.info(f"Applying algorithm optimization for {platform}")
                        ai_content = await self._apply_algorithm_optimization(ai_content, platform)
                    
                    # Step 3: User review (if enabled)
                    final_content = ai_content
                    if enable_user_review:
                        logger.info(f"Initiating user review for {platform}/{content_type}")
                        reviewed_content = self.review_system.review_generated_content(
                            ai_content, vulnerability
                        )
                        
                        if reviewed_content:
                            if reviewed_content.get('action') == 'regenerate':
                                # Regenerate content with different parameters
                                final_content = await self._regenerate_content(
                                    vulnerability, platform, content_type, reviewed_content
                                )
                            else:
                                final_content = reviewed_content
                        else:
                            logger.warning(f"Content rejected for {platform}/{content_type}")
                            continue
                    
                    # Step 4: Final quality assessment
                    quality_score = await self._assess_publication_quality(final_content, platform)
                    
                    platform_results[content_type] = {
                        'content': final_content,
                        'quality_score': quality_score,
                        'ready_for_publishing': quality_score >= 70,
                        'optimization_applied': auto_optimize,
                        'user_reviewed': enable_user_review
                    }
                    
                    publication_results['quality_scores'][f"{platform}_{content_type}"] = quality_score
                    
                    logger.info(f"✅ {platform}/{content_type} completed with quality score: {quality_score}")
                    
                except Exception as e:
                    logger.error(f"Error creating publication for {platform}/{content_type}: {e}")
                    platform_results[content_type] = {
                        'error': str(e),
                        'ready_for_publishing': False
                    }
            
            publication_results['publications'][platform] = platform_results
        
        # Generate publication summary
        publication_results['summary'] = self._generate_publication_summary(publication_results)
        
        return publication_results
    
    async def _apply_algorithm_optimization(self, content: Dict[str, Any], platform: str) -> Dict[str, Any]:
        """Apply platform-specific algorithm optimization"""
        
        profile = self.algorithm_profiles.get(platform)
        if not profile:
            return content
        
        optimized_content = content.copy()
        
        try:
            # Length optimization
            if 'optimal_length' in profile:
                optimized_content = await self._optimize_content_length(
                    optimized_content, profile['optimal_length']
                )
            
            # Hashtag optimization
            if 'hashtag_sweet_spot' in profile:
                optimized_content = self._optimize_hashtags(
                    optimized_content, profile['hashtag_sweet_spot']
                )
            
            # Engagement trigger optimization
            if 'engagement_triggers' in profile:
                optimized_content = self._add_engagement_triggers(
                    optimized_content, profile['engagement_triggers']
                )
            
            # Platform-specific optimizations
            if platform == 'twitter':
                optimized_content = await self._optimize_for_twitter(optimized_content, profile)
            elif platform == 'linkedin':
                optimized_content = await self._optimize_for_linkedin(optimized_content, profile)
            elif platform == 'medium':
                optimized_content = await self._optimize_for_medium(optimized_content, profile)
            elif platform == 'telegram':
                optimized_content = self._optimize_for_telegram(optimized_content, profile)
            elif platform == 'discord':
                optimized_content = self._optimize_for_discord(optimized_content, profile)
            
            optimized_content['algorithm_optimized'] = True
            optimized_content['optimization_applied'] = datetime.now().isoformat()
            
        except Exception as e:
            logger.error(f"Error applying algorithm optimization for {platform}: {e}")
        
        return optimized_content
    
    async def _optimize_content_length(self, content: Dict[str, Any], target_length: int) -> Dict[str, Any]:
        """Optimize content length for platform algorithm"""
        
        current_content = content.get('content', '')
        current_length = len(current_content)
        
        if abs(current_length - target_length) <= 50:  # Already within optimal range
            return content
        
        # Use AI to adjust length while maintaining quality
        prompt = f"""
        Optimize this cybersecurity content to be approximately {target_length} characters while maintaining all critical information.
        
        Current content ({current_length} characters):
        {current_content}
        
        Requirements:
        - Target length: {target_length} characters (±50)
        - Maintain all security-critical information
        - Preserve professional tone
        - Keep vulnerability details intact
        - Optimize for engagement
        
        Return the optimized content as plain text.
        """
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: self.ai_generator.client.chat.completions.create(
                    model="gpt-5",
                    messages=[
                        {
                            "role": "system", 
                            "content": "You are a content optimization expert specializing in cybersecurity communications."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3
                )
            )
            
            optimized_text = response.choices[0].message.content
            content['content'] = optimized_text
            content['length_optimized'] = True
            
        except Exception as e:
            logger.error(f"Error optimizing content length: {e}")
        
        return content
    
    def _optimize_hashtags(self, content: Dict[str, Any], target_count: int) -> Dict[str, Any]:
        """Optimize hashtag count for platform algorithm"""
        
        current_hashtags = content.get('hashtags', [])
        
        if len(current_hashtags) == target_count:
            return content
        
        # Prioritize hashtags by relevance and popularity
        prioritized_hashtags = self._prioritize_hashtags(current_hashtags, content)
        
        # Adjust to target count
        if len(prioritized_hashtags) > target_count:
            content['hashtags'] = prioritized_hashtags[:target_count]
        elif len(prioritized_hashtags) < target_count:
            # Add relevant cybersecurity hashtags
            additional_hashtags = self._get_additional_hashtags(content, target_count - len(prioritized_hashtags))
            content['hashtags'] = prioritized_hashtags + additional_hashtags
        
        content['hashtag_optimized'] = True
        return content
    
    def _prioritize_hashtags(self, hashtags: List[str], content: Dict[str, Any]) -> List[str]:
        """Prioritize hashtags by relevance and engagement potential"""
        
        # High-priority cybersecurity hashtags
        high_priority = ['CyberSecurity', 'InfoSec', 'VulnDisclosure', 'ThreatIntel', 'SecurityAlert']
        
        # Severity-based hashtags
        severity_hashtags = {
            'critical': ['CriticalVuln', 'HighRisk', 'UrgentPatch'],
            'high': ['HighSeverity', 'SecurityRisk', 'PatchNow'],
            'medium': ['MediumRisk', 'SecurityUpdate'],
            'low': ['SecurityInfo', 'LowRisk']
        }
        
        prioritized = []
        
        # Add high priority hashtags that exist
        for tag in hashtags:
            if tag in high_priority:
                prioritized.append(tag)
        
        # Add severity-specific hashtags
        content_text = content.get('content', '').lower()
        for severity, tags in severity_hashtags.items():
            if severity in content_text:
                for tag in tags:
                    if tag in hashtags and tag not in prioritized:
                        prioritized.append(tag)
                break
        
        # Add remaining hashtags
        for tag in hashtags:
            if tag not in prioritized:
                prioritized.append(tag)
        
        return prioritized
    
    def _get_additional_hashtags(self, content: Dict[str, Any], count: int) -> List[str]:
        """Get additional relevant hashtags"""
        
        content_text = content.get('content', '').lower()
        
        # Contextual hashtags based on content
        additional_pools = {
            'bug_bounty': ['BugBounty', 'HackerOne', 'Bugcrowd', 'ResponsibleDisclosure'],
            'exploit': ['ExploitAlert', 'ZeroDay', 'RCE', 'PrivEsc'],
            'enterprise': ['EnterpriseSecurity', 'CyberDefense', 'RiskManagement'],
            'compliance': ['Compliance', 'GRC', 'SecurityStandards'],
            'incident': ['IncidentResponse', 'SIEM', 'SOC', 'ThreatHunting']
        }
        
        additional = []
        for context, tags in additional_pools.items():
            if context.replace('_', ' ') in content_text:
                additional.extend(tags[:2])  # Add up to 2 from each relevant category
        
        # General cybersecurity hashtags as fallback
        fallback_tags = ['Cybersec', 'InfoSecNews', 'SecurityResearch', 'VulnMgmt', 'CyberThreat']
        additional.extend(fallback_tags)
        
        return additional[:count]
    
    def _add_engagement_triggers(self, content: Dict[str, Any], triggers: List[str]) -> Dict[str, Any]:
        """Add engagement triggers to content"""
        
        current_content = content.get('content', '')
        
        # Check if content already has engagement triggers
        has_trigger = any(trigger.lower() in current_content.lower() for trigger in triggers)
        
        if not has_trigger:
            # Select appropriate trigger based on content severity
            content_lower = current_content.lower()
            if 'critical' in content_lower or 'urgent' in content_lower:
                selected_trigger = next((t for t in triggers if '🚨' in t or 'BREAKING' in t), triggers[0])
            else:
                selected_trigger = triggers[0]
            
            # Add trigger to beginning of content
            content['content'] = f"{selected_trigger} {current_content}"
            content['engagement_trigger_added'] = selected_trigger
        
        return content
    
    async def _optimize_for_twitter(self, content: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
        """Apply Twitter-specific optimizations"""
        
        # Check if content should be a thread
        content_text = content.get('content', '')
        if len(content_text) > profile.get('thread_threshold', 280):
            content = await self._create_twitter_thread(content)
        
        # Add retweet factors
        retweet_factors = profile.get('retweet_factors', [])
        content = self._add_retweet_factors(content, retweet_factors)
        
        # Optimize for Twitter's algorithm weights
        content['twitter_optimized'] = {
            'thread_created': len(content_text) > 280,
            'hashtag_placement': 'end',
            'engagement_optimized': True
        }
        
        return content
    
    async def _create_twitter_thread(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Create a Twitter thread from long content"""
        
        full_content = content.get('content', '')
        
        prompt = f"""
        Convert this cybersecurity content into an engaging Twitter thread.
        
        Content to convert:
        {full_content}
        
        Requirements:
        - Split into tweets of max 250 characters each
        - Start with a compelling hook tweet
        - Use thread numbering (1/n, 2/n, etc.)
        - Maintain all critical security information
        - End with a summary/CTA tweet
        - Each tweet should be engaging and standalone readable
        
        Return as JSON with 'tweets' array and 'thread_count' field.
        """
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.ai_generator.client.chat.completions.create(
                    model="gpt-5",
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a Twitter content strategist specializing in cybersecurity thread creation."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.4
                )
            )
            
            content_text = response.choices[0].message.content
            if content_text is None:
                raise ValueError("No content received from AI response")
            thread_data = json.loads(content_text)
            
            content['twitter_thread'] = thread_data
            content['content_type'] = 'thread'
            content['content'] = thread_data['tweets'][0]  # First tweet as main content
            
        except Exception as e:
            logger.error(f"Error creating Twitter thread: {e}")
        
        return content
    
    def _add_retweet_factors(self, content: Dict[str, Any], factors: List[str]) -> Dict[str, Any]:
        """Add elements that encourage retweets"""
        
        content_text = content.get('content', '')
        
        # Add retweet-encouraging elements based on factors
        if 'question' in factors and '?' not in content_text:
            content['content'] += "\n\nWhat's your take on this vulnerability?"
        
        if 'shocking_stat' in factors:
            # Add shocking statistics if available
            if 'cvss' in content_text.lower():
                content['retweet_factor'] = 'high_cvss_score'
        
        if 'actionable_tip' in factors:
            content['content'] += "\n\n💡 Tip: Always patch critical vulnerabilities within 24-48 hours"
        
        return content
    
    async def _optimize_for_linkedin(self, content: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
        """Apply LinkedIn-specific optimizations"""
        
        # Add professional keywords
        professional_keywords = profile.get('professional_keywords', [])
        content = self._enhance_professional_language(content, professional_keywords)
        
        # Add industry insights
        content = await self._add_industry_insights(content)
        
        content['linkedin_optimized'] = {
            'professional_tone': True,
            'industry_focused': True,
            'network_engagement': True
        }
        
        return content
    
    def _enhance_professional_language(self, content: Dict[str, Any], keywords: List[str]) -> Dict[str, Any]:
        """Enhance content with professional cybersecurity language"""
        
        content_text = content.get('content', '')
        
        # Professional language mappings
        professional_replacements = {
            'bug': 'vulnerability',
            'hack': 'exploit',
            'bad guys': 'threat actors',
            'attack': 'security incident',
            'broken': 'compromised'
        }
        
        for casual, professional in professional_replacements.items():
            content_text = content_text.replace(casual, professional)
        
        content['content'] = content_text
        content['professional_language'] = True
        
        return content
    
    async def _add_industry_insights(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Add industry-specific insights to LinkedIn content"""
        
        prompt = f"""
        Enhance this cybersecurity content with industry insights and business context for LinkedIn professionals.
        
        Current content:
        {content.get('content', '')}
        
        Add:
        - Business impact perspective
        - Industry best practices
        - Executive-level considerations
        - Compliance implications
        - Strategic recommendations
        
        Keep the enhanced content professional and actionable for security leaders.
        Return the enhanced content as plain text.
        """
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.ai_generator.client.chat.completions.create(
                    model="gpt-5",
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a cybersecurity industry analyst providing insights for security executives and professionals."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3
                )
            )
            
            enhanced_content = response.choices[0].message.content
            content['content'] = enhanced_content
            content['industry_insights_added'] = True
            
        except Exception as e:
            logger.error(f"Error adding industry insights: {e}")
        
        return content
    
    async def _optimize_for_medium(self, content: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
        """Apply Medium-specific optimizations"""
        
        # Expand content for Medium's long-form preference
        content = await self._expand_for_medium(content)
        
        # Add Medium-specific formatting
        content = self._add_medium_formatting(content)
        
        # Optimize headline
        content = self._optimize_medium_headline(content, profile)
        
        content['medium_optimized'] = {
            'long_form': True,
            'formatted': True,
            'headline_optimized': True
        }
        
        return content
    
    async def _expand_for_medium(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Expand content for Medium's long-form format"""
        
        current_content = content.get('content', '')
        
        prompt = f"""
        Expand this cybersecurity content into a comprehensive Medium article.
        
        Current content:
        {current_content}
        
        Create a full article with:
        1. Compelling introduction
        2. Technical deep dive
        3. Real-world implications
        4. Case studies or examples
        5. Prevention strategies
        6. Conclusion with key takeaways
        
        Target length: 2500-3000 words
        Maintain technical accuracy while being accessible to security professionals.
        
        Return the expanded article content.
        """
        
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.ai_generator.client.chat.completions.create(
                    model="gpt-5",
                    messages=[
                        {
                            "role": "system",
                            "content": "You are a cybersecurity writer creating in-depth technical articles for Medium's professional audience."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.4
                )
            )
            
            expanded_content = response.choices[0].message.content
            content['content'] = expanded_content
            content['expanded_for_medium'] = True
            
        except Exception as e:
            logger.error(f"Error expanding content for Medium: {e}")
        
        return content
    
    def _add_medium_formatting(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Add Medium-style formatting"""
        
        content_text = content.get('content', '')
        
        # Add Medium-style headers, emphasis, and formatting
        formatted_content = content_text
        
        # Add proper headers
        if '## ' not in formatted_content:
            # Auto-add section headers
            paragraphs = formatted_content.split('\n\n')
            if len(paragraphs) > 3:
                # Add headers to major sections
                formatted_paragraphs = []
                for i, paragraph in enumerate(paragraphs):
                    if i == 0:
                        formatted_paragraphs.append(paragraph)
                    elif len(paragraph) > 100 and i % 2 == 1:
                        formatted_paragraphs.append(f"## Section {i//2 + 1}")
                        formatted_paragraphs.append(paragraph)
                    else:
                        formatted_paragraphs.append(paragraph)
                
                formatted_content = '\n\n'.join(formatted_paragraphs)
        
        content['content'] = formatted_content
        content['medium_formatted'] = True
        
        return content
    
    def _optimize_medium_headline(self, content: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize headline for Medium algorithm"""
        
        current_title = content.get('title', '')
        headline_optimization = profile.get('headline_optimization', [])
        
        # Add engaging elements to headline
        if 'numbers' in headline_optimization and not any(char.isdigit() for char in current_title):
            content['title'] = f"7 Critical Insights: {current_title}"
        
        if 'how_to' in headline_optimization and 'how to' not in current_title.lower():
            content['title'] = f"How to Understand {current_title}"
        
        if 'ultimate_guide' in headline_optimization:
            content['title'] = f"The Ultimate Guide to {current_title}"
        
        return content
    
    def _optimize_for_telegram(self, content: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
        """Apply Telegram-specific optimizations"""
        
        # Add forward factors
        forward_factors = profile.get('forward_factors', [])
        content = self._add_forward_factors(content, forward_factors)
        
        # Optimize for Telegram's global audience
        content = self._add_telegram_formatting(content)
        
        content['telegram_optimized'] = {
            'forward_optimized': True,
            'global_audience': True,
            'urgency_emphasized': True
        }
        
        return content
    
    def _add_forward_factors(self, content: Dict[str, Any], factors: List[str]) -> Dict[str, Any]:
        """Add elements that encourage forwarding on Telegram"""
        
        content_text = content.get('content', '')
        
        if 'urgency' in factors:
            if not any(word in content_text.upper() for word in ['URGENT', 'CRITICAL', 'IMMEDIATE']):
                content['content'] = f"🚨 URGENT: {content_text}"
        
        if 'actionable' in factors:
            content['content'] += "\n\n📌 Action Required: Review and patch immediately"
        
        if 'exclusive' in factors:
            content['content'] = f"🔥 Breaking: {content_text}"
        
        return content
    
    def _add_telegram_formatting(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Add Telegram-specific formatting"""
        
        content_text = content.get('content', '')
        
        # Add Telegram markdown formatting
        formatted_content = content_text
        
        # Bold important terms
        important_terms = ['CRITICAL', 'HIGH', 'CVE', 'CVSS', 'URGENT', 'PATCH']
        for term in important_terms:
            formatted_content = formatted_content.replace(term, f"**{term}**")
        
        # Add code formatting for technical terms
        tech_terms = ['SQL injection', 'XSS', 'RCE', 'buffer overflow']
        for term in tech_terms:
            formatted_content = formatted_content.replace(term, f"`{term}`")
        
        content['content'] = formatted_content
        content['telegram_formatted'] = True
        
        return content
    
    def _optimize_for_discord(self, content: Dict[str, Any], profile: Dict[str, Any]) -> Dict[str, Any]:
        """Apply Discord-specific optimizations"""
        
        # Add community engagement factors
        community_factors = profile.get('community_factors', [])
        content = self._add_community_factors(content, community_factors)
        
        # Add Discord-specific formatting
        content = self._add_discord_formatting(content)
        
        content['discord_optimized'] = {
            'community_focused': True,
            'discussion_friendly': True,
            'formatted_properly': True
        }
        
        return content
    
    def _add_community_factors(self, content: Dict[str, Any], factors: List[str]) -> Dict[str, Any]:
        """Add elements that encourage community engagement"""
        
        content_text = content.get('content', '')
        
        if 'discussion_starter' in factors:
            content['content'] += "\n\nWhat's your experience with similar vulnerabilities? Drop your thoughts below! 💭"
        
        if 'helpful' in factors:
            content['content'] += "\n\nReact with 👍 if this was helpful!"
        
        if 'timely' in factors:
            content['content'] = f"⏰ **Just In**: {content_text}"
        
        return content
    
    def _add_discord_formatting(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Add Discord-specific formatting"""
        
        content_text = content.get('content', '')
        
        # Add Discord markdown and emoji formatting
        formatted_content = content_text
        
        # Add severity emojis
        severity_emojis = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢'
        }
        
        for severity, emoji in severity_emojis.items():
            if severity in formatted_content.lower():
                formatted_content = f"{emoji} {formatted_content}"
                break
        
        # Add code blocks for technical details
        if 'CVE-' in formatted_content:
            formatted_content = formatted_content.replace('CVE-', '`CVE-')
            formatted_content = formatted_content.replace(' ', '` ', 1)  # Close the first code block
        
        content['content'] = formatted_content
        content['discord_formatted'] = True
        
        return content
    
    async def _regenerate_content(
        self, 
        vulnerability: Dict[str, Any], 
        platform: str, 
        content_type: str,
        previous_attempt: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Regenerate content with different parameters based on feedback"""
        
        logger.info(f"Regenerating content for {platform}/{content_type}")
        
        # Adjust generation parameters based on previous attempt
        new_content = await self.ai_generator.generate_vulnerability_content(
            vulnerability, platform, content_type
        )
        
        if new_content:
            new_content['regenerated'] = True
            new_content['previous_attempt'] = previous_attempt['original']
        
        return new_content
    
    async def _assess_publication_quality(self, content: Dict[str, Any], platform: str) -> float:
        """Assess overall publication quality"""
        
        quality_metrics = {
            'content_completeness': self._check_content_completeness(content),
            'platform_optimization': self._check_platform_optimization(content, platform),
            'engagement_potential': self._check_engagement_potential(content),
            'professional_quality': self._check_professional_quality(content),
            'technical_accuracy': self._check_technical_accuracy(content)
        }
        
        # Weighted average
        weights = {
            'content_completeness': 0.25,
            'platform_optimization': 0.20,
            'engagement_potential': 0.20,
            'professional_quality': 0.20,
            'technical_accuracy': 0.15
        }
        
        weighted_score = sum(
            score * weights[metric] 
            for metric, score in quality_metrics.items()
        )
        
        return weighted_score * 100
    
    def _check_content_completeness(self, content: Dict[str, Any]) -> float:
        """Check if content has all required elements"""
        
        required_elements = ['title', 'content', 'hashtags']
        score = sum(1 for element in required_elements if content.get(element)) / len(required_elements)
        
        # Bonus points for additional elements
        bonus_elements = ['engagement_score_prediction', 'algorithm_optimized', 'user_edited']
        bonus_score = sum(0.1 for element in bonus_elements if content.get(element))
        
        return min(score + bonus_score, 1.0)
    
    def _check_platform_optimization(self, content: Dict[str, Any], platform: str) -> float:
        """Check platform-specific optimization"""
        
        optimization_checks = {
            'algorithm_optimized': bool(content.get('algorithm_optimized')),
            'platform_formatted': bool(content.get(f'{platform}_formatted')),
            'length_appropriate': self._check_appropriate_length(content, platform),
            'hashtag_optimized': bool(content.get('hashtag_optimized'))
        }
        
        return sum(optimization_checks.values()) / len(optimization_checks)
    
    def _check_appropriate_length(self, content: Dict[str, Any], platform: str) -> bool:
        """Check if content length is appropriate for platform"""
        
        content_length = len(content.get('content', ''))
        
        platform_ranges = {
            'twitter': (50, 280),
            'linkedin': (300, 3000),
            'medium': (1000, 10000),
            'telegram': (100, 4000),
            'discord': (50, 2000)
        }
        
        if platform not in platform_ranges:
            return True
        
        min_length, max_length = platform_ranges[platform]
        return min_length <= content_length <= max_length
    
    def _check_engagement_potential(self, content: Dict[str, Any]) -> float:
        """Check content's potential for engagement"""
        
        content_text = content.get('content', '').lower()
        
        engagement_indicators = {
            'has_question': '?' in content_text,
            'has_call_to_action': any(cta in content_text for cta in ['comment', 'share', 'thoughts', 'experience']),
            'has_urgency': any(word in content_text for word in ['urgent', 'critical', 'immediate', 'breaking']),
            'has_emojis': any(char for char in content.get('content', '') if ord(char) > 127),
            'has_engagement_trigger': content.get('engagement_trigger_added', False)
        }
        
        return sum(engagement_indicators.values()) / len(engagement_indicators)
    
    def _check_professional_quality(self, content: Dict[str, Any]) -> float:
        """Check professional quality of content"""
        
        content_text = content.get('content', '')
        
        quality_checks = {
            'proper_grammar': len(content_text.split('.')) > 1,  # Has multiple sentences
            'no_typos': not any(word in content_text.lower() for word in ['teh', 'recieve', 'seperate']),
            'professional_language': content.get('professional_language', False),
            'appropriate_tone': not any(word in content_text.lower() for word in ['lol', 'omg', 'wtf']),
            'has_structure': '\n' in content_text or len(content_text.split('. ')) > 3
        }
        
        return sum(quality_checks.values()) / len(quality_checks)
    
    def _check_technical_accuracy(self, content: Dict[str, Any]) -> float:
        """Check technical accuracy of cybersecurity content"""
        
        content_text = content.get('content', '').lower()
        
        accuracy_indicators = {
            'uses_proper_cve_format': 'cve-' in content_text,
            'mentions_severity': any(severity in content_text for severity in ['critical', 'high', 'medium', 'low']),
            'technical_terms': any(term in content_text for term in ['vulnerability', 'exploit', 'patch', 'security']),
            'no_misinformation': not any(false_term in content_text for false_term in ['100% safe', 'impossible to exploit', 'no risk']),
            'mentions_remediation': any(term in content_text for term in ['patch', 'update', 'fix', 'remediation', 'mitigation'])
        }
        
        return sum(accuracy_indicators.values()) / len(accuracy_indicators)
    
    def _generate_publication_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of publication results"""
        
        total_publications = 0
        successful_publications = 0
        quality_scores = results.get('quality_scores', {})
        
        for platform_results in results['publications'].values():
            for content_result in platform_results.values():
                if isinstance(content_result, dict):
                    total_publications += 1
                    if content_result.get('ready_for_publishing', False):
                        successful_publications += 1
        
        average_quality = sum(quality_scores.values()) / len(quality_scores) if quality_scores else 0
        
        return {
            'total_publications_attempted': total_publications,
            'successful_publications': successful_publications,
            'success_rate': successful_publications / total_publications if total_publications > 0 else 0,
            'average_quality_score': average_quality,
            'ready_for_publishing': successful_publications,
            'needs_improvement': total_publications - successful_publications,
            'quality_grade': self._get_quality_grade(average_quality)
        }
    
    def _get_quality_grade(self, score: float) -> str:
        """Convert quality score to letter grade"""
        
        if score >= 90:
            return 'A+'
        elif score >= 85:
            return 'A'
        elif score >= 80:
            return 'B+'
        elif score >= 75:
            return 'B'
        elif score >= 70:
            return 'C+'
        elif score >= 65:
            return 'C'
        else:
            return 'D'
    
    async def batch_create_publications(
        self,
        vulnerabilities: List[Dict[str, Any]],
        platforms: List[str],
        content_types: List[str] = ['summary'],
        enable_user_review: bool = False,  # Disabled for batch processing
        auto_optimize: bool = True
    ) -> Dict[str, Any]:
        """Create publications for multiple vulnerabilities in batch mode"""
        
        logger.info(f"Starting batch publication creation for {len(vulnerabilities)} vulnerabilities")
        
        batch_results = {
            'batch_id': f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'started_at': datetime.now().isoformat(),
            'total_vulnerabilities': len(vulnerabilities),
            'platforms': platforms,
            'content_types': content_types,
            'publications': {},
            'batch_summary': {}
        }
        
        for i, vulnerability in enumerate(vulnerabilities):
            logger.info(f"Processing vulnerability {i+1}/{len(vulnerabilities)}: {vulnerability.get('vulnerability_id', 'Unknown')}")
            
            try:
                pub_result = await self.create_optimized_publication(
                    vulnerability,
                    platforms,
                    content_types,
                    enable_user_review=enable_user_review,
                    auto_optimize=auto_optimize
                )
                
                batch_results['publications'][vulnerability.get('vulnerability_id', f'vuln_{i}')] = pub_result
                
            except Exception as e:
                logger.error(f"Error processing vulnerability {i+1}: {e}")
                batch_results['publications'][vulnerability.get('vulnerability_id', f'vuln_{i}')] = {
                    'error': str(e),
                    'processed': False
                }
        
        # Generate batch summary
        batch_results['batch_summary'] = self._generate_batch_summary(batch_results)
        batch_results['completed_at'] = datetime.now().isoformat()
        
        return batch_results
    
    def _generate_batch_summary(self, batch_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary for batch processing results"""
        
        publications = batch_results['publications']
        
        total_processed = len(publications)
        successful = sum(1 for pub in publications.values() if not pub.get('error'))
        failed = total_processed - successful
        
        # Aggregate quality scores
        all_quality_scores = []
        for pub in publications.values():
            if not pub.get('error') and 'quality_scores' in pub:
                all_quality_scores.extend(pub['quality_scores'].values())
        
        average_quality = sum(all_quality_scores) / len(all_quality_scores) if all_quality_scores else 0
        
        return {
            'total_vulnerabilities_processed': total_processed,
            'successful_publications': successful,
            'failed_publications': failed,
            'success_rate': successful / total_processed if total_processed > 0 else 0,
            'average_quality_score': average_quality,
            'total_content_pieces': len(all_quality_scores),
            'processing_complete': True
        }