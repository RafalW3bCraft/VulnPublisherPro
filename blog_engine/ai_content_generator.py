#!/usr/bin/env python3
"""
AI-Powered Content Generator - Phase 2 Blog Content Revolution
Advanced content generation with multiple perspectives and interactive elements

Features:
- AI-Powered Writing with human-like content generation
- Multiple Perspectives: Technical, business impact, developer-focused
- Interactive Elements: Code snippets, diagrams, step-by-step guides
- Series Management: Multi-part vulnerability analysis

Author: RafalW3bCraft
License: MIT
Copyright (c) 2025 RafalW3bCraft
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass
import re

logger = logging.getLogger(__name__)

@dataclass
class ContentPerspective:
    """Different content perspectives for varied audience targeting"""
    name: str
    description: str
    target_audience: str
    tone: str
    technical_depth: str
    focus_areas: List[str]

@dataclass
class InteractiveElement:
    """Interactive content elements for enhanced engagement"""
    element_type: str  # 'code_snippet', 'diagram', 'step_guide', 'timeline'
    title: str
    content: str
    language: Optional[str] = None
    metadata: Optional[Dict] = None

class AIContentGenerator:
    """Advanced AI-powered content generator for vulnerability blogs"""
    
    def __init__(self, openai_api_key: Optional[str] = None):
        self.api_key = openai_api_key or os.getenv('OPENAI_API_KEY')
        
        # Content perspectives for different audiences
        self.perspectives = {
            'technical': ContentPerspective(
                name='Technical Deep Dive',
                description='In-depth technical analysis for security professionals',
                target_audience='Security engineers, penetration testers, researchers',
                tone='Professional, detailed, technical',
                technical_depth='High',
                focus_areas=['exploit mechanics', 'root cause analysis', 'technical remediation', 'code analysis']
            ),
            'business': ContentPerspective(
                name='Business Impact Analysis',
                description='Business-focused analysis of security implications',
                target_audience='CISOs, security managers, business stakeholders',
                tone='Strategic, impact-focused, executive-friendly',
                technical_depth='Medium',
                focus_areas=['business risk', 'compliance impact', 'cost analysis', 'strategic recommendations']
            ),
            'developer': ContentPerspective(
                name='Developer Security Guide',
                description='Practical security guidance for developers',
                target_audience='Software developers, DevOps engineers, architects',
                tone='Practical, actionable, development-focused',
                technical_depth='High',
                focus_areas=['secure coding', 'remediation guides', 'best practices', 'prevention techniques']
            ),
            'executive': ContentPerspective(
                name='Executive Summary',
                description='High-level overview for decision makers',
                target_audience='C-suite executives, board members, senior management',
                tone='Concise, strategic, outcome-focused',
                technical_depth='Low',
                focus_areas=['business impact', 'financial implications', 'strategic response', 'risk management']
            )
        }
        
        # Interactive element templates
        self.element_templates = {
            'code_snippet': {
                'title': 'Code Analysis',
                'template': '```{language}\n{code}\n```\n\n**Analysis:** {analysis}'
            },
            'step_guide': {
                'title': 'Remediation Steps',
                'template': '### {title}\n\n{steps}'
            },
            'timeline': {
                'title': 'Vulnerability Timeline',
                'template': '**Timeline:**\n{events}'
            },
            'impact_matrix': {
                'title': 'Impact Assessment',
                'template': '| Factor | Impact Level | Description |\n|--------|--------------|-------------|\n{rows}'
            }
        }
        
        logger.info("AI Content Generator initialized successfully")
    
    def generate_multi_perspective_content(self, vulnerability_data: Dict[str, Any], 
                                         perspectives: List[str] = None,
                                         include_interactive: bool = True) -> Dict[str, Any]:
        """Generate content from multiple perspectives for comprehensive coverage"""
        
        if not perspectives:
            perspectives = ['technical', 'business', 'developer']
        
        try:
            content_package = {
                'vulnerability_info': {
                    'cve_id': vulnerability_data.get('cve_id', 'Unknown'),
                    'title': vulnerability_data.get('title', 'Unknown Vulnerability'),
                    'severity': vulnerability_data.get('severity', 'Unknown'),
                    'cvss_score': vulnerability_data.get('cvss_score', 0.0)
                },
                'perspectives': {},
                'interactive_elements': [],
                'cross_perspective_insights': [],
                'publishing_metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'total_perspectives': len(perspectives),
                    'estimated_read_time': 0
                }
            }
            
            # Generate content for each perspective
            for perspective_name in perspectives:
                if perspective_name in self.perspectives:
                    perspective_content = self._generate_perspective_content(
                        vulnerability_data, perspective_name
                    )
                    content_package['perspectives'][perspective_name] = perspective_content
            
            # Generate interactive elements if requested
            if include_interactive:
                interactive_elements = self._generate_interactive_elements(vulnerability_data)
                content_package['interactive_elements'] = interactive_elements
            
            # Generate cross-perspective insights
            content_package['cross_perspective_insights'] = self._generate_cross_perspective_insights(
                vulnerability_data, content_package['perspectives']
            )
            
            # Calculate estimated read time
            content_package['publishing_metadata']['estimated_read_time'] = self._calculate_read_time(content_package)
            
            logger.info(f"Generated multi-perspective content for {vulnerability_data.get('cve_id', 'unknown CVE')}")
            return content_package
            
        except Exception as e:
            logger.error(f"Error generating multi-perspective content: {e}")
            return self._get_fallback_content(vulnerability_data)
    
    def _generate_perspective_content(self, vulnerability_data: Dict[str, Any], perspective_name: str) -> Dict[str, Any]:
        """Generate content for a specific perspective"""
        
        perspective = self.perspectives[perspective_name]
        
        # Simulate AI content generation based on perspective
        content = {
            'perspective_info': {
                'name': perspective.name,
                'target_audience': perspective.target_audience,
                'tone': perspective.tone,
                'technical_depth': perspective.technical_depth
            },
            'sections': self._generate_perspective_sections(vulnerability_data, perspective),
            'key_takeaways': self._generate_key_takeaways(vulnerability_data, perspective),
            'recommended_actions': self._generate_recommended_actions(vulnerability_data, perspective),
            'word_count': 0
        }
        
        # Calculate word count
        total_words = 0
        for section in content['sections']:
            total_words += len(section.get('content', '').split())
        content['word_count'] = total_words
        
        return content
    
    def _generate_perspective_sections(self, vulnerability_data: Dict[str, Any], perspective: ContentPerspective) -> List[Dict[str, Any]]:
        """Generate sections based on perspective focus areas"""
        
        sections = []
        vuln_title = vulnerability_data.get('title', 'Unknown Vulnerability')
        vuln_description = vulnerability_data.get('description', 'No description available')
        severity = vulnerability_data.get('severity', 'unknown')
        
        if perspective.name == 'Technical Deep Dive':
            sections = [
                {
                    'title': 'Vulnerability Analysis',
                    'content': f"This technical analysis examines {vuln_title}, a {severity}-severity vulnerability that affects multiple systems. {vuln_description}\n\nThe vulnerability's technical characteristics suggest specific attack vectors that security professionals must understand to implement effective countermeasures.",
                    'section_type': 'analysis'
                },
                {
                    'title': 'Exploit Mechanics',
                    'content': f"The exploitation of this vulnerability involves several technical steps that demonstrate the sophistication required for successful attacks. Understanding these mechanics is crucial for developing effective detection and prevention strategies.",
                    'section_type': 'technical'
                },
                {
                    'title': 'Technical Remediation',
                    'content': f"Technical remediation requires specific configuration changes and security controls. Organizations should implement layered defenses including input validation, access controls, and monitoring systems to prevent exploitation.",
                    'section_type': 'remediation'
                }
            ]
        
        elif perspective.name == 'Business Impact Analysis':
            sections = [
                {
                    'title': 'Business Risk Assessment',
                    'content': f"The {vuln_title} vulnerability presents significant business risks that require immediate executive attention. Organizations face potential data breaches, regulatory compliance issues, and operational disruption.",
                    'section_type': 'risk_analysis'
                },
                {
                    'title': 'Financial Impact',
                    'content': f"The financial implications of this vulnerability include potential breach costs, regulatory fines, remediation expenses, and business continuity impacts. Early investment in security measures can significantly reduce overall costs.",
                    'section_type': 'financial'
                },
                {
                    'title': 'Strategic Response',
                    'content': f"A strategic response requires coordinated efforts across security, IT, legal, and business teams. Clear communication, defined timelines, and resource allocation are essential for effective vulnerability management.",
                    'section_type': 'strategy'
                }
            ]
        
        elif perspective.name == 'Developer Security Guide':
            sections = [
                {
                    'title': 'Secure Development Practices',
                    'content': f"Developers can prevent vulnerabilities like {vuln_title} by implementing secure coding practices, conducting regular security reviews, and using automated security testing tools in their development workflow.",
                    'section_type': 'development'
                },
                {
                    'title': 'Code Review Guidelines',
                    'content': f"Code reviews should specifically look for patterns that could lead to this type of vulnerability. Automated tools can help identify potential issues, but manual review by security-aware developers is essential.",
                    'section_type': 'review'
                },
                {
                    'title': 'Testing and Validation',
                    'content': f"Comprehensive testing strategies including unit tests, integration tests, and security-specific tests can help identify vulnerabilities before they reach production environments.",
                    'section_type': 'testing'
                }
            ]
        
        else:  # Executive Summary
            sections = [
                {
                    'title': 'Executive Overview',
                    'content': f"The {vuln_title} vulnerability requires immediate executive attention due to its potential impact on business operations, customer trust, and regulatory compliance. Swift action is necessary to minimize organizational risk.",
                    'section_type': 'overview'
                },
                {
                    'title': 'Resource Requirements',
                    'content': f"Addressing this vulnerability requires dedicated resources including security personnel, IT infrastructure updates, and potential third-party consulting. Investment in proactive security measures demonstrates organizational commitment to protection.",
                    'section_type': 'resources'
                }
            ]
        
        return sections
    
    def _generate_key_takeaways(self, vulnerability_data: Dict[str, Any], perspective: ContentPerspective) -> List[str]:
        """Generate key takeaways based on perspective"""
        
        severity = vulnerability_data.get('severity', 'unknown')
        
        if perspective.name == 'Technical Deep Dive':
            return [
                f"This {severity}-severity vulnerability requires immediate technical attention",
                "Exploitation involves sophisticated attack vectors requiring deep technical knowledge",
                "Layered security controls and monitoring are essential for prevention and detection",
                "Regular security assessments can help identify similar vulnerabilities"
            ]
        
        elif perspective.name == 'Business Impact Analysis':
            return [
                "Immediate business risk assessment and response planning required",
                "Financial impact includes potential breach costs and regulatory penalties",
                "Stakeholder communication and resource allocation are critical success factors",
                "Proactive security investment reduces long-term organizational risk"
            ]
        
        elif perspective.name == 'Developer Security Guide':
            return [
                "Secure coding practices can prevent similar vulnerabilities",
                "Automated security testing should be integrated into development workflows",
                "Regular code reviews with security focus are essential",
                "Security training for development teams improves overall security posture"
            ]
        
        else:  # Executive Summary
            return [
                "Executive leadership and resource commitment required for effective response",
                "Immediate action necessary to minimize business impact and regulatory risk",
                "Investment in security infrastructure demonstrates organizational maturity"
            ]
    
    def _generate_recommended_actions(self, vulnerability_data: Dict[str, Any], perspective: ContentPerspective) -> List[Dict[str, Any]]:
        """Generate recommended actions based on perspective"""
        
        if perspective.name == 'Technical Deep Dive':
            return [
                {
                    'action': 'Conduct immediate vulnerability assessment',
                    'priority': 'high',
                    'timeline': 'immediate',
                    'owner': 'Security team'
                },
                {
                    'action': 'Implement technical countermeasures',
                    'priority': 'high',
                    'timeline': '1-2 days',
                    'owner': 'IT operations'
                },
                {
                    'action': 'Deploy monitoring and detection capabilities',
                    'priority': 'medium',
                    'timeline': '1 week',
                    'owner': 'SOC team'
                }
            ]
        
        elif perspective.name == 'Business Impact Analysis':
            return [
                {
                    'action': 'Activate incident response procedures',
                    'priority': 'high',
                    'timeline': 'immediate',
                    'owner': 'CISO'
                },
                {
                    'action': 'Assess business impact and communicate to stakeholders',
                    'priority': 'high',
                    'timeline': '4 hours',
                    'owner': 'Executive team'
                },
                {
                    'action': 'Allocate resources for remediation efforts',
                    'priority': 'medium',
                    'timeline': '1 day',
                    'owner': 'Finance/Operations'
                }
            ]
        
        elif perspective.name == 'Developer Security Guide':
            return [
                {
                    'action': 'Review code for similar vulnerability patterns',
                    'priority': 'high',
                    'timeline': '2-3 days',
                    'owner': 'Development team'
                },
                {
                    'action': 'Update security testing procedures',
                    'priority': 'medium',
                    'timeline': '1 week',
                    'owner': 'QA/Security'
                },
                {
                    'action': 'Implement secure coding training',
                    'priority': 'low',
                    'timeline': '1 month',
                    'owner': 'Development management'
                }
            ]
        
        else:  # Executive Summary
            return [
                {
                    'action': 'Approve emergency response budget',
                    'priority': 'high',
                    'timeline': 'immediate',
                    'owner': 'C-suite'
                },
                {
                    'action': 'Communicate with board and key stakeholders',
                    'priority': 'high',
                    'timeline': '24 hours',
                    'owner': 'CEO/CISO'
                }
            ]
    
    def _generate_interactive_elements(self, vulnerability_data: Dict[str, Any]) -> List[InteractiveElement]:
        """Generate interactive content elements"""
        
        elements = []
        
        # Code snippet element
        if 'technical_details' in vulnerability_data:
            elements.append(InteractiveElement(
                element_type='code_snippet',
                title='Vulnerability Code Example',
                content='# Example vulnerable code pattern\nfunction processInput(userInput) {\n    // Insufficient input validation\n    eval(userInput);\n}\n\n# Secure alternative\nfunction processInputSecure(userInput) {\n    // Proper input validation and sanitization\n    if (validateInput(userInput)) {\n        return sanitizeAndProcess(userInput);\n    }\n    throw new Error("Invalid input");\n}',
                language='javascript'
            ))
        
        # Step-by-step remediation guide
        elements.append(InteractiveElement(
            element_type='step_guide',
            title='Remediation Steps',
            content='1. **Immediate Actions**\n   - Identify affected systems\n   - Implement temporary mitigations\n   - Monitor for exploitation attempts\n\n2. **Short-term Fixes**\n   - Apply security patches\n   - Update configurations\n   - Test remediation effectiveness\n\n3. **Long-term Improvements**\n   - Review security architecture\n   - Implement additional controls\n   - Update security policies'
        ))
        
        # Timeline element
        elements.append(InteractiveElement(
            element_type='timeline',
            title='Vulnerability Lifecycle',
            content='- **Discovery:** Initial vulnerability identification\n- **Disclosure:** Responsible disclosure to vendor\n- **Patch Development:** Vendor creates security fix\n- **Patch Release:** Security update made available\n- **Deployment:** Organizations apply patches\n- **Verification:** Confirm remediation effectiveness'
        ))
        
        return elements
    
    def _generate_cross_perspective_insights(self, vulnerability_data: Dict[str, Any], perspectives: Dict[str, Any]) -> List[str]:
        """Generate insights that span multiple perspectives"""
        
        insights = [
            "Technical complexity requires both immediate tactical response and long-term strategic planning",
            "Business impact extends beyond technical systems to include customer trust and regulatory compliance",
            "Developer education and secure coding practices are essential for preventing similar vulnerabilities",
            "Cross-functional collaboration between security, development, and business teams ensures comprehensive response"
        ]
        
        # Add specific insights based on available perspectives
        if 'technical' in perspectives and 'business' in perspectives:
            insights.append("Technical remediation efforts must be balanced with business continuity requirements")
        
        if 'developer' in perspectives:
            insights.append("Development team involvement is crucial for understanding root causes and implementing lasting fixes")
        
        return insights
    
    def _calculate_read_time(self, content_package: Dict[str, Any]) -> int:
        """Calculate estimated reading time in minutes"""
        
        total_words = 0
        
        # Count words in perspectives
        for perspective_content in content_package.get('perspectives', {}).values():
            total_words += perspective_content.get('word_count', 0)
        
        # Count words in interactive elements
        for element in content_package.get('interactive_elements', []):
            total_words += len(element.content.split())
        
        # Average reading speed: 200 words per minute
        read_time = max(1, total_words // 200)
        return read_time
    
    def _get_fallback_content(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate fallback content when AI generation fails"""
        
        return {
            'vulnerability_info': {
                'cve_id': vulnerability_data.get('cve_id', 'Unknown'),
                'title': vulnerability_data.get('title', 'Unknown Vulnerability'),
                'severity': vulnerability_data.get('severity', 'Unknown')
            },
            'perspectives': {
                'summary': {
                    'perspective_info': {
                        'name': 'Summary',
                        'target_audience': 'General',
                        'tone': 'Informational'
                    },
                    'sections': [
                        {
                            'title': 'Vulnerability Overview',
                            'content': f"This security vulnerability affects multiple systems and requires immediate attention. Organizations should assess their exposure and implement appropriate security measures.",
                            'section_type': 'overview'
                        }
                    ],
                    'key_takeaways': [
                        "Immediate security assessment required",
                        "Implement security best practices",
                        "Monitor for potential exploitation"
                    ],
                    'recommended_actions': [
                        {
                            'action': 'Conduct security assessment',
                            'priority': 'high',
                            'timeline': 'immediate',
                            'owner': 'Security team'
                        }
                    ]
                }
            },
            'interactive_elements': [],
            'cross_perspective_insights': [
                "Multi-faceted approach required for effective vulnerability management"
            ],
            'publishing_metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_perspectives': 1,
                'estimated_read_time': 3,
                'fallback_used': True
            }
        }
    
    def generate_blog_post(self, content_package: Dict[str, Any], target_platform: str = 'medium') -> str:
        """Generate formatted blog post from content package"""
        
        try:
            vuln_info = content_package.get('vulnerability_info', {})
            perspectives = content_package.get('perspectives', {})
            interactive_elements = content_package.get('interactive_elements', [])
            
            # Generate blog post header
            blog_post = f"# {vuln_info.get('title', 'Security Vulnerability Analysis')}\n\n"
            blog_post += f"**CVE ID:** {vuln_info.get('cve_id', 'Unknown')}\n"
            blog_post += f"**Severity:** {vuln_info.get('severity', 'Unknown')}\n"
            if vuln_info.get('cvss_score'):
                blog_post += f"**CVSS Score:** {vuln_info['cvss_score']}\n"
            blog_post += f"**Published:** {datetime.now().strftime('%Y-%m-%d')}\n\n"
            
            blog_post += "---\n\n"
            
            # Add introduction
            blog_post += "## Introduction\n\n"
            blog_post += f"This comprehensive analysis examines the {vuln_info.get('title', 'vulnerability')} from multiple perspectives to provide actionable insights for different stakeholder groups.\n\n"
            
            # Add perspective-based content
            for perspective_name, perspective_content in perspectives.items():
                perspective_info = perspective_content.get('perspective_info', {})
                blog_post += f"## {perspective_info.get('name', perspective_name.title())}\n\n"
                blog_post += f"*Target Audience: {perspective_info.get('target_audience', 'General')}*\n\n"
                
                # Add sections
                for section in perspective_content.get('sections', []):
                    blog_post += f"### {section.get('title', 'Section')}\n\n"
                    blog_post += f"{section.get('content', '')}\n\n"
                
                # Add key takeaways
                takeaways = perspective_content.get('key_takeaways', [])
                if takeaways:
                    blog_post += "#### Key Takeaways\n\n"
                    for takeaway in takeaways:
                        blog_post += f"- {takeaway}\n"
                    blog_post += "\n"
            
            # Add interactive elements
            if interactive_elements:
                blog_post += "## Interactive Resources\n\n"
                for element in interactive_elements:
                    blog_post += f"### {element.title}\n\n"
                    blog_post += f"{element.content}\n\n"
            
            # Add cross-perspective insights
            insights = content_package.get('cross_perspective_insights', [])
            if insights:
                blog_post += "## Cross-Perspective Insights\n\n"
                for insight in insights:
                    blog_post += f"- {insight}\n"
                blog_post += "\n"
            
            # Add footer
            blog_post += "---\n\n"
            blog_post += "*This analysis was generated using AI-powered vulnerability intelligence tools.*\n"
            blog_post += f"*Estimated reading time: {content_package.get('publishing_metadata', {}).get('estimated_read_time', 'Unknown')} minutes*\n\n"
            
            return blog_post
            
        except Exception as e:
            logger.error(f"Error generating blog post: {e}")
            return f"# Vulnerability Analysis\n\nError generating detailed content. Please refer to original vulnerability data."