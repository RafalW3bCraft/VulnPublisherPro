"""
Industry-level publication formats for different platforms
Creates professional disclosure posts optimized for platform algorithms
Enhanced with AI-powered content generation and user review capabilities
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime
import json
import logging
import asyncio
from scrapers.disclosure_formats import VulnerabilityDisclosure, DisclosureFormatManager

logger = logging.getLogger(__name__)

@dataclass
class PlatformAlgorithmOptimization:
    """Platform-specific algorithm optimization parameters"""
    platform: str
    character_limit: Optional[int]
    optimal_hashtag_count: int
    engagement_triggers: List[str]
    posting_times: List[str]
    content_structure: str
    viral_factors: List[str]
    
@dataclass
class PublicationTemplate:
    """Template for publishing vulnerability disclosures"""
    platform: str
    format_type: str
    title_template: str
    content_template: str
    hashtags: List[str]
    character_limit: Optional[int] = None
    algorithm_optimization: Optional[PlatformAlgorithmOptimization] = None
    
class HackerOnePublicationFormat:
    """HackerOne disclosure publication format"""
    
    @staticmethod
    def create_summary_post(disclosure: VulnerabilityDisclosure) -> Dict[str, Any]:
        """Create a HackerOne summary post"""
        bounty_emoji = "💰" if disclosure.bounty_amount else "🔍"
        severity_emoji = {
            'critical': '🔴',
            'high': '🟠', 
            'medium': '🟡',
            'low': '🟢'
        }.get(disclosure.severity, '⚪')
        
        title = f"{severity_emoji} HackerOne Disclosure: {disclosure.title[:80]}..."
        
        content = f"""{severity_emoji} **HackerOne Disclosure Alert**

**Title:** {disclosure.title}
**Severity:** {disclosure.severity.upper()}
**Program:** {disclosure.program or 'Undisclosed'}
**Researcher:** @{disclosure.researcher or 'anonymous'}

{bounty_emoji} **Bounty:** ${disclosure.bounty_amount:,.0f} USD awarded!

**Summary:**
{disclosure.description[:300]}{'...' if len(disclosure.description) > 300 else ''}

**Affected Domain:** {', '.join(disclosure.affected_domains[:3]) if disclosure.affected_domains else 'Multiple'}

🔗 **Report:** https://hackerone.com/reports/{disclosure.disclosure_id}

#HackerOne #BugBounty #CyberSecurity #{disclosure.severity.title()}Severity #VulnDisclosure"""

        return {
            'title': title,
            'content': content,
            'platform': 'hackerone',
            'format_type': 'summary',
            'hashtags': ['HackerOne', 'BugBounty', 'CyberSecurity', f'{disclosure.severity.title()}Severity'],
            'metadata': {
                'bounty_amount': disclosure.bounty_amount,
                'researcher': disclosure.researcher,
                'program': disclosure.program,
                'report_url': f'https://hackerone.com/reports/{disclosure.disclosure_id}'
            }
        }
    
    @staticmethod
    def create_detailed_report(disclosure: VulnerabilityDisclosure) -> Dict[str, Any]:
        """Create a detailed HackerOne disclosure report"""
        title = f"[DETAILED] {disclosure.title} - HackerOne Bug Bounty Analysis"
        
        # Build timeline section
        timeline_section = ""
        if disclosure.timeline:
            timeline_section = "\n## 📅 **Disclosure Timeline**\n"
            for event in disclosure.timeline:
                timeline_section += f"- **{event['date']}:** {event['action']} - {event['details']}\n"
        
        # Build attachments section
        attachments_section = ""
        if disclosure.attachments:
            attachments_section = "\n## 📎 **Evidence & Attachments**\n"
            for attachment in disclosure.attachments:
                attachments_section += f"- {attachment['filename']} ({attachment['content_type']})\n"
        
        content = f"""# 🛡️ HackerOne Security Disclosure Analysis

## 📋 **Executive Summary**
**Report ID:** {disclosure.disclosure_id}
**Severity:** {disclosure.severity.upper()}
**CVE ID:** {disclosure.cve_id or 'Pending Assignment'}
**CVSS Score:** {disclosure.cvss_score or 'Not Available'}

## 🎯 **Program Information** 
**Target Program:** {disclosure.program or 'Confidential Program'}
**Researcher:** @{disclosure.researcher or 'Anonymous Researcher'}
**Disclosure Date:** {disclosure.disclosure_date.strftime('%Y-%m-%d') if disclosure.disclosure_date else 'Unknown'}

## 💰 **Bounty Information**
**Award Amount:** ${disclosure.bounty_amount:,.0f} USD
**Recognition:** Hall of Fame + Financial Reward

## 🔍 **Vulnerability Details**
**Type:** {disclosure.vulnerability_type or 'Not Specified'}
**Affected Assets:** {', '.join(disclosure.affected_domains) if disclosure.affected_domains else 'Multiple systems'}

### Description
{disclosure.description}

### Impact Assessment
{disclosure.impact or 'Impact details provided in original report'}

## 🔬 **Technical Analysis**
{disclosure.steps_to_reproduce or 'Detailed steps provided in original HackerOne report'}

## 🛠️ **Remediation**
{disclosure.remediation or 'Remediation steps coordinated with security team'}

{timeline_section}

{attachments_section}

## 🔗 **References**
- **Original Report:** https://hackerone.com/reports/{disclosure.disclosure_id}
- **HackerOne Program:** https://hackerone.com/{disclosure.program or 'program'}

---
*This analysis is based on publicly disclosed HackerOne reports. All credit goes to the original researcher and the responsible disclosure process.*

#HackerOne #BugBountyAnalysis #CybersecurityResearch #VulnerabilityDisclosure #SecurityResearch"""

        return {
            'title': title,
            'content': content,
            'platform': 'hackerone',
            'format_type': 'detailed',
            'tags': ['vulnerability', 'hackerone', 'bug-bounty', 'security-analysis', disclosure.severity],
            'metadata': {
                'bounty_amount': disclosure.bounty_amount,
                'researcher': disclosure.researcher,
                'program': disclosure.program,
                'report_url': f'https://hackerone.com/reports/{disclosure.disclosure_id}',
                'analysis_type': 'detailed_disclosure'
            }
        }

class BugcrowdPublicationFormat:
    """Bugcrowd disclosure publication format"""
    
    @staticmethod
    def create_summary_post(disclosure: VulnerabilityDisclosure) -> Dict[str, Any]:
        """Create a Bugcrowd summary post"""
        severity_emoji = {
            'critical': '🔴',
            'high': '🟠', 
            'medium': '🟡',
            'low': '🟢'
        }.get(disclosure.severity, '⚪')
        
        title = f"{severity_emoji} Bugcrowd Disclosure: {disclosure.title[:80]}..."
        
        content = f"""{severity_emoji} **Bugcrowd Security Disclosure**

**Title:** {disclosure.title}
**Priority:** {disclosure.severity.upper()}
**Target:** {disclosure.program or 'Confidential'}
**Hunter:** @{disclosure.researcher or 'anonymous'}

💸 **Bounty:** ${disclosure.bounty_amount:,.0f} awarded!

**Vulnerability Type:** {disclosure.vulnerability_type or 'Not specified'}

**Brief:**
{disclosure.description[:250]}{'...' if len(disclosure.description) > 250 else ''}

**Impact:** {disclosure.impact[:100] if disclosure.impact else 'See full disclosure'}

🔗 **Submission:** https://bugcrowd.com/submissions/{disclosure.disclosure_id}

#Bugcrowd #CrowdsourcedSecurity #VulnResearch #{disclosure.severity.title()}Priority #CyberSecurity"""

        return {
            'title': title,
            'content': content,
            'platform': 'bugcrowd',
            'format_type': 'summary',
            'hashtags': ['Bugcrowd', 'CrowdsourcedSecurity', 'VulnResearch', f'{disclosure.severity.title()}Priority'],
            'metadata': {
                'bounty_amount': disclosure.bounty_amount,
                'researcher': disclosure.researcher,
                'program': disclosure.program,
                'submission_url': f'https://bugcrowd.com/submissions/{disclosure.disclosure_id}'
            }
        }
    
    @staticmethod
    def create_detailed_report(disclosure: VulnerabilityDisclosure) -> Dict[str, Any]:
        """Create a detailed Bugcrowd disclosure report"""
        title = f"[ANALYSIS] {disclosure.title} - Bugcrowd Security Research"
        
        content = f"""# 🔍 Bugcrowd Security Research Analysis

## 📊 **Disclosure Overview**
**Submission ID:** {disclosure.disclosure_id}
**Priority Rating:** {disclosure.severity.upper()}
**CVE Assignment:** {disclosure.cve_id or 'TBD'}

## 🎯 **Engagement Details**
**Target Program:** {disclosure.program or 'Private Program'}
**Security Researcher:** @{disclosure.researcher or 'Anonymous'}
**Disclosure Date:** {disclosure.disclosure_date.strftime('%B %d, %Y') if disclosure.disclosure_date else 'Not Available'}

## 💰 **Reward Information**
**Monetary Award:** ${disclosure.bounty_amount:,.0f}
**Recognition:** Public acknowledgment in Bugcrowd Hall of Fame

## 🔐 **Vulnerability Classification**
**Category:** {disclosure.vulnerability_type or 'Classified'}
**Affected Systems:** {', '.join(disclosure.affected_domains) if disclosure.affected_domains else 'Multiple components'}

### Technical Description
{disclosure.description}

### Proof of Concept
{disclosure.steps_to_reproduce or 'PoC details available in original submission'}

### Business Impact Analysis
{disclosure.impact or 'Impact assessment conducted with program team'}

## 🛡️ **Security Implications**
This vulnerability demonstrates the importance of continuous security testing and the value of crowdsourced security research through platforms like Bugcrowd.

## 📈 **Research Methodology**
The discovery follows responsible disclosure practices:
1. Initial discovery and validation
2. Detailed documentation and PoC development  
3. Responsible disclosure through Bugcrowd platform
4. Collaboration with security team for remediation
5. Public disclosure after remediation

## 🔗 **Additional Resources**
- **Original Submission:** https://bugcrowd.com/submissions/{disclosure.disclosure_id}
- **Bugcrowd Program:** https://bugcrowd.com/{disclosure.program or 'program'}

---
*Analysis based on publicly disclosed Bugcrowd submissions. Recognition to the security researcher and coordinated disclosure process.*

#Bugcrowd #SecurityResearch #VulnerabilityDisclosure #CrowdsourcedSecurity #ResponsibleDisclosure"""

        return {
            'title': title,
            'content': content,
            'platform': 'bugcrowd',
            'format_type': 'detailed',
            'tags': ['vulnerability', 'bugcrowd', 'security-research', 'disclosure', disclosure.severity],
            'metadata': {
                'bounty_amount': disclosure.bounty_amount,
                'researcher': disclosure.researcher,
                'program': disclosure.program,
                'submission_url': f'https://bugcrowd.com/submissions/{disclosure.disclosure_id}'
            }
        }

class ExploitDBPublicationFormat:
    """Exploit-DB publication format"""
    
    @staticmethod
    def create_summary_post(disclosure: VulnerabilityDisclosure) -> Dict[str, Any]:
        """Create an Exploit-DB summary post"""
        severity_emoji = {
            'critical': '🔴',
            'high': '🟠', 
            'medium': '🟡',
            'low': '🟢'
        }.get(disclosure.severity, '⚪')
        
        title = f"{severity_emoji} Exploit-DB: {disclosure.title[:70]}..."
        
        content = f"""{severity_emoji} **Exploit-DB Publication Alert**

**EDB-ID:** {disclosure.disclosure_id}
**Title:** {disclosure.title}
**Type:** {disclosure.vulnerability_type or 'Exploit'}
**Author:** {disclosure.researcher or 'Anonymous'}

**CVE:** {disclosure.cve_id or 'Not assigned'}
**Severity:** {disclosure.severity.upper()}

**Target Platform:** {', '.join(disclosure.affected_domains) if disclosure.affected_domains else 'Multiple'}

💀 **Exploit Available:** Public PoC code released

**Description:**
{disclosure.description[:200]}{'...' if len(disclosure.description) > 200 else ''}

⚠️ **Impact:** {disclosure.impact or 'Code execution possible on vulnerable systems'}

🔗 **Exploit:** https://www.exploit-db.com/exploits/{disclosure.disclosure_id}

#ExploitDB #Exploit #SecurityResearch #{disclosure.severity.title()}Risk #CyberThreat"""

        return {
            'title': title,
            'content': content,
            'platform': 'exploit_db',
            'format_type': 'summary',
            'hashtags': ['ExploitDB', 'Exploit', 'SecurityResearch', f'{disclosure.severity.title()}Risk'],
            'metadata': {
                'edb_id': disclosure.disclosure_id,
                'author': disclosure.researcher,
                'exploit_url': f'https://www.exploit-db.com/exploits/{disclosure.disclosure_id}',
                'vulnerability_type': disclosure.vulnerability_type
            }
        }
    
    @staticmethod
    def create_detailed_report(disclosure: VulnerabilityDisclosure) -> Dict[str, Any]:
        """Create a detailed Exploit-DB analysis report"""
        title = f"[EXPLOIT ANALYSIS] {disclosure.title} - EDB-{disclosure.disclosure_id}"
        
        content = f"""# ⚠️ Exploit-DB Security Alert & Analysis

## 🎯 **Exploit Information**
**EDB-ID:** {disclosure.disclosure_id}
**Publication Date:** {disclosure.disclosure_date.strftime('%Y-%m-%d') if disclosure.disclosure_date else 'Unknown'}
**CVE Reference:** {disclosure.cve_id or 'Not Assigned'}

## 👨‍💻 **Research Credit**
**Author:** {disclosure.researcher or 'Anonymous Researcher'}
**Contribution:** Public exploit development and disclosure

## 🔍 **Vulnerability Details**
**Type:** {disclosure.vulnerability_type or 'Security Vulnerability'}
**Severity Assessment:** {disclosure.severity.upper()}
**Affected Platforms:** {', '.join(disclosure.affected_domains) if disclosure.affected_domains else 'Multiple systems'}

### Technical Description
{disclosure.description}

## 💀 **Exploit Analysis**
**Availability:** Public exploit code available
**Complexity:** Varies (see exploit code)

### Exploitation Method
{disclosure.steps_to_reproduce or 'Detailed exploitation steps available in the exploit code'}

## 🎯 **Impact Assessment**
{disclosure.impact}

**Risk Level:** {disclosure.severity.upper()}
**Potential Consequences:**
- Unauthorized access to vulnerable systems
- Data compromise or system manipulation
- Service disruption or denial of service

## 🛡️ **Defensive Measures**
1. **Immediate Actions:**
   - Identify vulnerable systems in your environment
   - Apply security patches if available
   - Implement temporary mitigations

2. **Long-term Security:**
   - Regular vulnerability assessments
   - Continuous monitoring for exploitation attempts
   - Security awareness training

## 🔗 **Technical Resources**
- **Exploit Code:** https://www.exploit-db.com/exploits/{disclosure.disclosure_id}
- **CVE Details:** {f'https://cve.mitre.org/cgi-bin/cvename.cgi?name={disclosure.cve_id}' if disclosure.cve_id else 'CVE pending assignment'}

## ⚡ **Detection & Monitoring**
Security teams should monitor for:
- Unusual network traffic patterns
- Unauthorized access attempts
- System behavior anomalies consistent with this exploit

---
*This analysis is for educational and defensive purposes. Always ensure responsible disclosure and ethical security research.*

#ExploitDB #ThreatIntelligence #SecurityAnalysis #VulnerabilityResearch #CyberDefense"""

        return {
            'title': title,
            'content': content,
            'platform': 'exploit_db', 
            'format_type': 'detailed',
            'tags': ['exploit', 'security-analysis', 'threat-intelligence', 'vulnerability', disclosure.severity],
            'metadata': {
                'edb_id': disclosure.disclosure_id,
                'author': disclosure.researcher,
                'exploit_url': f'https://www.exploit-db.com/exploits/{disclosure.disclosure_id}',
                'threat_level': disclosure.severity
            }
        }

class UniversalPublicationManager:
    """Manager for creating publications across all platforms"""
    
    def __init__(self):
        self.formatters = {
            'hackerone': HackerOnePublicationFormat,
            'bugcrowd': BugcrowdPublicationFormat,
            'exploit_db': ExploitDBPublicationFormat
        }
        self.disclosure_manager = DisclosureFormatManager()
    
    def create_publication(self, disclosure: VulnerabilityDisclosure, format_type: str = 'summary') -> Dict[str, Any]:
        """Create a publication based on the disclosure platform and format type"""
        formatter = self.formatters.get(disclosure.platform)
        if not formatter:
            logger.warning(f"No formatter available for platform: {disclosure.platform}")
            return self._create_generic_publication(disclosure, format_type)
        
        try:
            if format_type == 'summary':
                return formatter.create_summary_post(disclosure)
            elif format_type == 'detailed':
                return formatter.create_detailed_report(disclosure)
            else:
                raise ValueError(f"Unknown format type: {format_type}")
        except Exception as e:
            logger.error(f"Error creating publication for {disclosure.platform}: {e}")
            return self._create_generic_publication(disclosure, format_type)
    
    def _create_generic_publication(self, disclosure: VulnerabilityDisclosure, format_type: str) -> Dict[str, Any]:
        """Create a generic publication when no specific formatter is available"""
        title = f"Security Disclosure: {disclosure.title}"
        
        if format_type == 'summary':
            content = f"""🔒 **Security Disclosure Alert**

**Title:** {disclosure.title}
**Platform:** {disclosure.platform.title()}
**Severity:** {disclosure.severity.upper()}
**Researcher:** {disclosure.researcher or 'Anonymous'}

**Summary:** {disclosure.description[:300]}

#CyberSecurity #VulnerabilityDisclosure #{disclosure.platform.title()}"""
        else:
            content = f"""# Security Disclosure Analysis

## Overview
**Title:** {disclosure.title}
**Platform:** {disclosure.platform.title()}
**Severity:** {disclosure.severity.upper()}

## Details
{disclosure.description}

## Impact
{disclosure.impact or 'Impact assessment pending'}

#SecurityAnalysis #VulnerabilityResearch"""
        
        return {
            'title': title,
            'content': content,
            'platform': disclosure.platform,
            'format_type': format_type,
            'hashtags': ['CyberSecurity', 'VulnerabilityDisclosure', disclosure.platform.title()]
        }
    
    def get_supported_platforms(self) -> List[str]:
        """Get list of supported platforms for publication"""
        return list(self.formatters.keys())
    
    def create_multi_platform_publication(self, disclosure: VulnerabilityDisclosure, format_type: str = 'summary') -> Dict[str, List[Dict[str, Any]]]:
        """Create publications for multiple social media platforms"""
        base_publication = self.create_publication(disclosure, format_type)
        
        platforms = {
            'twitter': self._adapt_for_twitter(base_publication),
            'linkedin': self._adapt_for_linkedin(base_publication),
            'medium': self._adapt_for_medium(base_publication),
            'telegram': self._adapt_for_telegram(base_publication),
            'discord': self._adapt_for_discord(base_publication)
        }
        
        return platforms
    
    def _adapt_for_twitter(self, publication: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt publication for Twitter's character limit"""
        content = publication['content']
        if len(content) > 280:
            # Truncate and add link to full report
            content = content[:250] + "... (more details in thread)"
        
        return {
            **publication,
            'content': content,
            'character_count': len(content),
            'platform': 'twitter'
        }
    
    def _adapt_for_linkedin(self, publication: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt publication for LinkedIn's professional audience"""
        return {
            **publication,
            'content': f"🔒 Professional Security Update\n\n{publication['content']}\n\n#LinkedInSecurity #ProfessionalDevelopment",
            'platform': 'linkedin'
        }
    
    def _adapt_for_medium(self, publication: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt publication for Medium's long-form content"""
        return {
            **publication,
            'platform': 'medium',
            'subtitle': f"Analysis of {publication.get('metadata', {}).get('researcher', 'security research')} disclosure"
        }
    
    def _adapt_for_telegram(self, publication: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt publication for Telegram channels"""
        return {
            **publication,
            'content': publication['content'].replace('**', '*').replace('##', '\n'),
            'platform': 'telegram'
        }
    
    def _adapt_for_discord(self, publication: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt publication for Discord communities"""
        return {
            **publication,
            'content': f"```\n🛡️ SECURITY ALERT\n```\n{publication['content']}",
            'platform': 'discord'
        }