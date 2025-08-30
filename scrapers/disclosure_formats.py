"""
Industry-level disclosure format parsers for vulnerability platforms
Each platform has its own disclosure structure and data format
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime
import re
import logging

logger = logging.getLogger(__name__)

@dataclass
class DisclosureField:
    """Represents a field in a vulnerability disclosure"""
    name: str
    value: Any
    source: str
    confidence: float = 1.0

@dataclass
class VulnerabilityDisclosure:
    """Standardized vulnerability disclosure format"""
    platform: str
    disclosure_id: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float]
    cve_id: Optional[str]
    disclosure_date: Optional[datetime]
    bounty_amount: Optional[float]
    researcher: Optional[str]
    program: Optional[str]
    affected_domains: List[str]
    vulnerability_type: Optional[str]
    steps_to_reproduce: Optional[str]
    impact: Optional[str]
    remediation: Optional[str]
    timeline: List[Dict[str, Any]]
    attachments: List[Dict[str, str]]
    raw_data: Dict[str, Any]

class HackerOneDisclosureParser:
    """Parser for HackerOne disclosure format"""
    
    @staticmethod
    def parse(report_data: Dict[str, Any]) -> VulnerabilityDisclosure:
        """Parse HackerOne report data into standardized disclosure format"""
        attributes = report_data.get('attributes', {})
        relationships = report_data.get('relationships', {})
        
        # Extract timeline from activities
        timeline = []
        if 'activities' in relationships:
            for activity in relationships['activities'].get('data', []):
                if activity.get('attributes'):
                    timeline.append({
                        'date': activity['attributes'].get('created_at'),
                        'action': activity['attributes'].get('type'),
                        'details': activity['attributes'].get('message', '')
                    })
        
        # Extract bounty information
        bounty_amount = None
        if 'bounties' in relationships:
            bounties = relationships['bounties'].get('data', [])
            if bounties:
                bounty_amount = sum(float(b.get('attributes', {}).get('amount', 0)) for b in bounties)
        
        # Extract researcher information
        researcher = None
        if 'reporter' in relationships:
            reporter_data = relationships['reporter'].get('data', {})
            if reporter_data.get('attributes'):
                researcher = reporter_data['attributes'].get('username')
        
        # Extract program information
        program = None
        if 'program' in relationships:
            program_data = relationships['program'].get('data', {})
            if program_data.get('attributes'):
                program = program_data['attributes'].get('name')
        
        return VulnerabilityDisclosure(
            platform='hackerone',
            disclosure_id=report_data.get('id', ''),
            title=attributes.get('title', ''),
            description=attributes.get('vulnerability_information', ''),
            severity=attributes.get('severity_rating', 'unknown').lower(),
            cvss_score=attributes.get('cvss_score'),
            cve_id=HackerOneDisclosureParser._extract_cve(attributes.get('cve_ids', [])),
            disclosure_date=HackerOneDisclosureParser._parse_date(attributes.get('disclosed_at')),
            bounty_amount=bounty_amount,
            researcher=researcher,
            program=program,
            affected_domains=HackerOneDisclosureParser._extract_domains(attributes.get('structured_scope')),
            vulnerability_type=attributes.get('weakness', {}).get('name'),
            steps_to_reproduce=attributes.get('steps_to_reproduce'),
            impact=attributes.get('impact'),
            remediation=attributes.get('suggested_remediation_actions'),
            timeline=timeline,
            attachments=HackerOneDisclosureParser._extract_attachments(relationships.get('attachments', {})),
            raw_data=report_data
        )
    
    @staticmethod
    def _extract_cve(cve_list: List[str]) -> Optional[str]:
        """Extract CVE ID from list"""
        return cve_list[0] if cve_list else None
    
    @staticmethod
    def _parse_date(date_str: str) -> Optional[datetime]:
        """Parse HackerOne date format"""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except:
            return None
    
    @staticmethod
    def _extract_domains(structured_scope) -> List[str]:
        """Extract affected domains from structured scope"""
        domains = []
        if structured_scope and isinstance(structured_scope, list):
            for scope_item in structured_scope:
                if scope_item.get('asset_identifier'):
                    domains.append(scope_item['asset_identifier'])
        return domains
    
    @staticmethod
    def _extract_attachments(attachments_data: Dict) -> List[Dict[str, str]]:
        """Extract attachment information"""
        attachments = []
        if 'data' in attachments_data:
            for attachment in attachments_data['data']:
                if attachment.get('attributes'):
                    attrs = attachment['attributes']
                    attachments.append({
                        'filename': attrs.get('filename', ''),
                        'content_type': attrs.get('content_type', ''),
                        'file_size': str(attrs.get('file_size', 0)),
                        'expiring_url': attrs.get('expiring_url', '')
                    })
        return attachments

class BugcrowdDisclosureParser:
    """Parser for Bugcrowd disclosure format"""
    
    @staticmethod
    def parse(submission_data: Dict[str, Any]) -> VulnerabilityDisclosure:
        """Parse Bugcrowd submission data into standardized disclosure format"""
        attributes = submission_data.get('attributes', {})
        
        # Extract timeline from status changes
        timeline = []
        if 'status_transitions' in attributes:
            for transition in attributes['status_transitions']:
                timeline.append({
                    'date': transition.get('transitioned_at'),
                    'action': f"Status changed to {transition.get('to_status')}",
                    'details': transition.get('message', '')
                })
        
        # Extract bounty information
        bounty_amount = None
        if 'bounty' in attributes and attributes['bounty']:
            bounty_amount = float(attributes['bounty'].get('amount', 0))
        
        return VulnerabilityDisclosure(
            platform='bugcrowd',
            disclosure_id=submission_data.get('id', ''),
            title=attributes.get('title', ''),
            description=attributes.get('description', ''),
            severity=attributes.get('priority', 'unknown').lower(),
            cvss_score=attributes.get('cvss_score'),
            cve_id=attributes.get('cve_id'),
            disclosure_date=BugcrowdDisclosureParser._parse_date(attributes.get('disclosed_at')),
            bounty_amount=bounty_amount,
            researcher=attributes.get('researcher', {}).get('username'),
            program=attributes.get('target', {}).get('name'),
            affected_domains=BugcrowdDisclosureParser._extract_domains(attributes.get('target', {})),
            vulnerability_type=attributes.get('vulnerability_category'),
            steps_to_reproduce=attributes.get('proof_of_concept'),
            impact=attributes.get('business_impact'),
            remediation=attributes.get('remediation_advice'),
            timeline=timeline,
            attachments=BugcrowdDisclosureParser._extract_attachments(attributes.get('attachments', [])),
            raw_data=submission_data
        )
    
    @staticmethod
    def _parse_date(date_str: str) -> Optional[datetime]:
        """Parse Bugcrowd date format"""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except:
            return None
    
    @staticmethod
    def _extract_domains(target_data: Dict) -> List[str]:
        """Extract affected domains from target data"""
        domains = []
        if target_data.get('url'):
            domains.append(target_data['url'])
        if target_data.get('in_scope_urls'):
            domains.extend(target_data['in_scope_urls'])
        return domains
    
    @staticmethod
    def _extract_attachments(attachments_list: List) -> List[Dict[str, str]]:
        """Extract attachment information"""
        attachments = []
        for attachment in attachments_list:
            attachments.append({
                'filename': attachment.get('filename', ''),
                'content_type': attachment.get('content_type', ''),
                'file_size': str(attachment.get('size', 0)),
                'url': attachment.get('url', '')
            })
        return attachments

class ExploitDBDisclosureParser:
    """Parser for Exploit-DB disclosure format"""
    
    @staticmethod
    def parse(exploit_data: Dict[str, Any]) -> VulnerabilityDisclosure:
        """Parse Exploit-DB data into standardized disclosure format"""
        
        # Extract CVE from description or title
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cve_match = re.search(cve_pattern, exploit_data.get('description', '') + exploit_data.get('title', ''))
        cve_id = cve_match.group(0) if cve_match else None
        
        # Extract affected platforms
        platforms = []
        if exploit_data.get('platform'):
            platforms = [exploit_data['platform']]
        
        return VulnerabilityDisclosure(
            platform='exploit_db',
            disclosure_id=str(exploit_data.get('edb_id', '')),
            title=exploit_data.get('title', ''),
            description=exploit_data.get('description', ''),
            severity=ExploitDBDisclosureParser._determine_severity(exploit_data),
            cvss_score=None,  # Exploit-DB doesn't provide CVSS scores
            cve_id=cve_id,
            disclosure_date=ExploitDBDisclosureParser._parse_date(exploit_data.get('date_published') or ''),
            bounty_amount=None,  # No bounty information in Exploit-DB
            researcher=exploit_data.get('author'),
            program=None,  # No program information in Exploit-DB
            affected_domains=platforms,
            vulnerability_type=exploit_data.get('type'),
            steps_to_reproduce=exploit_data.get('exploit_code'),
            impact=ExploitDBDisclosureParser._extract_impact(exploit_data),
            remediation=None,  # Usually not provided in Exploit-DB
            timeline=[{
                'date': exploit_data.get('date_published'),
                'action': 'exploit_published',
                'details': f"Exploit published by {exploit_data.get('author', 'unknown')}"
            }],
            attachments=ExploitDBDisclosureParser._extract_attachments(exploit_data),
            raw_data=exploit_data
        )
    
    @staticmethod
    def _determine_severity(exploit_data: Dict) -> str:
        """Determine severity based on exploit type and description"""
        exploit_type = exploit_data.get('type', '').lower()
        description = exploit_data.get('description', '').lower()
        
        # High severity indicators
        if any(keyword in exploit_type or keyword in description for keyword in [
            'remote', 'rce', 'code execution', 'privilege escalation', 'buffer overflow'
        ]):
            return 'high'
        
        # Medium severity indicators
        if any(keyword in exploit_type or keyword in description for keyword in [
            'sql injection', 'xss', 'csrf', 'directory traversal'
        ]):
            return 'medium'
        
        # Default to medium for any exploit
        return 'medium'
    
    @staticmethod
    def _parse_date(date_str: str) -> Optional[datetime]:
        """Parse Exploit-DB date format"""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, '%Y-%m-%d')
        except:
            return None
    
    @staticmethod
    def _extract_impact(exploit_data: Dict) -> str:
        """Extract impact information from exploit data"""
        impact_parts = []
        if exploit_data.get('type'):
            impact_parts.append(f"Type: {exploit_data['type']}")
        if exploit_data.get('platform'):
            impact_parts.append(f"Platform: {exploit_data['platform']}")
        
        return "; ".join(impact_parts) if impact_parts else "Code execution possible"
    
    @staticmethod
    def _extract_attachments(exploit_data: Dict) -> List[Dict[str, str]]:
        """Extract attachment information"""
        attachments = []
        if exploit_data.get('file_path'):
            attachments.append({
                'filename': exploit_data.get('file_name', 'exploit'),
                'content_type': 'text/plain',
                'file_size': '0',
                'url': f"https://www.exploit-db.com/exploits/{exploit_data.get('edb_id')}"
            })
        return attachments

class DisclosureFormatManager:
    """Manager for handling different disclosure formats"""
    
    def __init__(self):
        self.parsers = {
            'hackerone': HackerOneDisclosureParser,
            'bugcrowd': BugcrowdDisclosureParser,
            'exploit_db': ExploitDBDisclosureParser
        }
    
    def parse_disclosure(self, platform: str, raw_data: Dict[str, Any]) -> Optional[VulnerabilityDisclosure]:
        """Parse raw data into standardized disclosure format"""
        parser = self.parsers.get(platform.lower())
        if not parser:
            logger.warning(f"No parser available for platform: {platform}")
            return None
        
        try:
            return parser.parse(raw_data)
        except Exception as e:
            logger.error(f"Error parsing {platform} disclosure: {e}")
            return None
    
    def get_supported_platforms(self) -> List[str]:
        """Get list of supported platforms"""
        return list(self.parsers.keys())
    
    def format_for_publication(self, disclosure: VulnerabilityDisclosure, format_type: str = 'summary') -> Dict[str, Any]:
        """Format disclosure for publication"""
        if format_type == 'summary':
            return self._format_summary(disclosure)
        elif format_type == 'detailed':
            return self._format_detailed(disclosure)
        elif format_type == 'report':
            return self._format_report(disclosure)
        else:
            raise ValueError(f"Unknown format type: {format_type}")
    
    def _format_summary(self, disclosure: VulnerabilityDisclosure) -> Dict[str, Any]:
        """Format as summary post"""
        bounty_text = f" | ${disclosure.bounty_amount:,.0f} bounty" if disclosure.bounty_amount else ""
        
        content = f"""🚨 {disclosure.severity.upper()} Vulnerability Disclosure
        
{disclosure.title}

Platform: {disclosure.platform.title()}
Researcher: {disclosure.researcher or 'Unknown'}
Program: {disclosure.program or 'N/A'}{bounty_text}

{disclosure.description[:200]}{'...' if len(disclosure.description) > 200 else ''}

#CyberSecurity #{disclosure.platform.title()} #VulnerabilityDisclosure"""
        
        return {
            'content': content,
            'title': disclosure.title,
            'platform': disclosure.platform,
            'severity': disclosure.severity,
            'hashtags': ['CyberSecurity', disclosure.platform.title(), 'VulnerabilityDisclosure']
        }
    
    def _format_detailed(self, disclosure: VulnerabilityDisclosure) -> Dict[str, Any]:
        """Format as detailed report"""
        content = f"""# {disclosure.title}

## Overview
**Platform:** {disclosure.platform.title()}
**Disclosure ID:** {disclosure.disclosure_id}
**Severity:** {disclosure.severity.upper()}
**CVE ID:** {disclosure.cve_id or 'Not assigned'}
**Researcher:** {disclosure.researcher or 'Unknown'}
**Program:** {disclosure.program or 'N/A'}

## Description
{disclosure.description}

## Technical Details
**Vulnerability Type:** {disclosure.vulnerability_type or 'Not specified'}
**Affected Domains:** {', '.join(disclosure.affected_domains) if disclosure.affected_domains else 'Not specified'}

## Steps to Reproduce
{disclosure.steps_to_reproduce or 'Not provided'}

## Impact
{disclosure.impact or 'Not specified'}

## Timeline
"""
        
        for event in disclosure.timeline:
            content += f"- **{event['date']}:** {event['action']} - {event['details']}\n"
        
        if disclosure.bounty_amount:
            content += f"\n## Bounty Information\n**Amount:** ${disclosure.bounty_amount:,.0f}"
        
        return {
            'content': content,
            'title': disclosure.title,
            'platform': disclosure.platform,
            'severity': disclosure.severity,
            'tags': ['vulnerability', 'cybersecurity', disclosure.platform, disclosure.severity]
        }
    
    def _format_report(self, disclosure: VulnerabilityDisclosure) -> Dict[str, Any]:
        """Format as formal vulnerability report"""
        report = {
            'executive_summary': f"A {disclosure.severity} severity vulnerability was disclosed on {disclosure.platform.title()} affecting {disclosure.program or 'multiple systems'}.",
            'vulnerability_details': {
                'id': disclosure.disclosure_id,
                'cve_id': disclosure.cve_id,
                'title': disclosure.title,
                'severity': disclosure.severity,
                'type': disclosure.vulnerability_type,
                'cvss_score': disclosure.cvss_score
            },
            'affected_systems': disclosure.affected_domains,
            'technical_description': disclosure.description,
            'reproduction_steps': disclosure.steps_to_reproduce,
            'impact_analysis': disclosure.impact,
            'remediation': disclosure.remediation,
            'disclosure_timeline': disclosure.timeline,
            'researcher_info': {
                'name': disclosure.researcher,
                'platform': disclosure.platform
            },
            'bounty_amount': disclosure.bounty_amount,
            'raw_data': disclosure.raw_data
        }
        
        return report