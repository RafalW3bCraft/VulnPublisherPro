"""
HackerOne API scraper
API Documentation: https://api.hackerone.com/v1/
Enhanced with industry-level disclosure format parsing
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import base64
from .base import BaseScraper
from .disclosure_formats import DisclosureFormatManager, VulnerabilityDisclosure
import logging

logger = logging.getLogger(__name__)

class HackerOneScraper(BaseScraper):
    """Scraper for HackerOne bug bounty platform"""
    
    def __init__(self, config):
        super().__init__(config, 'hackerone')
        self.base_url = "https://api.hackerone.com/v1"
        self.username = config.hackerone_username
        self.token = config.hackerone_token
        self.disclosure_manager = DisclosureFormatManager()
        
        # HackerOne rate limits vary by endpoint
        self.rate_limit_delay = 1.0
    
    async def scrape(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Scrape disclosed reports from HackerOne"""
        if not self.username or not self.token:
            logger.warning("HackerOne credentials not configured, skipping")
            return []
        
        vulnerabilities = []
        
        try:
            # Create authorization header
            auth_string = f"{self.username}:{self.token}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            headers = {
                'Authorization': f'Basic {auth_b64}',
                'Accept': 'application/json'
            }
            
            # Get disclosed reports from hacktivity feed
            params = {
                'page[size]': min(limit or 100, 100),
                'filter[disclosed_at]': f'{(datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")}..{datetime.now().strftime("%Y-%m-%d")}',
                'sort': '-disclosed_at'
            }
            
            page_number = 1
            
            while True:
                params['page[number]'] = page_number
                
                logger.info(f"Fetching HackerOne reports page {page_number}")
                
                response = await self.make_request(
                    url=f"{self.base_url}/hacktivity",
                    params=params,
                    headers=headers
                )
                
                if not response or 'data' not in response:
                    logger.error("Failed to get response from HackerOne API")
                    break
                
                reports = response['data']
                
                if not reports:
                    logger.info("No more reports found")
                    break
                
                logger.info(f"Processing {len(reports)} reports from HackerOne")
                
                for report in reports:
                    try:
                        # Parse using disclosure format manager
                        disclosure = self.disclosure_manager.parse_disclosure('hackerone', report)
                        if disclosure:
                            # Convert to legacy format for compatibility
                            vuln = self._disclosure_to_dict(disclosure)
                            vulnerabilities.append(vuln)
                            
                            # Check limit
                            if limit and len(vulnerabilities) >= limit:
                                logger.info(f"Reached limit of {limit} vulnerabilities")
                                return vulnerabilities
                                
                    except Exception as e:
                        logger.error(f"Error parsing report: {e}")
                        continue
                
                # Check if we have more pages
                if 'links' not in response or 'next' not in response['links']:
                    break
                
                page_number += 1
            
            logger.info(f"Scraped {len(vulnerabilities)} vulnerabilities from HackerOne")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scraping HackerOne: {e}")
            return []
        finally:
            await self.close_session()
    
    def _parse_report(self, report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single report from HackerOne format"""
        try:
            attributes = report.get('attributes', {})
            relationships = report.get('relationships', {})
            
            # Basic report information
            report_id = report.get('id', '')
            title = attributes.get('title', '')
            
            # Get vulnerability types
            vulnerability_types = []
            if 'vulnerability_types' in relationships:
                for vtype in relationships['vulnerability_types'].get('data', []):
                    vulnerability_types.append(vtype.get('attributes', {}).get('name', ''))
            
            # Get severity
            severity_data = attributes.get('severity_rating', '')
            severity = self._map_severity(severity_data)
            
            # Get CVSS score if available
            cvss_score = None
            if 'cvss_score' in attributes:
                cvss_score = attributes['cvss_score']
            
            # Get program information
            program_name = ''
            if 'program' in relationships:
                program_data = relationships['program'].get('data', {})
                if program_data:
                    program_name = program_data.get('attributes', {}).get('name', '')
            
            # Get bounty amount
            bounty_amount = attributes.get('bounty_awarded_at')
            
            # Get reporter information
            reporter = ''
            if 'reporter' in relationships:
                reporter_data = relationships['reporter'].get('data', {})
                if reporter_data:
                    reporter = reporter_data.get('attributes', {}).get('username', '')
            
            # Create description
            description = title
            if vulnerability_types:
                description += f"\n\nVulnerability Types: {', '.join(vulnerability_types)}"
            if program_name:
                description += f"\nProgram: {program_name}"
            if reporter:
                description += f"\nReported by: {reporter}"
            
            # Get URLs
            report_url = f"https://hackerone.com/reports/{report_id}"
            
            return self.create_vulnerability_dict(
                vulnerability_id=f"H1-{report_id}",
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                affected_products=[program_name] if program_name else [],
                references=[report_url],
                published_date=attributes.get('disclosed_at'),
                updated_date=attributes.get('last_activity_at'),
                source_url=report_url,
                tags=['hackerone', 'bug_bounty'] + vulnerability_types + ([reporter] if reporter else []),
                raw_data=report
            )
            
        except Exception as e:
            logger.error(f"Error parsing HackerOne report {report.get('id', 'unknown')}: {e}")
            return None
    
    def _disclosure_to_dict(self, disclosure: VulnerabilityDisclosure) -> Dict[str, Any]:
        """Convert disclosure format to legacy vulnerability dictionary"""
        description = disclosure.description
        if disclosure.researcher:
            description += f"\n\nReported by: {disclosure.researcher}"
        if disclosure.bounty_amount:
            description += f"\nBounty: ${disclosure.bounty_amount:,.0f}"
        if disclosure.steps_to_reproduce:
            description += f"\n\nSteps to Reproduce:\n{disclosure.steps_to_reproduce}"
        if disclosure.impact:
            description += f"\n\nImpact:\n{disclosure.impact}"
        
        return self.create_vulnerability_dict(
            vulnerability_id=f"H1-{disclosure.disclosure_id}",
            title=disclosure.title,
            description=description,
            severity=disclosure.severity,
            cvss_score=disclosure.cvss_score,
            cve_id=disclosure.cve_id,
            affected_products=[disclosure.program] if disclosure.program else [],
            references=[f"https://hackerone.com/reports/{disclosure.disclosure_id}"],
            published_date=disclosure.disclosure_date.isoformat() if disclosure.disclosure_date else None,
            source_url=f"https://hackerone.com/reports/{disclosure.disclosure_id}",
            tags=['hackerone', 'bug_bounty', disclosure.severity] + (
                [disclosure.vulnerability_type] if disclosure.vulnerability_type else []
            ),
            raw_data=disclosure.raw_data,
            exploit_available=disclosure.bounty_amount is not None,
            # Additional HackerOne-specific fields
            additional_data={
                'disclosure_format': 'hackerone_v1',
                'bounty_amount': disclosure.bounty_amount,
                'researcher': disclosure.researcher,
                'program': disclosure.program,
                'vulnerability_type': disclosure.vulnerability_type,
                'affected_domains': disclosure.affected_domains,
                'timeline': disclosure.timeline,
                'attachments': disclosure.attachments
            }
        )
    
    def _map_severity(self, severity: str) -> str:
        """Map HackerOne severity to standard levels"""
        if not severity:
            return 'unknown'
        
        severity_map = {
            'none': 'low',
            'low': 'low',
            'medium': 'medium',
            'high': 'high',
            'critical': 'critical'
        }
        
        return severity_map.get(severity.lower(), 'unknown')
    
    async def get_report_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific report by ID"""
        if not self.username or not self.token:
            return None
        
        try:
            auth_string = f"{self.username}:{self.token}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            headers = {
                'Authorization': f'Basic {auth_b64}',
                'Accept': 'application/json'
            }
            
            url = f"{self.base_url}/reports/{report_id}"
            response = await self.make_request(url=url, headers=headers)
            
            if response and 'data' in response:
                return self._parse_report(response['data'])
            
        except Exception as e:
            logger.error(f"Error getting report {report_id} from HackerOne: {e}")
        
        return None
    
    async def get_program_reports(self, program_handle: str) -> List[Dict[str, Any]]:
        """Get disclosed reports for a specific program"""
        if not self.username or not self.token:
            return []
        
        try:
            auth_string = f"{self.username}:{self.token}"
            auth_bytes = auth_string.encode('ascii')
            auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
            
            headers = {
                'Authorization': f'Basic {auth_b64}',
                'Accept': 'application/json'
            }
            
            params = {
                'filter[program]': program_handle,
                'filter[state]': 'disclosed',
                'sort': '-disclosed_at'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/hacktivity",
                params=params,
                headers=headers
            )
            
            if response and 'data' in response:
                vulnerabilities = []
                for report in response['data']:
                    vuln = self._parse_report(report)
                    if vuln:
                        vulnerabilities.append(vuln)
                return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error getting reports for program {program_handle}: {e}")
        
        return []
