"""
Intigriti API scraper
API Documentation: https://kb.intigriti.com/en/articles/6117846-intigriti-api
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .base import BaseScraper
import logging

logger = logging.getLogger(__name__)

class IntigritiScraper(BaseScraper):
    """Scraper for Intigriti bug bounty platform"""
    
    def __init__(self, config):
        super().__init__(config, 'intigriti')
        self.base_url = "https://api.intigriti.com/core"
        self.token = config.intigriti_token
        
        # Intigriti API rate limits
        self.rate_limit_delay = 1.0
    
    async def scrape(self, limit: int = None) -> List[Dict[str, Any]]:
        """Scrape disclosed submissions from Intigriti"""
        if not self.token:
            logger.warning("Intigriti token not configured, skipping")
            return []
        
        vulnerabilities = []
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            # Get disclosed submissions
            params = {
                'limit': min(limit or 100, 100),
                'offset': 0,
                'status': 'disclosed'
            }
            
            total_count = 0
            
            while True:
                logger.info(f"Fetching Intigriti submissions at offset {params['offset']}")
                
                response = await self.make_request(
                    url=f"{self.base_url}/submissions",
                    params=params,
                    headers=headers
                )
                
                if not response:
                    logger.error("Failed to get response from Intigriti API")
                    break
                
                # Handle different response formats
                if isinstance(response, dict):
                    submissions = response.get('data', response.get('submissions', []))
                    total_count = response.get('total', response.get('totalCount', 0))
                else:
                    submissions = response if isinstance(response, list) else []
                
                if not submissions:
                    logger.info("No more submissions found")
                    break
                
                logger.info(f"Processing {len(submissions)} submissions from Intigriti")
                
                for submission in submissions:
                    try:
                        vuln = self._parse_submission(submission)
                        if vuln:
                            vulnerabilities.append(vuln)
                            
                            # Check limit
                            if limit and len(vulnerabilities) >= limit:
                                logger.info(f"Reached limit of {limit} vulnerabilities")
                                return vulnerabilities
                                
                    except Exception as e:
                        logger.error(f"Error parsing submission: {e}")
                        continue
                
                # Check if we have more results
                next_offset = params['offset'] + len(submissions)
                if total_count > 0 and next_offset >= total_count:
                    break
                elif not submissions or len(submissions) < params['limit']:
                    break
                
                params['offset'] = next_offset
            
            logger.info(f"Scraped {len(vulnerabilities)} vulnerabilities from Intigriti")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scraping Intigriti: {e}")
            return []
        finally:
            await self.close_session()
    
    def _parse_submission(self, submission: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single submission from Intigriti format"""
        try:
            # Basic submission information
            submission_id = submission.get('id', submission.get('submissionId', ''))
            title = submission.get('title', submission.get('name', ''))
            description = submission.get('description', submission.get('details', ''))
            
            # Get severity/priority
            severity_data = submission.get('severity', submission.get('priority', ''))
            severity = self._map_severity(severity_data)
            
            # Get CVSS score if available
            cvss_score = submission.get('cvssScore', submission.get('cvss', {}).get('score'))
            
            # Get bounty amount
            bounty = submission.get('bounty', submission.get('reward'))
            
            # Get program information
            program_name = ''
            program_data = submission.get('program', submission.get('company'))
            if program_data:
                if isinstance(program_data, dict):
                    program_name = program_data.get('name', program_data.get('companyName', ''))
                else:
                    program_name = str(program_data)
            
            # Get researcher information
            researcher = ''
            researcher_data = submission.get('researcher', submission.get('user'))
            if researcher_data:
                if isinstance(researcher_data, dict):
                    researcher = researcher_data.get('username', researcher_data.get('name', ''))
                else:
                    researcher = str(researcher_data)
            
            # Get vulnerability type
            vuln_type = submission.get('type', submission.get('category', ''))
            
            # Create enhanced description
            full_description = description
            if vuln_type:
                full_description += f"\n\nVulnerability Type: {vuln_type}"
            if program_name:
                full_description += f"\nProgram: {program_name}"
            if researcher:
                full_description += f"\nResearcher: {researcher}"
            if bounty:
                full_description += f"\nBounty: €{bounty}"
            
            # Get submission URL
            submission_url = f"https://app.intigriti.com/submissions/{submission_id}"
            
            return self.create_vulnerability_dict(
                vulnerability_id=f"INT-{submission_id}",
                title=title,
                description=full_description,
                severity=severity,
                cvss_score=cvss_score,
                affected_products=[program_name] if program_name else [],
                references=[submission_url],
                published_date=submission.get('disclosedAt', submission.get('disclosed_at')),
                updated_date=submission.get('updatedAt', submission.get('updated_at')),
                source_url=submission_url,
                tags=['intigriti', 'bug_bounty'] + ([vuln_type] if vuln_type else []) + ([researcher] if researcher else []),
                raw_data=submission
            )
            
        except Exception as e:
            logger.error(f"Error parsing Intigriti submission {submission.get('id', 'unknown')}: {e}")
            return None
    
    def _map_severity(self, severity: Any) -> str:
        """Map Intigriti severity to standard levels"""
        if not severity:
            return 'unknown'
        
        severity_str = str(severity).lower()
        
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'low',
            'informational': 'low'
        }
        
        # Try direct mapping first
        mapped = severity_map.get(severity_str)
        if mapped:
            return mapped
        
        # Try numeric mapping
        if severity_str.isdigit():
            severity_num = int(severity_str)
            if severity_num >= 9:
                return 'critical'
            elif severity_num >= 7:
                return 'high'
            elif severity_num >= 4:
                return 'medium'
            else:
                return 'low'
        
        return 'unknown'
    
    async def get_submission_by_id(self, submission_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific submission by ID"""
        if not self.token:
            return None
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            url = f"{self.base_url}/submissions/{submission_id}"
            response = await self.make_request(url=url, headers=headers)
            
            if response:
                # Handle different response formats
                if isinstance(response, dict) and 'data' in response:
                    return self._parse_submission(response['data'])
                else:
                    return self._parse_submission(response)
            
        except Exception as e:
            logger.error(f"Error getting submission {submission_id} from Intigriti: {e}")
        
        return None
    
    async def get_program_submissions(self, program_id: str) -> List[Dict[str, Any]]:
        """Get disclosed submissions for a specific program"""
        if not self.token:
            return []
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            params = {
                'programId': program_id,
                'status': 'disclosed'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/submissions",
                params=params,
                headers=headers
            )
            
            if response:
                vulnerabilities = []
                submissions = response.get('data', response) if isinstance(response, dict) else response
                
                for submission in submissions:
                    vuln = self._parse_submission(submission)
                    if vuln:
                        vulnerabilities.append(vuln)
                return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error getting submissions for program {program_id}: {e}")
        
        return []
