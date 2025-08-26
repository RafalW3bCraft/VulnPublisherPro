"""
Bugcrowd API scraper
API Documentation: https://docs.bugcrowd.com/api/
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .base import BaseScraper
import logging

logger = logging.getLogger(__name__)

class BugcrowdScraper(BaseScraper):
    """Scraper for Bugcrowd bug bounty platform"""
    
    def __init__(self, config):
        super().__init__(config, 'bugcrowd')
        self.base_url = "https://api.bugcrowd.com"
        self.token = config.bugcrowd_token
        
        # Bugcrowd API rate limits
        self.rate_limit_delay = 1.0
    
    async def scrape(self, limit: int = None) -> List[Dict[str, Any]]:
        """Scrape disclosed submissions from Bugcrowd"""
        if not self.token:
            logger.warning("Bugcrowd token not configured, skipping")
            return []
        
        vulnerabilities = []
        
        try:
            headers = {
                'Authorization': f'Token {self.token}',
                'Accept': 'application/vnd.bugcrowd.v4+json'
            }
            
            # Get disclosed submissions
            params = {
                'page[limit]': min(limit or 100, 100),
                'page[offset]': 0,
                'filter[disclosure_state]': 'disclosed',
                'sort': '-submitted_at'
            }
            
            total_count = 0
            
            while True:
                logger.info(f"Fetching Bugcrowd submissions at offset {params['page[offset]']}")
                
                response = await self.make_request(
                    url=f"{self.base_url}/submissions",
                    params=params,
                    headers=headers
                )
                
                if not response or 'data' not in response:
                    logger.error("Failed to get response from Bugcrowd API")
                    break
                
                submissions = response['data']
                meta = response.get('meta', {})
                total_count = meta.get('total_hits', 0)
                
                if not submissions:
                    logger.info("No more submissions found")
                    break
                
                logger.info(f"Processing {len(submissions)} submissions from Bugcrowd")
                
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
                next_offset = params['page[offset]'] + len(submissions)
                if next_offset >= total_count or not submissions:
                    break
                
                params['page[offset]'] = next_offset
            
            logger.info(f"Scraped {len(vulnerabilities)} vulnerabilities from Bugcrowd")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scraping Bugcrowd: {e}")
            return []
        finally:
            await self.close_session()
    
    def _parse_submission(self, submission: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single submission from Bugcrowd format"""
        try:
            attributes = submission.get('attributes', {})
            relationships = submission.get('relationships', {})
            
            # Basic submission information
            submission_id = submission.get('id', '')
            title = attributes.get('title', '')
            description = attributes.get('description', '')
            
            # Get VRT (Vulnerability Rating Taxonomy) information
            vrt_id = attributes.get('vrt_id', '')
            
            # Get severity
            severity_data = attributes.get('severity', '')
            severity = self._map_severity(severity_data)
            
            # Get monetary reward
            monetary_reward = attributes.get('monetary_reward')
            
            # Get target information
            target_name = ''
            if 'target' in relationships:
                target_data = relationships['target'].get('data', {})
                if target_data:
                    target_name = target_data.get('attributes', {}).get('name', '')
            
            # Get researcher information
            researcher = ''
            if 'researcher' in relationships:
                researcher_data = relationships['researcher'].get('data', {})
                if researcher_data:
                    researcher = researcher_data.get('attributes', {}).get('username', '')
            
            # Create enhanced description
            full_description = description
            if vrt_id:
                full_description += f"\n\nVRT ID: {vrt_id}"
            if target_name:
                full_description += f"\nTarget: {target_name}"
            if researcher:
                full_description += f"\nResearcher: {researcher}"
            if monetary_reward:
                full_description += f"\nReward: ${monetary_reward}"
            
            # Get submission URL
            submission_url = f"https://bugcrowd.com/submissions/{submission_id}"
            
            return self.create_vulnerability_dict(
                vulnerability_id=f"BC-{submission_id}",
                title=title,
                description=full_description,
                severity=severity,
                affected_products=[target_name] if target_name else [],
                references=[submission_url],
                published_date=attributes.get('disclosed_at'),
                updated_date=attributes.get('updated_at'),
                source_url=submission_url,
                tags=['bugcrowd', 'bug_bounty'] + ([vrt_id] if vrt_id else []) + ([researcher] if researcher else []),
                raw_data=submission
            )
            
        except Exception as e:
            logger.error(f"Error parsing Bugcrowd submission {submission.get('id', 'unknown')}: {e}")
            return None
    
    def _map_severity(self, severity: str) -> str:
        """Map Bugcrowd severity to standard levels"""
        if not severity:
            return 'unknown'
        
        severity_map = {
            'p1': 'critical',
            'p2': 'high',
            'p3': 'medium',
            'p4': 'low',
            'p5': 'low'
        }
        
        # Try direct mapping first
        mapped = severity_map.get(severity.lower())
        if mapped:
            return mapped
        
        # Fallback to numeric severity
        if severity.isdigit():
            severity_num = int(severity)
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
                'Authorization': f'Token {self.token}',
                'Accept': 'application/vnd.bugcrowd.v4+json'
            }
            
            url = f"{self.base_url}/submissions/{submission_id}"
            response = await self.make_request(url=url, headers=headers)
            
            if response and 'data' in response:
                return self._parse_submission(response['data'])
            
        except Exception as e:
            logger.error(f"Error getting submission {submission_id} from Bugcrowd: {e}")
        
        return None
    
    async def get_program_submissions(self, program_code: str) -> List[Dict[str, Any]]:
        """Get disclosed submissions for a specific program"""
        if not self.token:
            return []
        
        try:
            headers = {
                'Authorization': f'Token {self.token}',
                'Accept': 'application/vnd.bugcrowd.v4+json'
            }
            
            params = {
                'filter[program]': program_code,
                'filter[disclosure_state]': 'disclosed',
                'sort': '-submitted_at'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/submissions",
                params=params,
                headers=headers
            )
            
            if response and 'data' in response:
                vulnerabilities = []
                for submission in response['data']:
                    vuln = self._parse_submission(submission)
                    if vuln:
                        vulnerabilities.append(vuln)
                return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error getting submissions for program {program_code}: {e}")
        
        return []
