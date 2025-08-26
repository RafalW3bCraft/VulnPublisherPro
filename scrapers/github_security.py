"""
GitHub Security Advisory scraper
API Documentation: https://docs.github.com/en/rest/security-advisories
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .base import BaseScraper
import logging

logger = logging.getLogger(__name__)

class GitHubSecurityScraper(BaseScraper):
    """Scraper for GitHub Security Advisory Database"""
    
    def __init__(self, config):
        super().__init__(config, 'github_security')
        self.base_url = "https://api.github.com"
        self.token = config.github_token
        
        # GitHub API rate limit: 60 requests/hour (unauthenticated), 5000/hour (authenticated)
        if self.token:
            self.rate_limit_delay = 0.72  # ~5000 requests per hour
        else:
            self.rate_limit_delay = 60  # 60 requests per hour
    
    async def scrape(self, limit: int = None) -> List[Dict[str, Any]]:
        """Scrape security advisories from GitHub"""
        vulnerabilities = []
        
        try:
            headers = {
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28'
            }
            
            if self.token:
                headers['Authorization'] = f'Bearer {self.token}'
            
            # Parameters for API request
            params = {
                'per_page': min(limit or 100, 100),  # Max 100 per request
                'sort': 'updated',
                'direction': 'desc'
            }
            
            # Get recent advisories (last 7 days)
            recent_date = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
            params['updated'] = f'>{recent_date}'
            
            page = 1
            
            while True:
                params['page'] = page
                
                logger.info(f"Fetching GitHub Security Advisories page {page}")
                
                response = await self.make_request(
                    url=f"{self.base_url}/advisories",
                    params=params,
                    headers=headers
                )
                
                if not response or not isinstance(response, list):
                    logger.error("Failed to get response from GitHub Security API")
                    break
                
                advisories = response
                
                if not advisories:
                    logger.info("No more advisories found")
                    break
                
                logger.info(f"Processing {len(advisories)} advisories from GitHub")
                
                for advisory in advisories:
                    try:
                        vuln = self._parse_advisory(advisory)
                        if vuln:
                            vulnerabilities.append(vuln)
                            
                            # Check limit
                            if limit and len(vulnerabilities) >= limit:
                                logger.info(f"Reached limit of {limit} vulnerabilities")
                                return vulnerabilities
                                
                    except Exception as e:
                        logger.error(f"Error parsing advisory: {e}")
                        continue
                
                # Check if we have more pages
                if len(advisories) < params['per_page']:
                    break
                
                page += 1
            
            logger.info(f"Scraped {len(vulnerabilities)} vulnerabilities from GitHub Security")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scraping GitHub Security: {e}")
            return []
        finally:
            await self.close_session()
    
    def _parse_advisory(self, advisory: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single advisory from GitHub format"""
        try:
            ghsa_id = advisory.get('ghsa_id', '')
            if not ghsa_id:
                return None
            
            # Extract CVE ID if available
            cve_id = advisory.get('cve_id')
            
            # Get summary and description
            summary = advisory.get('summary', '')
            description = advisory.get('description', '')
            
            # Combine summary and description
            full_description = summary
            if description and description != summary:
                full_description += f"\n\n{description}"
            
            # Get severity
            severity = advisory.get('severity', '').lower()
            
            # Get CVSS score
            cvss_score = None
            cvss_vector = None
            if 'cvss' in advisory and advisory['cvss']:
                cvss_score = advisory['cvss'].get('score')
                cvss_vector = advisory['cvss'].get('vector_string')
            
            # Get CWEs
            cwe_ids = []
            for cwe in advisory.get('cwe_ids', []):
                cwe_ids.append(cwe)
            
            # Get affected packages/products
            affected_products = []
            for vuln in advisory.get('vulnerabilities', []):
                package = vuln.get('package', {})
                if package:
                    ecosystem = package.get('ecosystem', '')
                    name = package.get('name', '')
                    
                    product_name = f"{ecosystem}: {name}" if ecosystem else name
                    if product_name and product_name not in affected_products:
                        affected_products.append(product_name)
            
            # Get references
            references = []
            for ref in advisory.get('references', []):
                if isinstance(ref, dict):
                    references.append(ref.get('url', ''))
                elif isinstance(ref, str):
                    references.append(ref)
            
            # Check if there are known exploits
            exploit_available = False
            poc_available = False
            
            # Look for exploit keywords in references
            for ref in references:
                ref_lower = ref.lower()
                if any(keyword in ref_lower for keyword in ['exploit', 'poc', 'proof-of-concept']):
                    if 'exploit' in ref_lower:
                        exploit_available = True
                    if 'poc' in ref_lower or 'proof-of-concept' in ref_lower:
                        poc_available = True
            
            # Get credits (researchers)
            credits = []
            if 'credits' in advisory:
                for credit in advisory['credits']:
                    if isinstance(credit, dict):
                        user = credit.get('user', {})
                        if user and user.get('login'):
                            credits.append(user['login'])
            
            return self.create_vulnerability_dict(
                cve_id=cve_id,
                vulnerability_id=ghsa_id,
                title=summary,
                description=full_description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_id=', '.join(cwe_ids) if cwe_ids else None,
                affected_products=affected_products,
                references=references,
                exploit_available=exploit_available,
                poc_available=poc_available,
                published_date=advisory.get('published_at'),
                updated_date=advisory.get('updated_at'),
                source_url=advisory.get('html_url'),
                tags=['github', 'ghsa'] + (credits if credits else []),
                raw_data=advisory
            )
            
        except Exception as e:
            logger.error(f"Error parsing advisory {advisory.get('ghsa_id', 'unknown')}: {e}")
            return None
    
    async def get_advisory_by_id(self, ghsa_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific advisory by GHSA ID"""
        try:
            headers = {
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28'
            }
            
            if self.token:
                headers['Authorization'] = f'Bearer {self.token}'
            
            url = f"{self.base_url}/advisories/{ghsa_id}"
            response = await self.make_request(url=url, headers=headers)
            
            if response:
                return self._parse_advisory(response)
            
        except Exception as e:
            logger.error(f"Error getting advisory {ghsa_id} from GitHub: {e}")
        
        return None
    
    async def search_advisories(self, query: str, ecosystem: str = None, 
                               severity: str = None) -> List[Dict[str, Any]]:
        """Search advisories with specific criteria"""
        try:
            headers = {
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28'
            }
            
            if self.token:
                headers['Authorization'] = f'Bearer {self.token}'
            
            params = {
                'per_page': 100,
                'sort': 'updated',
                'direction': 'desc'
            }
            
            # Add search filters
            if query:
                params['q'] = query
            if ecosystem:
                params['ecosystem'] = ecosystem
            if severity:
                params['severity'] = severity
            
            response = await self.make_request(
                url=f"{self.base_url}/advisories",
                params=params,
                headers=headers
            )
            
            if response and isinstance(response, list):
                vulnerabilities = []
                for advisory in response:
                    vuln = self._parse_advisory(advisory)
                    if vuln:
                        vulnerabilities.append(vuln)
                return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error searching GitHub advisories: {e}")
        
        return []
