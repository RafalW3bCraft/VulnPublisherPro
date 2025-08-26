"""
MITRE CVE scraper using VulnCheck Community API
API Documentation: https://docs.vulncheck.com/community/nist-nvd/mitre-cve
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .base import BaseScraper
import logging

logger = logging.getLogger(__name__)

class MITRECVEScraper(BaseScraper):
    """Scraper for MITRE CVE data via VulnCheck Community API"""
    
    def __init__(self, config):
        super().__init__(config, 'mitre_cve')
        self.base_url = "https://api.vulncheck.com/v3"
        self.token = config.vulncheck_token
        
        # VulnCheck Community API rate limits
        self.rate_limit_delay = 1.0
    
    async def scrape(self, limit: int = None) -> List[Dict[str, Any]]:
        """Scrape CVE data from MITRE via VulnCheck"""
        if not self.token:
            logger.warning("VulnCheck token not configured, skipping MITRE CVE scraper")
            return []
        
        vulnerabilities = []
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            # Get recent CVEs from the backup endpoint
            logger.info("Fetching MITRE CVE data from VulnCheck")
            
            response = await self.make_request(
                url=f"{self.base_url}/backup/mitre-cvelist-v5",
                headers=headers
            )
            
            if not response:
                logger.error("Failed to get response from VulnCheck MITRE API")
                return []
            
            # Parse the CVE list data
            cve_data = response.get('data', [])
            if not cve_data:
                logger.warning("No CVE data found in MITRE response")
                return []
            
            logger.info(f"Processing {len(cve_data)} CVEs from MITRE")
            
            # Filter recent CVEs if no limit specified
            if not limit:
                # Get CVEs modified in last 7 days
                cutoff_date = datetime.now() - timedelta(days=7)
                filtered_cves = []
                
                for cve in cve_data:
                    date_updated = cve.get('dateUpdated', cve.get('lastModified', ''))
                    try:
                        if date_updated:
                            # Handle different date formats
                            for fmt in ['%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d']:
                                try:
                                    cve_date = datetime.strptime(date_updated, fmt)
                                    if cve_date >= cutoff_date:
                                        filtered_cves.append(cve)
                                    break
                                except ValueError:
                                    continue
                    except:
                        # Include if we can't parse the date
                        filtered_cves.append(cve)
                
                cve_data = filtered_cves
            
            # Apply limit if specified
            if limit:
                cve_data = cve_data[:limit]
            
            for cve_item in cve_data:
                try:
                    vuln = self._parse_cve(cve_item)
                    if vuln:
                        vulnerabilities.append(vuln)
                        
                except Exception as e:
                    logger.error(f"Error parsing MITRE CVE: {e}")
                    continue
            
            logger.info(f"Scraped {len(vulnerabilities)} vulnerabilities from MITRE CVE")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scraping MITRE CVE: {e}")
            return []
        finally:
            await self.close_session()
    
    def _parse_cve(self, cve_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single CVE from MITRE format"""
        try:
            # Handle both direct CVE data and wrapped data
            if 'cveMetadata' in cve_data:
                metadata = cve_data['cveMetadata']
                containers = cve_data.get('containers', {})
                cna_data = containers.get('cna', {})
            else:
                metadata = cve_data
                cna_data = cve_data
            
            cve_id = metadata.get('cveId', '')
            if not cve_id:
                return None
            
            # Get descriptions
            descriptions = cna_data.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en' or not description:
                    description = desc.get('value', '')
                    if desc.get('lang') == 'en':
                        break
            
            # Get affected products
            affected_products = []
            affected_data = cna_data.get('affected', [])
            for affected in affected_data:
                vendor = affected.get('vendor', '')
                product = affected.get('product', '')
                versions = affected.get('versions', [])
                
                product_name = f"{vendor} {product}" if vendor and product else (vendor or product)
                if product_name:
                    # Add version info if available
                    if versions:
                        version_info = []
                        for version in versions[:3]:  # Limit to first 3 versions
                            version_value = version.get('version', '')
                            if version_value:
                                version_info.append(version_value)
                        if version_info:
                            product_name += f" ({', '.join(version_info)})"
                    
                    if product_name not in affected_products:
                        affected_products.append(product_name)
            
            # Get references
            references = []
            refs_data = cna_data.get('references', [])
            for ref in refs_data:
                url = ref.get('url', '')
                if url:
                    references.append(url)
            
            # Get problem types (CWE)
            cwe_ids = []
            problem_types = cna_data.get('problemTypes', [])
            for prob_type in problem_types:
                descriptions = prob_type.get('descriptions', [])
                for desc in descriptions:
                    cwe_id = desc.get('cweId', '')
                    if cwe_id and cwe_id not in cwe_ids:
                        cwe_ids.append(cwe_id)
            
            # Get metrics (CVSS)
            metrics = cna_data.get('metrics', [])
            cvss_score = None
            cvss_vector = None
            severity = 'unknown'
            
            for metric in metrics:
                if 'cvssV3_1' in metric:
                    cvss_data = metric['cvssV3_1']
                    cvss_score = cvss_data.get('baseScore')
                    cvss_vector = cvss_data.get('vectorString')
                    severity = cvss_data.get('baseSeverity', '').lower()
                    break
                elif 'cvssV3_0' in metric:
                    cvss_data = metric['cvssV3_0']
                    cvss_score = cvss_data.get('baseScore')
                    cvss_vector = cvss_data.get('vectorString')
                    severity = cvss_data.get('baseSeverity', '').lower()
                    break
            
            # Get timeline information
            date_published = metadata.get('datePublished', cve_data.get('datePublished'))
            date_updated = metadata.get('dateUpdated', cve_data.get('dateUpdated'))
            
            # Check for exploit information in references
            exploit_available = False
            poc_available = False
            
            for ref in references:
                ref_lower = ref.lower()
                if any(keyword in ref_lower for keyword in ['exploit', 'metasploit', 'exploit-db']):
                    exploit_available = True
                if any(keyword in ref_lower for keyword in ['poc', 'proof-of-concept', 'github.com']):
                    poc_available = True
            
            return self.create_vulnerability_dict(
                cve_id=cve_id,
                title=f"CVE-{cve_id.split('-')[1]}-{cve_id.split('-')[2]}",
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_id=', '.join(cwe_ids) if cwe_ids else None,
                affected_products=affected_products,
                references=references,
                exploit_available=exploit_available,
                poc_available=poc_available,
                published_date=date_published,
                updated_date=date_updated,
                source_url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                tags=['mitre', 'cve'],
                raw_data=cve_data
            )
            
        except Exception as e:
            logger.error(f"Error parsing MITRE CVE {cve_data.get('cveMetadata', {}).get('cveId', 'unknown')}: {e}")
            return None
    
    async def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific CVE by ID"""
        if not self.token:
            return None
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            # Search for specific CVE
            url = f"{self.base_url}/cve/{cve_id}"
            response = await self.make_request(url=url, headers=headers)
            
            if response and 'data' in response:
                return self._parse_cve(response['data'])
            
        except Exception as e:
            logger.error(f"Error getting CVE {cve_id} from MITRE: {e}")
        
        return None
