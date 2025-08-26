"""
VulnCheck Community API scraper
API Documentation: https://docs.vulncheck.com/
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .base import BaseScraper
import logging

logger = logging.getLogger(__name__)

class VulnCheckScraper(BaseScraper):
    """Scraper for VulnCheck Community vulnerability data"""
    
    def __init__(self, config):
        super().__init__(config, 'vulncheck')
        self.base_url = "https://api.vulncheck.com/v3"
        self.token = config.vulncheck_token
        
        # VulnCheck Community rate limits
        self.rate_limit_delay = 1.0
    
    async def scrape(self, limit: int = None) -> List[Dict[str, Any]]:
        """Scrape vulnerability data from VulnCheck Community"""
        if not self.token:
            logger.warning("VulnCheck token not configured, skipping")
            return []
        
        vulnerabilities = []
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            # Get recent vulnerabilities
            params = {
                'size': min(limit or 100, 100)
            }
            
            logger.info("Fetching vulnerabilities from VulnCheck Community")
            
            response = await self.make_request(
                url=f"{self.base_url}/index/vulncheck-nvd2",
                params=params,
                headers=headers
            )
            
            if not response:
                logger.error("Failed to get response from VulnCheck API")
                return []
            
            # Parse response
            data = response.get('data', [])
            if not data:
                logger.warning("No vulnerability data found in VulnCheck response")
                return []
            
            logger.info(f"Processing {len(data)} vulnerabilities from VulnCheck")
            
            for vuln_data in data:
                try:
                    vuln = self._parse_vulnerability(vuln_data)
                    if vuln:
                        vulnerabilities.append(vuln)
                        
                        # Check limit
                        if limit and len(vulnerabilities) >= limit:
                            logger.info(f"Reached limit of {limit} vulnerabilities")
                            break
                            
                except Exception as e:
                    logger.error(f"Error parsing VulnCheck vulnerability: {e}")
                    continue
            
            logger.info(f"Scraped {len(vulnerabilities)} vulnerabilities from VulnCheck")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scraping VulnCheck: {e}")
            return []
        finally:
            await self.close_session()
    
    def _parse_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single vulnerability from VulnCheck format"""
        try:
            cve_id = vuln_data.get('cve', '')
            if not cve_id:
                return None
            
            # Get basic information
            title = vuln_data.get('title', f"CVE-{cve_id.replace('CVE-', '')}")
            description = vuln_data.get('description', '')
            
            # Get severity and CVSS
            cvss_score = vuln_data.get('cvss', vuln_data.get('cvss_score'))
            cvss_vector = vuln_data.get('cvss_vector', '')
            
            # Map CVSS score to severity
            severity = 'unknown'
            if cvss_score:
                try:
                    score = float(cvss_score)
                    if score >= 9.0:
                        severity = 'critical'
                    elif score >= 7.0:
                        severity = 'high'
                    elif score >= 4.0:
                        severity = 'medium'
                    elif score > 0:
                        severity = 'low'
                except (ValueError, TypeError):
                    pass
            
            # Get CWE information
            cwe_id = vuln_data.get('cwe', '')
            
            # Get affected products/vendors
            affected_products = []
            vendors = vuln_data.get('vendors', [])
            if isinstance(vendors, list):
                for vendor in vendors:
                    if isinstance(vendor, dict):
                        vendor_name = vendor.get('vendor', '')
                        products = vendor.get('products', [])
                        for product in products:
                            if isinstance(product, dict):
                                product_name = product.get('product', '')
                                if vendor_name and product_name:
                                    affected_products.append(f"{vendor_name} {product_name}")
                            elif isinstance(product, str):
                                if vendor_name:
                                    affected_products.append(f"{vendor_name} {product}")
                    elif isinstance(vendor, str):
                        affected_products.append(vendor)
            
            # Get references
            references = vuln_data.get('references', [])
            if not isinstance(references, list):
                references = []
            
            # Get dates
            published_date = vuln_data.get('published', vuln_data.get('date_published'))
            updated_date = vuln_data.get('modified', vuln_data.get('date_modified'))
            
            # Check for exploit information
            exploit_available = vuln_data.get('exploit_available', False)
            poc_available = vuln_data.get('poc_available', False)
            
            # Look for exploit indicators in references
            if not exploit_available and not poc_available:
                for ref in references:
                    if isinstance(ref, str):
                        ref_lower = ref.lower()
                        if any(keyword in ref_lower for keyword in ['exploit', 'metasploit', 'exploit-db']):
                            exploit_available = True
                        if any(keyword in ref_lower for keyword in ['poc', 'proof-of-concept']):
                            poc_available = True
            
            # Get additional metadata
            tags = ['vulncheck']
            if vuln_data.get('kev', False):
                tags.append('cisa_kev')
            if exploit_available:
                tags.append('exploit_available')
            if poc_available:
                tags.append('poc_available')
            
            return self.create_vulnerability_dict(
                cve_id=cve_id,
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_id=cwe_id,
                affected_products=affected_products,
                references=references,
                exploit_available=exploit_available,
                poc_available=poc_available,
                published_date=published_date,
                updated_date=updated_date,
                source_url=f"https://vulncheck.com/vulncheck-nvd/{cve_id}",
                tags=tags,
                raw_data=vuln_data
            )
            
        except Exception as e:
            logger.error(f"Error parsing VulnCheck vulnerability {vuln_data.get('cve', 'unknown')}: {e}")
            return None
    
    async def get_vulnerability_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific vulnerability by CVE ID"""
        if not self.token:
            return None
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            url = f"{self.base_url}/cve/{cve_id}"
            response = await self.make_request(url=url, headers=headers)
            
            if response and 'data' in response:
                return self._parse_vulnerability(response['data'])
            
        except Exception as e:
            logger.error(f"Error getting vulnerability {cve_id} from VulnCheck: {e}")
        
        return None
    
    async def search_vulnerabilities(self, query: str) -> List[Dict[str, Any]]:
        """Search vulnerabilities by keyword"""
        if not self.token:
            return []
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            params = {
                'query': query,
                'size': 100
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/search/vulncheck-nvd2",
                params=params,
                headers=headers
            )
            
            if response and 'data' in response:
                vulnerabilities = []
                for vuln_data in response['data']:
                    vuln = self._parse_vulnerability(vuln_data)
                    if vuln:
                        vulnerabilities.append(vuln)
                return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error searching VulnCheck vulnerabilities: {e}")
        
        return []
    
    async def get_kev_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get CISA KEV vulnerabilities from VulnCheck"""
        if not self.token:
            return []
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/index/vulncheck-kev",
                headers=headers
            )
            
            if response and 'data' in response:
                vulnerabilities = []
                for vuln_data in response['data']:
                    vuln = self._parse_vulnerability(vuln_data)
                    if vuln:
                        vulnerabilities.append(vuln)
                return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error getting KEV vulnerabilities from VulnCheck: {e}")
        
        return []
