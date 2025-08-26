"""
CVEDetails.com API scraper
API Documentation: https://www.cvedetails.com/documentation/apis
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .base import BaseScraper
import logging

logger = logging.getLogger(__name__)

class CVEDetailsScraper(BaseScraper):
    """Scraper for CVEDetails.com vulnerability database"""
    
    def __init__(self, config):
        super().__init__(config, 'cve_details')
        self.base_url = "https://www.cvedetails.com/api/v1"
        self.token = config.cve_details_token
        
        # CVEDetails API rate limits (subscription-based)
        self.rate_limit_delay = 1.0
    
    async def scrape(self, limit: int = None) -> List[Dict[str, Any]]:
        """Scrape vulnerabilities from CVEDetails.com"""
        if not self.token:
            logger.warning("CVEDetails token not configured, skipping")
            return []
        
        vulnerabilities = []
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            # Get recent high-severity vulnerabilities
            params = {
                'limit': min(limit or 100, 100),
                'page': 1,
                'isInCISAKEV': 1,  # Focus on CISA KEV vulnerabilities
                'orderBy': 'updated',
                'orderDirection': 'desc'
            }
            
            page = 1
            
            while True:
                params['page'] = page
                
                logger.info(f"Fetching CVEDetails vulnerabilities page {page}")
                
                response = await self.make_request(
                    url=f"{self.base_url}/vulnerability/search",
                    params=params,
                    headers=headers
                )
                
                if not response:
                    logger.error("Failed to get response from CVEDetails API")
                    break
                
                # Parse response
                if 'data' in response:
                    vulns_data = response['data']
                elif 'vulnerabilities' in response:
                    vulns_data = response['vulnerabilities']
                else:
                    vulns_data = response if isinstance(response, list) else []
                
                if not vulns_data:
                    logger.info("No more vulnerabilities found")
                    break
                
                logger.info(f"Processing {len(vulns_data)} vulnerabilities from CVEDetails")
                
                for vuln_data in vulns_data:
                    try:
                        vuln = self._parse_vulnerability(vuln_data)
                        if vuln:
                            vulnerabilities.append(vuln)
                            
                            # Check limit
                            if limit and len(vulnerabilities) >= limit:
                                logger.info(f"Reached limit of {limit} vulnerabilities")
                                return vulnerabilities
                                
                    except Exception as e:
                        logger.error(f"Error parsing CVEDetails vulnerability: {e}")
                        continue
                
                # Check if we have more pages
                if len(vulns_data) < params['limit']:
                    break
                
                page += 1
            
            logger.info(f"Scraped {len(vulnerabilities)} vulnerabilities from CVEDetails")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scraping CVEDetails: {e}")
            return []
        finally:
            await self.close_session()
    
    def _parse_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single vulnerability from CVEDetails format"""
        try:
            cve_id = vuln_data.get('cveId', vuln_data.get('id', ''))
            if not cve_id:
                return None
            
            # Get basic information
            title = vuln_data.get('summary', vuln_data.get('title', f"CVE-{cve_id.replace('CVE-', '')}"))
            description = vuln_data.get('description', vuln_data.get('summary', ''))
            
            # Get CVSS information
            cvss_score = vuln_data.get('cvssScore', vuln_data.get('cvss'))
            cvss_vector = vuln_data.get('cvssVector', '')
            
            # Get severity
            severity = vuln_data.get('severity', '').lower()
            if not severity and cvss_score:
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
                    severity = 'unknown'
            
            # Get CWE information
            cwe_id = vuln_data.get('cweId', '')
            
            # Get affected products
            affected_products = []
            
            # Try different product field names
            for field in ['products', 'affectedProducts', 'vendors']:
                products_data = vuln_data.get(field, [])
                if products_data:
                    if isinstance(products_data, list):
                        for product in products_data:
                            if isinstance(product, dict):
                                vendor = product.get('vendor', product.get('vendorName', ''))
                                product_name = product.get('product', product.get('productName', ''))
                                version = product.get('version', '')
                                
                                full_name = f"{vendor} {product_name}" if vendor and product_name else (vendor or product_name)
                                if version:
                                    full_name += f" {version}"
                                
                                if full_name and full_name not in affected_products:
                                    affected_products.append(full_name)
                            elif isinstance(product, str):
                                if product not in affected_products:
                                    affected_products.append(product)
                    break
            
            # Get references
            references = []
            refs_data = vuln_data.get('references', vuln_data.get('links', []))
            if isinstance(refs_data, list):
                for ref in refs_data:
                    if isinstance(ref, dict):
                        url = ref.get('url', ref.get('link', ''))
                        if url:
                            references.append(url)
                    elif isinstance(ref, str):
                        references.append(ref)
            
            # Get dates
            published_date = vuln_data.get('publishedDate', vuln_data.get('published'))
            updated_date = vuln_data.get('lastModifiedDate', vuln_data.get('updated'))
            
            # Check for CISA KEV status
            is_kev = vuln_data.get('isInCISAKEV', False)
            
            # Check for exploit information
            exploit_available = vuln_data.get('exploitAvailable', False)
            poc_available = vuln_data.get('pocAvailable', False)
            
            # Look for exploit indicators if not explicitly set
            if not exploit_available and not poc_available:
                for ref in references:
                    ref_lower = ref.lower()
                    if any(keyword in ref_lower for keyword in ['exploit', 'metasploit', 'exploit-db']):
                        exploit_available = True
                    if any(keyword in ref_lower for keyword in ['poc', 'proof-of-concept']):
                        poc_available = True
            
            # Build tags
            tags = ['cvedetails']
            if is_kev:
                tags.append('cisa_kev')
            if exploit_available:
                tags.append('exploit_available')
            if poc_available:
                tags.append('poc_available')
            
            # Get vulnerability types
            vuln_types = vuln_data.get('vulnerabilityTypes', [])
            if isinstance(vuln_types, list):
                tags.extend([vtype.lower().replace(' ', '_') for vtype in vuln_types if isinstance(vtype, str)])
            
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
                source_url=f"https://www.cvedetails.com/cve/{cve_id}/",
                tags=tags,
                raw_data=vuln_data
            )
            
        except Exception as e:
            logger.error(f"Error parsing CVEDetails vulnerability {vuln_data.get('cveId', 'unknown')}: {e}")
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
            
            url = f"{self.base_url}/vulnerability/{cve_id}"
            response = await self.make_request(url=url, headers=headers)
            
            if response:
                if 'data' in response:
                    return self._parse_vulnerability(response['data'])
                else:
                    return self._parse_vulnerability(response)
            
        except Exception as e:
            logger.error(f"Error getting vulnerability {cve_id} from CVEDetails: {e}")
        
        return None
    
    async def search_vulnerabilities(self, vendor: str = None, product: str = None, 
                                   version: str = None) -> List[Dict[str, Any]]:
        """Search vulnerabilities by vendor/product/version"""
        if not self.token:
            return []
        
        try:
            headers = {
                'Authorization': f'Bearer {self.token}',
                'Accept': 'application/json'
            }
            
            params = {
                'limit': 100
            }
            
            if vendor:
                params['vendor'] = vendor
            if product:
                params['product'] = product
            if version:
                params['version'] = version
            
            response = await self.make_request(
                url=f"{self.base_url}/vulnerability/search",
                params=params,
                headers=headers
            )
            
            if response:
                vulnerabilities = []
                vulns_data = response.get('data', response.get('vulnerabilities', []))
                
                for vuln_data in vulns_data:
                    vuln = self._parse_vulnerability(vuln_data)
                    if vuln:
                        vulnerabilities.append(vuln)
                return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error searching CVEDetails vulnerabilities: {e}")
        
        return []
