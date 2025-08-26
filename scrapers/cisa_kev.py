"""
CISA KEV (Known Exploited Vulnerabilities) scraper
Data Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .base import BaseScraper
import logging

logger = logging.getLogger(__name__)

class CISAKEVScraper(BaseScraper):
    """Scraper for CISA Known Exploited Vulnerabilities Catalog"""
    
    def __init__(self, config):
        super().__init__(config, 'cisa_kev')
        self.base_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        # CISA KEV is a static JSON file, no rate limiting needed
        self.rate_limit_delay = 0.1
    
    async def scrape(self, limit: int = None) -> List[Dict[str, Any]]:
        """Scrape known exploited vulnerabilities from CISA KEV catalog"""
        vulnerabilities = []
        
        try:
            logger.info("Fetching CISA KEV catalog")
            
            response = await self.make_request(url=self.base_url)
            
            if not response:
                logger.error("Failed to get response from CISA KEV")
                return []
            
            # Parse the KEV catalog
            catalog_version = response.get('catalogVersion', 'Unknown')
            date_released = response.get('dateReleased', '')
            count = response.get('count', 0)
            vulnerabilities_data = response.get('vulnerabilities', [])
            
            logger.info(f"Processing CISA KEV catalog v{catalog_version} with {count} vulnerabilities")
            
            # Filter recent vulnerabilities if no limit specified
            if not limit:
                # Get vulnerabilities added in last 30 days
                cutoff_date = datetime.now() - timedelta(days=30)
                filtered_vulns = []
                
                for vuln in vulnerabilities_data:
                    date_added = vuln.get('dateAdded', '')
                    try:
                        vuln_date = datetime.strptime(date_added, '%Y-%m-%d')
                        if vuln_date >= cutoff_date:
                            filtered_vulns.append(vuln)
                    except ValueError:
                        # Include if we can't parse the date
                        filtered_vulns.append(vuln)
                
                vulnerabilities_data = filtered_vulns
            
            # Apply limit if specified
            if limit:
                vulnerabilities_data = vulnerabilities_data[:limit]
            
            for vuln_data in vulnerabilities_data:
                try:
                    vuln = self._parse_vulnerability(vuln_data)
                    if vuln:
                        vulnerabilities.append(vuln)
                        
                except Exception as e:
                    logger.error(f"Error parsing KEV vulnerability: {e}")
                    continue
            
            logger.info(f"Scraped {len(vulnerabilities)} vulnerabilities from CISA KEV")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scraping CISA KEV: {e}")
            return []
        finally:
            await self.close_session()
    
    def _parse_vulnerability(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single vulnerability from CISA KEV format"""
        try:
            cve_id = vuln_data.get('cveID', '')
            if not cve_id:
                return None
            
            vendor_project = vuln_data.get('vendorProject', '')
            product = vuln_data.get('product', '')
            vulnerability_name = vuln_data.get('vulnerabilityName', '')
            date_added = vuln_data.get('dateAdded', '')
            short_description = vuln_data.get('shortDescription', '')
            required_action = vuln_data.get('requiredAction', '')
            due_date = vuln_data.get('dueDate', '')
            known_ransomware = vuln_data.get('knownRansomwareCampaignUse', 'Unknown')
            notes = vuln_data.get('notes', '')
            
            # Create title from vendor and product
            title = vulnerability_name
            if not title and vendor_project and product:
                title = f"{vendor_project} {product} Vulnerability"
            elif not title:
                title = f"CVE-{cve_id.replace('CVE-', '')}"
            
            # Create comprehensive description
            description = short_description
            if vendor_project and product:
                description += f"\n\nAffected Product: {vendor_project} {product}"
            if required_action:
                description += f"\nRequired Action: {required_action}"
            if due_date:
                description += f"\nDue Date: {due_date}"
            if known_ransomware.lower() == 'known':
                description += f"\n⚠️ Known Ransomware Campaign Use: YES"
            if notes:
                description += f"\nNotes: {notes}"
            
            # All KEV vulnerabilities are actively exploited, so mark as critical
            severity = 'critical'
            
            # Create affected products list
            affected_products = []
            if vendor_project and product:
                affected_products.append(f"{vendor_project} {product}")
            
            # KEV URL
            kev_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            
            return self.create_vulnerability_dict(
                cve_id=cve_id,
                vulnerability_id=f"KEV-{cve_id}",
                title=title,
                description=description,
                severity=severity,
                affected_products=affected_products,
                references=[kev_url],
                exploit_available=True,  # All KEV vulnerabilities have known exploits
                technical_details=short_description,
                impact="Active exploitation observed in the wild",
                mitigation=required_action,
                published_date=date_added,
                source_url=kev_url,
                tags=['cisa', 'kev', 'actively_exploited'] + (['ransomware'] if known_ransomware.lower() == 'known' else []),
                raw_data=vuln_data
            )
            
        except Exception as e:
            logger.error(f"Error parsing KEV vulnerability {vuln_data.get('cveID', 'unknown')}: {e}")
            return None
    
    async def get_vulnerability_by_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific vulnerability by CVE ID from KEV catalog"""
        try:
            response = await self.make_request(url=self.base_url)
            
            if response and 'vulnerabilities' in response:
                for vuln_data in response['vulnerabilities']:
                    if vuln_data.get('cveID', '') == cve_id:
                        return self._parse_vulnerability(vuln_data)
            
        except Exception as e:
            logger.error(f"Error getting KEV vulnerability {cve_id}: {e}")
        
        return None
    
    async def get_ransomware_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get vulnerabilities known to be used in ransomware campaigns"""
        try:
            response = await self.make_request(url=self.base_url)
            
            if response and 'vulnerabilities' in response:
                vulnerabilities = []
                for vuln_data in response['vulnerabilities']:
                    if vuln_data.get('knownRansomwareCampaignUse', '').lower() == 'known':
                        vuln = self._parse_vulnerability(vuln_data)
                        if vuln:
                            vulnerabilities.append(vuln)
                return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error getting ransomware vulnerabilities: {e}")
        
        return []
