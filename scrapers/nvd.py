"""
NVD (National Vulnerability Database) scraper
API Documentation: https://services.nvd.nist.gov/rest/json/cves/2.0/
"""

import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .base import BaseScraper
import logging

logger = logging.getLogger(__name__)

class NVDScraper(BaseScraper):
    """Scraper for NIST National Vulnerability Database"""
    
    def __init__(self, config):
        super().__init__(config, 'nvd')
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # NVD API key (optional but recommended for higher rate limits)
        self.api_key = config.nvd_api_key
        
        # Rate limiting: 5 requests per 30 seconds without API key, 50 with key
        if self.api_key:
            self.rate_limit_delay = 0.6  # 50 requests per 30 seconds
        else:
            self.rate_limit_delay = 6.0  # 5 requests per 30 seconds
    
    async def scrape(self, limit: int = None) -> List[Dict[str, Any]]:
        """Scrape CVEs from NVD"""
        vulnerabilities = []
        
        try:
            # Parameters for API request
            params = {
                'resultsPerPage': min(limit or 2000, 2000),  # Max 2000 per request
                'startIndex': 0
            }
            
            # Add API key if available
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            # Get recent CVEs (last 7 days by default)
            recent_date = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%S.000')
            params['lastModStartDate'] = recent_date
            
            total_results = 0
            
            while True:
                logger.info(f"Fetching NVD CVEs starting at index {params['startIndex']}")
                
                response = await self.make_request(
                    url=self.base_url,
                    params=params,
                    headers=headers
                )
                
                if not response:
                    logger.error("Failed to get response from NVD API")
                    break
                
                # Parse response
                if 'vulnerabilities' not in response:
                    logger.warning("No vulnerabilities found in NVD response")
                    break
                
                cves = response['vulnerabilities']
                total_results = response.get('totalResults', 0)
                
                logger.info(f"Processing {len(cves)} CVEs from NVD")
                
                for cve_data in cves:
                    try:
                        vuln = self._parse_cve(cve_data)
                        if vuln:
                            vulnerabilities.append(vuln)
                            
                            # Check limit
                            if limit and len(vulnerabilities) >= limit:
                                logger.info(f"Reached limit of {limit} vulnerabilities")
                                return vulnerabilities
                                
                    except Exception as e:
                        logger.error(f"Error parsing CVE: {e}")
                        continue
                
                # Check if we have more results
                next_index = params['startIndex'] + len(cves)
                if next_index >= total_results or not cves:
                    break
                
                params['startIndex'] = next_index
            
            logger.info(f"Scraped {len(vulnerabilities)} vulnerabilities from NVD")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scraping NVD: {e}")
            return []
        finally:
            await self.close_session()
    
    def _parse_cve(self, cve_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single CVE from NVD format"""
        try:
            cve = cve_data.get('cve', {})
            
            # Basic CVE information
            cve_id = cve.get('id', '')
            if not cve_id:
                return None
            
            # Get descriptions
            descriptions = cve.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get references
            references = []
            for ref in cve.get('references', []):
                references.append(ref.get('url', ''))
            
            # Get CWE information
            weaknesses = cve.get('weaknesses', [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_ids.append(desc.get('value', ''))
            
            # Get CVSS metrics
            metrics = cve_data.get('metrics', {})
            cvss_score = None
            cvss_vector = None
            severity = 'unknown'
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    metric = metrics[version][0]  # Take first metric
                    cvss_data = metric.get('cvssData', {})
                    
                    cvss_score = cvss_data.get('baseScore')
                    cvss_vector = cvss_data.get('vectorString')
                    severity = cvss_data.get('baseSeverity', '').lower()
                    break
            
            # Get configurations (affected products)
            configurations = cve.get('configurations', [])
            affected_products = []
            
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        if cpe_match.get('vulnerable', False):
                            cpe_name = cpe_match.get('criteria', '')
                            if cpe_name:
                                # Parse CPE to extract product info
                                product_info = self._parse_cpe(cpe_name)
                                if product_info:
                                    affected_products.append(product_info)
            
            # Get vendor advisory URLs
            vendor_advisories = []
            for ref in cve.get('references', []):
                tags = ref.get('tags', [])
                if 'Vendor Advisory' in tags or 'Patch' in tags:
                    vendor_advisories.append(ref.get('url', ''))
            
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
                vendor_response=vendor_advisories[0] if vendor_advisories else None,
                published_date=cve.get('published'),
                updated_date=cve.get('lastModified'),
                source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                tags=['nvd', 'cve'],
                raw_data=cve_data
            )
            
        except Exception as e:
            logger.error(f"Error parsing CVE {cve_data.get('cve', {}).get('id', 'unknown')}: {e}")
            return None
    
    def _parse_cpe(self, cpe_string: str) -> Optional[str]:
        """Parse CPE string to extract product information"""
        try:
            # CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
            parts = cpe_string.split(':')
            if len(parts) >= 5:
                vendor = parts[3]
                product = parts[4]
                version = parts[5] if len(parts) > 5 and parts[5] != '*' else ''
                
                product_str = f"{vendor} {product}"
                if version:
                    product_str += f" {version}"
                
                return product_str
        except Exception:
            pass
        
        return None
    
    async def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific CVE by ID"""
        try:
            url = f"{self.base_url}/cveId/{cve_id}"
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            response = await self.make_request(url=url, headers=headers)
            
            if response and 'vulnerabilities' in response and response['vulnerabilities']:
                return self._parse_cve(response['vulnerabilities'][0])
            
        except Exception as e:
            logger.error(f"Error getting CVE {cve_id} from NVD: {e}")
        
        return None
