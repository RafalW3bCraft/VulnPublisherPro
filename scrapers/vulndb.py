"""
VulDB scraper (web scraping)
Website: https://vuldb.com/
"""

import trafilatura
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .base import BaseScraper
import logging
import re

logger = logging.getLogger(__name__)

class VulnDBScraper(BaseScraper):
    """Scraper for VulDB vulnerability database"""
    
    def __init__(self, config):
        super().__init__(config, 'vulndb')
        self.base_url = "https://vuldb.com"
        self.token = config.vulndb_token
        
        # Be respectful with rate limiting for web scraping
        self.rate_limit_delay = 2.0
    
    async def scrape(self, limit: int = None) -> List[Dict[str, Any]]:
        """Scrape recent vulnerabilities from VulDB"""
        vulnerabilities = []
        
        try:
            # Get recent vulnerabilities from the main page
            logger.info("Scraping recent vulnerabilities from VulDB")
            
            response = await self.make_request(url=self.base_url)
            
            if not response or 'text' not in response:
                logger.error("Failed to get response from VulDB")
                return []
            
            html_content = response['text']
            vulnerability_links = self._parse_main_page(html_content)
            
            if not vulnerability_links:
                logger.info("No vulnerabilities found")
                return []
            
            logger.info(f"Processing {len(vulnerability_links)} vulnerabilities from VulDB")
            
            for vuln_link in vulnerability_links:
                try:
                    vuln = await self._get_vulnerability_details(vuln_link)
                    if vuln:
                        vulnerabilities.append(vuln)
                        
                        # Check limit
                        if limit and len(vulnerabilities) >= limit:
                            logger.info(f"Reached limit of {limit} vulnerabilities")
                            break
                            
                except Exception as e:
                    logger.error(f"Error processing vulnerability: {e}")
                    continue
            
            logger.info(f"Scraped {len(vulnerabilities)} vulnerabilities from VulDB")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scraping VulDB: {e}")
            return []
        finally:
            await self.close_session()
    
    def _parse_main_page(self, html_content: str) -> List[Dict[str, Any]]:
        """Parse the main page to extract recent vulnerability links"""
        vulnerability_links = []
        
        try:
            # Look for vulnerability links in the HTML
            # VulDB uses specific URL patterns like /id.123456
            vuln_pattern = r'href="(/id\.(\d+))"[^>]*>([^<]+)</a>'
            matches = re.findall(vuln_pattern, html_content)
            
            for url_path, vuln_id, title in matches:
                vulnerability_links.append({
                    'id': vuln_id,
                    'title': title.strip(),
                    'url': f"{self.base_url}{url_path}",
                    'path': url_path
                })
                
                # Limit to avoid too many requests
                if len(vulnerability_links) >= 20:
                    break
            
            # Also look for CVE-based links
            cve_pattern = r'href="(/cve\.([^"]+))"[^>]*>([^<]+)</a>'
            cve_matches = re.findall(cve_pattern, html_content)
            
            for url_path, cve_id, title in cve_matches:
                vulnerability_links.append({
                    'id': cve_id,
                    'cve_id': cve_id,
                    'title': title.strip(),
                    'url': f"{self.base_url}{url_path}",
                    'path': url_path
                })
                
                if len(vulnerability_links) >= 30:
                    break
            
        except Exception as e:
            logger.error(f"Error parsing VulDB main page: {e}")
        
        return vulnerability_links
    
    async def _get_vulnerability_details(self, vuln_link: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific vulnerability"""
        try:
            vuln_url = vuln_link['url']
            
            # Get the vulnerability details page
            response = await self.make_request(url=vuln_url)
            
            if not response or 'text' not in response:
                return None
            
            html_content = response['text']
            
            # Extract clean text content
            clean_text = trafilatura.extract(html_content)
            if not clean_text:
                return None
            
            # Parse the vulnerability details
            vuln = self._parse_vulnerability_details(vuln_link, html_content, clean_text)
            return vuln
            
        except Exception as e:
            logger.error(f"Error getting vulnerability details for {vuln_link.get('id', 'unknown')}: {e}")
            return None
    
    def _parse_vulnerability_details(self, vuln_link: Dict[str, Any], 
                                   html_content: str, clean_text: str) -> Optional[Dict[str, Any]]:
        """Parse detailed vulnerability information"""
        try:
            title = vuln_link['title']
            vuln_id = vuln_link['id']
            vuln_url = vuln_link['url']
            
            # Get CVE ID
            cve_id = vuln_link.get('cve_id')
            if not cve_id:
                # Extract CVE IDs from title and content
                cve_ids = self.extract_cve_ids(title + ' ' + clean_text)
                cve_id = cve_ids[0] if cve_ids else None
            
            # Create description from clean text
            description = title
            if clean_text:
                # Take relevant sections as description
                paragraphs = clean_text.split('\n\n')
                desc_parts = []
                
                for paragraph in paragraphs[:5]:
                    para = paragraph.strip()
                    if para and len(para) > 30:
                        # Skip navigation and header text
                        if not any(skip in para.lower() for skip in ['vuldb', 'menu', 'search', 'login']):
                            desc_parts.append(para)
                            if len(desc_parts) >= 2:
                                break
                
                if desc_parts:
                    description += '\n\n' + '\n\n'.join(desc_parts)
            
            # Extract metadata from HTML
            metadata = self._extract_metadata(html_content, clean_text)
            
            # Get severity and CVSS
            severity = metadata.get('severity', 'medium')
            cvss_score = metadata.get('cvss_score')
            
            # Get affected products
            affected_products = metadata.get('affected_products', [])
            
            # Extract product information from title if not found
            if not affected_products:
                # VulDB titles often have format: "Product Version Vulnerability"
                product_patterns = [
                    r'^([A-Za-z0-9\s]+?)(?:\s+(?:\d+\.[\d\.]+|Vulnerability|up to))',
                    r'^([A-Za-z0-9\s]+?)(?:\s+(?:remote|local|privilege))',
                    r'^([A-Za-z0-9\s]+?)(?:\s+-)'
                ]
                
                for pattern in product_patterns:
                    match = re.match(pattern, title, re.IGNORECASE)
                    if match:
                        product = match.group(1).strip()
                        if product and len(product) > 2:
                            affected_products.append(product)
                        break
            
            # Get references
            references = [vuln_url]
            
            # Look for external references in HTML
            ref_pattern = r'href="(https?://[^"]+)"'
            ref_matches = re.findall(ref_pattern, html_content)
            for ref in ref_matches[:5]:
                if ref not in references and 'vuldb.com' not in ref:
                    references.append(ref)
            
            # Determine exploit availability
            exploit_available = False
            poc_available = False
            
            # Check for exploit indicators
            exploit_keywords = ['exploit', 'remote code execution', 'rce', 'metasploit']
            for keyword in exploit_keywords:
                if keyword in title.lower() or keyword in clean_text.lower():
                    exploit_available = True
                    break
            
            # Check for PoC indicators
            poc_keywords = ['proof of concept', 'poc', 'demonstration', 'code']
            for keyword in poc_keywords:
                if keyword in clean_text.lower():
                    poc_available = True
                    break
            
            # Get threat intelligence data
            threat_actor = metadata.get('threat_actor')
            malware_family = metadata.get('malware_family')
            
            # Build tags
            tags = ['vulndb']
            if exploit_available:
                tags.append('exploit_available')
            if poc_available:
                tags.append('poc_available')
            if threat_actor:
                tags.append(f'threat_actor_{threat_actor.lower().replace(" ", "_")}')
            if malware_family:
                tags.append(f'malware_{malware_family.lower().replace(" ", "_")}')
            
            # Add vulnerability type tags
            vuln_types = ['sql injection', 'xss', 'buffer overflow', 'privilege escalation']
            for vtype in vuln_types:
                if vtype in title.lower() or vtype in clean_text.lower():
                    tags.append(vtype.replace(' ', '_'))
            
            # VulDB specific features
            price = metadata.get('exploit_price')
            if price:
                description += f'\n\nExploit Price: ${price}'
            
            return self.create_vulnerability_dict(
                cve_id=cve_id,
                vulnerability_id=f"VDB-{vuln_id}",
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                affected_products=affected_products,
                references=references,
                exploit_available=exploit_available,
                poc_available=poc_available,
                published_date=metadata.get('published_date'),
                updated_date=metadata.get('updated_date'),
                source_url=vuln_url,
                vendor_response=threat_actor,
                tags=tags,
                raw_data=vuln_link
            )
            
        except Exception as e:
            logger.error(f"Error parsing vulnerability details {vuln_link.get('id', 'unknown')}: {e}")
            return None
    
    def _extract_metadata(self, html_content: str, clean_text: str) -> Dict[str, Any]:
        """Extract metadata from HTML content"""
        metadata = {}
        
        try:
            # Look for CVSS score
            cvss_patterns = [
                r'CVSS[:\s]*(\d+\.?\d*)',
                r'Score[:\s]*(\d+\.?\d*)',
                r'cvss["\s:]*(\d+\.?\d*)'
            ]
            
            for pattern in cvss_patterns:
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    try:
                        metadata['cvss_score'] = float(match.group(1))
                        # Map CVSS score to severity
                        score = metadata['cvss_score']
                        if score >= 9.0:
                            metadata['severity'] = 'critical'
                        elif score >= 7.0:
                            metadata['severity'] = 'high'
                        elif score >= 4.0:
                            metadata['severity'] = 'medium'
                        else:
                            metadata['severity'] = 'low'
                        break
                    except ValueError:
                        pass
            
            # Look for exploit pricing (VulDB specific feature)
            price_patterns = [
                r'Price[:\s]*\$?(\d+)',
                r'Exploit[:\s]*\$(\d+)',
                r'\$(\d+).*exploit'
            ]
            
            for pattern in price_patterns:
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    try:
                        metadata['exploit_price'] = int(match.group(1))
                        break
                    except ValueError:
                        pass
            
            # Look for threat actor information
            actor_patterns = [
                r'(?:Threat Actor|Actor|APT)[:\s]*([^<\n]+)',
                r'(?:Group|Campaign)[:\s]*([^<\n]+)'
            ]
            
            for pattern in actor_patterns:
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    actor = match.group(1).strip()
                    if actor and len(actor) > 2:
                        metadata['threat_actor'] = actor
                        break
            
            # Look for malware family information
            malware_patterns = [
                r'(?:Malware|Family)[:\s]*([^<\n]+)',
                r'(?:Trojan|Ransomware|Backdoor)[:\s]*([^<\n]+)'
            ]
            
            for pattern in malware_patterns:
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    malware = match.group(1).strip()
                    if malware and len(malware) > 2:
                        metadata['malware_family'] = malware
                        break
            
            # Look for dates
            date_patterns = [
                r'(?:Published|Disclosed|Date)[:\s]*(\d{4}-\d{2}-\d{2})',
                r'(\d{4}-\d{2}-\d{2})'
            ]
            
            for pattern in date_patterns:
                match = re.search(pattern, html_content)
                if match:
                    metadata['published_date'] = match.group(1)
                    break
            
            # Look for affected products
            product_patterns = [
                r'(?:Product|Application|Software)[:\s]*([^<\n]+)',
                r'(?:Affected|Vendor)[:\s]*([^<\n]+)'
            ]
            
            for pattern in product_patterns:
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    product = match.group(1).strip()
                    if product and len(product) > 2:
                        metadata['affected_products'] = [product]
                    break
            
        except Exception as e:
            logger.error(f"Error extracting VulDB metadata: {e}")
        
        return metadata
    
    async def search_vulnerabilities(self, query: str) -> List[Dict[str, Any]]:
        """Search vulnerabilities by keyword"""
        try:
            params = {
                'search': query
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/search",
                params=params
            )
            
            if response and 'text' in response:
                vulnerability_links = self._parse_main_page(response['text'])
                vulnerabilities = []
                
                for vuln_link in vulnerability_links[:10]:  # Limit to first 10 results
                    vuln = await self._get_vulnerability_details(vuln_link)
                    if vuln:
                        vulnerabilities.append(vuln)
                
                return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error searching VulDB: {e}")
        
        return []
