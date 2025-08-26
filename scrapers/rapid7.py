"""
Rapid7 Vulnerability Database scraper (web scraping)
Website: https://www.rapid7.com/db/
"""

import trafilatura
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .base import BaseScraper
import logging
import re

logger = logging.getLogger(__name__)

class Rapid7Scraper(BaseScraper):
    """Scraper for Rapid7 Vulnerability Database"""
    
    def __init__(self, config):
        super().__init__(config, 'rapid7')
        self.base_url = "https://www.rapid7.com/db"
        
        # Be respectful with rate limiting for web scraping
        self.rate_limit_delay = 2.0
    
    async def scrape(self, limit: int = None) -> List[Dict[str, Any]]:
        """Scrape recent vulnerabilities from Rapid7 DB"""
        vulnerabilities = []
        
        try:
            # Get recent vulnerabilities from the search page
            params = {
                'q': '',  # Empty query to get all recent
                'type': 'vulnerability'
            }
            
            logger.info("Scraping recent vulnerabilities from Rapid7 DB")
            
            response = await self.make_request(
                url=f"{self.base_url}/search",
                params=params
            )
            
            if not response or 'text' not in response:
                logger.error("Failed to get response from Rapid7 DB")
                return []
            
            html_content = response['text']
            vulnerability_links = self._parse_search_page(html_content)
            
            if not vulnerability_links:
                logger.info("No vulnerabilities found")
                return []
            
            logger.info(f"Processing {len(vulnerability_links)} vulnerabilities from Rapid7 DB")
            
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
            
            logger.info(f"Scraped {len(vulnerabilities)} vulnerabilities from Rapid7 DB")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error scraping Rapid7 DB: {e}")
            return []
        finally:
            await self.close_session()
    
    def _parse_search_page(self, html_content: str) -> List[Dict[str, Any]]:
        """Parse the search results page to extract vulnerability links"""
        vulnerability_links = []
        
        try:
            # Look for vulnerability links in the HTML
            # Rapid7 uses specific URL patterns for vulnerabilities
            vuln_pattern = r'href="(/db/[^"]*(?:vulnerabilities?|modules?)/[^"]+)"[^>]*>([^<]+)</a>'
            matches = re.findall(vuln_pattern, html_content, re.IGNORECASE)
            
            for url_path, title in matches:
                if 'vulnerabilities' in url_path.lower() or 'modules' in url_path.lower():
                    # Extract ID from URL
                    id_match = re.search(r'/([^/]+)/?$', url_path)
                    vuln_id = id_match.group(1) if id_match else url_path.split('/')[-1]
                    
                    vulnerability_links.append({
                        'id': vuln_id,
                        'title': title.strip(),
                        'url': f"https://www.rapid7.com{url_path}",
                        'path': url_path
                    })
                    
                    # Limit to avoid too many requests
                    if len(vulnerability_links) >= 20:
                        break
            
        except Exception as e:
            logger.error(f"Error parsing Rapid7 search page: {e}")
        
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
            
            # Extract CVE IDs from title and content
            cve_ids = self.extract_cve_ids(title + ' ' + clean_text)
            cve_id = cve_ids[0] if cve_ids else None
            
            # Create description from clean text
            description = title
            if clean_text:
                # Take first paragraph as description
                paragraphs = clean_text.split('\n\n')
                for paragraph in paragraphs[:3]:
                    if paragraph.strip() and len(paragraph.strip()) > 50:
                        # Skip if it's just the title repeated
                        if paragraph.strip().lower() != title.lower():
                            description += f'\n\n{paragraph.strip()}'
                        break
            
            # Extract metadata from HTML
            metadata = self._extract_metadata(html_content)
            
            # Get severity from metadata or content
            severity = metadata.get('severity', 'medium')
            
            # Get CVSS score if available
            cvss_score = metadata.get('cvss_score')
            
            # Get affected products/platforms
            affected_products = metadata.get('affected_products', [])
            
            # Look for additional product information in title
            if not affected_products:
                # Common patterns: "ProductName Vulnerability", "ProductName Version Exploit"
                product_patterns = [
                    r'^([A-Za-z0-9\s]+?)(?:\s+(?:Vulnerability|Exploit|Module))',
                    r'^([A-Za-z0-9\s]+?)(?:\s+\d+\.\d+)',  # Product with version
                    r'^([A-Za-z0-9\s]+?)(?:\s+-)'  # Product before dash
                ]
                
                for pattern in product_patterns:
                    match = re.match(pattern, title)
                    if match:
                        product = match.group(1).strip()
                        if product and len(product) > 2:
                            affected_products.append(product)
                        break
            
            # Extract references
            references = [vuln_url]
            ref_pattern = r'href="(https?://[^"]+)"'
            ref_matches = re.findall(ref_pattern, html_content)
            for ref in ref_matches[:5]:  # Limit to first 5 external references
                if ref not in references and 'rapid7.com' not in ref:
                    references.append(ref)
            
            # Determine if exploit is available
            exploit_available = False
            poc_available = False
            
            # Check for exploit indicators
            exploit_keywords = ['exploit', 'metasploit', 'module', 'payload']
            for keyword in exploit_keywords:
                if keyword in title.lower() or keyword in clean_text.lower():
                    exploit_available = True
                    break
            
            # Check for PoC indicators
            poc_keywords = ['proof of concept', 'poc', 'demonstration']
            for keyword in poc_keywords:
                if keyword in clean_text.lower():
                    poc_available = True
                    break
            
            # Build tags
            tags = ['rapid7']
            if exploit_available:
                tags.append('exploit_available')
            if poc_available:
                tags.append('poc_available')
            if 'metasploit' in title.lower() or 'metasploit' in clean_text.lower():
                tags.append('metasploit')
            
            # Add platform tags
            platform_keywords = ['windows', 'linux', 'unix', 'android', 'ios', 'web', 'php', 'java']
            for keyword in platform_keywords:
                if keyword in title.lower() or keyword in clean_text.lower():
                    tags.append(keyword)
            
            return self.create_vulnerability_dict(
                cve_id=cve_id,
                vulnerability_id=f"R7-{vuln_id}",
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
                tags=tags,
                raw_data=vuln_link
            )
            
        except Exception as e:
            logger.error(f"Error parsing vulnerability details {vuln_link.get('id', 'unknown')}: {e}")
            return None
    
    def _extract_metadata(self, html_content: str) -> Dict[str, Any]:
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
            
            # Look for affected products in metadata sections
            product_patterns = [
                r'(?:Platform|Product|Application)[:\s]*([^<\n]+)',
                r'(?:Affected|Target)[:\s]*([^<\n]+)'
            ]
            
            for pattern in product_patterns:
                match = re.search(pattern, html_content, re.IGNORECASE)
                if match:
                    product = match.group(1).strip()
                    if product and len(product) > 2:
                        metadata['affected_products'] = [product]
                    break
            
        except Exception as e:
            logger.error(f"Error extracting metadata: {e}")
        
        return metadata
    
    async def search_vulnerabilities(self, query: str) -> List[Dict[str, Any]]:
        """Search vulnerabilities by keyword"""
        try:
            params = {
                'q': query,
                'type': 'vulnerability'
            }
            
            response = await self.make_request(
                url=f"{self.base_url}/search",
                params=params
            )
            
            if response and 'text' in response:
                vulnerability_links = self._parse_search_page(response['text'])
                vulnerabilities = []
                
                for vuln_link in vulnerability_links[:10]:  # Limit to first 10 results
                    vuln = await self._get_vulnerability_details(vuln_link)
                    if vuln:
                        vulnerabilities.append(vuln)
                
                return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error searching Rapid7 DB: {e}")
        
        return []
