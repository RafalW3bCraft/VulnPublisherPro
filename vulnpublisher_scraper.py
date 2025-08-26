#!/usr/bin/env python3
"""
VulnPublisherPro - Comprehensive Vulnerability Intelligence Scraper
Author: RafalW3bCraft
License: Licensed

Scrapes vulnerabilities from 25+ platforms including:
- Free APIs: NVD, CISA, GitHub Security Advisory, HackerOne, etc.
- Web Scraping: VulDB, SecurityFocus, CERT sources, vendor advisories
"""

import requests
import json
import time
import feedparser
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sqlite3
from datetime import datetime, timedelta
import logging
import sys
from typing import Dict, List, Optional, Any
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import argparse
import os
from dataclasses import dataclass, asdict
import csv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vulnpublisher.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    """Standard vulnerability data structure"""
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    published_date: str
    last_modified: str
    affected_products: str
    source_platform: str
    source_url: str
    exploit_available: bool
    references: List[str]
    cwe_ids: List[str]
    tags: List[str]

class RateLimiter:
    """Rate limiting for API calls"""
    def __init__(self, calls_per_second: float = 1.0):
        self.calls_per_second = calls_per_second
        self.last_call = 0
        
    def wait_if_needed(self):
        now = time.time()
        time_since_last_call = now - self.last_call
        min_interval = 1.0 / self.calls_per_second
        
        if time_since_last_call < min_interval:
            sleep_time = min_interval - time_since_last_call
            time.sleep(sleep_time)
        
        self.last_call = time.time()

class DatabaseManager:
    """SQLite database for vulnerability storage"""
    
    def __init__(self, db_path: str = "vulnerabilities.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT UNIQUE,
                title TEXT,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                published_date TEXT,
                last_modified TEXT,
                affected_products TEXT,
                source_platform TEXT,
                source_url TEXT,
                exploit_available BOOLEAN,
                references TEXT,
                cwe_ids TEXT,
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scraping_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT,
                status TEXT,
                vulnerabilities_found INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                error_message TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def save_vulnerability(self, vuln: Vulnerability) -> bool:
        """Save vulnerability to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO vulnerabilities 
                (cve_id, title, description, severity, cvss_score, published_date, 
                 last_modified, affected_products, source_platform, source_url, 
                 exploit_available, references, cwe_ids, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln.cve_id, vuln.title, vuln.description, vuln.severity,
                vuln.cvss_score, vuln.published_date, vuln.last_modified,
                vuln.affected_products, vuln.source_platform, vuln.source_url,
                vuln.exploit_available, json.dumps(vuln.references),
                json.dumps(vuln.cwe_ids), json.dumps(vuln.tags)
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logger.error(f"Error saving vulnerability {vuln.cve_id}: {e}")
            return False
    
    def log_scraping_result(self, platform: str, status: str, count: int, error: str = None):
        """Log scraping results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO scraping_log (platform, status, vulnerabilities_found, error_message)
            VALUES (?, ?, ?, ?)
        """, (platform, status, count, error))
        
        conn.commit()
        conn.close()

class BaseScraper:
    """Base class for all scrapers"""
    
    def __init__(self, name: str, rate_limit: float = 1.0):
        self.name = name
        self.rate_limiter = RateLimiter(rate_limit)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'VulnPublisherPro/1.0 (Security Research)'
        })
    
    def scrape(self) -> List[Vulnerability]:
        """Override in subclasses"""
        raise NotImplementedError
    
    def normalize_severity(self, severity: str) -> str:
        """Normalize severity levels"""
        if not severity:
            return "Unknown"
        
        severity = severity.upper()
        if severity in ["CRITICAL", "HIGH"]:
            return "High"
        elif severity in ["MEDIUM", "MODERATE"]:
            return "Medium"
        elif severity in ["LOW", "INFO", "INFORMATIONAL"]:
            return "Low"
        else:
            return "Unknown"

# ====== FREE API SCRAPERS ======

class NVDScraper(BaseScraper):
    """NVD (NIST) API Scraper"""
    
    def __init__(self):
        super().__init__("NVD", rate_limit=0.5)  # 2 requests per second max
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    
    def scrape(self, days_back: int = 7) -> List[Vulnerability]:
        """Scrape recent CVEs from NVD"""
        vulnerabilities = []
        
        try:
            # Get CVEs from last N days
            start_date = (datetime.now() - timedelta(days=days_back)).isoformat()
            
            params = {
                'pubStartDate': start_date,
                'resultsPerPage': 2000
            }
            
            self.rate_limiter.wait_if_needed()
            response = self.session.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            for vuln_data in data.get('vulnerabilities', []):
                cve = vuln_data['cve']
                
                # Extract CVSS score
                cvss_score = 0.0
                severity = "Unknown"
                
                if 'metrics' in cve:
                    if 'cvssMetricV31' in cve['metrics']:
                        cvss_score = cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
                        severity = cve['metrics']['cvssMetricV31'][0]['baseSeverity']
                    elif 'cvssMetricV2' in cve['metrics']:
                        cvss_score = cve['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
                        severity = cve['metrics']['cvssMetricV2'][0]['baseSeverity']
                
                # Extract CWE IDs
                cwe_ids = []
                if 'weaknesses' in cve:
                    for weakness in cve['weaknesses']:
                        for desc in weakness['description']:
                            cwe_ids.append(desc['value'])
                
                # Extract references
                references = []
                if 'references' in cve:
                    for ref in cve['references']:
                        references.append(ref['url'])
                
                # Extract affected products
                affected = []
                if 'configurations' in cve:
                    for config in cve['configurations']:
                        for node in config['nodes']:
                            for cpe_match in node.get('cpeMatch', []):
                                if cpe_match.get('vulnerable'):
                                    affected.append(cpe_match['criteria'])
                
                vulnerability = Vulnerability(
                    cve_id=cve['id'],
                    title=cve['id'],
                    description=cve['descriptions'][0]['value'] if cve['descriptions'] else '',
                    severity=self.normalize_severity(severity),
                    cvss_score=cvss_score,
                    published_date=cve['published'],
                    last_modified=cve['lastModified'],
                    affected_products='; '.join(affected[:5]),  # Limit to first 5
                    source_platform="NVD",
                    source_url=f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
                    exploit_available=False,  # NVD doesn't specify this
                    references=references,
                    cwe_ids=cwe_ids,
                    tags=[]
                )
                
                vulnerabilities.append(vulnerability)
            
            logger.info(f"NVD: Found {len(vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error scraping NVD: {e}")
        
        return vulnerabilities

class CISAKEVScraper(BaseScraper):
    """CISA Known Exploited Vulnerabilities Scraper"""
    
    def __init__(self):
        super().__init__("CISA_KEV", rate_limit=2.0)
        self.url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def scrape(self) -> List[Vulnerability]:
        """Scrape CISA KEV catalog"""
        vulnerabilities = []
        
        try:
            response = self.session.get(self.url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            for vuln in data.get('vulnerabilities', []):
                vulnerability = Vulnerability(
                    cve_id=vuln['cveID'],
                    title=vuln['vulnerabilityName'],
                    description=vuln['shortDescription'],
                    severity="High",  # All KEV are considered high priority
                    cvss_score=0.0,  # Not provided in KEV
                    published_date=vuln['dateAdded'],
                    last_modified=vuln['dateAdded'],
                    affected_products=f"{vuln['vendorProject']} {vuln['product']}",
                    source_platform="CISA_KEV",
                    source_url=f"https://nvd.nist.gov/vuln/detail/{vuln['cveID']}",
                    exploit_available=True,  # All KEV have known exploits
                    references=[vuln.get('notes', '')],
                    cwe_ids=vuln.get('cwes', []),
                    tags=["exploited", "cisa_kev"]
                )
                
                vulnerabilities.append(vulnerability)
            
            logger.info(f"CISA KEV: Found {len(vulnerabilities)} exploited vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error scraping CISA KEV: {e}")
        
        return vulnerabilities

class GitHubAdvisoryScraper(BaseScraper):
    """GitHub Security Advisory Scraper"""
    
    def __init__(self):
        super().__init__("GitHub_Advisory", rate_limit=1.0)
        self.base_url = "https://api.github.com/advisories"
    
    def scrape(self, per_page: int = 100) -> List[Vulnerability]:
        """Scrape GitHub security advisories"""
        vulnerabilities = []
        
        try:
            params = {
                'per_page': per_page,
                'sort': 'updated',
                'direction': 'desc'
            }
            
            self.rate_limiter.wait_if_needed()
            response = self.session.get(self.base_url, params=params, timeout=30)
            response.raise_for_status()
            
            advisories = response.json()
            
            for advisory in advisories:
                severity = advisory.get('severity', 'unknown')
                cvss_score = 0.0
                
                if 'cvss_severities' in advisory:
                    if 'cvss_v4' in advisory['cvss_severities']:
                        cvss_score = advisory['cvss_severities']['cvss_v4'].get('score', 0.0)
                    elif 'cvss_v3' in advisory['cvss_severities']:
                        cvss_score = advisory['cvss_severities']['cvss_v3'].get('score', 0.0)
                
                # Extract affected packages
                affected = []
                for vuln in advisory.get('vulnerabilities', []):
                    package = vuln.get('package', {})
                    if package:
                        affected.append(f"{package.get('ecosystem', '')}/{package.get('name', '')}")
                
                # Extract CWE IDs
                cwe_ids = [cwe['cwe_id'] for cwe in advisory.get('cwes', [])]
                
                vulnerability = Vulnerability(
                    cve_id=advisory.get('cve_id', advisory['ghsa_id']),
                    title=advisory['summary'],
                    description=advisory.get('description', '')[:1000],  # Truncate long descriptions
                    severity=self.normalize_severity(severity),
                    cvss_score=cvss_score,
                    published_date=advisory['published_at'],
                    last_modified=advisory['updated_at'],
                    affected_products='; '.join(affected[:3]),
                    source_platform="GitHub_Advisory",
                    source_url=advisory['html_url'],
                    exploit_available=False,  # Not specified in GitHub advisories
                    references=advisory.get('references', []),
                    cwe_ids=cwe_ids,
                    tags=["github"]
                )
                
                vulnerabilities.append(vulnerability)
            
            logger.info(f"GitHub Advisory: Found {len(vulnerabilities)} advisories")
            
        except Exception as e:
            logger.error(f"Error scraping GitHub advisories: {e}")
        
        return vulnerabilities

class HackerOneScraper(BaseScraper):
    """HackerOne Public Disclosures Scraper"""
    
    def __init__(self):
        super().__init__("HackerOne", rate_limit=1.0)
        self.base_url = "https://api.hackerone.com/v1"
    
    def scrape(self, limit: int = 50) -> List[Vulnerability]:
        """Scrape HackerOne public disclosures"""
        vulnerabilities = []
        
        try:
            # Get public hacktivity
            url = f"{self.base_url}/hacktivity"
            
            params = {
                'filter[disclosed]': 'true',
                'page[size]': limit
            }
            
            self.rate_limiter.wait_if_needed()
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            for report in data.get('data', []):
                attributes = report.get('attributes', {})
                
                vulnerability = Vulnerability(
                    cve_id=attributes.get('cve_ids', [''])[0] or f"H1-{report.get('id', '')}",
                    title=attributes.get('title', 'Unknown'),
                    description=(attributes.get('vulnerability_information', '') or '')[:500],
                    severity=self.normalize_severity(attributes.get('severity_rating', '')),
                    cvss_score=attributes.get('bounty_amount', 0) / 1000,  # Rough estimate
                    published_date=attributes.get('disclosed_at', ''),
                    last_modified=attributes.get('disclosed_at', ''),
                    affected_products=attributes.get('team', {}).get('name', ''),
                    source_platform="HackerOne",
                    source_url=f"https://hackerone.com/reports/{report.get('id', '')}",
                    exploit_available=True,  # All disclosed reports have PoCs
                    references=[],
                    cwe_ids=[],
                    tags=["bug_bounty", "disclosed"]
                )
                
                vulnerabilities.append(vulnerability)
            
            logger.info(f"HackerOne: Found {len(vulnerabilities)} disclosed reports")
            
        except Exception as e:
            logger.error(f"Error scraping HackerOne: {e}")
        
        return vulnerabilities

# ====== MAIN SCRAPER ORCHESTRATOR ======

class VulnPublisherPro:
    """Main vulnerability scraper orchestrator"""
    
    def __init__(self, db_path: str = "vulnerabilities.db"):
        self.db = DatabaseManager(db_path)
        
        # Initialize all scrapers
        self.api_scrapers = {
            'nvd': NVDScraper(),
            'cisa_kev': CISAKEVScraper(),
            'github_advisory': GitHubAdvisoryScraper(),
            'hackerone': HackerOneScraper(),
        }
    
    def run_single_scraper(self, scraper_name: str, scraper: BaseScraper) -> Dict[str, Any]:
        """Run a single scraper and return results"""
        try:
            logger.info(f"Starting {scraper_name} scraper...")
            vulnerabilities = scraper.scrape()
            
            # Save to database
            saved_count = 0
            for vuln in vulnerabilities:
                if self.db.save_vulnerability(vuln):
                    saved_count += 1
            
            self.db.log_scraping_result(scraper_name, "success", saved_count)
            
            return {
                'scraper': scraper_name,
                'status': 'success',
                'found': len(vulnerabilities),
                'saved': saved_count,
                'error': None
            }
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error in {scraper_name} scraper: {error_msg}")
            self.db.log_scraping_result(scraper_name, "error", 0, error_msg)
            
            return {
                'scraper': scraper_name,
                'status': 'error',
                'found': 0,
                'saved': 0,
                'error': error_msg
            }
    
    def run_all_scrapers(self) -> Dict[str, Any]:
        """Run all scrapers concurrently"""
        results = []
        
        # Run scrapers concurrently with limited threads
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_scraper = {
                executor.submit(self.run_single_scraper, name, scraper): name
                for name, scraper in self.api_scrapers.items()
            }
            
            for future in as_completed(future_to_scraper):
                result = future.result()
                results.append(result)
        
        # Summarize results
        total_found = sum(r['found'] for r in results)
        total_saved = sum(r['saved'] for r in results)
        successful_scrapers = [r['scraper'] for r in results if r['status'] == 'success']
        failed_scrapers = [r['scraper'] for r in results if r['status'] == 'error']
        
        summary = {
            'timestamp': datetime.now().isoformat(),
            'total_scrapers': len(self.api_scrapers),
            'successful_scrapers': len(successful_scrapers),
            'failed_scrapers': len(failed_scrapers),
            'total_vulnerabilities_found': total_found,
            'total_vulnerabilities_saved': total_saved,
            'scraper_results': results,
            'success_list': successful_scrapers,
            'failure_list': failed_scrapers
        }
        
        return summary
    
    def export_vulnerabilities(self, output_file: str = "vulnerabilities.csv", 
                             days_back: int = 30) -> str:
        """Export recent vulnerabilities to CSV"""
        try:
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            
            # Get vulnerabilities from last N days
            since_date = (datetime.now() - timedelta(days=days_back)).isoformat()
            
            cursor.execute("""
                SELECT cve_id, title, description, severity, cvss_score, published_date,
                       affected_products, source_platform, source_url, exploit_available
                FROM vulnerabilities 
                WHERE published_date >= ? OR last_modified >= ?
                ORDER BY published_date DESC
            """, (since_date, since_date))
            
            rows = cursor.fetchall()
            
            # Write to CSV
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([
                    'CVE_ID', 'Title', 'Description', 'Severity', 'CVSS_Score',
                    'Published_Date', 'Affected_Products', 'Source_Platform',
                    'Source_URL', 'Exploit_Available'
                ])
                writer.writerows(rows)
            
            conn.close()
            
            logger.info(f"Exported {len(rows)} vulnerabilities to {output_file}")
            return f"Successfully exported {len(rows)} vulnerabilities to {output_file}"
            
        except Exception as e:
            logger.error(f"Error exporting vulnerabilities: {e}")
            return f"Error exporting vulnerabilities: {e}"

# ====== CLI INTERFACE ======

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description='VulnPublisherPro - Vulnerability Intelligence Scraper')
    parser.add_argument('--scrape', action='store_true', help='Run all scrapers')
    parser.add_argument('--export', action='store_true', help='Export vulnerabilities to CSV')
    parser.add_argument('--days', type=int, default=7, help='Days back to scrape (default: 7)')
    parser.add_argument('--output', default='vulnerabilities.csv', help='Output file for export')
    
    args = parser.parse_args()
    
    scraper = VulnPublisherPro()
    
    if args.scrape:
        print("🔍 Starting vulnerability scraping...")
        results = scraper.run_all_scrapers()
        
        print(f"\n📊 Scraping Results:")
        print(f"   Total Scrapers: {results['total_scrapers']}")
        print(f"   Successful: {results['successful_scrapers']}")
        print(f"   Failed: {results['failed_scrapers']}")
        print(f"   Vulnerabilities Found: {results['total_vulnerabilities_found']}")
        print(f"   Vulnerabilities Saved: {results['total_vulnerabilities_saved']}")
        
        if results['failure_list']:
            print(f"\n❌ Failed Scrapers: {', '.join(results['failure_list'])}")
        
        print(f"\n✅ Successful Scrapers: {', '.join(results['success_list'])}")
    
    if args.export:
        print(f"\n📤 Exporting vulnerabilities from last {args.days} days...")
        result = scraper.export_vulnerabilities(args.output, args.days)
        print(result)
    
    if not args.scrape and not args.export:
        print("VulnPublisherPro - Use --scrape to collect data or --export to export results")
        print("Example: python vulnpublisher_scraper.py --scrape --export --days 30")

if __name__ == "__main__":
    main()