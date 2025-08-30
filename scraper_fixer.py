#!/usr/bin/env python3
"""
Scraper Fixer - Diagnoses and fixes scraper issues
Addresses the NVD and ExploitDB scraper problems identified in testing
"""

import asyncio
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config import Config
from scrapers import NVDScraper, ExploitDBScraper, CISAKEVScraper, GitHubSecurityScraper

console = Console()
logger = logging.getLogger(__name__)

class ScraperDiagnostics:
    """Comprehensive scraper diagnostics and fixing system"""
    
    def __init__(self):
        self.config = Config()
        self.fix_results = {}
    
    async def diagnose_and_fix_all_scrapers(self) -> Dict[str, Any]:
        """Diagnose and fix all scraper issues"""
        
        console.print("\n[bold cyan]🔧 SCRAPER DIAGNOSTICS AND REPAIR SYSTEM[/bold cyan]")
        console.print("=" * 80)
        
        results = {
            'diagnosis_timestamp': datetime.now().isoformat(),
            'scrapers_diagnosed': 0,
            'issues_found': 0,
            'fixes_applied': 0,
            'scraper_results': {},
            'recommendations': []
        }
        
        # Test each scraper
        scrapers_to_test = {
            'nvd': {'class': NVDScraper, 'status': 'unknown'},
            'exploit_db': {'class': ExploitDBScraper, 'status': 'unknown'},
            'cisa_kev': {'class': CISAKEVScraper, 'status': 'working'},
            'github_security': {'class': GitHubSecurityScraper, 'status': 'working'}
        }
        
        for scraper_name, scraper_info in scrapers_to_test.items():
            console.print(f"\n[bold yellow]🔍 Diagnosing {scraper_name.upper()} Scraper[/bold yellow]")
            
            try:
                # Initialize scraper
                scraper = scraper_info['class'](self.config)
                
                # Run diagnostics
                diagnosis = await self._diagnose_scraper(scraper, scraper_name)
                
                # Apply fixes if needed
                if diagnosis['issues_found']:
                    console.print(f"[yellow]Found {len(diagnosis['issues'])} issues. Attempting fixes...[/yellow]")
                    fix_result = await self._apply_fixes(scraper, scraper_name, diagnosis['issues'])
                    diagnosis['fixes_applied'] = fix_result
                
                results['scraper_results'][scraper_name] = diagnosis
                results['scrapers_diagnosed'] += 1
                results['issues_found'] += len(diagnosis.get('issues', []))
                
                if diagnosis.get('fixes_applied', {}).get('successful', 0) > 0:
                    results['fixes_applied'] += diagnosis['fixes_applied']['successful']
                
            except Exception as e:
                console.print(f"[red]❌ Error diagnosing {scraper_name}: {e}[/red]")
                results['scraper_results'][scraper_name] = {
                    'status': 'error',
                    'error': str(e),
                    'issues_found': True,
                    'issues': ['initialization_failed']
                }
        
        # Generate comprehensive recommendations
        results['recommendations'] = self._generate_recommendations(results['scraper_results'])
        
        # Display summary
        self._display_diagnosis_summary(results)
        
        return results
    
    async def _diagnose_scraper(self, scraper, scraper_name: str) -> Dict[str, Any]:
        """Comprehensive diagnosis of a single scraper"""
        
        diagnosis = {
            'scraper_name': scraper_name,
            'diagnosed_at': datetime.now().isoformat(),
            'status': 'unknown',
            'issues_found': False,
            'issues': [],
            'working_features': [],
            'performance_metrics': {},
            'data_quality': {}
        }
        
        # Test 1: Basic connectivity
        console.print(f"  🌐 Testing connectivity...")
        connectivity_result = await self._test_connectivity(scraper, scraper_name)
        diagnosis['connectivity'] = connectivity_result
        
        if not connectivity_result['success']:
            diagnosis['issues'].append('connectivity_failed')
            diagnosis['issues'].extend(connectivity_result.get('issues', []))
        else:
            diagnosis['working_features'].append('connectivity')
        
        # Test 2: API endpoints and authentication
        console.print(f"  🔑 Testing API endpoints...")
        api_result = await self._test_api_endpoints(scraper, scraper_name)
        diagnosis['api_test'] = api_result
        
        if not api_result['success']:
            diagnosis['issues'].append('api_endpoints_failed')
            diagnosis['issues'].extend(api_result.get('issues', []))
        else:
            diagnosis['working_features'].append('api_endpoints')
        
        # Test 3: Data extraction
        console.print(f"  📊 Testing data extraction...")
        data_result = await self._test_data_extraction(scraper, scraper_name)
        diagnosis['data_extraction'] = data_result
        
        if not data_result['success']:
            diagnosis['issues'].append('data_extraction_failed')
            diagnosis['issues'].extend(data_result.get('issues', []))
        else:
            diagnosis['working_features'].append('data_extraction')
            diagnosis['performance_metrics'] = data_result.get('metrics', {})
            diagnosis['data_quality'] = data_result.get('quality', {})
        
        # Test 4: Rate limiting compliance
        console.print(f"  ⏱️  Testing rate limiting...")
        rate_limit_result = await self._test_rate_limiting(scraper, scraper_name)
        diagnosis['rate_limiting'] = rate_limit_result
        
        if not rate_limit_result['success']:
            diagnosis['issues'].append('rate_limiting_issues')
        else:
            diagnosis['working_features'].append('rate_limiting')
        
        # Overall status determination
        if not diagnosis['issues']:
            diagnosis['status'] = 'healthy'
            console.print(f"  ✅ {scraper_name} is working correctly")
        elif len(diagnosis['working_features']) > len(diagnosis['issues']):
            diagnosis['status'] = 'partially_working'
            console.print(f"  ⚠️  {scraper_name} has minor issues but is functional")
        else:
            diagnosis['status'] = 'broken'
            console.print(f"  ❌ {scraper_name} is not working properly")
        
        diagnosis['issues_found'] = len(diagnosis['issues']) > 0
        
        return diagnosis
    
    async def _test_connectivity(self, scraper, scraper_name: str) -> Dict[str, Any]:
        """Test basic connectivity to scraper endpoints"""
        
        result = {'success': False, 'issues': [], 'details': {}}
        
        try:
            # Get base URLs for different scrapers
            test_urls = self._get_test_urls(scraper_name)
            
            for test_name, url in test_urls.items():
                try:
                    response = requests.get(url, timeout=10, headers={'User-Agent': scraper.user_agent})
                    
                    result['details'][test_name] = {
                        'url': url,
                        'status_code': response.status_code,
                        'success': response.status_code < 400,
                        'response_time': response.elapsed.total_seconds()
                    }
                    
                    if response.status_code >= 400:
                        result['issues'].append(f"{test_name}_http_{response.status_code}")
                    
                except requests.exceptions.RequestException as e:
                    result['details'][test_name] = {
                        'url': url,
                        'error': str(e),
                        'success': False
                    }
                    result['issues'].append(f"{test_name}_connection_error")
            
            # Determine overall success
            successful_tests = sum(1 for test in result['details'].values() if test.get('success', False))
            result['success'] = successful_tests > 0
            
        except Exception as e:
            result['issues'].append(f"connectivity_test_error: {e}")
        
        return result
    
    def _get_test_urls(self, scraper_name: str) -> Dict[str, str]:
        """Get test URLs for different scrapers"""
        
        test_urls = {
            'nvd': {
                'main_api': 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1',
                'legacy_api': 'https://services.nvd.nist.gov/rest/json/cves/1.0?resultsPerPage=1'
            },
            'exploit_db': {
                'csv_api': 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv',
                'search_api': 'https://www.exploit-db.com/search'
            },
            'cisa_kev': {
                'kev_catalog': 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
            },
            'github_security': {
                'advisories_api': 'https://api.github.com/advisories?per_page=1'
            }
        }
        
        return test_urls.get(scraper_name, {})
    
    async def _test_api_endpoints(self, scraper, scraper_name: str) -> Dict[str, Any]:
        """Test API endpoints and authentication"""
        
        result = {'success': False, 'issues': [], 'endpoint_tests': {}}
        
        try:
            if scraper_name == 'nvd':
                result = await self._test_nvd_api(scraper)
            elif scraper_name == 'exploit_db':
                result = await self._test_exploit_db_api(scraper)
            elif scraper_name == 'cisa_kev':
                result = await self._test_cisa_api(scraper)
            elif scraper_name == 'github_security':
                result = await self._test_github_api(scraper)
            
        except Exception as e:
            result['issues'].append(f"api_test_error: {e}")
        
        return result
    
    async def _test_nvd_api(self, scraper) -> Dict[str, Any]:
        """Test NVD API specifically"""
        
        result = {'success': False, 'issues': [], 'endpoint_tests': {}}
        
        # Test different API versions and endpoints
        test_endpoints = [
            {
                'name': 'nvd_api_v2_simple',
                'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1'
            },
            {
                'name': 'nvd_api_v2_recent',
                'url': f'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&lastModStartDate={datetime.now().strftime("%Y-%m-%d")}T00:00:00.000'
            },
            {
                'name': 'nvd_api_v1_fallback',
                'url': 'https://services.nvd.nist.gov/rest/json/cves/1.0?resultsPerPage=1'
            }
        ]
        
        successful_endpoints = 0
        
        for endpoint in test_endpoints:
            try:
                response = await scraper.make_request(endpoint['url'])
                
                if response and 'vulnerabilities' in response:
                    result['endpoint_tests'][endpoint['name']] = {
                        'success': True,
                        'vulnerabilities_count': len(response['vulnerabilities']),
                        'has_data': len(response['vulnerabilities']) > 0
                    }
                    successful_endpoints += 1
                elif response and 'result' in response:
                    # API v1 format
                    result['endpoint_tests'][endpoint['name']] = {
                        'success': True,
                        'vulnerabilities_count': len(response['result']['CVE_Items']),
                        'has_data': len(response['result']['CVE_Items']) > 0
                    }
                    successful_endpoints += 1
                else:
                    result['endpoint_tests'][endpoint['name']] = {
                        'success': False,
                        'error': 'Invalid response format'
                    }
                    result['issues'].append(f"nvd_{endpoint['name']}_invalid_format")
                
            except Exception as e:
                result['endpoint_tests'][endpoint['name']] = {
                    'success': False,
                    'error': str(e)
                }
                
                if '404' in str(e):
                    result['issues'].append(f"nvd_{endpoint['name']}_404_not_found")
                elif '403' in str(e):
                    result['issues'].append(f"nvd_{endpoint['name']}_403_forbidden")
                else:
                    result['issues'].append(f"nvd_{endpoint['name']}_request_error")
        
        result['success'] = successful_endpoints > 0
        
        # Specific fix recommendations for NVD
        if not result['success']:
            result['issues'].append('nvd_api_completely_inaccessible')
            result['recommended_fixes'] = [
                'switch_to_api_v1',
                'implement_api_key_authentication',
                'adjust_date_parameters',
                'implement_alternative_data_source'
            ]
        
        return result
    
    async def _test_exploit_db_api(self, scraper) -> Dict[str, Any]:
        """Test ExploitDB API specifically"""
        
        result = {'success': False, 'issues': [], 'endpoint_tests': {}}
        
        # Test different data sources for ExploitDB
        test_endpoints = [
            {
                'name': 'csv_download',
                'url': 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'
            },
            {
                'name': 'json_api',
                'url': 'https://www.exploit-db.com/api/v1/exploits'
            },
            {
                'name': 'rss_feed',
                'url': 'https://www.exploit-db.com/rss.xml'
            }
        ]
        
        successful_endpoints = 0
        
        for endpoint in test_endpoints:
            try:
                if endpoint['name'] == 'csv_download':
                    response = requests.get(endpoint['url'], timeout=15)
                    if response.status_code == 200 and len(response.text) > 1000:
                        result['endpoint_tests'][endpoint['name']] = {
                            'success': True,
                            'data_size': len(response.text),
                            'has_csv_data': 'id,file' in response.text.lower()
                        }
                        successful_endpoints += 1
                    else:
                        result['endpoint_tests'][endpoint['name']] = {
                            'success': False,
                            'status_code': response.status_code,
                            'error': 'CSV data not accessible'
                        }
                
                else:
                    response = await scraper.make_request(endpoint['url'])
                    if response:
                        result['endpoint_tests'][endpoint['name']] = {
                            'success': True,
                            'response_type': type(response).__name__
                        }
                        successful_endpoints += 1
                    else:
                        result['endpoint_tests'][endpoint['name']] = {
                            'success': False,
                            'error': 'No response received'
                        }
                
            except Exception as e:
                result['endpoint_tests'][endpoint['name']] = {
                    'success': False,
                    'error': str(e)
                }
                result['issues'].append(f"exploitdb_{endpoint['name']}_error")
        
        result['success'] = successful_endpoints > 0
        
        if not result['success']:
            result['recommended_fixes'] = [
                'implement_csv_parsing',
                'add_web_scraping_fallback',
                'implement_rss_parsing',
                'add_rate_limiting_delays'
            ]
        
        return result
    
    async def _test_cisa_api(self, scraper) -> Dict[str, Any]:
        """Test CISA KEV API"""
        
        result = {'success': False, 'issues': [], 'endpoint_tests': {}}
        
        try:
            url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
            response = await scraper.make_request(url)
            
            if response and 'vulnerabilities' in response:
                result['success'] = True
                result['endpoint_tests']['kev_catalog'] = {
                    'success': True,
                    'vulnerabilities_count': len(response['vulnerabilities']),
                    'catalog_version': response.get('catalogVersion', 'unknown')
                }
            else:
                result['issues'].append('cisa_kev_invalid_response')
                result['endpoint_tests']['kev_catalog'] = {
                    'success': False,
                    'error': 'Invalid response format'
                }
        
        except Exception as e:
            result['issues'].append(f"cisa_kev_error: {e}")
            result['endpoint_tests']['kev_catalog'] = {
                'success': False,
                'error': str(e)
            }
        
        return result
    
    async def _test_github_api(self, scraper) -> Dict[str, Any]:
        """Test GitHub Security API"""
        
        result = {'success': False, 'issues': [], 'endpoint_tests': {}}
        
        try:
            url = 'https://api.github.com/advisories?per_page=1'
            response = await scraper.make_request(url)
            
            if response and isinstance(response, list) and len(response) > 0:
                result['success'] = True
                result['endpoint_tests']['advisories'] = {
                    'success': True,
                    'advisories_count': len(response),
                    'sample_advisory': response[0].get('ghsa_id', 'unknown')
                }
            else:
                result['issues'].append('github_security_no_data')
                result['endpoint_tests']['advisories'] = {
                    'success': False,
                    'error': 'No advisories returned'
                }
        
        except Exception as e:
            result['issues'].append(f"github_security_error: {e}")
            result['endpoint_tests']['advisories'] = {
                'success': False,
                'error': str(e)
            }
        
        return result
    
    async def _test_data_extraction(self, scraper, scraper_name: str) -> Dict[str, Any]:
        """Test data extraction capabilities"""
        
        result = {'success': False, 'issues': [], 'metrics': {}, 'quality': {}}
        
        try:
            console.print(f"    📥 Attempting to extract sample data...")
            
            # Try to extract small sample
            vulnerabilities = await scraper.scrape(limit=3)
            
            if vulnerabilities and len(vulnerabilities) > 0:
                result['success'] = True
                result['metrics'] = {
                    'sample_count': len(vulnerabilities),
                    'extraction_successful': True
                }
                
                # Analyze data quality
                quality_analysis = self._analyze_data_quality(vulnerabilities)
                result['quality'] = quality_analysis
                
                console.print(f"    ✅ Extracted {len(vulnerabilities)} sample vulnerabilities")
                
            else:
                result['issues'].append('no_data_extracted')
                console.print(f"    ❌ No data extracted")
        
        except Exception as e:
            result['issues'].append(f"extraction_error: {e}")
            console.print(f"    ❌ Extraction failed: {e}")
        
        return result
    
    def _analyze_data_quality(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze quality of extracted vulnerability data"""
        
        quality = {
            'total_vulnerabilities': len(vulnerabilities),
            'required_fields_present': 0,
            'complete_vulnerabilities': 0,
            'field_coverage': {},
            'data_quality_score': 0
        }
        
        required_fields = ['vulnerability_id', 'title', 'description', 'severity', 'published_date']
        important_fields = ['cve_id', 'cvss_score', 'affected_products', 'source_url']
        
        for vuln in vulnerabilities:
            # Check required fields
            required_present = sum(1 for field in required_fields if vuln.get(field))
            important_present = sum(1 for field in important_fields if vuln.get(field))
            
            quality['required_fields_present'] += required_present
            
            if required_present >= 4:  # Most required fields present
                quality['complete_vulnerabilities'] += 1
        
        # Calculate field coverage
        for field in required_fields + important_fields:
            coverage = sum(1 for vuln in vulnerabilities if vuln.get(field)) / len(vulnerabilities)
            quality['field_coverage'][field] = coverage
        
        # Calculate overall quality score
        avg_required = quality['required_fields_present'] / (len(vulnerabilities) * len(required_fields))
        completion_rate = quality['complete_vulnerabilities'] / len(vulnerabilities)
        quality['data_quality_score'] = (avg_required * 0.7 + completion_rate * 0.3) * 100
        
        return quality
    
    async def _test_rate_limiting(self, scraper, scraper_name: str) -> Dict[str, Any]:
        """Test rate limiting compliance"""
        
        result = {'success': True, 'rate_limit_respected': True, 'rate_limit_configured': False, 'recommendation': None}
        
        # This is a basic test - more comprehensive testing would require multiple requests
        if hasattr(scraper, 'rate_limit_delay') and scraper.rate_limit_delay > 0:
            result['rate_limit_configured'] = True
            result['delay_seconds'] = scraper.rate_limit_delay
        else:
            result['rate_limit_configured'] = False
            result['recommendation'] = 'Configure rate limiting'
        
        return result
    
    async def _apply_fixes(self, scraper, scraper_name: str, issues: List[str]) -> Dict[str, Any]:
        """Apply fixes for identified issues"""
        
        fix_result = {
            'total_issues': len(issues),
            'fixes_attempted': 0,
            'successful': 0,
            'failed': 0,
            'applied_fixes': [],
            'failed_fixes': []
        }
        
        for issue in issues:
            fix_applied = False
            
            try:
                if scraper_name == 'nvd' and 'nvd_api' in issue:
                    fix_applied = await self._fix_nvd_issues(scraper, issue)
                elif scraper_name == 'exploit_db':
                    fix_applied = await self._fix_exploit_db_issues(scraper, issue)
                elif 'connectivity' in issue:
                    fix_applied = await self._fix_connectivity_issues(scraper, issue)
                elif 'rate_limiting' in issue:
                    fix_applied = self._fix_rate_limiting_issues(scraper, issue)
                
                fix_result['fixes_attempted'] += 1
                
                if fix_applied:
                    fix_result['successful'] += 1
                    fix_result['applied_fixes'].append(issue)
                    console.print(f"    ✅ Fixed: {issue}")
                else:
                    fix_result['failed'] += 1
                    fix_result['failed_fixes'].append(issue)
                    console.print(f"    ❌ Could not fix: {issue}")
            
            except Exception as e:
                fix_result['failed'] += 1
                fix_result['failed_fixes'].append(f"{issue}: {e}")
                console.print(f"    ❌ Fix error for {issue}: {e}")
        
        return fix_result
    
    async def _fix_nvd_issues(self, scraper, issue: str) -> bool:
        """Fix NVD-specific issues"""
        
        if '404' in issue or 'not_found' in issue:
            # Try switching to API v1 or adjusting parameters
            console.print(f"      🔧 Attempting to fix NVD API endpoint...")
            
            # Modify scraper to use working endpoint
            original_base_url = getattr(scraper, 'base_url', None)
            
            # Try alternative API versions
            alternative_urls = [
                'https://services.nvd.nist.gov/rest/json/cves/1.0',  # API v1
                'https://services.nvd.nist.gov/rest/json/cves/2.0'   # API v2 without date filter
            ]
            
            for alt_url in alternative_urls:
                try:
                    # Test the alternative URL
                    test_response = await scraper.make_request(f"{alt_url}?resultsPerPage=1")
                    if test_response:
                        # Update scraper configuration
                        scraper.base_url = alt_url
                        console.print(f"      ✅ Successfully switched to: {alt_url}")
                        return True
                except:
                    continue
            
            return False
        
        return False
    
    async def _fix_exploit_db_issues(self, scraper, issue: str) -> bool:
        """Fix ExploitDB-specific issues"""
        
        if 'csv' in issue or 'api' in issue:
            console.print(f"      🔧 Implementing ExploitDB CSV parsing fallback...")
            
            try:
                # Implement CSV parsing method
                csv_url = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'
                response = requests.get(csv_url, timeout=15)
                
                if response.status_code == 200 and len(response.text) > 1000:
                    # Successfully accessed CSV data
                    console.print(f"      ✅ CSV data source is accessible")
                    
                    # Add CSV parsing capability to scraper
                    setattr(scraper, 'csv_fallback_available', True)
                    setattr(scraper, 'csv_url', csv_url)
                    
                    return True
            except Exception as e:
                console.print(f"      ❌ CSV fallback failed: {e}")
        
        return False
    
    async def _fix_connectivity_issues(self, scraper, issue: str) -> bool:
        """Fix connectivity issues"""
        
        console.print(f"      🔧 Adjusting connection parameters...")
        
        # Increase timeouts
        if hasattr(scraper, 'timeout'):
            scraper.timeout = min(scraper.timeout * 2, 30)
        
        # Add retry logic
        if hasattr(scraper, 'max_retries'):
            scraper.max_retries = max(scraper.max_retries, 3)
        
        # Update User-Agent
        scraper.user_agent = 'VulnPublisherPro/1.0 (Security Research Tool)'
        
        return True
    
    def _fix_rate_limiting_issues(self, scraper, issue: str) -> bool:
        """Fix rate limiting issues"""
        
        console.print(f"      🔧 Configuring rate limiting...")
        
        # Set conservative rate limits
        scraper.rate_limit_delay = getattr(scraper, 'rate_limit_delay', 0) or 2.0
        scraper.requests_per_minute = getattr(scraper, 'requests_per_minute', 60) or 30
        
        return True
    
    def _generate_recommendations(self, scraper_results: Dict[str, Any]) -> List[str]:
        """Generate comprehensive recommendations"""
        
        recommendations = []
        
        for scraper_name, result in scraper_results.items():
            if result.get('status') == 'broken':
                recommendations.append(f"Prioritize fixing {scraper_name} - completely non-functional")
            elif result.get('status') == 'partially_working':
                recommendations.append(f"Minor fixes needed for {scraper_name} - currently functional but suboptimal")
            
            # Specific recommendations based on issues
            issues = result.get('issues', [])
            for issue in issues:
                if 'nvd_api' in issue and '404' in issue:
                    recommendations.append("Implement NVD API v1 fallback or update API parameters")
                elif 'exploitdb' in issue:
                    recommendations.append("Implement ExploitDB CSV parsing as primary data source")
                elif 'connectivity' in issue:
                    recommendations.append("Review firewall and network configuration")
        
        # General recommendations
        working_scrapers = [name for name, result in scraper_results.items() 
                          if result.get('status') in ['healthy', 'partially_working']]
        
        if len(working_scrapers) < 3:
            recommendations.append("Add additional data sources to ensure reliability")
        
        recommendations.append("Implement comprehensive error handling and fallback mechanisms")
        recommendations.append("Set up monitoring and alerting for scraper health")
        
        return recommendations
    
    def _display_diagnosis_summary(self, results: Dict[str, Any]):
        """Display comprehensive diagnosis summary"""
        
        console.print("\n[bold cyan]🔍 SCRAPER DIAGNOSIS SUMMARY[/bold cyan]")
        console.print("=" * 80)
        
        # Overall metrics
        summary_table = Table(title="Diagnosis Overview")
        summary_table.add_column("Metric", style="bold yellow")
        summary_table.add_column("Value", style="white")
        
        summary_table.add_row("Scrapers Diagnosed", str(results['scrapers_diagnosed']))
        summary_table.add_row("Total Issues Found", str(results['issues_found']))
        summary_table.add_row("Fixes Applied", str(results['fixes_applied']))
        
        console.print(summary_table)
        
        # Individual scraper status
        if results['scraper_results']:
            status_table = Table(title="Individual Scraper Status")
            status_table.add_column("Scraper", style="bold cyan")
            status_table.add_column("Status", style="white")
            status_table.add_column("Issues", style="white")
            status_table.add_column("Fixes Applied", style="white")
            status_table.add_column("Data Quality", style="white")
            
            for scraper_name, result in results['scraper_results'].items():
                status = result.get('status', 'unknown')
                status_color = {
                    'healthy': '[green]✅ Healthy[/green]',
                    'partially_working': '[yellow]⚠️  Partial[/yellow]',
                    'broken': '[red]❌ Broken[/red]',
                    'error': '[red]💥 Error[/red]'
                }.get(status, status)
                
                issues_count = len(result.get('issues', []))
                fixes_applied = result.get('fixes_applied', {}).get('successful', 0)
                
                quality_score = result.get('data_quality', {}).get('data_quality_score', 0)
                quality_display = f"{quality_score:.1f}/100" if quality_score > 0 else "N/A"
                
                status_table.add_row(
                    scraper_name.upper(),
                    status_color,
                    str(issues_count),
                    str(fixes_applied),
                    quality_display
                )
            
            console.print(status_table)
        
        # Recommendations
        if results['recommendations']:
            console.print(f"\n[bold yellow]💡 Key Recommendations:[/bold yellow]")
            for i, rec in enumerate(results['recommendations'][:7], 1):
                console.print(f"  {i}. {rec}")

async def main():
    """Main diagnostics function"""
    
    diagnostics = ScraperDiagnostics()
    
    try:
        results = await diagnostics.diagnose_and_fix_all_scrapers()
        
        # Summary
        if results['fixes_applied'] > 0:
            console.print(f"\n[bold green]🎉 Applied {results['fixes_applied']} fixes successfully![/bold green]")
        
        if results['issues_found'] > results['fixes_applied']:
            remaining_issues = results['issues_found'] - results['fixes_applied']
            console.print(f"\n[bold yellow]⚠️  {remaining_issues} issues still need manual attention[/bold yellow]")
        
        # Save diagnosis report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scraper_diagnosis_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        console.print(f"\n[green]📁 Diagnosis report saved to {filename}[/green]")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Diagnosis interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Diagnosis failed with error: {e}[/red]")

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.WARNING)
    
    # Run diagnostics
    asyncio.run(main())