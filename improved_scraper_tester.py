#!/usr/bin/env python3
"""
Improved Scraper Testing System
Tests all scrapers for proper data extraction, validates data quality, and generates reports
"""

import asyncio
import json
import logging
from typing import Dict, Any, List
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import os

# Configure OpenAI for AI content generation testing
os.environ.setdefault('OPENAI_API_KEY', 'test-key')

from config import Config
from scrapers import (
    NVDScraper, GitHubSecurityScraper, HackerOneScraper, BugcrowdScraper,
    CISAKEVScraper, ExploitDBScraper
)
from content_generator import ContentGenerator
from user_review_system import UserReviewSystem

console = Console()
logger = logging.getLogger(__name__)

class ImprovedScraperTester:
    """Enhanced scraper testing system with quality validation"""
    
    def __init__(self):
        self.config = Config()
        self.test_results = {}
        self.content_generator = ContentGenerator(self.config.openai_api_key or "test-key")
        self.review_system = UserReviewSystem()
        
        # Initialize scrapers that are most likely to work
        self.scrapers = {
            'cisa_kev': CISAKEVScraper(self.config),
            'nvd': NVDScraper(self.config),
            'exploit_db': ExploitDBScraper(self.config),
            'github_security': GitHubSecurityScraper(self.config)
        }
        
    async def test_all_scrapers(self, limit_per_scraper: int = 5) -> Dict[str, Any]:
        """Test all scrapers and validate data quality"""
        
        console.print("\n[bold cyan]🔍 TESTING ALL SCRAPERS FOR DATA QUALITY[/bold cyan]")
        console.print("=" * 80)
        
        results = {
            'test_timestamp': datetime.now().isoformat(),
            'scrapers_tested': len(self.scrapers),
            'results': {},
            'overall_quality_score': 0,
            'recommendations': []
        }
        
        successful_scrapers = []
        failed_scrapers = []
        
        for scraper_name, scraper in self.scrapers.items():
            console.print(f"\n[bold yellow]Testing {scraper_name.upper()} Scraper[/bold yellow]")
            
            try:
                # Test scraping with small limit
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    console=console
                ) as progress:
                    task = progress.add_task(f"Scraping from {scraper_name}...", total=None)
                    
                    vulnerabilities = await scraper.scrape(limit=limit_per_scraper)
                    
                    progress.update(task, description=f"✅ Got {len(vulnerabilities)} vulnerabilities")
                
                if vulnerabilities:
                    # Validate data quality
                    quality_score = self._validate_data_quality(vulnerabilities)
                    
                    # Test required fields
                    field_completeness = self._check_required_fields(vulnerabilities)
                    
                    # Test data formats
                    format_compliance = self._check_data_formats(vulnerabilities)
                    
                    result = {
                        'status': 'success',
                        'vulnerabilities_count': len(vulnerabilities),
                        'quality_score': quality_score,
                        'field_completeness': field_completeness,
                        'format_compliance': format_compliance,
                        'overall_score': (quality_score + field_completeness + format_compliance) / 3,
                        'sample_data': vulnerabilities[:2]  # Store 2 samples
                    }
                    
                    successful_scrapers.append(scraper_name)
                    console.print(f"[green]✅ Success - Quality Score: {result['overall_score']:.1f}/100[/green]")
                    
                else:
                    result = {
                        'status': 'no_data',
                        'error': 'No vulnerabilities returned',
                        'overall_score': 0
                    }
                    failed_scrapers.append(scraper_name)
                    console.print(f"[yellow]⚠️  No data returned[/yellow]")
                
            except Exception as e:
                result = {
                    'status': 'error',
                    'error': str(e),
                    'overall_score': 0
                }
                failed_scrapers.append(scraper_name)
                console.print(f"[red]❌ Error: {str(e)[:100]}[/red]")
            
            results['results'][scraper_name] = result
        
        # Calculate overall quality score
        valid_scores = [r['overall_score'] for r in results['results'].values() if r['overall_score'] > 0]
        results['overall_quality_score'] = sum(valid_scores) / len(valid_scores) if valid_scores else 0
        
        # Generate summary
        self._display_test_summary(results, successful_scrapers, failed_scrapers)
        
        # Generate recommendations
        results['recommendations'] = self._generate_improvement_recommendations(results['results'])
        
        return results
    
    def _validate_data_quality(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Validate data quality of scraped vulnerabilities"""
        
        if not vulnerabilities:
            return 0.0
        
        quality_checks = []
        
        for vuln in vulnerabilities:
            checks = {
                'has_meaningful_title': self._has_meaningful_title(vuln.get('title', '')),
                'has_detailed_description': self._has_detailed_description(vuln.get('description', '')),
                'has_valid_severity': self._has_valid_severity(vuln.get('severity')),
                'has_source_attribution': bool(vuln.get('source_url', '').strip()),
                'has_publication_date': bool(vuln.get('published_date')),
                'no_duplicate_content': self._check_no_duplicates(vuln),
                'proper_formatting': self._check_proper_formatting(vuln)
            }
            
            quality_score = sum(checks.values()) / len(checks)
            quality_checks.append(quality_score)
        
        return sum(quality_checks) / len(quality_checks) * 100
    
    def _check_required_fields(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Check if all required fields are present and complete"""
        
        required_fields = [
            'vulnerability_id', 'title', 'description', 'severity', 
            'published_date', 'source_url'
        ]
        
        important_fields = [
            'cve_id', 'cvss_score', 'affected_products', 'references', 'tags'
        ]
        
        completeness_scores = []
        
        for vuln in vulnerabilities:
            required_present = sum(1 for field in required_fields if vuln.get(field))
            important_present = sum(1 for field in important_fields if vuln.get(field))
            
            required_score = required_present / len(required_fields)
            important_score = important_present / len(important_fields)
            
            total_score = (required_score * 0.8) + (important_score * 0.2)
            completeness_scores.append(total_score)
        
        return sum(completeness_scores) / len(completeness_scores) * 100
    
    def _check_data_formats(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Check if data follows proper formats and standards"""
        
        format_scores = []
        
        for vuln in vulnerabilities:
            checks = {
                'proper_cve_format': self._validate_cve_format(vuln.get('cve_id')),
                'valid_severity_values': vuln.get('severity') in ['critical', 'high', 'medium', 'low', 'info', 'unknown'],
                'valid_cvss_score': self._validate_cvss_score(vuln.get('cvss_score')),
                'proper_date_format': self._validate_date_format(vuln.get('published_date')),
                'clean_text_content': self._validate_clean_text(vuln),
                'proper_list_formats': self._validate_list_formats(vuln)
            }
            
            format_score = sum(checks.values()) / len(checks)
            format_scores.append(format_score)
        
        return sum(format_scores) / len(format_scores) * 100
    
    def _has_meaningful_title(self, title: str) -> bool:
        """Check if title is meaningful and descriptive"""
        if not title or len(title.strip()) < 10:
            return False
        
        # Check for common meaningless patterns
        meaningless_patterns = ['test', 'example', 'placeholder', 'null', 'undefined']
        title_lower = title.lower()
        
        return not any(pattern in title_lower for pattern in meaningless_patterns)
    
    def _has_detailed_description(self, description: str) -> bool:
        """Check if description provides adequate detail"""
        if not description or len(description.strip()) < 50:
            return False
        
        # Check for technical depth indicators
        technical_indicators = [
            'vulnerability', 'exploit', 'attack', 'payload', 'injection', 
            'bypass', 'overflow', 'disclosure', 'exposure', 'flaw'
        ]
        
        description_lower = description.lower()
        return any(indicator in description_lower for indicator in technical_indicators)
    
    def _has_valid_severity(self, severity: str) -> bool:
        """Check if severity is valid"""
        valid_severities = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
        return severity in valid_severities if severity else False
    
    def _check_no_duplicates(self, vuln: Dict[str, Any]) -> bool:
        """Check for duplicate content patterns"""
        title = vuln.get('title', '')
        description = vuln.get('description', '')
        
        # Simple duplicate check - more sophisticated logic could be added
        return title.lower() not in description.lower() if title and description else True
    
    def _check_proper_formatting(self, vuln: Dict[str, Any]) -> bool:
        """Check if text content is properly formatted"""
        text_fields = ['title', 'description']
        
        for field in text_fields:
            value = vuln.get(field, '')
            if value:
                # Check for excessive whitespace, HTML tags, etc.
                if '  ' in value or '<' in value or value != value.strip():
                    return False
        
        return True
    
    def _validate_cve_format(self, cve_id: str) -> bool:
        """Validate CVE ID format"""
        if not cve_id:
            return True  # Optional field
        
        import re
        cve_pattern = r'^CVE-\d{4}-\d{4,}$'
        return bool(re.match(cve_pattern, cve_id))
    
    def _validate_cvss_score(self, cvss_score: Any) -> bool:
        """Validate CVSS score"""
        if cvss_score is None:
            return True  # Optional field
        
        try:
            score = float(cvss_score)
            return 0.0 <= score <= 10.0
        except (ValueError, TypeError):
            return False
    
    def _validate_date_format(self, date_str: str) -> bool:
        """Validate date format"""
        if not date_str:
            return False
        
        try:
            datetime.fromisoformat(str(date_str).replace('Z', '+00:00'))
            return True
        except ValueError:
            try:
                datetime.strptime(str(date_str), '%Y-%m-%d')
                return True
            except ValueError:
                return False
    
    def _validate_clean_text(self, vuln: Dict[str, Any]) -> bool:
        """Validate that text content is clean"""
        text_fields = ['title', 'description']
        
        for field in text_fields:
            value = vuln.get(field, '')
            if value and ('<script>' in value.lower() or '&lt;' in value):
                return False
        
        return True
    
    def _validate_list_formats(self, vuln: Dict[str, Any]) -> bool:
        """Validate that list fields are properly formatted"""
        list_fields = ['affected_products', 'references', 'tags']
        
        for field in list_fields:
            value = vuln.get(field)
            if value is not None and not isinstance(value, list):
                return False
        
        return True
    
    def _display_test_summary(self, results: Dict[str, Any], successful: List[str], failed: List[str]):
        """Display test summary"""
        
        console.print("\n[bold cyan]📊 SCRAPER TEST SUMMARY[/bold cyan]")
        console.print("=" * 80)
        
        # Success/Failure table
        summary_table = Table(title="Test Results Overview")
        summary_table.add_column("Metric", style="bold yellow")
        summary_table.add_column("Value", style="white")
        
        summary_table.add_row("Total Scrapers Tested", str(results['scrapers_tested']))
        summary_table.add_row("Successful Scrapers", f"[green]{len(successful)}[/green]")
        summary_table.add_row("Failed Scrapers", f"[red]{len(failed)}[/red]")
        summary_table.add_row("Overall Quality Score", f"{results['overall_quality_score']:.1f}/100")
        
        console.print(summary_table)
        
        # Detailed results table
        if results['results']:
            details_table = Table(title="Detailed Scraper Results")
            details_table.add_column("Scraper", style="bold cyan")
            details_table.add_column("Status", style="white")
            details_table.add_column("Count", style="white")
            details_table.add_column("Quality", style="white")
            details_table.add_column("Completeness", style="white")
            details_table.add_column("Format", style="white")
            details_table.add_column("Overall", style="bold white")
            
            for scraper_name, result in results['results'].items():
                status = "✅ Success" if result['status'] == 'success' else "❌ Failed"
                count = str(result.get('vulnerabilities_count', 0))
                quality = f"{result.get('quality_score', 0):.1f}"
                completeness = f"{result.get('field_completeness', 0):.1f}"
                format_score = f"{result.get('format_compliance', 0):.1f}"
                overall = f"{result.get('overall_score', 0):.1f}"
                
                details_table.add_row(
                    scraper_name.upper(), status, count, 
                    quality, completeness, format_score, overall
                )
            
            console.print(details_table)
        
        # Working scrapers
        if successful:
            console.print(f"\n[bold green]✅ Working Scrapers:[/bold green]")
            for scraper in successful:
                console.print(f"  • {scraper.upper()}")
        
        # Failed scrapers
        if failed:
            console.print(f"\n[bold red]❌ Failed Scrapers:[/bold red]")
            for scraper in failed:
                error = results['results'][scraper].get('error', 'Unknown error')
                console.print(f"  • {scraper.upper()}: {error[:50]}...")
    
    def _generate_improvement_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate recommendations for improving scrapers"""
        
        recommendations = []
        
        for scraper_name, result in results.items():
            if result['status'] == 'success':
                overall_score = result['overall_score']
                
                if overall_score < 70:
                    recommendations.append(f"Improve {scraper_name} data quality - score below 70%")
                
                if result.get('quality_score', 0) < 60:
                    recommendations.append(f"Enhance {scraper_name} data validation and cleanup")
                
                if result.get('field_completeness', 0) < 80:
                    recommendations.append(f"Extract more complete metadata for {scraper_name}")
                
                if result.get('format_compliance', 0) < 70:
                    recommendations.append(f"Improve data formatting standards for {scraper_name}")
            
            elif result['status'] == 'no_data':
                recommendations.append(f"Check {scraper_name} API credentials and data availability")
            
            elif result['status'] == 'error':
                recommendations.append(f"Fix {scraper_name} scraper errors: {result.get('error', '')[:50]}")
        
        # General recommendations
        working_scrapers = [name for name, result in results.items() if result['status'] == 'success']
        if len(working_scrapers) < 3:
            recommendations.append("Consider adding more reliable data sources")
        
        high_quality_scrapers = [name for name, result in results.items() 
                               if result.get('overall_score', 0) > 80]
        if not high_quality_scrapers:
            recommendations.append("Implement stricter data validation and quality controls")
        
        return recommendations
    
    async def test_ai_content_generation(self, sample_vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Test AI content generation with sample data"""
        
        console.print("\n[bold cyan]🤖 TESTING AI CONTENT GENERATION[/bold cyan]")
        console.print("=" * 80)
        
        if not sample_vulnerabilities:
            console.print("[red]No sample data available for AI testing[/red]")
            return {'status': 'no_data'}
        
        # Test different content types
        content_types = ['summary', 'detailed', 'alert']
        platforms = ['twitter', 'linkedin', 'medium']
        
        test_results = {
            'tested_at': datetime.now().isoformat(),
            'sample_vuln_used': sample_vulnerabilities[0]['vulnerability_id'],
            'content_generation_results': {},
            'quality_scores': {},
            'overall_ai_score': 0
        }
        
        total_score = 0
        test_count = 0
        
        test_vuln = sample_vulnerabilities[0]
        
        for content_type in content_types:
            try:
                console.print(f"  📝 Generating {content_type} content...")
                
                # Generate content
                content = await self.content_generator.generate_content(test_vuln, content_type)
                
                if content and content.get('content'):
                    # Assess content quality
                    quality_score = self._assess_ai_content_quality(content, content_type)
                    
                    test_results['content_generation_results'][content_type] = {
                        'status': 'success',
                        'content_length': len(content.get('content', '')),
                        'has_hashtags': bool(content.get('hashtags')),
                        'quality_score': quality_score,
                        'sample_content': content.get('content', '')[:200] + '...'
                    }
                    
                    test_results['quality_scores'][content_type] = quality_score
                    total_score += quality_score
                    test_count += 1
                    
                    console.print(f"    ✅ Success - Quality: {quality_score:.1f}/100")
                else:
                    test_results['content_generation_results'][content_type] = {
                        'status': 'failed',
                        'error': 'No content generated'
                    }
                    console.print(f"    ❌ Failed to generate content")
                
            except Exception as e:
                test_results['content_generation_results'][content_type] = {
                    'status': 'error',
                    'error': str(e)
                }
                console.print(f"    ❌ Error: {str(e)[:50]}...")
        
        test_results['overall_ai_score'] = total_score / test_count if test_count > 0 else 0
        
        console.print(f"\n[bold green]AI Content Generation Score: {test_results['overall_ai_score']:.1f}/100[/bold green]")
        
        return test_results
    
    def _assess_ai_content_quality(self, content: Dict[str, Any], content_type: str) -> float:
        """Assess quality of AI-generated content"""
        
        text = content.get('content', '')
        if not text:
            return 0.0
        
        quality_checks = {
            'appropriate_length': self._check_content_length(text, content_type),
            'technical_accuracy': self._check_technical_accuracy(text),
            'readability': self._check_readability(text),
            'professional_tone': self._check_professional_tone(text),
            'actionable_info': self._check_actionable_info(text),
            'proper_formatting': self._check_ai_formatting(text)
        }
        
        return sum(quality_checks.values()) / len(quality_checks) * 100
    
    def _check_content_length(self, text: str, content_type: str) -> bool:
        """Check if content length is appropriate for type"""
        length = len(text)
        
        if content_type == 'summary':
            return 50 <= length <= 300
        elif content_type == 'detailed':
            return 200 <= length <= 1000
        elif content_type == 'alert':
            return 30 <= length <= 200
        
        return True
    
    def _check_technical_accuracy(self, text: str) -> bool:
        """Check for technical accuracy indicators"""
        technical_terms = [
            'vulnerability', 'exploit', 'CVE', 'security', 'patch', 
            'update', 'mitigation', 'attack', 'risk'
        ]
        
        text_lower = text.lower()
        return any(term in text_lower for term in technical_terms)
    
    def _check_readability(self, text: str) -> bool:
        """Check basic readability"""
        # Simple checks
        sentences = text.split('.')
        if not sentences:
            return False
        
        # Check for reasonable sentence length
        avg_sentence_length = sum(len(s.split()) for s in sentences) / len(sentences)
        return 5 <= avg_sentence_length <= 25
    
    def _check_professional_tone(self, text: str) -> bool:
        """Check for professional tone"""
        unprofessional_indicators = ['lol', 'omg', '!!!', 'wow', 'amazing']
        text_lower = text.lower()
        
        return not any(indicator in text_lower for indicator in unprofessional_indicators)
    
    def _check_actionable_info(self, text: str) -> bool:
        """Check if content provides actionable information"""
        actionable_indicators = [
            'update', 'patch', 'upgrade', 'mitigate', 'protect', 
            'secure', 'fix', 'apply', 'install', 'configure'
        ]
        
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in actionable_indicators)
    
    def _check_ai_formatting(self, text: str) -> bool:
        """Check if AI content is properly formatted"""
        # Check for proper capitalization and punctuation
        if not text or not text[0].isupper():
            return False
        
        if not text.endswith(('.', '!', '?')):
            return False
        
        return True
    
    async def run_comprehensive_test(self, limit_per_scraper: int = 5) -> Dict[str, Any]:
        """Run comprehensive test of entire system"""
        
        console.print("\n[bold cyan]🚀 COMPREHENSIVE SYSTEM TEST[/bold cyan]")
        console.print("=" * 80)
        
        comprehensive_results = {
            'test_timestamp': datetime.now().isoformat(),
            'scraper_test_results': {},
            'ai_test_results': {},
            'system_ready': False,
            'overall_system_score': 0,
            'critical_issues': [],
            'recommendations': []
        }
        
        # Test scrapers
        scraper_results = await self.test_all_scrapers(limit_per_scraper)
        comprehensive_results['scraper_test_results'] = scraper_results
        
        # Get sample data for AI testing
        sample_vulnerabilities = []
        for result in scraper_results['results'].values():
            if result.get('sample_data'):
                sample_vulnerabilities.extend(result['sample_data'])
        
        # Test AI content generation
        if sample_vulnerabilities:
            ai_results = await self.test_ai_content_generation(sample_vulnerabilities)
            comprehensive_results['ai_test_results'] = ai_results
        
        # Calculate overall system score
        scores = []
        if scraper_results.get('overall_quality_score', 0) > 0:
            scores.append(scraper_results['overall_quality_score'])
        if comprehensive_results['ai_test_results'].get('overall_ai_score', 0) > 0:
            scores.append(comprehensive_results['ai_test_results']['overall_ai_score'])
        
        comprehensive_results['overall_system_score'] = sum(scores) / len(scores) if scores else 0
        
        # Determine system readiness
        comprehensive_results['system_ready'] = (
            comprehensive_results['overall_system_score'] >= 70 and
            len([r for r in scraper_results['results'].values() if r['status'] == 'success']) >= 2
        )
        
        # Generate final recommendations
        comprehensive_results['recommendations'] = scraper_results.get('recommendations', [])
        
        # Display final summary
        self._display_comprehensive_summary(comprehensive_results)
        
        # Save results
        self._save_test_results(comprehensive_results)
        
        return comprehensive_results
    
    def _display_comprehensive_summary(self, results: Dict[str, Any]):
        """Display comprehensive test summary"""
        
        console.print("\n[bold cyan]📊 COMPREHENSIVE TEST SUMMARY[/bold cyan]")
        console.print("=" * 80)
        
        # Overall status
        status_color = "green" if results['system_ready'] else "red"
        status_text = "READY FOR PRODUCTION" if results['system_ready'] else "NEEDS IMPROVEMENT"
        
        console.print(f"\n[bold {status_color}]System Status: {status_text}[/bold {status_color}]")
        console.print(f"Overall System Score: {results['overall_system_score']:.1f}/100")
        
        # Component scores
        scraper_score = results['scraper_test_results'].get('overall_quality_score', 0)
        ai_score = results['ai_test_results'].get('overall_ai_score', 0)
        
        scores_table = Table(title="Component Scores")
        scores_table.add_column("Component", style="bold yellow")
        scores_table.add_column("Score", style="white")
        scores_table.add_column("Status", style="white")
        
        def score_status(score):
            if score >= 80:
                return "[green]EXCELLENT[/green]"
            elif score >= 70:
                return "[yellow]GOOD[/yellow]"
            elif score >= 50:
                return "[orange]NEEDS WORK[/orange]"
            else:
                return "[red]POOR[/red]"
        
        scores_table.add_row("Data Scrapers", f"{scraper_score:.1f}/100", score_status(scraper_score))
        scores_table.add_row("AI Content Generation", f"{ai_score:.1f}/100", score_status(ai_score))
        
        console.print(scores_table)
        
        # Recommendations
        if results.get('recommendations'):
            console.print(f"\n[bold yellow]💡 Key Recommendations:[/bold yellow]")
            for i, rec in enumerate(results['recommendations'][:5], 1):
                console.print(f"  {i}. {rec}")
    
    def _save_test_results(self, results: Dict[str, Any]):
        """Save test results to file"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"comprehensive_system_test_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            console.print(f"\n[green]✅ Test results saved to {filename}[/green]")
            
        except Exception as e:
            console.print(f"[red]❌ Error saving results: {e}[/red]")

async def main():
    """Main test function"""
    tester = ImprovedScraperTester()
    
    try:
        # Run comprehensive test
        results = await tester.run_comprehensive_test(limit_per_scraper=10)
        
        # Show final status
        if results['system_ready']:
            console.print("\n[bold green]🎉 System is ready for production use![/bold green]")
        else:
            console.print("\n[bold red]⚠️  System needs improvements before production use[/bold red]")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Test failed with error: {e}[/red]")

if __name__ == "__main__":
    # Setup logging
    logging.basicConfig(level=logging.WARNING)
    
    # Run the test
    asyncio.run(main())