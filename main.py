#!/usr/bin/env python3
"""
VulnPublisherPro - Comprehensive vulnerability scraping and publishing tool
"""

import click
import json
import sqlite3
import logging
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Any
import asyncio

from config import Config
from database import DatabaseManager
from content_generator import ContentGenerator
from utils import setup_logging, validate_config
from scheduler import SchedulerManager
from ai_integration.auto_categorizer import AutoCategorizer
from ai_integration.expert_simulator import ExpertInterviewSimulator
from blog_engine.ai_content_generator import AIContentGenerator
from blog_engine.autonomous_publisher import AutonomousPublisher
# Interactive CLI utilities
import inquirer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

# Import all scrapers
from scrapers import (
    NVDScraper, GitHubSecurityScraper, HackerOneScraper, BugcrowdScraper,
    IntigritiScraper, CISAKEVScraper, MITRECVEScraper, VulnCheckScraper,
    CVEDetailsScraper, ExploitDBScraper, Rapid7Scraper, VulnDBScraper,
    RedditSecurityScraper
)

# Import all publishers
from publishers import (
    TwitterPublisher, LinkedInPublisher, TelegramPublisher, DiscordPublisher,
    RedditPublisher, MediumPublisher, FacebookPublisher, InstagramPublisher,
    YouTubePublisher, TikTokPublisher, MastodonPublisher, SlackPublisher,
    TeamsPublisher
)

logger = logging.getLogger(__name__)
console = Console()

class VulnPublisherPro:
    """Main application class for VulnPublisherPro"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = Config(config_path)
        # Use DATABASE_URL if available, otherwise fall back to local SQLite
        db_connection = self.config.database_url or self.config.database_path
        self.db = DatabaseManager(db_connection)
        # Ensure OpenAI API key is available
        openai_key = self.config.openai_api_key
        if not openai_key:
            logger.warning("OpenAI API key not found - content generation will be limited")
            openai_key = "dummy_key"  # Provide fallback for initialization
        self.content_generator = ContentGenerator(openai_key)
        self.scheduler = SchedulerManager()
        
        # Initialize AI integration components
        self.auto_categorizer = AutoCategorizer()
        self.expert_simulator = ExpertInterviewSimulator(self.db)
        
        # Initialize blog engine components
        self.ai_content_generator = AIContentGenerator(openai_key)
        self.autonomous_publisher = AutonomousPublisher(self.db)
        
        # Initialize scrapers
        self.scrapers = {
            'nvd': NVDScraper(self.config),
            'github': GitHubSecurityScraper(self.config),
            'hackerone': HackerOneScraper(self.config),
            'bugcrowd': BugcrowdScraper(self.config),
            'intigriti': IntigritiScraper(self.config),
            'cisa_kev': CISAKEVScraper(self.config),
            'mitre': MITRECVEScraper(self.config),
            'vulncheck': VulnCheckScraper(self.config),
            'cve_details': CVEDetailsScraper(self.config),
            'exploit_db': ExploitDBScraper(self.config),
            'rapid7': Rapid7Scraper(self.config),
            'vulndb': VulnDBScraper(self.config),
            'reddit': RedditSecurityScraper(self.config)
        }
        
        # Initialize publishers
        self.publishers = {
            'twitter': TwitterPublisher(self.config),
            'linkedin': LinkedInPublisher(self.config),
            'telegram': TelegramPublisher(self.config),
            'discord': DiscordPublisher(self.config),
            'reddit': RedditPublisher(self.config),
            'medium': MediumPublisher(self.config),
            'facebook': FacebookPublisher(self.config),
            'instagram': InstagramPublisher(self.config),
            'youtube': YouTubePublisher(self.config),
            'tiktok': TikTokPublisher(self.config),
            'mastodon': MastodonPublisher(self.config),
            'slack': SlackPublisher(self.config),
            'teams': TeamsPublisher(self.config)
        }
    
    async def scrape_vulnerabilities(self, sources: Optional[List[str]] = None, limit: Optional[int] = None, interactive: bool = False) -> Dict:
        """Scrape vulnerabilities from specified sources"""
        if not sources:
            sources = list(self.scrapers.keys())
        
        results = {
            'total_scraped': 0,
            'total_new': 0,
            'total_updated': 0,
            'sources': {}
        }
        
        if interactive:
            console.print("\n[bold blue]🔍 Starting Vulnerability Scraping[/bold blue]")
            console.print(f"[cyan]Sources: {', '.join(sources)}[/cyan]")
            console.print(f"[cyan]Limit per source: {limit or 'No limit'}[/cyan]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console if interactive else None,
            disable=not interactive
        ) as progress:
            
            for i, source in enumerate(sources, 1):
                if source not in self.scrapers:
                    if interactive:
                        console.print(f"[red]❌ Unknown scraper source: {source}[/red]")
                    logger.warning(f"Unknown scraper source: {source}")
                    continue
                
                task = progress.add_task(f"[cyan]Scraping {source}... ({i}/{len(sources)})", total=None) if interactive else None
                
                try:
                    scraper = self.scrapers[source]
                    vulnerabilities = await scraper.scrape(limit=limit)
                    
                    # Process vulnerabilities with progress
                    new_count = 0
                    updated_count = 0
                    
                    if interactive and vulnerabilities and task is not None:
                        progress.update(task, description=f"[green]Processing {len(vulnerabilities)} vulns from {source}...")
                    
                    for vuln in vulnerabilities:
                        is_new = self.db.store_vulnerability(vuln)
                        if is_new:
                            new_count += 1
                        else:
                            updated_count += 1
                    
                    results['sources'][source] = {
                        'scraped': len(vulnerabilities),
                        'new': new_count,
                        'updated': updated_count
                    }
                    
                    results['total_scraped'] += len(vulnerabilities)
                    results['total_new'] += new_count
                    results['total_updated'] += updated_count
                    
                    if interactive and task is not None:
                        progress.update(task, description=f"[green]✅ {source}: {len(vulnerabilities)} scraped, {new_count} new")
                        console.print(f"[green]✅ {source}: {len(vulnerabilities)} scraped, {new_count} new, {updated_count} updated[/green]")
                    
                    logger.info(f"Scraped {len(vulnerabilities)} vulnerabilities from {source}")
                    
                except Exception as e:
                    error_msg = f"Error scraping from {source}: {e}"
                    if interactive and task is not None:
                        progress.update(task, description=f"[red]❌ {source}: Error")
                        console.print(f"[red]❌ {source}: {str(e)}[/red]")
                    
                    logger.error(error_msg)
                    results['sources'][source] = {'error': str(e)}
                
                finally:
                    if interactive and task:
                        progress.remove_task(task)
        
        if interactive:
            console.print(f"\n[bold green]📊 Scraping Summary:[/bold green]")
            console.print(f"[green]Total scraped: {results['total_scraped']}[/green]")
            console.print(f"[green]New vulnerabilities: {results['total_new']}[/green]")
            console.print(f"[green]Updated vulnerabilities: {results['total_updated']}[/green]")
        
        return results
    
    async def generate_and_publish(self, vulnerability_ids: Optional[List[str]] = None, 
                                 platforms: Optional[List[str]] = None, 
                                 content_type: str = 'summary') -> Dict:
        """Generate content and publish to specified platforms"""
        if not platforms:
            platforms = list(self.publishers.keys())
        
        # Get vulnerabilities to publish
        if vulnerability_ids:
            vulnerabilities = []
            for vuln_id in vulnerability_ids:
                vuln = self.db.get_vulnerability(vuln_id)
                if vuln:
                    vulnerabilities.append(vuln)
        else:
            # Get recent high-severity vulnerabilities
            vulnerabilities = self.db.get_vulnerabilities(
                severity=['high', 'critical'],
                limit=10,
                published_since=datetime.now() - timedelta(days=1)
            )
        
        if not vulnerabilities:
            logger.warning("No vulnerabilities found to publish")
            return {'published': 0, 'platforms': {}}
        
        results = {
            'published': 0,
            'platforms': {}
        }
        
        for vuln in vulnerabilities:
            try:
                # Generate content
                content = await self.content_generator.generate_content(vuln, content_type)
                
                # Publish to each platform
                for platform in platforms:
                    if platform not in self.publishers:
                        logger.warning(f"Unknown publisher platform: {platform}")
                        continue
                    
                    try:
                        publisher = self.publishers[platform]
                        post_result = await publisher.publish(content, vuln)
                        
                        if platform not in results['platforms']:
                            results['platforms'][platform] = {'success': 0, 'failed': 0}
                        
                        if post_result.get('success'):
                            results['platforms'][platform]['success'] += 1
                            # Store publication record
                            self.db.store_publication(vuln['id'], platform, post_result)
                        else:
                            results['platforms'][platform]['failed'] += 1
                            
                    except Exception as e:
                        logger.error(f"Error publishing to {platform}: {e}")
                        if platform not in results['platforms']:
                            results['platforms'][platform] = {'success': 0, 'failed': 0}
                        results['platforms'][platform]['failed'] += 1
                
                results['published'] += 1
                
            except Exception as e:
                logger.error(f"Error processing vulnerability {vuln.get('id', 'unknown')}: {e}")
        
        return results

@click.group()
@click.option('--config', '-c', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--debug', '-d', is_flag=True, help='Enable debug logging')
@click.pass_context
def cli(ctx, config, verbose, debug):
    """VulnPublisherPro - Comprehensive vulnerability scraping and publishing tool"""
    ctx.ensure_object(dict)
    
    # Setup logging
    log_level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    setup_logging(log_level)
    
    # Validate configuration
    if not validate_config(config):
        click.echo("Configuration validation failed. Please check your config file.", err=True)
        sys.exit(1)
    
    # Initialize application
    ctx.obj['app'] = VulnPublisherPro(config)

@cli.command()
@click.option('--sources', '-s', multiple=True, help='Specific sources to scrape')
@click.option('--limit', '-l', type=int, help='Limit number of vulnerabilities per source')
@click.option('--output', '-o', type=click.File('w'), help='Output results to file')
@click.pass_context
def scrape(ctx, sources, limit, output):
    """Scrape vulnerabilities from specified sources"""
    app = ctx.obj['app']
    
    async def run_scrape():
        results = await app.scrape_vulnerabilities(list(sources) if sources else None, limit)
        
        if output:
            json.dump(results, output, indent=2, default=str)
        else:
            click.echo(json.dumps(results, indent=2, default=str))
        
        click.echo(f"\nScraping completed:")
        click.echo(f"  Total scraped: {results['total_scraped']}")
        click.echo(f"  New vulnerabilities: {results['total_new']}")
        click.echo(f"  Updated vulnerabilities: {results['total_updated']}")
    
    asyncio.run(run_scrape())

@cli.command()
@click.option('--platforms', '-p', multiple=True, help='Specific platforms to publish to')
@click.option('--vulnerability-ids', '-i', multiple=True, help='Specific vulnerability IDs')
@click.option('--content-type', '-t', default='summary', 
              type=click.Choice(['summary', 'detailed', 'alert', 'thread']),
              help='Type of content to generate')
@click.option('--dry-run', is_flag=True, help='Generate content without publishing')
@click.pass_context
def publish(ctx, platforms, vulnerability_ids, content_type, dry_run):
    """Generate content and publish vulnerabilities"""
    app = ctx.obj['app']
    
    async def run_publish():
        if dry_run:
            click.echo("DRY RUN MODE - Content will be generated but not published")
        
        results = await app.generate_and_publish(
            list(vulnerability_ids) if vulnerability_ids else None,
            list(platforms) if platforms else None,
            content_type
        )
        
        click.echo(json.dumps(results, indent=2, default=str))
        
        click.echo(f"\nPublishing completed:")
        click.echo(f"  Vulnerabilities processed: {results['published']}")
        for platform, stats in results['platforms'].items():
            click.echo(f"  {platform}: {stats.get('success', 0)} success, {stats.get('failed', 0)} failed")
    
    asyncio.run(run_publish())

@cli.command()
@click.option('--severity', multiple=True, type=click.Choice(['low', 'medium', 'high', 'critical']))
@click.option('--source', multiple=True, help='Filter by source')
@click.option('--days', type=int, default=7, help='Number of days to look back')
@click.option('--limit', type=int, default=50, help='Maximum number of results')
@click.option('--format', 'output_format', default='table', 
              type=click.Choice(['table', 'json', 'csv']),
              help='Output format')
@click.pass_context
def list_vulns(ctx, severity, source, days, limit, output_format):
    """List vulnerabilities from database"""
    app = ctx.obj['app']
    
    vulnerabilities = app.db.get_vulnerabilities(
        severity=list(severity) if severity else None,
        sources=list(source) if source else None,
        limit=limit,
        published_since=datetime.now() - timedelta(days=days)
    )
    
    if output_format == 'json':
        click.echo(json.dumps(vulnerabilities, indent=2, default=str))
    elif output_format == 'csv':
        import csv
        import io
        
        if vulnerabilities:
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=vulnerabilities[0].keys())
            writer.writeheader()
            writer.writerows(vulnerabilities)
            click.echo(output.getvalue())
    else:
        # Table format
        from rich.console import Console
        from rich.table import Table
        
        console = Console()
        table = Table(show_header=True, header_style="bold magenta")
        
        if vulnerabilities:
            table.add_column("ID")
            table.add_column("CVE ID")
            table.add_column("Severity")
            table.add_column("Source")
            table.add_column("Published")
            
            for vuln in vulnerabilities:
                table.add_row(
                    str(vuln.get('id', '')),
                    vuln.get('cve_id', 'N/A'),
                    vuln.get('severity', 'Unknown'),
                    vuln.get('source', 'Unknown'),
                    str(vuln.get('published_date', ''))
                )
        
        console.print(table)
        click.echo(f"\nTotal: {len(vulnerabilities)} vulnerabilities")

@cli.command()
@click.option('--enable', is_flag=True, help='Enable scheduled scraping')
@click.option('--disable', is_flag=True, help='Disable scheduled scraping')
@click.option('--interval', type=int, default=3600, help='Scraping interval in seconds')
@click.option('--publish-interval', type=int, default=7200, help='Publishing interval in seconds')
@click.pass_context
def schedule(ctx, enable, disable, interval, publish_interval):
    """Manage scheduled operations"""
    app = ctx.obj['app']
    
    if enable:
        app.scheduler.schedule_scraping(interval)
        app.scheduler.schedule_publishing(publish_interval)
        app.scheduler.start()
        click.echo("Scheduled operations enabled")
        click.echo(f"Scraping interval: {interval} seconds")
        click.echo(f"Publishing interval: {publish_interval} seconds")
    elif disable:
        app.scheduler.stop()
        click.echo("Scheduled operations disabled")
    else:
        status = app.scheduler.get_status()
        click.echo(f"Scheduler status: {'Running' if status['running'] else 'Stopped'}")
        click.echo(f"Next scrape: {status.get('next_scrape', 'Not scheduled')}")
        click.echo(f"Next publish: {status.get('next_publish', 'Not scheduled')}")

@cli.command()
@click.pass_context  
def interactive(ctx):
    """Start interactive CLI mode"""
    app = ctx.obj['app']
    
    if not validate_config(app.config):
        console.print("[red]❌ Configuration validation failed[/red]")
        sys.exit(1)
    
    asyncio.run(_interactive_mode(app))

async def _interactive_mode(app):
    """Interactive CLI mode with rich menus"""
    console.print(Panel.fit(
        "[bold blue]🛡️  VulnPublisherPro - Interactive CLI Mode[/bold blue]\n"
        "[cyan]Comprehensive vulnerability intelligence platform[/cyan]\n"
        "[dim]By RafalW3bCraft | MIT License[/dim]", 
        border_style="blue"
    ))
    
    while True:
        try:
            # Main menu
            choices = [
                inquirer.List('action',
                    message="What would you like to do?",
                    choices=[
                        ('🔍 Scrape Vulnerabilities', 'scrape'),
                        ('📊 View Database Stats', 'stats'),
                        ('📝 List Vulnerabilities', 'list'),
                        ('🤖 Generate Content', 'generate'),
                        ('🧠 AI Categorization', 'categorize'),
                        ('👥 Expert Simulation', 'expert'),
                        ('📰 Blog Content Generation', 'blog_generate'),
                        ('🚀 Autonomous Publishing', 'auto_publish'),
                        ('📤 Publish Content', 'publish'),
                        ('⚙️  Configuration', 'config'),
                        ('🔄 Scheduler Management', 'scheduler'),
                        ('🚪 Exit', 'exit')
                    ]
                )
            ]
            
            answer = inquirer.prompt(choices)
            if not answer or answer['action'] == 'exit':
                console.print("[yellow]👋 Goodbye![/yellow]")
                break
            
            if answer['action'] == 'scrape':
                await _interactive_scrape(app)
            elif answer['action'] == 'stats':
                _show_database_stats(app)
            elif answer['action'] == 'list':
                await _interactive_list_vulnerabilities(app)
            elif answer['action'] == 'generate':
                await _interactive_generate_content(app)
            elif answer['action'] == 'categorize':
                await _interactive_ai_categorization(app)
            elif answer['action'] == 'expert':
                await _interactive_expert_simulation(app)
            elif answer['action'] == 'blog_generate':
                await _interactive_blog_generation(app)
            elif answer['action'] == 'auto_publish':
                await _interactive_autonomous_publishing(app)
            elif answer['action'] == 'publish':
                await _interactive_publish(app)
            elif answer['action'] == 'config':
                _show_configuration(app)
            elif answer['action'] == 'scheduler':
                _manage_scheduler(app)
                
            # Pause before showing menu again
            input("\nPress Enter to continue...")
            console.clear()
            
        except KeyboardInterrupt:
            console.print("\n[yellow]👋 Goodbye![/yellow]")
            break
        except Exception as e:
            console.print(f"[red]❌ Error: {e}[/red]")
            input("Press Enter to continue...")

async def _interactive_scrape(app):
    """Interactive vulnerability scraping"""
    console.print("\n[bold blue]🔍 Vulnerability Scraping[/bold blue]\n")
    
    # Select sources
    available_sources = list(app.scrapers.keys())
    source_choices = [
        inquirer.Checkbox('sources',
            message="Select sources to scrape (use spacebar to select):",
            choices=available_sources,
            default=['nvd', 'github', 'cisa_kev']
        )
    ]
    
    source_answer = inquirer.prompt(source_choices)
    if not source_answer:
        return
        
    selected_sources = source_answer['sources']
    if not selected_sources:
        console.print("[yellow]⚠️  No sources selected[/yellow]")
        return
    
    # Get limit
    limit_choices = [
        inquirer.Text('limit',
            message="Limit per source (leave empty for no limit):",
            default=""
        )
    ]
    
    limit_answer = inquirer.prompt(limit_choices)
    limit = int(limit_answer['limit']) if limit_answer and limit_answer['limit'].isdigit() else None
    
    # Execute scraping
    results = await app.scrape_vulnerabilities(sources=selected_sources, limit=limit, interactive=True)
    
    # Show results summary
    if results['total_scraped'] > 0:
        console.print(f"\n[bold green]🎉 Scraping completed successfully![/bold green]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Source")
        table.add_column("Scraped", justify="right")
        table.add_column("New", justify="right") 
        table.add_column("Updated", justify="right")
        
        for source, data in results['sources'].items():
            if 'error' in data:
                table.add_row(source, "[red]Error[/red]", "-", "-")
            else:
                table.add_row(
                    source,
                    str(data['scraped']),
                    f"[green]{data['new']}[/green]",
                    f"[yellow]{data['updated']}[/yellow]"
                )
        
        console.print(table)
    else:
        console.print("[yellow]ℹ️  No new vulnerabilities found[/yellow]")

def _show_database_stats(app):
    """Show database statistics"""
    console.print("\n[bold blue]📊 Database Statistics[/bold blue]\n")
    
    try:
        stats = app.db.get_statistics()
        
        # Overview table
        overview_table = Table(show_header=False, border_style="blue")
        overview_table.add_column("Metric", style="bold")
        overview_table.add_column("Value", justify="right")
        
        overview_table.add_row("Total Vulnerabilities", str(stats.get('total_vulnerabilities', 0)))
        overview_table.add_row("Publications", str(sum(stats.get('publications_by_platform', {}).values())))
        
        console.print("📈 Overview:")
        console.print(overview_table)
        
        # Severity breakdown
        if stats.get('by_severity'):
            console.print("\n🚨 By Severity:")
            severity_table = Table(show_header=True, header_style="bold red")
            severity_table.add_column("Severity")
            severity_table.add_column("Count", justify="right")
            
            for severity, count in stats['by_severity'].items():
                severity_table.add_row(severity.upper() if severity else "UNKNOWN", str(count))
            
            console.print(severity_table)
        
        # Source breakdown
        if stats.get('by_source'):
            console.print("\n🔍 By Source:")
            source_table = Table(show_header=True, header_style="bold green")
            source_table.add_column("Source")
            source_table.add_column("Count", justify="right")
            
            for source, count in list(stats['by_source'].items())[:10]:  # Top 10
                source_table.add_row(source, str(count))
            
            console.print(source_table)
            
    except Exception as e:
        console.print(f"[red]❌ Error getting stats: {e}[/red]")

def _show_configuration(app):
    """Show current configuration"""
    console.print("\n[bold blue]⚙️  Configuration[/bold blue]\n")
    
    config_table = Table(show_header=True, header_style="bold cyan")
    config_table.add_column("Setting")
    config_table.add_column("Value") 
    config_table.add_column("Status")
    
    # Database
    db_status = "[green]✅ Connected[/green]" if app.db else "[red]❌ Not connected[/red]"
    config_table.add_row("Database", "PostgreSQL" if app.db.is_postgres else "SQLite", db_status)
    
    # OpenAI API
    openai_status = "[green]✅ Configured[/green]" if app.config.openai_api_key else "[red]❌ Missing[/red]"
    config_table.add_row("OpenAI API", "••••••••", openai_status)
    
    # Scrapers
    active_scrapers = len([s for s in app.scrapers.values() if s.is_configured()])
    config_table.add_row("Active Scrapers", f"{active_scrapers}/{len(app.scrapers)}", 
                        "[green]✅[/green]" if active_scrapers > 0 else "[yellow]⚠️[/yellow]")
    
    # Publishers
    active_publishers = len([p for p in app.publishers.values() if p.is_configured()])
    config_table.add_row("Active Publishers", f"{active_publishers}/{len(app.publishers)}", 
                        "[green]✅[/green]" if active_publishers > 0 else "[yellow]⚠️[/yellow]")
    
    console.print(config_table)

async def _interactive_list_vulnerabilities(app):
    """Interactive vulnerability listing"""
    console.print("\n[bold blue]📝 List Vulnerabilities[/bold blue]\n")
    
    # Get filters
    filters = {}
    
    # Severity filter
    severity_choices = [
        inquirer.Checkbox('severity',
            message="Filter by severity (optional):",
            choices=['critical', 'high', 'medium', 'low', 'info'],
        )
    ]
    
    severity_answer = inquirer.prompt(severity_choices)
    if severity_answer and severity_answer['severity']:
        filters['severity'] = severity_answer['severity']
    
    # Source filter  
    available_sources = list(app.scrapers.keys())
    source_choices = [
        inquirer.Checkbox('sources',
            message="Filter by source (optional):",
            choices=available_sources,
        )
    ]
    
    source_answer = inquirer.prompt(source_choices)
    if source_answer and source_answer['sources']:
        filters['sources'] = source_answer['sources']
    
    # Limit
    limit_choices = [
        inquirer.Text('limit',
            message="Number of results (default 10):",
            default="10"
        )
    ]
    
    limit_answer = inquirer.prompt(limit_choices)
    limit = int(limit_answer['limit']) if limit_answer and limit_answer['limit'].isdigit() else 10
    
    # Get vulnerabilities
    vulnerabilities = app.db.get_vulnerabilities(
        severity=filters.get('severity'),
        sources=filters.get('sources'),
        limit=limit
    )
    
    if vulnerabilities:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", width=8)
        table.add_column("CVE ID", width=15)
        table.add_column("Severity", width=10)
        table.add_column("Source", width=12)
        table.add_column("Title", width=40)
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').upper()
            severity_color = {
                'CRITICAL': '[bright_red]',
                'HIGH': '[red]',
                'MEDIUM': '[yellow]',
                'LOW': '[green]',
                'INFO': '[blue]'
            }.get(severity, '[white]')
            
            table.add_row(
                str(vuln.get('id', '')),
                vuln.get('cve_id', 'N/A'),
                f"{severity_color}{severity}[/]",
                vuln.get('source', 'Unknown'),
                vuln.get('title', '')[:37] + "..." if len(vuln.get('title', '')) > 40 else vuln.get('title', '')
            )
        
        console.print(table)
        console.print(f"\n[cyan]Total: {len(vulnerabilities)} vulnerabilities[/cyan]")
    else:
        console.print("[yellow]ℹ️  No vulnerabilities found matching criteria[/yellow]")

async def _interactive_generate_content(app):
    """Interactive content generation"""
    console.print("\n[bold blue]🤖 Content Generation[/bold blue]\n")
    console.print("[yellow]ℹ️  This feature requires OpenAI API key configuration[/yellow]\n")
    
    if not app.config.openai_api_key:
        console.print("[red]❌ OpenAI API key not configured[/red]")
        return
    
    # Get recent vulnerabilities to generate content for
    vulnerabilities = app.db.get_vulnerabilities(limit=20)
    
    if not vulnerabilities:
        console.print("[yellow]ℹ️  No vulnerabilities found in database[/yellow]")
        return
    
    # Select vulnerabilities
    vuln_choices = [
        (f"{v.get('cve_id', 'N/A')} - {v.get('title', '')[:50]}...", str(v['id']))
        for v in vulnerabilities[:10]
    ]
    
    selection_choices = [
        inquirer.Checkbox('vulns',
            message="Select vulnerabilities to generate content for:",
            choices=vuln_choices,
        )
    ]
    
    selection_answer = inquirer.prompt(selection_choices)
    if not selection_answer or not selection_answer['vulns']:
        console.print("[yellow]⚠️  No vulnerabilities selected[/yellow]")
        return
    
    # Select content type
    content_choices = [
        inquirer.List('content_type',
            message="Select content type:",
            choices=[
                ('📄 Summary', 'summary'),
                ('🚨 Alert', 'alert'), 
                ('🧵 Thread', 'thread'),
                ('📋 Report', 'report')
            ]
        )
    ]
    
    content_answer = inquirer.prompt(content_choices)
    if not content_answer:
        return
        
    content_type = content_answer['content_type']
    selected_ids = selection_answer['vulns']
    
    # Generate content
    console.print(f"\n[cyan]🤖 Generating {content_type} content for {len(selected_ids)} vulnerabilities...[/cyan]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        for i, vuln_id in enumerate(selected_ids, 1):
            task = progress.add_task(f"[cyan]Generating content {i}/{len(selected_ids)}...", total=None)
            
            try:
                vuln = app.db.get_vulnerability(vuln_id)
                if vuln:
                    content = await app.content_generator.generate_content(
                        vuln, content_type=content_type
                    )
                    
                    progress.update(task, description=f"[green]✅ Generated for {vuln.get('cve_id', vuln_id)}")
                    
                    # Show generated content
                    console.print(Panel(
                        content[:500] + "..." if len(content) > 500 else content,
                        title=f"[bold]{vuln.get('cve_id', vuln_id)} - {content_type.title()}[/bold]",
                        border_style="green"
                    ))
                    
            except Exception as e:
                progress.update(task, description=f"[red]❌ Error for {vuln_id}")
                console.print(f"[red]❌ Error generating content for {vuln_id}: {e}[/red]")
            
            finally:
                progress.remove_task(task)

async def _interactive_publish(app):
    """Interactive publishing"""
    console.print("\n[bold blue]📤 Publish Content[/bold blue]\n")
    
    # Get recent vulnerabilities 
    vulnerabilities = app.db.get_vulnerabilities(limit=5)
    
    if not vulnerabilities:
        console.print("[yellow]ℹ️  No vulnerabilities available for publishing[/yellow]")
        return
    
    # Show available platforms (configured or not)
    all_publishers = list(app.publishers.keys())
    configured_publishers = [k for k, v in app.publishers.items() if v.is_configured()]
    
    console.print(f"[cyan]Available platforms:[/cyan] {', '.join(all_publishers)}")
    console.print(f"[green]Configured platforms:[/green] {', '.join(configured_publishers) if configured_publishers else 'None'}")
    console.print(f"[yellow]⚠️  Demo mode: Simulated publishing (no actual API calls)[/yellow]\n")
    
    # Select vulnerabilities
    vuln_choices = [
        (f"{v.get('cve_id', 'N/A')} - {v.get('title', '')[:50]}...", str(v['id']))
        for v in vulnerabilities
    ]
    
    selection_choices = [
        inquirer.Checkbox('vulns',
            message="Select vulnerabilities to publish:",
            choices=vuln_choices,
            default=[str(vulnerabilities[0]['id'])] if vulnerabilities else []
        )
    ]
    
    selection_answer = inquirer.prompt(selection_choices)
    if not selection_answer or not selection_answer['vulns']:
        console.print("[yellow]⚠️  No vulnerabilities selected[/yellow]")
        return
    
    selected_ids = selection_answer['vulns']
    
    # Select demo platforms
    platform_choices = [
        inquirer.Checkbox('platforms',
            message="Select platforms for demo publishing:",
            choices=['twitter', 'linkedin', 'telegram', 'discord', 'reddit'],
            default=['twitter', 'linkedin']
        )
    ]
    
    platform_answer = inquirer.prompt(platform_choices)
    if not platform_answer or not platform_answer['platforms']:
        console.print("[yellow]⚠️  No platforms selected[/yellow]")
        return
    
    selected_platforms = platform_answer['platforms']
    
    # Simulate publishing
    console.print(f"\n[cyan]📤 Demo Publishing to {len(selected_platforms)} platforms...[/cyan]\n")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        
        for i, vuln_id in enumerate(selected_ids, 1):
            vuln = app.db.get_vulnerability(vuln_id)
            if not vuln:
                continue
                
            task = progress.add_task(f"[cyan]Publishing {vuln.get('cve_id', vuln_id)}... ({i}/{len(selected_ids)})", total=None)
            
            try:
                # Simulate publishing to each platform
                for platform in selected_platforms:
                    progress.update(task, description=f"[yellow]📤 Publishing to {platform}...")
                    await asyncio.sleep(0.5)  # Simulate API call time
                    
                    # Simulate success
                    console.print(f"[green]✅ {platform}: Published {vuln.get('cve_id', vuln_id)}[/green]")
                    
                    # Store simulated publication record
                    app.db.store_publication(
                        vulnerability_id=vuln['id'],
                        platform=platform,
                        publication_data={
                            'post_id': f'demo_{platform}_{vuln_id}',
                            'content_type': 'summary',
                            'content': f"Demo publication of {vuln.get('cve_id', vuln_id)}",
                            'status': 'simulated'
                        }
                    )
                
                progress.update(task, description=f"[green]✅ Published {vuln.get('cve_id', vuln_id)} to all platforms")
                
            except Exception as e:
                progress.update(task, description=f"[red]❌ Error publishing {vuln_id}")
                console.print(f"[red]❌ Error: {e}[/red]")
            
            finally:
                progress.remove_task(task)
    
    console.print(f"\n[bold green]🎉 Demo publishing completed![/bold green]")
    console.print(f"[cyan]Published {len(selected_ids)} vulnerabilities to {len(selected_platforms)} platforms[/cyan]")

def _manage_scheduler(app):
    """Manage scheduler operations"""
    console.print("\n[bold blue]🔄 Scheduler Management[/bold blue]\n")
    
    status = app.scheduler.get_status()
    
    status_color = "[green]Running[/green]" if status.get('running') else "[red]Stopped[/red]"
    console.print(f"Status: {status_color}")
    
    if status.get('next_scrape'):
        console.print(f"Next scrape: [cyan]{status['next_scrape']}[/cyan]")
    if status.get('next_publish'):
        console.print(f"Next publish: [cyan]{status['next_publish']}[/cyan]")

@cli.command()
@click.option('--export-format', default='json', 
              type=click.Choice(['json', 'csv', 'xml']),
              help='Export format')
@click.option('--output', '-o', required=True, help='Output file path')
@click.option('--days', type=int, default=30, help='Number of days to export')
@click.pass_context
def export(ctx, export_format, output, days):
    """Export vulnerability data"""
    app = ctx.obj['app']
    
    vulnerabilities = app.db.get_vulnerabilities(
        limit=None,
        published_since=datetime.now() - timedelta(days=days)
    )
    
    if export_format == 'json':
        with open(output, 'w') as f:
            json.dump(vulnerabilities, f, indent=2, default=str)
    elif export_format == 'csv':
        import csv
        if vulnerabilities:
            with open(output, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=vulnerabilities[0].keys())
                writer.writeheader()
                writer.writerows(vulnerabilities)
    elif export_format == 'xml':
        import xml.etree.ElementTree as ET
        root = ET.Element('vulnerabilities')
        for vuln in vulnerabilities:
            vuln_elem = ET.SubElement(root, 'vulnerability')
            for key, value in vuln.items():
                elem = ET.SubElement(vuln_elem, key)
                elem.text = str(value) if value is not None else ''
        
        tree = ET.ElementTree(root)
        tree.write(output, encoding='utf-8', xml_declaration=True)
    
    click.echo(f"Exported {len(vulnerabilities)} vulnerabilities to {output}")

@cli.command()
@click.confirmation_option(prompt='Are you sure you want to reset the database?')
@click.pass_context
def reset_db(ctx):
    """Reset the database (WARNING: This will delete all data)"""
    app = ctx.obj['app']
    app.db.reset_database()
    click.echo("Database has been reset")

@cli.command()
@click.option('--vulnerability-ids', '-v', multiple=True, required=True, help='Vulnerability IDs to generate content for')
@click.option('--content-type', default='summary', 
              type=click.Choice(['summary', 'alert', 'thread', 'report']),
              help='Type of content to generate')
@click.pass_context
def generate(ctx, vulnerability_ids, content_type):
    """Generate AI-powered content for vulnerabilities"""
    app = ctx.obj['app']
    
    if not app.config.openai_api_key:
        console.print("[red]❌ OpenAI API key not configured[/red]")
        return
    
    console.print(f"\n[blue]🤖 Generating {content_type} content for {len(vulnerability_ids)} vulnerabilities...[/blue]\n")
    
    async def run_generation():
        for vuln_id in vulnerability_ids:
            try:
                vuln = app.db.get_vulnerability(vuln_id)
                if not vuln:
                    console.print(f"[red]❌ Vulnerability {vuln_id} not found[/red]")
                    continue
                
                console.print(f"[cyan]🔄 Generating content for {vuln.get('cve_id', vuln_id)}...[/cyan]")
                
                content = await app.content_generator.generate_content(
                    vuln, content_type=content_type
                )
                
                # Extract the main content for display
                if isinstance(content, dict):
                    main_content = content.get('content', str(content))
                    platform_variants = content.get('platform_variants', {})
                    hashtags = content.get('hashtags', [])
                    
                    display_content = f"{main_content}\n\n"
                    if hashtags:
                        display_content += f"Hashtags: {' '.join(hashtags)}\n"
                    if platform_variants:
                        display_content += f"\nPlatform variants: {len(platform_variants)} platforms"
                else:
                    display_content = str(content)
                
                console.print(Panel(
                    display_content,
                    title=f"[bold green]{vuln.get('cve_id', vuln_id)} - {content_type.title()}[/bold green]",
                    border_style="green"
                ))
                
            except Exception as e:
                console.print(f"[red]❌ Error generating content for {vuln_id}: {e}[/red]")
    
    asyncio.run(run_generation())

async def _interactive_ai_categorization(app):
    """Interactive AI-powered vulnerability categorization"""
    console.print("\n[bold blue]🧠 AI-Powered Vulnerability Categorization[/bold blue]\n")
    
    # Get vulnerabilities to categorize
    vulnerabilities = app.db.get_vulnerabilities(limit=20)
    
    if not vulnerabilities:
        console.print("[yellow]⚠️  No vulnerabilities found in database[/yellow]")
        return
    
    # Select vulnerability to categorize
    vuln_choices = []
    for vuln in vulnerabilities:
        title = vuln.get('title', 'No title')[:60]
        cve_id = vuln.get('cve_id', vuln.get('id', 'Unknown'))
        vuln_choices.append((f"{cve_id}: {title}", vuln))
    
    choice = inquirer.prompt([
        inquirer.List('vulnerability',
            message="Select a vulnerability to categorize:",
            choices=vuln_choices
        )
    ])
    
    if not choice:
        return
    
    selected_vuln = choice['vulnerability']
    
    console.print(f"\n[cyan]🔄 Analyzing {selected_vuln.get('cve_id', 'vulnerability')}...[/cyan]")
    
    try:
        # Perform AI categorization
        categorization = app.auto_categorizer.categorize_vulnerability(selected_vuln)
        
        # Display results
        console.print(Panel(
            f"[bold]Primary Category:[/bold] {categorization.get('primary_category', 'Unknown')}\n"
            f"[bold]Confidence:[/bold] {categorization.get('confidence_scores', {}).get(categorization.get('primary_category', ''), 0):.2f}\n"
            f"[bold]Severity Assessment:[/bold] {categorization.get('severity_assessment', {}).get('level', 'Unknown')}\n"
            f"[bold]Remediation Priority:[/bold] {categorization.get('remediation_priority', 'Unknown')}\n"
            f"[bold]Suggested Tags:[/bold] {', '.join(categorization.get('suggested_tags', []))}\n"
            f"[bold]Impact Analysis:[/bold]\n"
            f"  - Confidentiality: {categorization.get('impact_analysis', {}).get('confidentiality', 'Unknown')}\n"
            f"  - Integrity: {categorization.get('impact_analysis', {}).get('integrity', 'Unknown')}\n"
            f"  - Availability: {categorization.get('impact_analysis', {}).get('availability', 'Unknown')}",
            title=f"[bold green]AI Categorization Results[/bold green]",
            border_style="green"
        ))
        
        # Show secondary categories if any
        if categorization.get('secondary_categories'):
            console.print("\n[bold yellow]Secondary Categories:[/bold yellow]")
            for sec_cat in categorization['secondary_categories']:
                console.print(f"  - {sec_cat['category']} (confidence: {sec_cat['confidence']:.2f})")
        
    except Exception as e:
        console.print(f"[red]❌ Error performing AI categorization: {e}[/red]")

async def _interactive_expert_simulation(app):
    """Interactive expert interview simulation"""
    console.print("\n[bold blue]👥 Expert Interview Simulation[/bold blue]\n")
    
    # Get vulnerabilities for interview
    vulnerabilities = app.db.get_vulnerabilities(limit=20)
    
    if not vulnerabilities:
        console.print("[yellow]⚠️  No vulnerabilities found in database[/yellow]")
        return
    
    # Select vulnerability
    vuln_choices = []
    for vuln in vulnerabilities:
        title = vuln.get('title', 'No title')[:60]
        cve_id = vuln.get('cve_id', vuln.get('id', 'Unknown'))
        vuln_choices.append((f"{cve_id}: {title}", vuln))
    
    choices = [
        inquirer.List('vulnerability',
            message="Select a vulnerability for expert interview:",
            choices=vuln_choices
        ),
        inquirer.List('expert_type',
            message="Select expert type:",
            choices=[
                ('Security Researcher', 'security_researcher'),
                ('CISO (Chief Information Security Officer)', 'ciso'),
                ('Incident Responder', 'incident_responder'),
                ('Penetration Tester', 'penetration_tester'),
                ('Compliance Officer', 'compliance_officer')
            ]
        ),
        inquirer.List('interview_type',
            message="Select interview type:",
            choices=[
                ('Vulnerability Analysis', 'vulnerability_analysis'),
                ('Incident Response', 'incident_response'),
                ('Business Impact', 'business_impact')
            ]
        )
    ]
    
    answers = inquirer.prompt(choices)
    if not answers:
        return
    
    selected_vuln = answers['vulnerability']
    expert_type = answers['expert_type']
    interview_type = answers['interview_type']
    
    console.print(f"\n[cyan]🔄 Generating expert interview...[/cyan]")
    
    try:
        # Generate expert interview
        interview = app.expert_simulator.simulate_expert_interview(
            selected_vuln, expert_type, interview_type
        )
        
        # Display expert profile
        expert_profile = interview.get('expert_profile', {})
        console.print(Panel(
            f"[bold]Name:[/bold] {expert_profile.get('name', 'Unknown')}\n"
            f"[bold]Title:[/bold] {expert_profile.get('title', 'Unknown')}\n"
            f"[bold]Expertise:[/bold] {', '.join(expert_profile.get('expertise', []))}",
            title="[bold blue]Expert Profile[/bold blue]",
            border_style="blue"
        ))
        
        # Display interview Q&A
        qa_pairs = interview.get('questions_and_responses', [])
        for qa in qa_pairs[:3]:  # Show first 3 Q&As
            console.print(f"\n[bold yellow]Q{qa.get('question_number', '?')}:[/bold yellow] {qa.get('question', 'No question')}")
            console.print(f"[bold green]A:[/bold green] {qa.get('response', 'No response')}")
            
            if qa.get('follow_up'):
                console.print(f"[bold yellow]Follow-up:[/bold yellow] {qa['follow_up'].get('question', '')}")
                console.print(f"[bold green]A:[/bold green] {qa['follow_up'].get('response', '')}")
        
        # Display key insights
        insights = interview.get('key_insights', [])
        if insights:
            console.print("\n[bold magenta]Key Insights:[/bold magenta]")
            for insight in insights:
                console.print(f"  • {insight}")
        
        # Display recommendations
        recommendations = interview.get('expert_recommendations', [])
        if recommendations:
            console.print("\n[bold cyan]Expert Recommendations:[/bold cyan]")
            for rec in recommendations:
                console.print(f"  • {rec}")
        
        # Option to generate expert panel
        panel_choice = inquirer.prompt([
            inquirer.Confirm('generate_panel',
                message="Would you like to generate a multi-expert panel discussion?",
                default=False
            )
        ])
        
        if panel_choice and panel_choice['generate_panel']:
            console.print(f"\n[cyan]🔄 Generating expert panel discussion...[/cyan]")
            panel = app.expert_simulator.simulate_expert_panel(selected_vuln)
            
            console.print(Panel(
                f"[bold]Experts:[/bold] {panel.get('panel_metadata', {}).get('experts_count', 0)} participants\n"
                f"[bold]Format:[/bold] {panel.get('panel_metadata', {}).get('discussion_format', 'Unknown')}\n"
                f"[bold]Consensus Points:[/bold]\n" +
                '\n'.join([f"  • {point}" for point in panel.get('consensus_points', [])]),
                title="[bold magenta]Expert Panel Discussion[/bold magenta]",
                border_style="magenta"
            ))
        
    except Exception as e:
        console.print(f"[red]❌ Error generating expert interview: {e}[/red]")

async def _interactive_blog_generation(app):
    """Interactive multi-perspective blog content generation"""
    console.print("\n[bold blue]📰 Multi-Perspective Blog Content Generation[/bold blue]\n")
    
    # Get vulnerabilities for blog generation
    vulnerabilities = app.db.get_vulnerabilities(limit=20)
    
    if not vulnerabilities:
        console.print("[yellow]⚠️  No vulnerabilities found in database[/yellow]")
        return
    
    # Select vulnerability
    vuln_choices = []
    for vuln in vulnerabilities:
        title = vuln.get('title', 'No title')[:60]
        cve_id = vuln.get('cve_id', vuln.get('id', 'Unknown'))
        vuln_choices.append((f"{cve_id}: {title}", vuln))
    
    choices = [
        inquirer.List('vulnerability',
            message="Select a vulnerability for blog content generation:",
            choices=vuln_choices
        ),
        inquirer.Checkbox('perspectives',
            message="Select content perspectives (use spacebar to select):",
            choices=[
                ('Technical Deep Dive', 'technical'),
                ('Business Impact Analysis', 'business'),
                ('Developer Security Guide', 'developer'),
                ('Executive Summary', 'executive')
            ],
            default=['technical', 'business', 'developer']
        ),
        inquirer.Confirm('include_interactive',
            message="Include interactive elements (code snippets, guides)?",
            default=True
        )
    ]
    
    answers = inquirer.prompt(choices)
    if not answers:
        return
    
    selected_vuln = answers['vulnerability']
    perspectives = answers['perspectives']
    include_interactive = answers['include_interactive']
    
    console.print(f"\n[cyan]🔄 Generating multi-perspective blog content...[/cyan]")
    
    try:
        # Generate multi-perspective content
        content_package = app.ai_content_generator.generate_multi_perspective_content(
            selected_vuln, perspectives, include_interactive
        )
        
        # Display content summary
        vuln_info = content_package.get('vulnerability_info', {})
        console.print(Panel(
            f"[bold]CVE ID:[/bold] {vuln_info.get('cve_id', 'Unknown')}\n"
            f"[bold]Title:[/bold] {vuln_info.get('title', 'Unknown')}\n"
            f"[bold]Perspectives Generated:[/bold] {content_package.get('publishing_metadata', {}).get('total_perspectives', 0)}\n"
            f"[bold]Interactive Elements:[/bold] {len(content_package.get('interactive_elements', []))}\n"
            f"[bold]Estimated Read Time:[/bold] {content_package.get('publishing_metadata', {}).get('estimated_read_time', 'Unknown')} minutes",
            title="[bold green]Content Generation Summary[/bold green]",
            border_style="green"
        ))
        
        # Show perspective previews
        for perspective_name, perspective_content in content_package.get('perspectives', {}).items():
            perspective_info = perspective_content.get('perspective_info', {})
            console.print(f"\n[bold yellow]{perspective_info.get('name', perspective_name.title())}[/bold yellow]")
            console.print(f"Target Audience: {perspective_info.get('target_audience', 'Unknown')}")
            console.print(f"Word Count: {perspective_content.get('word_count', 0)}")
            
            # Show first section preview
            sections = perspective_content.get('sections', [])
            if sections:
                first_section = sections[0]
                preview = first_section.get('content', '')[:200] + "..." if len(first_section.get('content', '')) > 200 else first_section.get('content', '')
                console.print(f"Preview: {preview}")
        
        # Show cross-perspective insights
        insights = content_package.get('cross_perspective_insights', [])
        if insights:
            console.print("\n[bold magenta]Cross-Perspective Insights:[/bold magenta]")
            for insight in insights[:3]:  # Show first 3 insights
                console.print(f"  • {insight}")
        
        # Option to generate blog post
        blog_choice = inquirer.prompt([
            inquirer.Confirm('generate_blog',
                message="Would you like to generate a formatted blog post?",
                default=True
            )
        ])
        
        if blog_choice and blog_choice['generate_blog']:
            platform_choice = inquirer.prompt([
                inquirer.List('platform',
                    message="Select target platform for formatting:",
                    choices=[
                        ('Medium', 'medium'),
                        ('Dev.to', 'devto'),
                        ('Hashnode', 'hashnode'),
                        ('WordPress', 'wordpress'),
                        ('General Markdown', 'markdown')
                    ],
                    default='medium'
                )
            ])
            
            if platform_choice:
                platform = platform_choice['platform']
                blog_post = app.ai_content_generator.generate_blog_post(content_package, platform)
                
                console.print(f"\n[bold green]Generated Blog Post for {platform.title()}:[/bold green]")
                console.print(Panel(
                    blog_post[:1000] + "..." if len(blog_post) > 1000 else blog_post,
                    title="Blog Post Preview",
                    border_style="blue"
                ))
                
                # Store content for potential publishing
                app.generated_content = {
                    'content_package': content_package,
                    'blog_post': blog_post,
                    'platform': platform,
                    'generated_at': datetime.now()
                }
                
                console.print(f"\n[green]✅ Blog content generated and stored for publishing![/green]")
        
    except Exception as e:
        console.print(f"[red]❌ Error generating blog content: {e}[/red]")

async def _interactive_autonomous_publishing(app):
    """Interactive autonomous publishing to multiple platforms"""
    console.print("\n[bold blue]🚀 Autonomous Multi-Platform Publishing[/bold blue]\n")
    
    # Check if there's generated content to publish
    if not hasattr(app, 'generated_content') or not app.generated_content:
        console.print("[yellow]⚠️  No generated content found. Please generate blog content first.[/yellow]")
        return
    
    generated_content = app.generated_content
    
    # Display content info
    content_package = generated_content.get('content_package', {})
    vuln_info = content_package.get('vulnerability_info', {})
    
    console.print(Panel(
        f"[bold]Content:[/bold] {vuln_info.get('title', 'Unknown')}\n"
        f"[bold]CVE ID:[/bold] {vuln_info.get('cve_id', 'Unknown')}\n"
        f"[bold]Generated:[/bold] {generated_content.get('generated_at', datetime.now()).strftime('%Y-%m-%d %H:%M')}\n"
        f"[bold]Perspectives:[/bold] {content_package.get('publishing_metadata', {}).get('total_perspectives', 0)}",
        title="[bold cyan]Content Ready for Publishing[/bold cyan]",
        border_style="cyan"
    ))
    
    # Select publishing platforms
    platform_choice = inquirer.prompt([
        inquirer.Checkbox('platforms',
            message="Select platforms for publishing (use spacebar to select):",
            choices=[
                ('Medium', 'medium'),
                ('Dev.to', 'devto'),
                ('Hashnode', 'hashnode'),
                ('LinkedIn', 'linkedin'),
                ('WordPress', 'wordpress')
            ],
            default=['medium', 'devto']
        )
    ])
    
    if not platform_choice or not platform_choice['platforms']:
        console.print("[yellow]⚠️  No platforms selected[/yellow]")
        return
    
    selected_platforms = platform_choice['platforms']
    
    # Publishing options
    publish_options = inquirer.prompt([
        inquirer.List('mode',
            message="Select publishing mode:",
            choices=[
                ('Immediate Publishing', 'immediate'),
                ('Schedule for Later', 'scheduled'),
                ('Demo Mode (Simulation)', 'demo')
            ],
            default='demo'
        )
    ])
    
    if not publish_options:
        return
    
    publish_mode = publish_options['mode']
    
    # Prepare content for publishing
    publishing_content = {
        'title': vuln_info.get('title', 'Cybersecurity Vulnerability Analysis'),
        'content': generated_content.get('blog_post', ''),
        'tags': ['cybersecurity', 'vulnerability', 'security'],
        'vulnerability_id': vuln_info.get('cve_id', 'unknown'),
        'generated_at': generated_content.get('generated_at', datetime.now()).isoformat()
    }
    
    console.print(f"\n[cyan]🔄 Publishing to {len(selected_platforms)} platforms...[/cyan]")
    
    try:
        if publish_mode == 'immediate':
            # Immediate publishing
            results = app.autonomous_publisher.publish_immediately(publishing_content, selected_platforms)
            _display_publishing_results(results)
            
        elif publish_mode == 'scheduled':
            # Schedule for later
            job_id = app.autonomous_publisher.schedule_publication(publishing_content, selected_platforms)
            console.print(f"[green]✅ Content scheduled for publishing (Job ID: {job_id})[/green]")
            
        else:  # Demo mode
            # Simulate publishing
            console.print("[yellow]📋 Running in demo mode - simulating publishing process...[/yellow]")
            
            with Progress() as progress:
                for platform in selected_platforms:
                    task = progress.add_task(f"Publishing to {platform.title()}", total=100)
                    
                    for i in range(100):
                        time.sleep(0.03)  # Simulate processing
                        progress.update(task, advance=1)
                    
                    # Simulate result
                    success = True  # Demo always succeeds
                    if success:
                        console.print(f"[green]✅ {platform.title()}: Published successfully (Demo)[/green]")
                    else:
                        console.print(f"[red]❌ {platform.title()}: Publishing failed (Demo)[/red]")
            
            console.print(f"\n[bold green]🎉 Demo publishing completed![/bold green]")
            console.print(f"[cyan]Content would be published to {len(selected_platforms)} platforms in real mode[/cyan]")
        
        # Show queue statistics
        queue_stats = app.autonomous_publisher.get_queue_statistics()
        console.print(f"\n[bold blue]📊 Publishing Queue Statistics:[/bold blue]")
        console.print(f"Total jobs: {queue_stats.get('total_jobs', 0)}")
        console.print(f"Pending: {queue_stats.get('pending', 0)}")
        console.print(f"Completed: {queue_stats.get('completed', 0)}")
        console.print(f"Failed: {queue_stats.get('failed', 0)}")
        
    except Exception as e:
        console.print(f"[red]❌ Error in autonomous publishing: {e}[/red]")

def _display_publishing_results(results: Dict[str, Any]):
    """Display publishing results in a formatted table"""
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Platform")
    table.add_column("Status")
    table.add_column("Post ID")
    table.add_column("URL")
    table.add_column("Error")
    
    for platform, result in results.items():
        status = "[green]✅ Success[/green]" if result.success else "[red]❌ Failed[/red]"
        post_id = result.post_id or "-"
        post_url = result.post_url or "-"
        error = result.error_message or "-"
        
        table.add_row(platform.title(), status, post_id, post_url, error)
    
    console.print(table)

if __name__ == '__main__':
    cli()
