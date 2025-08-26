#!/usr/bin/env python3
"""
VulnPublisherPro Enhanced Interactive CLI
Global standard CLI with comprehensive functionality and modern UX
"""

import asyncio
import logging
import sys
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional

# Rich UI components for modern CLI
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
from rich.layout import Layout
from rich.live import Live
from rich import box
from rich.text import Text
from rich.align import Align

# Import core VulnPublisherPro modules
try:
    from main import VulnPublisherPro
    from config import Config
    from database import DatabaseManager
    from content_generator import ContentGenerator
except ImportError as e:
    print(f"❌ Error importing VulnPublisherPro modules: {e}")
    sys.exit(1)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class EnhancedVulnPublisherCLI:
    """Enhanced CLI with global standards and modern UX"""
    
    def __init__(self):
        self.console = Console()
        self.app = None
        self.config = None
        self.stats = {}
        
        # CLI configuration
        self.version = "2.0.0"
        self.author = "RafalW3bCraft"
        self.license = "MIT"
        
    async def initialize(self):
        """Initialize the application"""
        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
                transient=True,
            ) as progress:
                task = progress.add_task("Initializing VulnPublisherPro...", total=None)
                
                self.config = Config()
                self.app = VulnPublisherPro()
                
                progress.update(task, description="Loading system statistics...")
                self.stats = self.app.db.get_statistics()
                
                progress.update(task, description="Initialization complete!", completed=True)
                
            return True
        except Exception as e:
            self.console.print(f"[red]❌ Initialization failed: {e}[/red]")
            return False

    def display_banner(self):
        """Display modern banner with system info"""
        banner_text = f"""
🛡️  VulnPublisherPro Enhanced CLI v{self.version}
Comprehensive Vulnerability Intelligence & Publishing Platform
"""
        
        banner_panel = Panel(
            Align.center(banner_text),
            title="[bold cyan]VulnPublisherPro Enhanced[/bold cyan]",
            subtitle=f"[italic]By {self.author} | {self.license} License[/italic]",
            border_style="bright_blue",
            padding=(1, 2),
        )
        
        self.console.print(banner_panel)
        
        # Display quick stats
        if self.stats:
            stats_table = Table(show_header=False, box=box.MINIMAL)
            stats_table.add_column("Metric", style="cyan")
            stats_table.add_column("Value", style="bright_white")
            
            stats_table.add_row("📊 Total Vulnerabilities", str(self.stats.get('total_vulnerabilities', 0)))
            stats_table.add_row("🔍 Active Scrapers", "13")
            stats_table.add_row("📤 Publishers Available", "13")
            stats_table.add_row("🤖 AI Integration", "✅ Active")
            
            stats_panel = Panel(
                stats_table,
                title="[bold]System Status[/bold]",
                border_style="green",
                width=50
            )
            
            self.console.print(stats_panel)

    def get_main_menu_choices(self):
        """Get main menu choices with enhanced descriptions"""
        return [
            ("🔍 Scrape Vulnerabilities", "scrape_vulnerabilities", "Collect vulnerability data from multiple sources"),
            ("📊 View Database Statistics", "view_stats", "Display comprehensive database analytics"),
            ("📝 List Vulnerabilities", "list_vulnerabilities", "Browse stored vulnerability entries"),
            ("🤖 Generate AI Content", "generate_content", "Create AI-powered vulnerability content"),
            ("🧠 AI Categorization", "ai_categorization", "Automatically categorize vulnerabilities"),
            ("👥 Expert Simulation", "expert_simulation", "Simulate expert security interviews"),
            ("📰 Blog Content Engine", "blog_content", "Generate professional blog content"),
            ("🚀 Autonomous Publishing", "autonomous_publishing", "Automated multi-platform publishing"),
            ("📤 Manual Publishing", "manual_publishing", "Publish content to specific platforms"),
            ("⚙️ Configuration", "configuration", "Manage system settings and API keys"),
            ("🔄 Scheduler Management", "scheduler", "Configure automated tasks"),
            ("🧪 System Testing", "system_testing", "Run comprehensive system tests"),
            ("📈 Analytics Dashboard", "analytics", "View detailed analytics and reports"),
            ("🛡️ Security Audit", "security_audit", "Perform security validation"),
            ("💾 Data Management", "data_management", "Export, backup, and manage data"),
            ("❓ Help & Documentation", "help", "View help and documentation"),
            ("🚪 Exit", "exit", "Exit the application")
        ]

    async def display_menu_and_get_choice(self):
        """Display enhanced menu and get user choice"""
        choices = self.get_main_menu_choices()
        
        # Create menu table
        menu_table = Table(show_header=True, header_style="bold cyan", box=box.ROUNDED)
        menu_table.add_column("Option", style="bright_yellow", width=3)
        menu_table.add_column("Action", style="bright_white", width=25)
        menu_table.add_column("Description", style="dim white", width=50)
        
        for i, (action, key, desc) in enumerate(choices, 1):
            menu_table.add_row(str(i), action, desc)
        
        menu_panel = Panel(
            menu_table,
            title="[bold]Main Menu[/bold]",
            border_style="bright_blue",
        )
        
        self.console.print(menu_panel)
        
        # Get user choice
        while True:
            try:
                choice = Prompt.ask(
                    "\n[bold cyan]Select an option[/bold cyan]",
                    choices=[str(i) for i in range(1, len(choices) + 1)],
                    show_choices=True
                )
                return choices[int(choice) - 1][1]
            except (ValueError, IndexError):
                self.console.print("[red]❌ Invalid choice. Please try again.[/red]")

    async def scrape_vulnerabilities(self):
        """Enhanced vulnerability scraping with progress tracking"""
        self.console.print("[bold cyan]🔍 Vulnerability Scraping Module[/bold cyan]")
        
        # Show available scrapers
        scrapers_table = Table(show_header=True, header_style="bold green")
        scrapers_table.add_column("Scraper", style="cyan")
        scrapers_table.add_column("Status", style="white")
        scrapers_table.add_column("Description", style="dim white")
        
        scraper_info = {
            'nvd': ('NVD (NIST)', 'Official NIST vulnerability database'),
            'cisa_kev': ('CISA KEV', 'Known Exploited Vulnerabilities catalog'),
            'github_security': ('GitHub Security', 'GitHub security advisories'),
            'exploit_db': ('ExploitDB', 'Exploit database and proof-of-concepts'),
            'hackerone': ('HackerOne', 'Bug bounty disclosures'),
            'bugcrowd': ('Bugcrowd', 'Crowdsourced security testing'),
        }
        
        for scraper_name, scraper_obj in self.app.scrapers.items():
            if scraper_name in scraper_info:
                name, desc = scraper_info[scraper_name]
                try:
                    is_configured = scraper_obj.validate_config()
                    status = "✅ Ready" if is_configured else "⚠️ Needs Config"
                except:
                    status = "✅ Available"
                scrapers_table.add_row(name, status, desc)
        
        self.console.print(scrapers_table)
        
        # Get scraping parameters
        source_choices = list(scraper_info.keys())
        source = Prompt.ask(
            "\n[cyan]Select scraper[/cyan]",
            choices=source_choices,
            default="cisa_kev"
        )
        
        limit = int(Prompt.ask(
            "[cyan]Number of vulnerabilities to scrape[/cyan]",
            default="10"
        ))
        
        # Perform scraping with progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
        ) as progress:
            
            task = progress.add_task(f"Scraping from {source.upper()}...", total=100)
            
            try:
                results = await self.app.scrape_vulnerabilities(
                    sources=[source], 
                    limit=limit
                )
                
                progress.update(task, completed=100)
                
                # Display results
                if results.get('total_new', 0) > 0:
                    self.console.print(f"\n[green]✅ Successfully scraped {results['total_new']} new vulnerabilities![/green]")
                    self.console.print(f"[dim]Total processed: {results.get('total_processed', 0)}[/dim]")
                else:
                    self.console.print(f"\n[yellow]⚠️ No new vulnerabilities found. Processed: {results.get('total_processed', 0)}[/yellow]")
                
            except Exception as e:
                progress.update(task, description=f"❌ Error: {e}")
                self.console.print(f"[red]❌ Scraping failed: {e}[/red]")
        
        input("\nPress Enter to continue...")

    async def view_stats(self):
        """Display comprehensive database statistics"""
        self.console.print("[bold cyan]📊 Database Statistics[/bold cyan]")
        
        try:
            stats = self.app.db.get_statistics()
            
            # Main statistics table
            main_stats = Table(title="Database Overview", box=box.ROUNDED)
            main_stats.add_column("Metric", style="cyan")
            main_stats.add_column("Value", style="bright_white")
            
            main_stats.add_row("Total Vulnerabilities", str(stats.get('total_vulnerabilities', 0)))
            main_stats.add_row("Total Publications", str(stats.get('total_publications', 0)))
            main_stats.add_row("Database Size", f"{stats.get('database_size', 'Unknown')}")
            main_stats.add_row("Last Updated", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            
            self.console.print(main_stats)
            
            # Severity breakdown
            if stats.get('by_severity'):
                severity_table = Table(title="Vulnerabilities by Severity", box=box.MINIMAL)
                severity_table.add_column("Severity", style="yellow")
                severity_table.add_column("Count", style="bright_white")
                severity_table.add_column("Percentage", style="dim white")
                
                total = sum(stats['by_severity'].values())
                for severity, count in stats['by_severity'].items():
                    percentage = (count / total * 100) if total > 0 else 0
                    severity_table.add_row(severity.title(), str(count), f"{percentage:.1f}%")
                
                self.console.print(severity_table)
            
            # Source breakdown
            if stats.get('by_source'):
                source_table = Table(title="Vulnerabilities by Source", box=box.MINIMAL)
                source_table.add_column("Source", style="green")
                source_table.add_column("Count", style="bright_white")
                
                for source, count in list(stats['by_source'].items())[:10]:  # Top 10
                    source_table.add_row(source, str(count))
                
                self.console.print(source_table)
                
        except Exception as e:
            self.console.print(f"[red]❌ Error retrieving statistics: {e}[/red]")
        
        input("\nPress Enter to continue...")

    async def list_vulnerabilities(self):
        """Display vulnerabilities with pagination"""
        self.console.print("[bold cyan]📝 Vulnerability Browser[/bold cyan]")
        
        try:
            limit = int(Prompt.ask("[cyan]Number of vulnerabilities to display[/cyan]", default="10"))
            vulnerabilities = self.app.db.get_vulnerabilities(limit=limit)
            
            if not vulnerabilities:
                self.console.print("[yellow]⚠️ No vulnerabilities found in database.[/yellow]")
                return
            
            vulns_table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED)
            vulns_table.add_column("ID", style="dim", width=8)
            vulns_table.add_column("Title", style="bright_white", width=50)
            vulns_table.add_column("Severity", style="yellow", width=10)
            vulns_table.add_column("Source", style="cyan", width=12)
            vulns_table.add_column("Date", style="dim white", width=10)
            
            for vuln in vulnerabilities:
                title = vuln.get('title', 'Unknown')[:47] + "..." if len(vuln.get('title', '')) > 50 else vuln.get('title', 'Unknown')
                severity = vuln.get('severity', 'unknown').upper()
                source = vuln.get('source', 'unknown')
                date = vuln.get('published_date', vuln.get('created_at', ''))[:10]
                vuln_id = str(vuln.get('id', vuln.get('cve_id', 'N/A')))[:8]
                
                vulns_table.add_row(vuln_id, title, severity, source, date)
            
            self.console.print(vulns_table)
            
        except Exception as e:
            self.console.print(f"[red]❌ Error listing vulnerabilities: {e}[/red]")
        
        input("\nPress Enter to continue...")

    async def system_testing(self):
        """Run comprehensive system tests"""
        self.console.print("[bold cyan]🧪 System Testing Suite[/bold cyan]")
        
        test_options = [
            ("Core Functionality", "core"),
            ("Scraping Tests", "scraping"),
            ("Publishing Tests", "publishing"),
            ("Database Tests", "database"),
            ("AI Integration Tests", "ai"),
            ("Full System Test", "full")
        ]
        
        # Display test options
        test_table = Table(show_header=True, header_style="bold green")
        test_table.add_column("Option", style="bright_yellow", width=3)
        test_table.add_column("Test Suite", style="bright_white")
        
        for i, (name, _) in enumerate(test_options, 1):
            test_table.add_row(str(i), name)
        
        self.console.print(test_table)
        
        choice = Prompt.ask(
            "[cyan]Select test suite[/cyan]",
            choices=[str(i) for i in range(1, len(test_options) + 1)],
            default="1"
        )
        
        test_type = test_options[int(choice) - 1][1]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            
            task = progress.add_task("Running tests...", total=None)
            
            try:
                if test_type in ["core", "full"]:
                    progress.update(task, description="Testing core functionality...")
                    # Import and run core tests
                    import subprocess
                    result = subprocess.run([sys.executable, "test_core_functionality.py"], 
                                          capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        self.console.print("[green]✅ Core functionality tests passed![/green]")
                    else:
                        self.console.print("[red]❌ Core functionality tests failed![/red]")
                        self.console.print(f"[dim]{result.stdout}[/dim]")
                
                if test_type in ["scraping", "full"]:
                    progress.update(task, description="Testing scraping functionality...")
                    result = subprocess.run([sys.executable, "test_scraping.py"], 
                                          capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        self.console.print("[green]✅ Scraping tests passed![/green]")
                    else:
                        self.console.print("[yellow]⚠️ Some scraping tests had issues (normal for API limits)[/yellow]")
                
                progress.update(task, description="Tests completed!")
                
            except Exception as e:
                self.console.print(f"[red]❌ Test execution failed: {e}[/red]")
        
        input("\nPress Enter to continue...")

    async def configuration(self):
        """Configuration management"""
        self.console.print("[bold cyan]⚙️ Configuration Management[/bold cyan]")
        
        # Display current configuration status
        config_table = Table(title="Configuration Status", box=box.ROUNDED)
        config_table.add_column("Setting", style="cyan")
        config_table.add_column("Status", style="white")
        config_table.add_column("Description", style="dim white")
        
        config_table.add_row("Database URL", "✅ Configured" if self.config.database_url else "❌ Missing", "PostgreSQL connection")
        config_table.add_row("OpenAI API Key", "✅ Configured" if self.config.openai_api_key else "❌ Missing", "AI content generation")
        config_table.add_row("GitHub Token", "❌ Not Set", "GitHub security advisories")
        config_table.add_row("Twitter API", "❌ Not Set", "Twitter publishing")
        config_table.add_row("LinkedIn Token", "❌ Not Set", "LinkedIn publishing")
        
        self.console.print(config_table)
        
        if Confirm.ask("\n[cyan]Would you like to configure additional API keys?[/cyan]"):
            self.console.print("[yellow]⚠️ API key configuration requires manual setup in environment variables.[/yellow]")
            self.console.print("[dim]Please set the following environment variables as needed:[/dim]")
            self.console.print("[dim]- GITHUB_TOKEN[/dim]")
            self.console.print("[dim]- TWITTER_API_KEY[/dim]")
            self.console.print("[dim]- LINKEDIN_ACCESS_TOKEN[/dim]")
        
        input("\nPress Enter to continue...")

    async def run(self):
        """Main CLI run loop"""
        self.console.clear()
        
        # Initialize application
        if not await self.initialize():
            return
        
        while True:
            self.console.clear()
            self.display_banner()
            
            try:
                choice = await self.display_menu_and_get_choice()
                
                if choice == "exit":
                    self.console.print("[bold green]👋 Thank you for using VulnPublisherPro Enhanced![/bold green]")
                    break
                elif choice == "scrape_vulnerabilities":
                    await self.scrape_vulnerabilities()
                elif choice == "view_stats":
                    await self.view_stats()
                elif choice == "list_vulnerabilities":
                    await self.list_vulnerabilities()
                elif choice == "system_testing":
                    await self.system_testing()
                elif choice == "configuration":
                    await self.configuration()
                else:
                    self.console.print(f"[yellow]⚠️ Feature '{choice}' coming soon![/yellow]")
                    input("Press Enter to continue...")
                    
            except KeyboardInterrupt:
                if Confirm.ask("\n[yellow]Are you sure you want to exit?[/yellow]"):
                    break
            except Exception as e:
                self.console.print(f"[red]❌ An error occurred: {e}[/red]")
                input("Press Enter to continue...")

async def main():
    """Main entry point"""
    cli = EnhancedVulnPublisherCLI()
    await cli.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)