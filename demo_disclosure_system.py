#!/usr/bin/env python3
"""
VulnPublisherPro Disclosure System Demo
Demonstrates industry-level vulnerability disclosure scraping and publication
"""

import asyncio
import json
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich.text import Text
from datetime import datetime
from scrapers.disclosure_formats import DisclosureFormatManager
from publication_formats import UniversalPublicationManager

console = Console()

def display_banner():
    """Display VulnPublisherPro banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                            🛡️ VULNPUBLISHERPRO 🛡️                          ║
║                      Industry-Level Disclosure Intelligence                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Author: RafalW3bCraft                                License: MIT           ║
║  Enhanced with Professional Disclosure Format Parsing & Publication         ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold blue")

def display_platform_capabilities():
    """Display platform-specific capabilities"""
    table = Table(title="🔍 Platform-Specific Disclosure Capabilities", style="cyan")
    
    table.add_column("Platform", style="bold yellow", width=15)
    table.add_column("Data Source", style="green", width=20)
    table.add_column("Key Features", style="white", width=40)
    table.add_column("Status", style="bold", width=10)
    
    table.add_row(
        "HackerOne", 
        "API v1 + GraphQL", 
        "• Bounty tracking & amounts\n• Researcher attribution\n• Program details & timeline\n• Disclosure status tracking",
        "[green]✓ Ready[/green]"
    )
    
    table.add_row(
        "Bugcrowd", 
        "REST API v4", 
        "• VRT classification system\n• Priority-based scoring\n• Submission tracking\n• Hunter recognition",
        "[green]✓ Ready[/green]"
    )
    
    table.add_row(
        "Exploit-DB", 
        "Web Scraping", 
        "• Exploit code extraction\n• CVE correlation\n• Platform identification\n• Author attribution",
        "[green]✓ Ready[/green]"
    )
    
    console.print("\n")
    console.print(table)

def display_publication_formats():
    """Display available publication formats"""
    table = Table(title="📝 Professional Publication Formats", style="magenta")
    
    table.add_column("Format Type", style="bold yellow", width=15)
    table.add_column("Platforms", style="green", width=25)
    table.add_column("Key Elements", style="white", width=35)
    
    table.add_row(
        "Summary Posts",
        "Twitter, LinkedIn, Telegram",
        "• Severity indicators\n• Bounty highlights\n• Researcher recognition\n• Quick impact overview"
    )
    
    table.add_row(
        "Detailed Reports",
        "Medium, LinkedIn, Slack",
        "• Executive summaries\n• Technical analysis\n• Timeline documentation\n• Remediation guidance"
    )
    
    table.add_row(
        "Threat Intelligence",
        "Discord, Teams, Telegram",
        "• CVE correlation\n• Exploit availability\n• Risk assessment\n• IOC extraction"
    )
    
    console.print("\n")
    console.print(table)

def display_sample_disclosures():
    """Display sample disclosure data"""
    console.print("\n")
    console.print(Panel.fit("🎯 Sample Disclosure Formats Generated", style="bold green"))
    
    # Load and display sample data
    sample_files = [
        "content/sample_publications/hackerone_123456_summary.json",
        "content/sample_publications/bugcrowd_BC-789012_summary.json",
        "content/sample_publications/exploit_db_50123_summary.json"
    ]
    
    for file_path in sample_files:
        if os.path.exists(file_path):
            platform = file_path.split('_')[0].split('/')[-1].title()
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            console.print(f"\n[bold cyan]🔹 {platform} Disclosure Sample:[/bold cyan]")
            console.print(f"[yellow]Title:[/yellow] {data['title'][:60]}...")
            
            # Show first few lines of content
            content_lines = data['content'].split('\n')[:3]
            for line in content_lines:
                console.print(f"  {line[:80]}{'...' if len(line) > 80 else ''}")
            
            if 'metadata' in data:
                metadata = data['metadata']
                if 'bounty_amount' in metadata and metadata['bounty_amount']:
                    console.print(f"[green]💰 Bounty:[/green] ${metadata['bounty_amount']:,.0f}")
                if 'researcher' in metadata:
                    console.print(f"[blue]👤 Researcher:[/blue] @{metadata['researcher']}")

def display_technical_features():
    """Display technical implementation features"""
    console.print("\n")
    console.print(Panel.fit("⚙️ Technical Implementation Features", style="bold blue"))
    
    features = [
        "✅ Standardized VulnerabilityDisclosure class for all platforms",
        "✅ Platform-specific parsers (HackerOne, Bugcrowd, Exploit-DB)",
        "✅ Automated disclosure format detection and parsing",
        "✅ Professional publication template system",
        "✅ Multi-platform content adaptation (Twitter, LinkedIn, Medium, etc.)",
        "✅ Legacy compatibility with existing vulnerability dictionary format",
        "✅ Enhanced metadata extraction (bounties, researchers, timelines)",
        "✅ Industry-standard disclosure format compliance"
    ]
    
    for feature in features:
        console.print(f"  {feature}")

def display_usage_examples():
    """Display usage examples"""
    console.print("\n")
    console.print(Panel.fit("🚀 Usage Examples", style="bold yellow"))
    
    examples = [
        {
            "command": "python main.py scrape --sources hackerone,bugcrowd --limit 10",
            "description": "Scrape 10 latest disclosures from HackerOne and Bugcrowd"
        },
        {
            "command": "python main.py generate-content --platform hackerone --format detailed",
            "description": "Generate detailed publications for HackerOne disclosures"
        },
        {
            "command": "python main.py publish --platforms twitter,linkedin --format summary",
            "description": "Publish summary posts to Twitter and LinkedIn"
        },
        {
            "command": "python test_disclosure_formats.py",
            "description": "Run comprehensive disclosure format testing"
        }
    ]
    
    for example in examples:
        console.print(f"\n[bold green]Command:[/bold green] [cyan]{example['command']}[/cyan]")
        console.print(f"[yellow]Description:[/yellow] {example['description']}")

def display_api_requirements():
    """Display API key requirements"""
    console.print("\n")
    console.print(Panel.fit("🔑 API Configuration Requirements", style="bold red"))
    
    requirements = Table(show_header=True, header_style="bold magenta")
    requirements.add_column("Platform", style="yellow", width=15)
    requirements.add_column("Required Secrets", style="green", width=25)
    requirements.add_column("Purpose", style="white", width=30)
    
    requirements.add_row(
        "HackerOne",
        "HACKERONE_USERNAME\nHACKERONE_TOKEN",
        "Access disclosed reports via API\nAuthenticate API requests"
    )
    
    requirements.add_row(
        "Bugcrowd", 
        "BUGCROWD_TOKEN",
        "Access disclosed submissions\nRetrieve bounty information"
    )
    
    requirements.add_row(
        "Exploit-DB",
        "None required",
        "Web scraping (respectful)\nPublic exploit database"
    )
    
    requirements.add_row(
        "OpenAI",
        "OPENAI_API_KEY", 
        "AI content generation\nVulnerability analysis"
    )
    
    console.print(requirements)
    
    console.print("\n[bold yellow]💡 To configure API keys:[/bold yellow]")
    console.print("1. Set environment variables in your system")
    console.print("2. Or use the interactive configuration in main.py")
    console.print("3. Run the application - it will prompt for missing keys")

async def run_live_demo():
    """Run a live demonstration of the disclosure system"""
    console.print("\n")
    console.print(Panel.fit("🎬 Live System Demonstration", style="bold green"))
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Initialize managers
        task1 = progress.add_task("[cyan]Initializing disclosure format manager...", total=None)
        await asyncio.sleep(1)
        disclosure_manager = DisclosureFormatManager()
        progress.remove_task(task1)
        
        task2 = progress.add_task("[cyan]Initializing publication manager...", total=None)
        await asyncio.sleep(1)
        publication_manager = UniversalPublicationManager()
        progress.remove_task(task2)
        
        task3 = progress.add_task("[cyan]Loading sample disclosure data...", total=None)
        await asyncio.sleep(1)
        progress.remove_task(task3)
        
    console.print("[bold green]✅ System initialization complete![/bold green]")
    
    # Show supported platforms
    platforms = disclosure_manager.get_supported_platforms()
    console.print(f"\n[bold yellow]🔧 Supported platforms:[/bold yellow] {', '.join(platforms)}")
    
    pub_platforms = publication_manager.get_supported_platforms() 
    console.print(f"[bold yellow]📱 Publication platforms:[/bold yellow] {', '.join(pub_platforms)}")
    
    console.print("\n[bold blue]🎯 System ready for industry-level vulnerability disclosure processing![/bold blue]")

def display_next_steps():
    """Display recommended next steps"""
    console.print("\n")
    console.print(Panel.fit("📈 Recommended Next Steps", style="bold cyan"))
    
    steps = [
        "1️⃣  Configure API credentials for HackerOne and Bugcrowd platforms",
        "2️⃣  Run python test_disclosure_formats.py to validate the system",
        "3️⃣  Execute python main.py interactive for full CLI experience", 
        "4️⃣  Set up automated scraping schedules for continuous monitoring",
        "5️⃣  Customize publication templates for your brand/organization",
        "6️⃣  Configure social media platform credentials for publishing",
        "7️⃣  Deploy the system for production vulnerability intelligence"
    ]
    
    for step in steps:
        console.print(f"  {step}")

def main():
    """Main demonstration function"""
    console.clear()
    display_banner()
    
    display_platform_capabilities()
    display_publication_formats()
    display_sample_disclosures()
    display_technical_features()
    display_usage_examples()
    display_api_requirements()
    
    # Run live demo
    asyncio.run(run_live_demo())
    
    display_next_steps()
    
    console.print("\n" + "="*80)
    console.print("[bold green]🎉 VulnPublisherPro Disclosure System Demo Complete![/bold green]")
    console.print("[bold cyan]Ready for industry-level vulnerability intelligence operations.[/bold cyan]")
    console.print("="*80)

if __name__ == "__main__":
    main()