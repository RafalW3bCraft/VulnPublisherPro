"""
User Review and Editing System for Scraped Data and Generated Content
Provides interactive interfaces for reviewing and editing vulnerability data before publication
"""

import json
import os
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.syntax import Syntax
import inquirer

logger = logging.getLogger(__name__)
console = Console()

class UserReviewSystem:
    """Interactive system for user review and editing of vulnerability data and content"""
    
    def __init__(self):
        self.review_history = []
        self.pending_reviews = []
        
    def review_scraped_data(self, vulnerabilities: List[Dict[str, Any]], source: str) -> List[Dict[str, Any]]:
        """Interactive review of scraped vulnerability data"""
        
        console.print(f"\n[bold cyan]🔍 Reviewing Scraped Data from {source.upper()}[/bold cyan]")
        console.print(f"Found {len(vulnerabilities)} vulnerabilities for review\n")
        
        reviewed_vulnerabilities = []
        
        for i, vuln in enumerate(vulnerabilities, 1):
            console.print(f"[bold yellow]Reviewing {i}/{len(vulnerabilities)}[/bold yellow]")
            
            # Display vulnerability details
            self._display_vulnerability(vuln, source)
            
            # Review options
            action = self._get_review_action()
            
            if action == 'approve':
                reviewed_vulnerabilities.append(vuln)
                console.print("[green]✅ Approved[/green]\n")
                
            elif action == 'edit':
                edited_vuln = self._edit_vulnerability(vuln)
                if edited_vuln:
                    reviewed_vulnerabilities.append(edited_vuln)
                    console.print("[green]✅ Edited and Approved[/green]\n")
                
            elif action == 'reject':
                reason = Prompt.ask("Rejection reason (optional)")
                self._log_rejection(vuln, reason)
                console.print("[red]❌ Rejected[/red]\n")
                
            elif action == 'skip':
                console.print("[yellow]⏭️  Skipped for later review[/yellow]\n")
                self.pending_reviews.append(vuln)
                
            elif action == 'approve_all':
                # Approve all remaining vulnerabilities
                reviewed_vulnerabilities.extend(vulnerabilities[i-1:])
                console.print(f"[green]✅ Approved all remaining {len(vulnerabilities) - i + 1} vulnerabilities[/green]")
                break
        
        self._save_review_session(source, len(vulnerabilities), len(reviewed_vulnerabilities))
        
        console.print(f"\n[bold green]Review Complete![/bold green]")
        console.print(f"Approved: {len(reviewed_vulnerabilities)}")
        console.print(f"Rejected: {len(vulnerabilities) - len(reviewed_vulnerabilities) - len(self.pending_reviews)}")
        console.print(f"Pending: {len(self.pending_reviews)}")
        
        return reviewed_vulnerabilities
    
    def review_generated_content(self, content: Dict[str, Any], vulnerability: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Interactive review of AI-generated content"""
        
        console.print(f"\n[bold cyan]📝 Reviewing Generated Content[/bold cyan]")
        console.print(f"Platform: {content.get('platform', 'Unknown').title()}")
        console.print(f"Content Type: {content.get('content_type', 'Unknown').title()}\n")
        
        # Display content details
        self._display_generated_content(content, vulnerability)
        
        # Review options
        action = self._get_content_review_action()
        
        if action == 'approve':
            console.print("[green]✅ Content Approved for Publication[/green]")
            return content
            
        elif action == 'edit':
            edited_content = self._edit_content(content)
            if edited_content:
                console.print("[green]✅ Content Edited and Approved[/green]")
                return edited_content
            
        elif action == 'regenerate':
            console.print("[yellow]🔄 Marked for Regeneration[/yellow]")
            return {'action': 'regenerate', 'original': content}
            
        elif action == 'reject':
            reason = Prompt.ask("Rejection reason (optional)")
            self._log_content_rejection(content, reason)
            console.print("[red]❌ Content Rejected[/red]")
            return None
        
        return None
    
    def batch_review_mode(self, items: List[Dict[str, Any]], item_type: str) -> List[Dict[str, Any]]:
        """Batch review mode for multiple items"""
        
        console.print(f"\n[bold cyan]📦 Batch Review Mode - {item_type.title()}[/bold cyan]")
        console.print(f"Items to review: {len(items)}\n")
        
        # Show batch options
        batch_options = [
            'Review each item individually',
            'Quick approve all (review summary only)',
            'Apply filter criteria',
            'Export for external review'
        ]
        
        choice = inquirer.list_input(
            "Select batch review approach:",
            choices=batch_options
        )
        
        if choice == 'Review each item individually':
            if item_type == 'vulnerabilities':
                return self.review_scraped_data(items, 'batch')
            else:
                reviewed_items = []
                for item in items:
                    reviewed = self.review_generated_content(item, {})
                    if reviewed:
                        reviewed_items.append(reviewed)
                return reviewed_items
                
        elif choice == 'Quick approve all (review summary only)':
            return self._quick_batch_approve(items, item_type)
            
        elif choice == 'Apply filter criteria':
            return self._filtered_batch_review(items, item_type)
            
        elif choice == 'Export for external review':
            self._export_for_review(items, item_type)
            return []
        
        return items
    
    def _display_vulnerability(self, vuln: Dict[str, Any], source: str):
        """Display vulnerability details in a formatted table"""
        
        table = Table(title=f"Vulnerability Details - {source.upper()}", show_header=True)
        table.add_column("Field", style="bold yellow", width=20)
        table.add_column("Value", style="white", width=60)
        
        # Key fields to display
        display_fields = [
            ('ID', vuln.get('vulnerability_id', 'N/A')),
            ('Title', vuln.get('title', 'N/A')[:100] + '...' if len(vuln.get('title', '')) > 100 else vuln.get('title', 'N/A')),
            ('Severity', vuln.get('severity', 'Unknown').upper()),
            ('CVE ID', vuln.get('cve_id', 'Pending')),
            ('CVSS Score', vuln.get('cvss_score', 'N/A')),
            ('Published Date', vuln.get('published_date', 'Unknown')),
            ('Affected Products', ', '.join(vuln.get('affected_products', [])[:3])),
            ('Tags', ', '.join(vuln.get('tags', [])[:5]))
        ]
        
        for field, value in display_fields:
            table.add_row(field, str(value))
        
        console.print(table)
        
        # Display description separately
        if vuln.get('description'):
            desc_text = vuln['description'][:300] + '...' if len(vuln.get('description', '')) > 300 else vuln.get('description', '')
            console.print(f"\n[bold]Description:[/bold]\n{desc_text}")
        
        # Show references if available
        if vuln.get('references'):
            console.print(f"\n[bold]References:[/bold]")
            for ref in vuln['references'][:3]:
                console.print(f"  • {ref}")
    
    def _display_generated_content(self, content: Dict[str, Any], vulnerability: Dict[str, Any]):
        """Display generated content for review"""
        
        # Content metadata table
        meta_table = Table(title="Content Metadata", show_header=True)
        meta_table.add_column("Property", style="bold yellow")
        meta_table.add_column("Value", style="white")
        
        meta_fields = [
            ('Platform', content.get('platform', 'Unknown')),
            ('Content Type', content.get('content_type', 'Unknown')),
            ('Character Count', len(content.get('content', ''))),
            ('Hashtag Count', len(content.get('hashtags', []))),
            ('Generated At', content.get('generated_at', 'Unknown')),
            ('Optimization Level', content.get('optimization_level', 'Standard'))
        ]
        
        for prop, value in meta_fields:
            meta_table.add_row(prop, str(value))
        
        console.print(meta_table)
        
        # Display title
        if content.get('title'):
            console.print(f"\n[bold cyan]Title:[/bold cyan]\n{content['title']}")
        
        # Display content
        if content.get('content'):
            console.print(f"\n[bold cyan]Content:[/bold cyan]")
            # Use syntax highlighting for better readability
            syntax = Syntax(content['content'], "markdown", theme="monokai", line_numbers=False)
            console.print(Panel(syntax, title="Generated Content", border_style="blue"))
        
        # Display hashtags
        if content.get('hashtags'):
            console.print(f"\n[bold cyan]Hashtags:[/bold cyan] {' '.join(['#' + tag for tag in content['hashtags']])}")
        
        # Show quality metrics if available
        if 'engagement_score_prediction' in content:
            console.print(f"\n[bold green]Engagement Prediction:[/bold green] {content['engagement_score_prediction']}/10")
        
        if 'technical_depth_score' in content:
            console.print(f"[bold green]Technical Depth:[/bold green] {content['technical_depth_score']}/10")
    
    def _get_review_action(self) -> str:
        """Get user's review action choice"""
        
        choices = [
            'approve - Approve this vulnerability',
            'edit - Edit vulnerability details',
            'reject - Reject this vulnerability',
            'skip - Skip for later review',
            'approve_all - Approve all remaining'
        ]
        
        action = inquirer.list_input(
            "Review Action:",
            choices=choices
        )
        
        return action.split(' - ')[0]
    
    def _get_content_review_action(self) -> str:
        """Get user's content review action choice"""
        
        choices = [
            'approve - Approve for publication',
            'edit - Edit content manually',
            'regenerate - Generate new version',
            'reject - Reject this content'
        ]
        
        action = inquirer.list_input(
            "Content Review Action:",
            choices=choices
        )
        
        return action.split(' - ')[0]
    
    def _edit_vulnerability(self, vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Interactive vulnerability editing"""
        
        console.print("\n[bold cyan]✏️  Edit Mode - Vulnerability[/bold cyan]")
        
        editable_fields = [
            'title',
            'description', 
            'severity',
            'cvss_score',
            'affected_products',
            'tags'
        ]
        
        field_to_edit = inquirer.list_input(
            "Which field would you like to edit?",
            choices=editable_fields + ['cancel']
        )
        
        if field_to_edit == 'cancel':
            return vuln
        
        current_value = vuln.get(field_to_edit, '')
        
        if field_to_edit in ['affected_products', 'tags']:
            if isinstance(current_value, list):
                current_value = ', '.join(current_value)
        
        console.print(f"\n[yellow]Current value:[/yellow] {current_value}")
        
        if field_to_edit == 'severity':
            new_value = inquirer.list_input(
                "Select new severity:",
                choices=['critical', 'high', 'medium', 'low', 'info']
            )
        else:
            new_value = Prompt.ask(f"New value for {field_to_edit}", default=str(current_value))
        
        # Process list fields
        if field_to_edit in ['affected_products', 'tags']:
            new_value = [item.strip() for item in new_value.split(',') if item.strip()]
        
        # Update the vulnerability
        vuln[field_to_edit] = new_value
        
        console.print(f"[green]✅ Updated {field_to_edit}[/green]")
        
        # Ask if user wants to edit more fields
        if Confirm.ask("Edit another field?"):
            return self._edit_vulnerability(vuln)
        
        return vuln
    
    def _edit_content(self, content: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Interactive content editing"""
        
        console.print("\n[bold cyan]✏️  Edit Mode - Content[/bold cyan]")
        
        editable_fields = [
            'title',
            'content',
            'hashtags'
        ]
        
        field_to_edit = inquirer.list_input(
            "Which field would you like to edit?",
            choices=editable_fields + ['cancel']
        )
        
        if field_to_edit == 'cancel':
            return content
        
        current_value = content.get(field_to_edit, '')
        
        if field_to_edit == 'hashtags':
            if isinstance(current_value, list):
                current_value = ', '.join(current_value)
        
        console.print(f"\n[yellow]Current value:[/yellow]")
        if field_to_edit == 'content':
            # Show content in a panel for better visibility
            console.print(Panel(current_value, title="Current Content"))
        else:
            console.print(current_value)
        
        new_value = Prompt.ask(f"New value for {field_to_edit}", default=str(current_value))
        
        # Process hashtags
        if field_to_edit == 'hashtags':
            new_value = [tag.strip().replace('#', '') for tag in new_value.split(',') if tag.strip()]
        
        # Update the content
        content[field_to_edit] = new_value
        content['edited_at'] = datetime.now().isoformat()
        content['user_edited'] = True
        
        console.print(f"[green]✅ Updated {field_to_edit}[/green]")
        
        # Ask if user wants to edit more fields
        if Confirm.ask("Edit another field?"):
            return self._edit_content(content)
        
        return content
    
    def _quick_batch_approve(self, items: List[Dict[str, Any]], item_type: str) -> List[Dict[str, Any]]:
        """Quick batch approval with summary review"""
        
        console.print(f"\n[bold cyan]⚡ Quick Batch Review - {item_type.title()}[/bold cyan]")
        
        # Show summary statistics
        if item_type == 'vulnerabilities':
            self._show_vulnerability_summary(items)
        else:
            self._show_content_summary(items)
        
        if Confirm.ask(f"Approve all {len(items)} {item_type}?"):
            console.print(f"[green]✅ Approved all {len(items)} {item_type}[/green]")
            return items
        else:
            console.print("[yellow]Batch approval cancelled[/yellow]")
            return []
    
    def _filtered_batch_review(self, items: List[Dict[str, Any]], item_type: str) -> List[Dict[str, Any]]:
        """Apply filters for batch review"""
        
        console.print(f"\n[bold cyan]🔍 Filtered Batch Review - {item_type.title()}[/bold cyan]")
        
        if item_type == 'vulnerabilities':
            filters = self._get_vulnerability_filters()
            filtered_items = self._apply_vulnerability_filters(items, filters)
        else:
            filters = self._get_content_filters()
            filtered_items = self._apply_content_filters(items, filters)
        
        console.print(f"Filtered results: {len(filtered_items)}/{len(items)} {item_type}")
        
        if filtered_items and Confirm.ask(f"Approve filtered {item_type}?"):
            return filtered_items
        
        return []
    
    def _show_vulnerability_summary(self, vulnerabilities: List[Dict[str, Any]]):
        """Show vulnerability batch summary"""
        
        # Count by severity
        severity_counts = {}
        sources = set()
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            if vuln.get('tags'):
                sources.update(vuln['tags'])
        
        table = Table(title="Batch Summary - Vulnerabilities")
        table.add_column("Metric", style="bold yellow")
        table.add_column("Value", style="white")
        
        table.add_row("Total Vulnerabilities", str(len(vulnerabilities)))
        for severity, count in severity_counts.items():
            table.add_row(f"{severity.title()} Severity", str(count))
        table.add_row("Data Sources", str(len(sources)))
        
        console.print(table)
    
    def _show_content_summary(self, content_items: List[Dict[str, Any]]):
        """Show content batch summary"""
        
        platform_counts = {}
        type_counts = {}
        
        for content in content_items:
            platform = content.get('platform', 'unknown')
            content_type = content.get('content_type', 'unknown')
            
            platform_counts[platform] = platform_counts.get(platform, 0) + 1
            type_counts[content_type] = type_counts.get(content_type, 0) + 1
        
        table = Table(title="Batch Summary - Generated Content")
        table.add_column("Metric", style="bold yellow")
        table.add_column("Value", style="white")
        
        table.add_row("Total Content Items", str(len(content_items)))
        for platform, count in platform_counts.items():
            table.add_row(f"{platform.title()} Platform", str(count))
        for ctype, count in type_counts.items():
            table.add_row(f"{ctype.title()} Type", str(count))
        
        console.print(table)
    
    def _log_rejection(self, item: Dict[str, Any], reason: str):
        """Log rejection with reason"""
        
        rejection_log = {
            'item_id': item.get('vulnerability_id', item.get('id', 'unknown')),
            'rejected_at': datetime.now().isoformat(),
            'reason': reason,
            'item_data': item
        }
        
        self.review_history.append({
            'action': 'reject',
            'timestamp': datetime.now().isoformat(),
            'data': rejection_log
        })
    
    def _log_content_rejection(self, content: Dict[str, Any], reason: str):
        """Log content rejection with reason"""
        
        rejection_log = {
            'content_type': content.get('content_type', 'unknown'),
            'platform': content.get('platform', 'unknown'),
            'rejected_at': datetime.now().isoformat(),
            'reason': reason,
            'content_data': content
        }
        
        self.review_history.append({
            'action': 'reject_content',
            'timestamp': datetime.now().isoformat(),
            'data': rejection_log
        })
    
    def _save_review_session(self, source: str, total: int, approved: int):
        """Save review session summary"""
        
        session_log = {
            'source': source,
            'total_items': total,
            'approved_items': approved,
            'rejection_rate': (total - approved) / total if total > 0 else 0,
            'session_date': datetime.now().isoformat()
        }
        
        self.review_history.append({
            'action': 'review_session',
            'timestamp': datetime.now().isoformat(),
            'data': session_log
        })
    
    def _export_for_review(self, items: List[Dict[str, Any]], item_type: str):
        """Export items for external review"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"review_export_{item_type}_{timestamp}.json"
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'item_type': item_type,
            'total_items': len(items),
            'items': items
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        console.print(f"[green]✅ Exported {len(items)} {item_type} to {filename}[/green]")
    
    def get_review_history(self) -> List[Dict[str, Any]]:
        """Get review history"""
        return self.review_history
    
    def get_pending_reviews(self) -> List[Dict[str, Any]]:
        """Get pending review items"""
        return self.pending_reviews
    
    def _get_vulnerability_filters(self) -> Dict[str, Any]:
        """Get vulnerability filtering criteria from user"""
        
        severity_choices = ['critical', 'high', 'medium', 'low', 'all']
        selected_severities = inquirer.checkbox(
            "Select severities to include:",
            choices=severity_choices
        )
        
        source_filter = Prompt.ask("Filter by source (optional, comma-separated)", default="")
        
        return {
            'severities': [s for s in selected_severities if s != 'all'],
            'sources': [s.strip() for s in source_filter.split(',') if s.strip()]
        }
    
    def _apply_vulnerability_filters(self, items: List[Dict[str, Any]], filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Apply vulnerability filters"""
        
        filtered_items = []
        
        for item in items:
            # Check severity filter
            if filters['severities'] and item.get('severity') not in filters['severities']:
                continue
                
            # Check source filter
            if filters['sources'] and item.get('source') not in filters['sources']:
                continue
                
            filtered_items.append(item)
        
        return filtered_items
    
    def _get_content_filters(self) -> Dict[str, Any]:
        """Get content filtering criteria from user"""
        
        platform_choices = ['twitter', 'linkedin', 'medium', 'telegram', 'discord', 'all']
        selected_platforms = inquirer.checkbox(
            "Select platforms to include:",
            choices=platform_choices
        )
        
        content_types = ['summary', 'detailed', 'alert', 'thread', 'all']
        selected_types = inquirer.checkbox(
            "Select content types to include:",
            choices=content_types
        )
        
        return {
            'platforms': [p for p in selected_platforms if p != 'all'],
            'content_types': [t for t in selected_types if t != 'all']
        }
    
    def _apply_content_filters(self, items: List[Dict[str, Any]], filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Apply content filters"""
        
        filtered_items = []
        
        for item in items:
            # Check platform filter
            if filters['platforms'] and item.get('platform') not in filters['platforms']:
                continue
                
            # Check content type filter
            if filters['content_types'] and item.get('content_type') not in filters['content_types']:
                continue
                
            filtered_items.append(item)
        
        return filtered_items