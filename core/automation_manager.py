#!/usr/bin/env python3
"""
Automation Manager - Orchestrates all strategic automation features
Production-ready automation with intelligent targeting and monitoring
"""

import time
from datetime import datetime
from typing import Dict, List, Optional
import json
from pathlib import Path

from .github_api import GitHubAPI
from .database import DatabaseManager
from .strategic_automation import StrategicAutomation
from .scheduler import AutomationScheduler
from .ban_manager import BanManager
from .logger import Logger


class AutomationManager:
    """Master controller for GitHub automation features"""
    
    def __init__(self, github_api: GitHubAPI):
        self.github_api = github_api
        self.logger = Logger()
        
        # Initialize core components
        self.database = DatabaseManager()
        self.ban_manager = BanManager()
        self.strategic_automation = StrategicAutomation(
            github_api, self.database, self.ban_manager
        )
        self.scheduler = AutomationScheduler(
            github_api, self.database, self.ban_manager
        )
        
        self.logger.info("Automation Manager initialized")
    
    def start_strategic_automation(self, daemon: bool = True) -> Dict:
        """Start the strategic follower growth automation"""
        try:
            self.logger.info("🚀 Starting Strategic Follower Growth Automation")
            
            # Start the scheduler in daemon mode
            self.scheduler.start(daemon=daemon)
            
            if daemon:
                return {
                    'status': 'started',
                    'message': 'Strategic automation running in background',
                    'scheduler_status': self.scheduler.get_scheduler_status()
                }
            else:
                return {
                    'status': 'running',
                    'message': 'Strategic automation running in foreground'
                }
                
        except Exception as e:
            self.logger.error(f"Failed to start strategic automation: {e}")
            return {
                'status': 'error',
                'message': f'Failed to start automation: {e}'
            }
    
    def stop_automation(self) -> Dict:
        """Stop all automation"""
        try:
            self.scheduler.stop()
            return {
                'status': 'stopped',
                'message': 'Automation stopped successfully'
            }
        except Exception as e:
            self.logger.error(f"Failed to stop automation: {e}")
            return {
                'status': 'error',
                'message': f'Failed to stop automation: {e}'
            }
    
    def run_manual_cycle(self) -> Dict:
        """Run a single manual automation cycle"""
        try:
            self.logger.info("🎯 Running manual automation cycle")
            
            results = self.strategic_automation.execute_strategic_follow_cycle()
            
            return {
                'status': 'completed',
                'results': results,
                'message': f"Cycle complete: {results['followed']} followed, {results['unfollowed']} unfollowed"
            }
            
        except Exception as e:
            self.logger.error(f"Manual cycle failed: {e}")
            return {
                'status': 'error',
                'message': f'Manual cycle failed: {e}',
                'results': {'errors': 1}
            }
    
    def get_comprehensive_status(self) -> Dict:
        """Get comprehensive automation status"""
        try:
            # Get scheduler status
            scheduler_status = self.scheduler.get_scheduler_status()
            
            # Get automation statistics
            stats = self.strategic_automation.get_comprehensive_stats()
            
            # Get current GitHub metrics
            try:
                # Only attempt to get metrics if GitHub API has a valid username
                if hasattr(self.github_api, 'username') and self.github_api.username:
                    current_followers = len(self.github_api.get_followers())
                    current_following = len(self.github_api.get_following())
                else:
                    self.logger.warning("GitHub username not available - cannot fetch follower metrics")
                    current_followers = 0
                    current_following = 0
            except Exception as e:
                self.logger.error(f"Failed to fetch GitHub metrics: {e}")
                current_followers = 0
                current_following = 0
            
            # Get recent activity from database
            recent_activity = self._get_recent_activity()
            
            return {
                'status': 'active' if scheduler_status['is_running'] else 'stopped',
                'scheduler': scheduler_status,
                'statistics': stats,
                'github_metrics': {
                    'current_followers': current_followers,
                    'current_following': current_following,
                    'ratio': round(current_followers / max(current_following, 1), 2)
                },
                'recent_activity': recent_activity,
                'last_updated': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get status: {e}")
            return {
                'status': 'error',
                'message': f'Failed to get status: {e}'
            }
    
    def _get_recent_activity(self, hours: int = 24) -> List[Dict]:
        """Get recent automation activity"""
        try:
            cursor = self.database.connection.cursor()
            
            from datetime import timedelta
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            if self.database.use_postgresql:
                cursor.execute("""
                    SELECT action, username, success, details, timestamp
                    FROM automation_logs 
                    WHERE timestamp >= %s
                    ORDER BY timestamp DESC
                    LIMIT 50
                """, (cutoff_time,))
            else:
                cursor.execute("""
                    SELECT action, username, success, details, timestamp
                    FROM automation_logs 
                    WHERE timestamp >= ?
                    ORDER BY timestamp DESC
                    LIMIT 50
                """, (cutoff_time,))
            
            activities = []
            for row in cursor.fetchall():
                activities.append({
                    'action': row[0],
                    'username': row[1],
                    'success': bool(row[2]),
                    'details': row[3],
                    'timestamp': str(row[4]) if row[4] else None
                })
            
            return activities
            
        except Exception as e:
            self.logger.error(f"Failed to get recent activity: {e}")
            return []
    
    def configure_automation(self, settings: Dict) -> Dict:
        """Configure automation settings"""
        try:
            # Update strategic automation settings
            if 'strategic_settings' in settings:
                for key, value in settings['strategic_settings'].items():
                    if key in self.strategic_automation.settings:
                        self.strategic_automation.settings[key] = value
                
                self.strategic_automation.save_settings()
            
            # Update scheduler settings
            if 'scheduler_settings' in settings:
                for job_name, job_config in settings['scheduler_settings'].items():
                    if job_name in self.scheduler.schedules:
                        self.scheduler.schedules[job_name].update(job_config)
                
                self.scheduler.save_schedule_config()
            
            return {
                'status': 'updated',
                'message': 'Automation settings updated successfully'
            }
            
        except Exception as e:
            self.logger.error(f"Failed to configure automation: {e}")
            return {
                'status': 'error',
                'message': f'Failed to configure automation: {e}'
            }
    
    def get_damaged_users_report(self) -> Dict:
        """Get detailed report of damaged/blacklisted users"""
        try:
            cursor = self.database.connection.cursor()
            
            if self.database.use_postgresql:
                cursor.execute("""
                    SELECT username, reason, retry_count, final_moon_symbols, blacklisted_date
                    FROM damaged_users
                    ORDER BY blacklisted_date DESC
                    LIMIT 100
                """)
            else:
                cursor.execute("""
                    SELECT username, reason, retry_count, final_moon_symbols, blacklisted_date
                    FROM damaged_users
                    ORDER BY blacklisted_date DESC
                    LIMIT 100
                """)
            
            damaged_users = []
            for row in cursor.fetchall():
                damaged_users.append({
                    'username': row[0],
                    'reason': row[1],
                    'retry_count': row[2],
                    'moon_symbols': row[3],
                    'blacklisted_date': row[4]
                })
            
            return {
                'status': 'success',
                'damaged_users': damaged_users,
                'total_count': len(damaged_users)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get damaged users report: {e}")
            return {
                'status': 'error',
                'message': f'Failed to get report: {e}'
            }
    
    def export_automation_data(self, export_path: Optional[str] = None) -> Dict:
        """Export all automation data for backup/analysis"""
        try:
            if not export_path:
                export_path = f"data/exports/automation_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            export_file = Path(export_path)
            export_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Collect all data
            export_data = {
                'export_timestamp': datetime.now().isoformat(),
                'status': self.get_comprehensive_status(),
                'settings': {
                    'strategic': self.strategic_automation.settings,
                    'scheduler': self.scheduler.schedules
                },
                'statistics': self.strategic_automation.get_comprehensive_stats(),
                'damaged_users': self.get_damaged_users_report(),
                'recent_activity': self._get_recent_activity(hours=168)  # 7 days
            }
            
            # Save to file
            with open(export_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Automation data exported to {export_file}")
            
            return {
                'status': 'exported',
                'export_path': str(export_file),
                'message': f'Data exported successfully to {export_file}'
            }
            
        except Exception as e:
            self.logger.error(f"Failed to export automation data: {e}")
            return {
                'status': 'error',
                'message': f'Export failed: {e}'
            }
    
    def cleanup_old_data(self, days_to_keep: int = 90) -> Dict:
        """Cleanup old automation data"""
        try:
            cursor = self.database.connection.cursor()
            
            from datetime import timedelta
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            
            # Clean old logs
            if self.database.use_postgresql:
                cursor.execute("""
                    DELETE FROM automation_logs 
                    WHERE timestamp < %s
                """, (cutoff_date,))
                
                cursor.execute("""
                    DELETE FROM follow_requests 
                    WHERE status IN ('unfollowed', 'followed_back') AND updated_at < %s
                """, (cutoff_date,))
            else:
                cursor.execute("""
                    DELETE FROM automation_logs 
                    WHERE timestamp < ?
                """, (cutoff_date,))
                
                cursor.execute("""
                    DELETE FROM follow_requests 
                    WHERE status IN ('unfollowed', 'followed_back') AND updated_at < ?
                """, (cutoff_date,))
                
                self.database.connection.commit()
            
            return {
                'status': 'cleaned',
                'message': f'Cleaned data older than {days_to_keep} days'
            }
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup data: {e}")
            return {
                'status': 'error',
                'message': f'Cleanup failed: {e}'
            }
    
    def close(self):
        """Close all resources"""
        try:
            self.scheduler.stop()
            self.database.close()
            self.logger.info("Automation Manager closed")
        except Exception as e:
            self.logger.error(f"Error closing Automation Manager: {e}")