#!/usr/bin/env python3
"""
Advanced Scheduler for GitHub Repository Manager
Handles background automation, cron-like scheduling, and continuous operations
"""

import time
import schedule
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Callable, Optional
from pathlib import Path
import json
import signal
import sys

from .logger import Logger
from .strategic_automation import StrategicAutomation
from .github_api import GitHubAPI
from .database import DatabaseManager
from .ban_manager import BanManager


class AutomationScheduler:
    """Enterprise-grade scheduler for GitHub automation"""
    
    def __init__(self, github_api: GitHubAPI, database: DatabaseManager, 
                 ban_manager: BanManager):
        self.github_api = github_api
        self.database = database
        self.ban_manager = ban_manager
        self.logger = Logger()
        
        # Initialize strategic automation
        self.strategic_automation = StrategicAutomation(
            github_api, database, ban_manager
        )
        
        # Scheduler state
        self.is_running = False
        self.scheduler_thread = None
        self.stop_event = threading.Event()
        
        # Enhanced schedule configuration for 100% reliability
        self.schedules = {
            'comprehensive_followback_check': {
                'interval': 'every(2).hours',
                'function': self._comprehensive_followback_check_job,
                'enabled': True,
                'last_run': None,
                'priority': 'high',
                'max_duration': 600  # 10 minutes max
            },
            'strategic_automation_cycle': {
                'interval': 'every(3).hours',
                'function': self._strategic_automation_cycle_job,
                'enabled': True,
                'last_run': None,
                'priority': 'critical',
                'max_duration': 1800  # 30 minutes max
            },
            'moon_tracking_cleanup': {
                'interval': 'every(4).hours',
                'function': self._moon_tracking_cleanup_job,
                'enabled': True,
                'last_run': None,
                'priority': 'medium',
                'max_duration': 300  # 5 minutes max
            },
            'damaged_list_maintenance': {
                'interval': 'every(12).hours',
                'function': self._damaged_list_maintenance_job,
                'enabled': True,
                'last_run': None,
                'priority': 'medium',
                'max_duration': 600  # 10 minutes max
            },
            'comprehensive_statistics': {
                'interval': 'every().day.at("09:00")',
                'function': self._daily_statistics_job,
                'enabled': True,
                'last_run': None,
                'priority': 'low',
                'max_duration': 300  # 5 minutes max
            },
            'weekly_performance_analysis': {
                'interval': 'every().sunday.at("10:00")',
                'function': self._weekly_analysis_job,
                'enabled': True,
                'last_run': None,
                'priority': 'low',
                'max_duration': 900  # 15 minutes max
            },
            'health_check_monitor': {
                'interval': 'every(30).minutes',
                'function': self._health_check_monitor_job,
                'enabled': True,
                'last_run': None,
                'priority': 'high',
                'max_duration': 60  # 1 minute max
            },
            'quarterly_data_purge': {
                'interval': 'every(90).days',  # Every 3 months
                'function': self._quarterly_data_purge_job,
                'enabled': True,
                'last_run': None,
                'priority': 'low',
                'max_duration': 1800  # 30 minutes max
            },
            'performance_based_limit_adjustment': {
                'interval': 'every().sunday.at("11:00")',  # Weekly performance adjustment
                'function': self._performance_limit_adjustment_job,
                'enabled': True,
                'last_run': None,
                'priority': 'medium',
                'max_duration': 300  # 5 minutes max
            }
        }
        
        self.load_schedule_config()
        self.setup_signal_handlers()
    
    def load_schedule_config(self):
        """Load schedule configuration from file"""
        try:
            config_file = Path("data/scheduler_config.json")
            if config_file.exists():
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    
                # Update schedules with saved config
                for schedule_name, schedule_config in config.items():
                    if schedule_name in self.schedules:
                        self.schedules[schedule_name].update(schedule_config)
                
                self.logger.info("Loaded scheduler configuration")
        except Exception as e:
            self.logger.warning(f"Could not load scheduler config: {e}")
    
    def save_schedule_config(self):
        """Save current schedule configuration"""
        try:
            config_file = Path("data/scheduler_config.json")
            config_file.parent.mkdir(exist_ok=True)
            
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(self.schedules, f, indent=2, default=str)
            
            self.logger.info("Saved scheduler configuration")
        except Exception as e:
            self.logger.error(f"Failed to save scheduler config: {e}")
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            self.logger.info("Received shutdown signal, stopping scheduler...")
            self.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def start(self, daemon: bool = False):
        """Start the automation scheduler"""
        if self.is_running:
            self.logger.warning("Scheduler is already running")
            return
        
        self.logger.info("🚀 Starting GitHub Automation Scheduler...")
        
        # Clear any existing scheduled jobs
        schedule.clear()
        
        # Setup scheduled jobs
        self._setup_scheduled_jobs()
        
        self.is_running = True
        
        if daemon:
            # Run in daemon mode (background thread)
            self.scheduler_thread = threading.Thread(target=self._run_scheduler_loop, daemon=True)
            self.scheduler_thread.start()
            self.logger.info("Scheduler started in daemon mode")
        else:
            # Run in foreground
            self._run_scheduler_loop()
    
    def stop(self):
        """Stop the automation scheduler"""
        if not self.is_running:
            return
        
        self.logger.info("🛑 Stopping scheduler...")
        self.is_running = False
        self.stop_event.set()
        
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            self.scheduler_thread.join(timeout=5)
        
        schedule.clear()
        self.save_schedule_config()
        self.logger.info("Scheduler stopped")
    
    def _setup_scheduled_jobs(self):
        """Setup all scheduled jobs"""
        for job_name, job_config in self.schedules.items():
            if not job_config['enabled']:
                continue
            
            try:
                # Parse interval string and schedule job
                interval_str = job_config['interval']
                
                # Enhanced scheduler parsing with support for days, minutes, and complex intervals
                if 'hours' in interval_str:
                    hours = int(interval_str.split('(')[1].split(')')[0])
                    schedule.every(hours).hours.do(self._run_job_wrapper, job_name, job_config['function'])
                
                elif 'minutes' in interval_str:
                    minutes = int(interval_str.split('(')[1].split(')')[0])
                    schedule.every(minutes).minutes.do(self._run_job_wrapper, job_name, job_config['function'])
                
                elif 'days' in interval_str:
                    days = int(interval_str.split('(')[1].split(')')[0])
                    schedule.every(days).days.do(self._run_job_wrapper, job_name, job_config['function'])
                
                elif 'day' in interval_str and 'at' in interval_str:
                    time_str = interval_str.split('"')[1]
                    schedule.every().day.at(time_str).do(self._run_job_wrapper, job_name, job_config['function'])
                
                elif 'sunday' in interval_str and 'at' in interval_str:
                    time_str = interval_str.split('"')[1]
                    schedule.every().sunday.at(time_str).do(self._run_job_wrapper, job_name, job_config['function'])
                
                self.logger.info(f"Scheduled job: {job_name} - {interval_str}")
                
            except Exception as e:
                self.logger.error(f"Failed to schedule job {job_name}: {e}")
    
    def _run_scheduler_loop(self):
        """Main scheduler loop"""
        self.logger.info("Scheduler loop started")
        
        while self.is_running and not self.stop_event.is_set():
            try:
                schedule.run_pending()
                
                # Check every 30 seconds
                if self.stop_event.wait(30):
                    break
                
            except Exception as e:
                self.logger.error(f"Scheduler loop error: {e}")
                time.sleep(60)  # Wait a minute before retrying
        
        self.logger.info("Scheduler loop ended")
    
    def _run_job_wrapper(self, job_name: str, job_function: Callable):
        """Wrapper for running scheduled jobs with error handling"""
        try:
            self.logger.info(f"🔧 Starting scheduled job: {job_name}")
            start_time = datetime.now()
            
            # Run the job
            result = job_function()
            
            # Update last run time
            self.schedules[job_name]['last_run'] = start_time.isoformat()
            
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.info(f"✅ Completed job {job_name} in {execution_time:.2f}s")
            
            # Log the job execution
            self.database.log_action(f"scheduled_job_{job_name}", "system", True, 
                                   f"Execution time: {execution_time:.2f}s")
            
            return result
            
        except Exception as e:
            self.logger.error(f"❌ Job {job_name} failed: {e}")
            self.database.log_action(f"scheduled_job_{job_name}", "system", False, str(e))
    
    # Scheduled job implementations
    def _check_followbacks_job(self) -> Dict:
        """Scheduled job to check for followbacks"""
        self.logger.info("🔄 Checking for followbacks...")
        
        results = {'followback_confirmed': 0, 'errors': 0}
        
        try:
            current_followers = set(self.github_api.get_followers())
            
            # Get pending follow requests
            cursor = self.database.connection.cursor()
            
            if self.database.use_postgresql:
                cursor.execute("SELECT username FROM follow_requests WHERE status = 'pending'")
            else:
                cursor.execute("SELECT username FROM follow_requests WHERE status = 'pending'")
            
            pending_users = [row[0] for row in cursor.fetchall()]
            
            for username in pending_users:
                try:
                    if username in current_followers:
                        if self.database.update_followback_status(username, True):
                            results['followback_confirmed'] += 1
                            self.logger.info(f"✅ {username} followed back!")
                except Exception as e:
                    self.logger.error(f"Error checking {username}: {e}")
                    results['errors'] += 1
            
            self.logger.info(f"Followback check complete: {results}")
            return results
            
        except Exception as e:
            self.logger.error(f"Followback check job failed: {e}")
            results['errors'] += 1
            return results
    
    def _strategic_follow_job(self) -> Dict:
        """Scheduled job for strategic following"""
        self.logger.info("🎯 Running strategic follow job...")
        
        try:
            return self.strategic_automation.execute_strategic_follow_cycle()
        except Exception as e:
            self.logger.error(f"Strategic follow job failed: {e}")
            return {'errors': 1}
    
    def _cleanup_expired_job(self) -> Dict:
        """Scheduled job to cleanup expired follow requests"""
        self.logger.info("🧹 Running cleanup job...")
        
        results = {'unfollowed': 0, 'blacklisted': 0, 'errors': 0}
        
        try:
            expired_requests = self.database.get_expired_follow_requests()
            
            for request in expired_requests:
                try:
                    username = request['username']
                    moon_symbols = request['moon_symbols']
                    retry_count = request['retry_count']
                    
                    # Unfollow user
                    if self.github_api.unfollow_user(username):
                        self.database.mark_unfollowed(username, add_moon=True)
                        results['unfollowed'] += 1
                        
                        # Check if should be blacklisted
                        if moon_symbols + 1 >= self.strategic_automation.settings['max_moon_symbols']:
                            self.database.add_to_damaged_list(
                                username, retry_count, moon_symbols + 1,
                                "Automated cleanup - multiple failed attempts"
                            )
                            results['blacklisted'] += 1
                        
                        # Rate limiting
                        time.sleep(1)
                    
                except Exception as e:
                    self.logger.error(f"Error processing {username}: {e}")
                    results['errors'] += 1
            
            self.logger.info(f"Cleanup job complete: {results}")
            return results
            
        except Exception as e:
            self.logger.error(f"Cleanup job failed: {e}")
            results['errors'] += 1
            return results
    
    def _daily_statistics_job(self) -> Dict:
        """Daily statistics and reporting job"""
        self.logger.info("📊 Running daily statistics job...")
        
        try:
            stats = self.strategic_automation.get_comprehensive_stats()
            
            # Log daily summary
            self.logger.info("📈 Daily Statistics Summary:")
            self.logger.info(f"  Current Followers: {stats.get('current_followers', 0)}")
            self.logger.info(f"  Pending Requests: {stats.get('follow_requests', {}).get('pending', 0)}")
            self.logger.info(f"  Success Rate: {stats.get('success_rate', 0)}%")
            self.logger.info(f"  Damaged Users: {stats.get('damaged_users', 0)}")
            
            # Save daily report
            report_file = Path("data/daily_reports") / f"report_{datetime.now().strftime('%Y%m%d')}.json"
            report_file.parent.mkdir(exist_ok=True)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'date': datetime.now().isoformat(),
                    'statistics': stats
                }, f, indent=2)
            
            return {'report_generated': True}
            
        except Exception as e:
            self.logger.error(f"Daily statistics job failed: {e}")
            return {'errors': 1}
    
    def _weekly_analysis_job(self) -> Dict:
        """Weekly analysis and optimization job"""
        self.logger.info("🔍 Running weekly analysis job...")
        
        try:
            # Perform weekly analysis
            stats = self.strategic_automation.get_comprehensive_stats()
            
            # Calculate weekly growth and check for quarterly maintenance
            week_ago = datetime.now() - timedelta(days=7)
            three_months_ago = datetime.now() - timedelta(days=90)
            
            # Log weekly summary
            self.logger.info("📊 Weekly Analysis Summary:")
            self.logger.info(f"  Total Actions This Week: {sum(stats.get('recent_actions', {}).values())}")
            self.logger.info(f"  Follow Success Rate: {stats.get('success_rate', 0)}%")
            
            # Optimization suggestions
            suggestions = []
            
            success_rate = stats.get('success_rate', 0)
            if success_rate < 20:
                suggestions.append("Consider improving target user selection criteria")
            elif success_rate > 40:
                suggestions.append("Great success rate! Consider increasing daily follow limits")
            
            if stats.get('damaged_users', 0) > 100:
                suggestions.append("High number of damaged users - review targeting strategy")
            
            # Check if quarterly purge is needed
            try:
                cursor = self.database.connection.cursor()
                cursor.execute("SELECT COUNT(*) FROM follow_requests")
                total_requests = cursor.fetchone()[0] if cursor.fetchone() else 0
                
                if total_requests > 10000:
                    suggestions.append("Database cleanup recommended - Consider running quarterly data purge")
                
            except Exception:
                pass  # Non-critical check
            
            for suggestion in suggestions:
                self.logger.info(f"💡 Suggestion: {suggestion}")
            
            # Save weekly report
            report_file = Path("data/weekly_reports") / f"weekly_{datetime.now().strftime('%Y_W%U')}.json"
            report_file.parent.mkdir(exist_ok=True)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'week': datetime.now().strftime('%Y-W%U'),
                    'statistics': stats,
                    'suggestions': suggestions
                }, f, indent=2)
            
            return {'analysis_complete': True, 'suggestions_count': len(suggestions)}
            
        except Exception as e:
            self.logger.error(f"Weekly analysis job failed: {e}")
            return {'errors': 1}
    
    def _comprehensive_followback_check_job(self) -> Dict:
        """Comprehensive followback verification with enhanced tracking"""
        job_start_time = datetime.now()
        
        try:
            self.logger.info("🔍 Starting COMPREHENSIVE followback check job...")
            
            # Get all pending follow requests
            cursor = self.database.connection.cursor()
            
            if self.database.use_postgresql:
                cursor.execute("""
                    SELECT username, follow_date, stars_count, is_high_value, retry_count 
                    FROM follow_requests 
                    WHERE status = 'pending'
                """)
            else:
                cursor.execute("""
                    SELECT username, follow_date, stars_count, is_high_value, retry_count 
                    FROM follow_requests 
                    WHERE status = 'pending'
                """)
            
            pending_requests = cursor.fetchall()
            
            if not pending_requests:
                self.logger.info("ℹ️ No pending follow requests to check")
                return {'followbacks_checked': 0, 'new_followbacks': 0, 'pending_count': 0}
            
            # Get current followers
            current_followers = set(self.github_api.get_followers())
            
            new_followbacks = 0
            
            for request in pending_requests:
                username = request[0]
                
                if username in current_followers:
                    # User has followed back!
                    if self.database.update_followback_status(username, True):
                        new_followbacks += 1
                        self.logger.info(f"✅ {username} has FOLLOWED BACK!")
            
            job_duration = (datetime.now() - job_start_time).total_seconds()
            
            results = {
                'followbacks_checked': len(pending_requests),
                'new_followbacks': new_followbacks,
                'pending_count': len(pending_requests) - new_followbacks,
                'job_duration': job_duration,
                'job_type': 'comprehensive_followback_check'
            }
            
            self.logger.info(f"✅ Comprehensive followback check completed in {job_duration:.1f}s")
            self.logger.info(f"Results: {new_followbacks} new followbacks from {len(pending_requests)} pending")
            
            # Log job success
            self.database.log_action(
                "scheduler_job_success", "followback_check", True,
                f"Checked: {len(pending_requests)}, New: {new_followbacks}, Duration: {job_duration:.1f}s"
            )
            
            return results
            
        except Exception as e:
            job_duration = (datetime.now() - job_start_time).total_seconds()
            self.logger.error(f"❌ Comprehensive followback check job FAILED after {job_duration:.1f}s: {e}")
            
            self.database.log_action(
                "scheduler_job_failure", "followback_check", False,
                f"FAILED after {job_duration:.1f}s: {str(e)[:100]}"
            )
            
            return {'errors': 1, 'job_duration': job_duration, 'error_message': str(e)}
    
    def _strategic_automation_cycle_job(self) -> Dict:
        """Execute comprehensive strategic automation cycle with 100% reliability"""
        job_start_time = datetime.now()
        
        try:
            self.logger.info("🚀 Starting COMPREHENSIVE strategic automation cycle job...")
            
            # Execute the enhanced strategic follow cycle
            results = self.strategic_automation.execute_strategic_follow_cycle()
            
            # Add job metadata
            results['job_type'] = 'strategic_automation_cycle'
            results['job_start_time'] = job_start_time.isoformat()
            results['job_duration'] = (datetime.now() - job_start_time).total_seconds()
            
            # Log comprehensive results
            self.logger.info(f"✅ Strategic automation cycle job completed successfully")
            self.logger.info(f"Job Duration: {results['job_duration']:.1f}s")
            self.logger.info(f"Reliability Score: {results.get('reliability_score', 0):.1f}%")
            
            # Store job results for monitoring
            self.database.log_action(
                "scheduler_job_success", "strategic_automation_cycle", True,
                f"Duration: {results['job_duration']:.1f}s, Reliability: {results.get('reliability_score', 0):.1f}%"
            )
            
            return results
            
        except Exception as e:
            job_duration = (datetime.now() - job_start_time).total_seconds()
            self.logger.error(f"❌ Strategic automation cycle job FAILED after {job_duration:.1f}s: {e}")
            
            # Log job failure
            self.database.log_action(
                "scheduler_job_failure", "strategic_automation_cycle", False,
                f"FAILED after {job_duration:.1f}s: {str(e)[:100]}"
            )
            
            # Attempt recovery
            self._attempt_job_recovery("strategic_automation_cycle", e)
            
            return {'errors': 1, 'job_duration': job_duration, 'error_message': str(e)}
    
    def _moon_tracking_cleanup_job(self) -> Dict:
        """Enhanced moon tracking and cleanup job"""
        job_start_time = datetime.now()
        
        try:
            self.logger.info("🌙 Starting moon tracking cleanup job...")
            
            # Get all users with moon symbols to review
            cursor = self.database.connection.cursor()
            
            if self.database.use_postgresql:
                cursor.execute("""
                    SELECT username, moon_symbols, retry_count, unfollow_date 
                    FROM follow_requests 
                    WHERE moon_symbols > 0 AND status = 'unfollowed'
                    ORDER BY moon_symbols DESC, unfollow_date ASC
                """)
            else:
                cursor.execute("""
                    SELECT username, moon_symbols, retry_count, unfollow_date 
                    FROM follow_requests 
                    WHERE moon_symbols > 0 AND status = 'unfollowed'
                    ORDER BY moon_symbols DESC, unfollow_date ASC
                """)
            
            moon_users = cursor.fetchall()
            cleanup_count = 0
            
            for user_record in moon_users:
                username = user_record[0]
                moon_count = user_record[1]
                retry_count = user_record[2]
                
                # If user has reached moon limit and should be cleaned up
                if moon_count >= self.strategic_automation.settings['max_moon_symbols']:
                    # Ensure they're in the comprehensive blacklist
                    if not self.database.is_damaged_user(username):
                        self.database.add_to_damaged_list(
                            username, retry_count, moon_count,
                            f"Moon cleanup - {moon_count} moon symbols"
                        )
                        cleanup_count += 1
                        self.logger.info(f"🌙 Added {username} to blacklist ({moon_count} moons)")
            
            job_duration = (datetime.now() - job_start_time).total_seconds()
            
            results = {
                'moon_users_reviewed': len(moon_users),
                'users_cleaned_up': cleanup_count,
                'job_duration': job_duration,
                'job_type': 'moon_tracking_cleanup'
            }
            
            self.logger.info(f"✅ Moon tracking cleanup completed in {job_duration:.1f}s")
            self.logger.info(f"Reviewed: {len(moon_users)}, Cleaned up: {cleanup_count}")
            
            return results
            
        except Exception as e:
            job_duration = (datetime.now() - job_start_time).total_seconds()
            self.logger.error(f"❌ Moon tracking cleanup job FAILED after {job_duration:.1f}s: {e}")
            return {'errors': 1, 'job_duration': job_duration, 'error_message': str(e)}
    
    def _damaged_list_maintenance_job(self) -> Dict:
        """Maintain and optimize the damaged user blacklist"""
        job_start_time = datetime.now()
        
        try:
            self.logger.info("🚫 Starting damaged list maintenance job...")
            
            # Get damaged users stats
            cursor = self.database.connection.cursor()
            
            if self.database.use_postgresql:
                cursor.execute("SELECT COUNT(*) FROM damaged_users")
            else:
                cursor.execute("SELECT COUNT(*) FROM damaged_users")
            
            total_damaged = cursor.fetchone()[0] if cursor.fetchone() else 0
            
            # Ensure damaged.txt is up to date
            damaged_file = Path("data/damaged.txt")
            if damaged_file.exists():
                with open(damaged_file, 'r', encoding='utf-8') as f:
                    file_count = len([line for line in f if line.strip()])
            else:
                file_count = 0
            
            job_duration = (datetime.now() - job_start_time).total_seconds()
            
            results = {
                'total_damaged_users': total_damaged,
                'damaged_file_entries': file_count,
                'maintenance_complete': True,
                'job_duration': job_duration
            }
            
            self.logger.info(f"✅ Damaged list maintenance completed in {job_duration:.1f}s")
            self.logger.info(f"Total damaged users: {total_damaged}, File entries: {file_count}")
            
            return results
            
        except Exception as e:
            job_duration = (datetime.now() - job_start_time).total_seconds()
            self.logger.error(f"❌ Damaged list maintenance job FAILED after {job_duration:.1f}s: {e}")
            return {'errors': 1, 'job_duration': job_duration, 'error_message': str(e)}
    
    def _health_check_monitor_job(self) -> Dict:
        """Monitor automation health and performance"""
        job_start_time = datetime.now()
        
        try:
            self.logger.info("❤️ Starting health check monitor job...")
            
            # Check GitHub API connectivity
            api_healthy = self.github_api.validate_token()
            
            # Check database connectivity
            try:
                cursor = self.database.connection.cursor()
                cursor.execute("SELECT 1")
                db_healthy = True
            except:
                db_healthy = False
            
            # Get automation status
            automation_status = self.strategic_automation.get_automation_status()
            
            # Check for recent errors
            cursor = self.database.connection.cursor()
            recent_time = datetime.now() - timedelta(hours=1)
            
            if self.database.use_postgresql:
                cursor.execute("""
                    SELECT COUNT(*) FROM automation_logs 
                    WHERE success = FALSE AND timestamp >= %s
                """, (recent_time,))
            else:
                cursor.execute("""
                    SELECT COUNT(*) FROM automation_logs 
                    WHERE success = 0 AND timestamp >= ?
                """, (recent_time,))
            
            recent_errors = cursor.fetchone()[0] if cursor.fetchone() else 0
            
            job_duration = (datetime.now() - job_start_time).total_seconds()
            
            health_status = 'healthy' if api_healthy and db_healthy and recent_errors < 5 else 'degraded'
            
            results = {
                'health_status': health_status,
                'api_healthy': api_healthy,
                'database_healthy': db_healthy,
                'recent_errors_count': recent_errors,
                'automation_active': automation_status.get('active', False),
                'job_duration': job_duration
            }
            
            if health_status == 'healthy':
                self.logger.info(f"✅ System health check PASSED in {job_duration:.1f}s")
            else:
                self.logger.warning(f"⚠️ System health check DEGRADED in {job_duration:.1f}s")
                self.logger.warning(f"API: {api_healthy}, DB: {db_healthy}, Errors: {recent_errors}")
            
            return results
            
        except Exception as e:
            job_duration = (datetime.now() - job_start_time).total_seconds()
            self.logger.error(f"❌ Health check monitor job FAILED after {job_duration:.1f}s: {e}")
            return {'errors': 1, 'job_duration': job_duration, 'error_message': str(e)}
    
    def _attempt_job_recovery(self, job_name: str, error: Exception):
        """Attempt to recover from job failures"""
        try:
            self.logger.warning(f"🔧 Attempting recovery for job: {job_name}")
            
            # Log recovery attempt
            self.database.log_action(
                "job_recovery_attempt", job_name, True,
                f"Recovery attempted for: {str(error)[:100]}"
            )
            
            # Basic recovery strategies
            if "rate limit" in str(error).lower():
                self.logger.info("🔄 Implementing rate limit recovery")
                time.sleep(300)  # Wait 5 minutes
            
            if "connection" in str(error).lower():
                self.logger.info("🔄 Testing API connection")
                if self.github_api.validate_token():
                    self.logger.info("✅ API connection restored")
            
        except Exception as recovery_error:
            self.logger.error(f"Job recovery failed: {recovery_error}")
    
    def _quarterly_data_purge_job(self) -> Dict:
        """Quarterly data purge job - runs every 3 months"""
        job_start_time = datetime.now()
        
        try:
            self.logger.info("🗑️ Starting quarterly data purge job...")
            
            # Execute the comprehensive data purge
            purge_results = self.strategic_automation.execute_quarterly_data_purge()
            
            # Add job metadata
            purge_results['job_type'] = 'quarterly_data_purge'
            purge_results['job_start_time'] = job_start_time.isoformat()
            purge_results['job_duration'] = (datetime.now() - job_start_time).total_seconds()
            
            # Log comprehensive results
            success = purge_results.get('errors', 1) == 0
            
            if success:
                self.logger.info(f"✅ Quarterly data purge job completed successfully")
                self.logger.info(f"Job Duration: {purge_results['job_duration']:.1f}s")
                self.logger.info(f"Data purged: {purge_results.get('follow_requests_purged', 0)} requests, {purge_results.get('automation_logs_purged', 0)} logs")
            else:
                self.logger.warning(f"⚠️ Quarterly data purge completed with {purge_results.get('errors', 0)} errors")
            
            # Store job results for monitoring
            self.database.log_action(
                "scheduler_job_success" if success else "scheduler_job_warning", 
                "quarterly_data_purge", success,
                f"Duration: {purge_results['job_duration']:.1f}s, Errors: {purge_results.get('errors', 0)}"
            )
            
            return purge_results
            
        except Exception as e:
            job_duration = (datetime.now() - job_start_time).total_seconds()
            self.logger.error(f"❌ Quarterly data purge job FAILED after {job_duration:.1f}s: {e}")
            
            # Log job failure
            self.database.log_action(
                "scheduler_job_failure", "quarterly_data_purge", False,
                f"FAILED after {job_duration:.1f}s: {str(e)[:100]}"
            )
            
            return {'errors': 1, 'job_duration': job_duration, 'error_message': str(e)}
    
    def _performance_limit_adjustment_job(self) -> Dict:
        """Performance-based limit adjustment job - runs weekly"""
        job_start_time = datetime.now()
        
        try:
            self.logger.info("📊 Starting performance-based limit adjustment job...")
            
            # Get current performance metrics and adjust limits accordingly
            adjustment_results = self.strategic_automation.adjust_follow_limits_by_performance()
            
            # Add job metadata
            adjustment_results['job_type'] = 'performance_limit_adjustment'
            adjustment_results['job_start_time'] = job_start_time.isoformat()
            adjustment_results['job_duration'] = (datetime.now() - job_start_time).total_seconds()
            
            # Log results
            self.logger.info(f"✅ Performance limit adjustment completed in {adjustment_results['job_duration']:.1f}s")
            self.logger.info(f"Action: {adjustment_results.get('action', 'unknown')}")
            self.logger.info(f"Reason: {adjustment_results.get('reason', 'No reason provided')}")
            
            # Store job results for monitoring
            self.database.log_action(
                "scheduler_job_success", "performance_limit_adjustment", True,
                f"Action: {adjustment_results.get('action')}, Rate: {adjustment_results.get('follow_back_rate', 0):.1f}%"
            )
            
            return adjustment_results
            
        except Exception as e:
            job_duration = (datetime.now() - job_start_time).total_seconds()
            self.logger.error(f"❌ Performance limit adjustment job FAILED after {job_duration:.1f}s: {e}")
            
            # Log job failure
            self.database.log_action(
                "scheduler_job_failure", "performance_limit_adjustment", False,
                f"FAILED after {job_duration:.1f}s: {str(e)[:100]}"
            )
            
            return {'errors': 1, 'job_duration': job_duration, 'error_message': str(e)}
    
    def trigger_manual_data_purge(self) -> Dict:
        """Manually trigger quarterly data purge"""
        try:
            self.logger.info("🔧 Manual data purge triggered")
            return self._quarterly_data_purge_job()
        except Exception as e:
            self.logger.error(f"Manual data purge failed: {e}")
            return {'error': str(e)}
    
    def adjust_follow_limits_manual(self, action: str, amount: int = 25) -> Dict:
        """Manually adjust follow limits"""
        try:
            if action.lower() == 'increase':
                return self.strategic_automation.increase_follow_limits(amount, amount)
            elif action.lower() == 'decrease':
                return self.strategic_automation.decrease_follow_limits(amount, amount)
            else:
                raise ValueError("Action must be 'increase' or 'decrease'")
        except Exception as e:
            self.logger.error(f"Manual limit adjustment failed: {e}")
            return {'error': str(e)}
    
    def get_system_optimization_status(self) -> Dict:
        """Get comprehensive system optimization and performance status"""
        try:
            # Get follow limits status
            limits_status = self.strategic_automation.get_follow_limits_status()
            
            # Get database size estimate
            cursor = self.database.connection.cursor()
            
            # Count records in key tables
            tables_info = {}
            key_tables = ['follow_requests', 'automation_logs', 'damaged_users']
            
            for table in key_tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    count = cursor.fetchone()[0] if cursor.fetchone() else 0
                    tables_info[table] = count
                except:
                    tables_info[table] = 0
            
            # Check if purge is needed
            total_records = sum(tables_info.values())
            purge_recommended = total_records > 50000  # Recommend purge if > 50k total records
            
            # Get last purge date
            try:
                cursor.execute("""
                    SELECT timestamp FROM automation_logs 
                    WHERE action = 'quarterly_data_purge' 
                    ORDER BY timestamp DESC LIMIT 1
                """)
                last_purge_result = cursor.fetchone()
                last_purge_date = last_purge_result[0] if last_purge_result else None
            except:
                last_purge_date = None
            
            return {
                'follow_limits_status': limits_status,
                'database_info': tables_info,
                'total_database_records': total_records,
                'purge_recommended': purge_recommended,
                'last_purge_date': last_purge_date.isoformat() if last_purge_date else 'Never',
                'optimization_score': self._calculate_optimization_score(total_records, limits_status),
                'recommendations': self._get_optimization_recommendations(total_records, limits_status, last_purge_date)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get optimization status: {e}")
            return {'error': str(e)}
    
    def _calculate_optimization_score(self, total_records: int, limits_status: Dict) -> int:
        """Calculate system optimization score (0-100)"""
        score = 100
        
        # Penalize for too many database records
        if total_records > 100000:
            score -= 30
        elif total_records > 50000:
            score -= 15
        
        # Adjust for performance status
        performance_status = limits_status.get('performance_status', 'AVERAGE')
        if performance_status == 'NEEDS_IMPROVEMENT':
            score -= 20
        elif performance_status == 'AVERAGE':
            score -= 5
        elif performance_status == 'EXCELLENT':
            score += 0  # No change
        
        return max(0, min(100, score))
    
    def _get_optimization_recommendations(self, total_records: int, limits_status: Dict, last_purge_date) -> List[str]:
        """Get optimization recommendations"""
        recommendations = []
        
        if total_records > 50000:
            recommendations.append("Database cleanup recommended - Run quarterly data purge")
        
        if not last_purge_date or (datetime.now() - last_purge_date).days > 90:
            recommendations.append("Quarterly data purge is overdue - Schedule maintenance")
        
        performance_status = limits_status.get('performance_status', 'AVERAGE')
        if performance_status == 'NEEDS_IMPROVEMENT':
            recommendations.append("Performance improvement needed - Consider decreasing follow limits for quality focus")
        elif performance_status == 'EXCELLENT':
            recommendations.append("Excellent performance - Consider increasing follow limits for aggressive growth")
        
        if not recommendations:
            recommendations.append("System is well optimized - Continue current settings")
        
        return recommendations
    
    def get_scheduler_status(self) -> Dict:
        """Get current scheduler status"""
        # Create JSON-safe version of schedules
        safe_schedules = {}
        for job_name, config in self.schedules.items():
            safe_config = config.copy()
            # Remove function reference for JSON serialization
            if 'function' in safe_config:
                safe_config['function_name'] = safe_config['function'].__name__
                del safe_config['function']
            # Convert last_run to string if it's a datetime
            if safe_config.get('last_run'):
                safe_config['last_run'] = str(safe_config['last_run'])
            safe_schedules[job_name] = safe_config
            
        return {
            'is_running': self.is_running,
            'schedules': safe_schedules,
            'next_runs': {
                job_name: str(schedule.next_run()) if schedule.next_run() else None
                for job_name in self.schedules.keys()
            }
        }
    
    def enable_job(self, job_name: str) -> bool:
        """Enable a scheduled job"""
        if job_name in self.schedules:
            self.schedules[job_name]['enabled'] = True
            self.save_schedule_config()
            self.logger.info(f"Enabled job: {job_name}")
            return True
        return False
    
    def disable_job(self, job_name: str) -> bool:
        """Disable a scheduled job"""
        if job_name in self.schedules:
            self.schedules[job_name]['enabled'] = False
            self.save_schedule_config()
            self.logger.info(f"Disabled job: {job_name}")
            return True
        return False