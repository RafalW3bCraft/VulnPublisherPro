"""
Scheduler for automated vulnerability scanning and publishing
"""

import asyncio
import logging
import schedule
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Callable
from threading import Thread, Event
import signal

logger = logging.getLogger(__name__)

class SchedulerManager:
    """Manages scheduled tasks for VulnPublisherPro"""
    
    def __init__(self):
        self.running = False
        self.thread = None
        self.stop_event = Event()
        
        # Task references
        self.scrape_job = None
        self.publish_job = None
        self.cleanup_job = None
        
        # Callbacks
        self.scrape_callback = None
        self.publish_callback = None
        self.cleanup_callback = None
        
        # Statistics
        self.last_scrape = None
        self.last_publish = None
        self.last_cleanup = None
        self.scrape_count = 0
        self.publish_count = 0
        
        logger.info("Scheduler manager initialized")
    
    def schedule_scraping(self, interval_seconds: int = 3600, 
                         callback: Optional[Callable] = None):
        """Schedule automatic vulnerability scraping"""
        
        if callback:
            self.scrape_callback = callback
        
        # Clear existing job
        if self.scrape_job:
            schedule.cancel_job(self.scrape_job)
        
        # Schedule new job
        if interval_seconds >= 60:  # Minimum 1 minute
            hours = interval_seconds / 3600
            if hours >= 1:
                self.scrape_job = schedule.every(int(hours)).hours.do(self._run_scrape_task)
            else:
                minutes = interval_seconds / 60
                self.scrape_job = schedule.every(int(minutes)).minutes.do(self._run_scrape_task)
        else:
            logger.warning("Scraping interval too short, minimum is 60 seconds")
            return False
        
        logger.info(f"Scheduled vulnerability scraping every {interval_seconds} seconds")
        return True
    
    def schedule_publishing(self, interval_seconds: int = 7200,
                           callback: Optional[Callable] = None):
        """Schedule automatic vulnerability publishing"""
        
        if callback:
            self.publish_callback = callback
        
        # Clear existing job
        if self.publish_job:
            schedule.cancel_job(self.publish_job)
        
        # Schedule new job
        if interval_seconds >= 300:  # Minimum 5 minutes
            hours = interval_seconds / 3600
            if hours >= 1:
                self.publish_job = schedule.every(int(hours)).hours.do(self._run_publish_task)
            else:
                minutes = interval_seconds / 60
                self.publish_job = schedule.every(int(minutes)).minutes.do(self._run_publish_task)
        else:
            logger.warning("Publishing interval too short, minimum is 300 seconds")
            return False
        
        logger.info(f"Scheduled vulnerability publishing every {interval_seconds} seconds")
        return True
    
    def schedule_cleanup(self, interval_seconds: int = 86400,
                        callback: Optional[Callable] = None):
        """Schedule automatic database cleanup"""
        
        if callback:
            self.cleanup_callback = callback
        
        # Clear existing job
        if self.cleanup_job:
            schedule.cancel_job(self.cleanup_job)
        
        # Schedule daily cleanup
        self.cleanup_job = schedule.every().day.at("02:00").do(self._run_cleanup_task)
        
        logger.info("Scheduled daily cleanup at 2:00 AM")
        return True
    
    def _run_scrape_task(self):
        """Run vulnerability scraping task"""
        try:
            logger.info("Starting scheduled vulnerability scraping")
            
            if self.scrape_callback:
                # Run async callback in new event loop
                result = asyncio.run(self.scrape_callback())
                
                self.last_scrape = datetime.now()
                self.scrape_count += 1
                
                logger.info(f"Scheduled scraping completed: {result.get('total_scraped', 0)} vulnerabilities")
            else:
                logger.warning("No scrape callback configured")
                
        except Exception as e:
            logger.error(f"Error in scheduled scraping: {e}")
    
    def _run_publish_task(self):
        """Run vulnerability publishing task"""
        try:
            logger.info("Starting scheduled vulnerability publishing")
            
            if self.publish_callback:
                # Run async callback in new event loop
                result = asyncio.run(self.publish_callback())
                
                self.last_publish = datetime.now()
                self.publish_count += 1
                
                logger.info(f"Scheduled publishing completed: {result.get('published', 0)} vulnerabilities")
            else:
                logger.warning("No publish callback configured")
                
        except Exception as e:
            logger.error(f"Error in scheduled publishing: {e}")
    
    def _run_cleanup_task(self):
        """Run database cleanup task"""
        try:
            logger.info("Starting scheduled database cleanup")
            
            if self.cleanup_callback:
                result = self.cleanup_callback()
                
                self.last_cleanup = datetime.now()
                
                logger.info(f"Scheduled cleanup completed: {result}")
            else:
                logger.warning("No cleanup callback configured")
                
        except Exception as e:
            logger.error(f"Error in scheduled cleanup: {e}")
    
    def start(self):
        """Start the scheduler"""
        if self.running:
            logger.warning("Scheduler is already running")
            return False
        
        self.running = True
        self.stop_event.clear()
        
        # Start scheduler thread
        self.thread = Thread(target=self._scheduler_loop, daemon=True)
        self.thread.start()
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info("Scheduler started")
        return True
    
    def stop(self):
        """Stop the scheduler"""
        if not self.running:
            logger.warning("Scheduler is not running")
            return False
        
        logger.info("Stopping scheduler...")
        
        self.running = False
        self.stop_event.set()
        
        # Wait for thread to finish
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        
        # Clear all scheduled jobs
        schedule.clear()
        
        logger.info("Scheduler stopped")
        return True
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        logger.info("Scheduler loop started")
        
        while self.running and not self.stop_event.is_set():
            try:
                schedule.run_pending()
                time.sleep(1)  # Check every second
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                time.sleep(5)  # Wait before retrying
        
        logger.info("Scheduler loop stopped")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"Received signal {signum}, stopping scheduler")
        self.stop()
    
    def get_status(self) -> Dict[str, Any]:
        """Get scheduler status"""
        status = {
            'running': self.running,
            'scrape_count': self.scrape_count,
            'publish_count': self.publish_count,
            'last_scrape': self.last_scrape.isoformat() if self.last_scrape else None,
            'last_publish': self.last_publish.isoformat() if self.last_publish else None,
            'last_cleanup': self.last_cleanup.isoformat() if self.last_cleanup else None,
            'scheduled_jobs': len(schedule.jobs),
            'jobs': []
        }
        
        # Get job details
        for job in schedule.jobs:
            job_info = {
                'job': str(job.job_func),
                'interval': job.interval,
                'unit': job.unit,
                'next_run': job.next_run.isoformat() if job.next_run else None
            }
            status['jobs'].append(job_info)
        
        return status
    
    def get_next_run_times(self) -> Dict[str, Optional[str]]:
        """Get next run times for scheduled tasks"""
        next_runs = {
            'scrape': None,
            'publish': None,
            'cleanup': None
        }
        
        for job in schedule.jobs:
            if job == self.scrape_job:
                next_runs['scrape'] = job.next_run.isoformat() if job.next_run else None
            elif job == self.publish_job:
                next_runs['publish'] = job.next_run.isoformat() if job.next_run else None
            elif job == self.cleanup_job:
                next_runs['cleanup'] = job.next_run.isoformat() if job.next_run else None
        
        return next_runs
    
    def run_scrape_now(self):
        """Run scraping task immediately"""
        logger.info("Running immediate scrape task")
        self._run_scrape_task()
    
    def run_publish_now(self):
        """Run publishing task immediately"""
        logger.info("Running immediate publish task")
        self._run_publish_task()
    
    def run_cleanup_now(self):
        """Run cleanup task immediately"""
        logger.info("Running immediate cleanup task")
        self._run_cleanup_task()
    
    def set_callbacks(self, scrape_callback: Optional[Callable] = None,
                     publish_callback: Optional[Callable] = None,
                     cleanup_callback: Optional[Callable] = None):
        """Set callback functions for scheduled tasks"""
        if scrape_callback:
            self.scrape_callback = scrape_callback
            logger.info("Scrape callback configured")
        
        if publish_callback:
            self.publish_callback = publish_callback
            logger.info("Publish callback configured")
        
        if cleanup_callback:
            self.cleanup_callback = cleanup_callback
            logger.info("Cleanup callback configured")
    
    def reschedule_scraping(self, interval_seconds: int):
        """Reschedule scraping with new interval"""
        was_running = self.running
        
        if was_running:
            self.stop()
        
        self.schedule_scraping(interval_seconds, self.scrape_callback)
        
        if was_running:
            self.start()
        
        logger.info(f"Rescheduled scraping to {interval_seconds} seconds")
    
    def reschedule_publishing(self, interval_seconds: int):
        """Reschedule publishing with new interval"""
        was_running = self.running
        
        if was_running:
            self.stop()
        
        self.schedule_publishing(interval_seconds, self.publish_callback)
        
        if was_running:
            self.start()
        
        logger.info(f"Rescheduled publishing to {interval_seconds} seconds")
    
    def pause(self):
        """Pause scheduler (keep jobs but stop running)"""
        if self.running:
            self.running = False
            self.stop_event.set()
            logger.info("Scheduler paused")
            return True
        return False
    
    def resume(self):
        """Resume paused scheduler"""
        if not self.running:
            self.start()
            logger.info("Scheduler resumed")
            return True
        return False
    
    def clear_all_jobs(self):
        """Clear all scheduled jobs"""
        schedule.clear()
        self.scrape_job = None
        self.publish_job = None
        self.cleanup_job = None
        logger.info("All scheduled jobs cleared")
    
    def get_uptime(self) -> Optional[timedelta]:
        """Get scheduler uptime"""
        if self.thread and self.thread.is_alive():
            # This is a simplified version - in a real implementation,
            # you'd track the actual start time
            return timedelta(seconds=time.time() % 86400)  # Approximate
        return None

class CronScheduler:
    """Alternative cron-style scheduler for more complex scheduling"""
    
    def __init__(self):
        self.jobs = {}
        self.running = False
        self.thread = None
        
    def add_cron_job(self, name: str, cron_expression: str, callback: Callable):
        """Add a cron-style job"""
        # This would require a cron parsing library like python-crontab
        # For now, it's a placeholder for future implementation
        logger.info(f"Cron job '{name}' with expression '{cron_expression}' would be added here")
        
    def remove_job(self, name: str):
        """Remove a cron job"""
        if name in self.jobs:
            del self.jobs[name]
            logger.info(f"Removed cron job: {name}")
    
    def start(self):
        """Start cron scheduler"""
        self.running = True
        logger.info("Cron scheduler started")
    
    def stop(self):
        """Stop cron scheduler"""
        self.running = False
        logger.info("Cron scheduler stopped")
