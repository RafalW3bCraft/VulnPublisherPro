#!/usr/bin/env python3
"""
Rate Limiter for GitHub API compliance
Ensures strategic automation respects GitHub API rate limits
"""

import time
from datetime import datetime, timedelta
from typing import Dict, Optional
import json
from pathlib import Path

from .logger import Logger


class RateLimiter:
    """GitHub API rate limiter with intelligent backoff"""
    
    def __init__(self):
        self.logger = Logger()
        
        # GitHub API rate limits
        self.limits = {
            'core': {
                'limit': 5000,
                'remaining': 5000,
                'reset': time.time() + 3600,
                'used': 0
            },
            'search': {
                'limit': 30,
                'remaining': 30,
                'reset': time.time() + 60,
                'used': 0
            },
            'graphql': {
                'limit': 5000,
                'remaining': 5000,
                'reset': time.time() + 3600,
                'used': 0
            }
        }
        
        # Rate limiting state
        self.request_history = []
        self.backoff_until = None
        
        # Load persisted state
        self.load_state()
    
    def load_state(self):
        """Load rate limiter state from file"""
        try:
            state_file = Path("data/rate_limiter_state.json")
            if state_file.exists():
                with open(state_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                    self.limits.update(state.get('limits', {}))
                    self.backoff_until = state.get('backoff_until')
                    if self.backoff_until:
                        self.backoff_until = float(self.backoff_until)
        except Exception as e:
            self.logger.warning(f"Could not load rate limiter state: {e}")
    
    def save_state(self):
        """Save rate limiter state to file"""
        try:
            state_file = Path("data/rate_limiter_state.json")
            state_file.parent.mkdir(exist_ok=True)
            
            with open(state_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'limits': self.limits,
                    'backoff_until': self.backoff_until
                }, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save rate limiter state: {e}")
    
    def update_limits(self, rate_limit_info: Dict):
        """Update rate limits from GitHub API response"""
        try:
            core_info = rate_limit_info.get('core', {})
            if core_info:
                self.limits['core'].update({
                    'limit': core_info.get('limit', self.limits['core']['limit']),
                    'remaining': core_info.get('remaining', self.limits['core']['remaining']),
                    'reset': core_info.get('reset', self.limits['core']['reset']),
                    'used': core_info.get('used', self.limits['core']['used'])
                })
            
            search_info = rate_limit_info.get('search', {})
            if search_info:
                self.limits['search'].update({
                    'limit': search_info.get('limit', self.limits['search']['limit']),
                    'remaining': search_info.get('remaining', self.limits['search']['remaining']),
                    'reset': search_info.get('reset', self.limits['search']['reset']),
                    'used': search_info.get('used', self.limits['search']['used'])
                })
            
            self.save_state()
            
        except Exception as e:
            self.logger.error(f"Failed to update rate limits: {e}")
    
    def check_rate_limit(self, api_type: str = 'core') -> bool:
        """Check if we can make a request without hitting rate limits"""
        if api_type not in self.limits:
            return True
        
        current_time = time.time()
        limit_info = self.limits[api_type]
        
        # Check if we're in backoff period
        if self.backoff_until and current_time < self.backoff_until:
            return False
        
        # Reset limits if reset time has passed
        if current_time >= limit_info['reset']:
            limit_info['remaining'] = limit_info['limit']
            limit_info['used'] = 0
            limit_info['reset'] = current_time + (3600 if api_type == 'core' else 60)
        
        # Check if we have remaining requests
        return limit_info['remaining'] > 0
    
    def wait_for_rate_limit(self, api_type: str = 'core') -> float:
        """Wait until rate limit allows requests"""
        current_time = time.time()
        
        # Check backoff
        if self.backoff_until and current_time < self.backoff_until:
            wait_time = self.backoff_until - current_time
            self.logger.info(f"Rate limiter: waiting {wait_time:.1f}s for backoff")
            return wait_time
        
        # Check API-specific limits
        if api_type in self.limits:
            limit_info = self.limits[api_type]
            
            if limit_info['remaining'] <= 0:
                wait_time = limit_info['reset'] - current_time
                if wait_time > 0:
                    self.logger.info(f"Rate limiter: waiting {wait_time:.1f}s for {api_type} reset")
                    return wait_time
        
        return 0
    
    def consume_request(self, api_type: str = 'core'):
        """Record a request consumption"""
        if api_type in self.limits:
            self.limits[api_type]['remaining'] = max(0, self.limits[api_type]['remaining'] - 1)
            self.limits[api_type]['used'] += 1
        
        # Track request history for intelligent backoff
        self.request_history.append(time.time())
        
        # Keep only last hour of requests
        cutoff = time.time() - 3600
        self.request_history = [t for t in self.request_history if t > cutoff]
        
        # Implement intelligent backoff if making too many requests
        if len(self.request_history) > 4500:  # Close to limit
            self.backoff_until = time.time() + 300  # 5 minute backoff
            self.logger.warning("Rate limiter: implementing intelligent backoff")
        
        self.save_state()
    
    def get_status(self) -> Dict:
        """Get current rate limiter status"""
        current_time = time.time()
        
        status = {
            'current_time': current_time,
            'backoff_active': self.backoff_until and current_time < self.backoff_until,
            'backoff_remaining': max(0, self.backoff_until - current_time) if self.backoff_until else 0,
            'requests_last_hour': len(self.request_history),
            'limits': {}
        }
        
        for api_type, limit_info in self.limits.items():
            # Update remaining if reset time passed
            if current_time >= limit_info['reset']:
                remaining = limit_info['limit']
                reset_in = (3600 if api_type == 'core' else 60)
            else:
                remaining = limit_info['remaining']
                reset_in = limit_info['reset'] - current_time
            
            status['limits'][api_type] = {
                'limit': limit_info['limit'],
                'remaining': remaining,
                'used': limit_info['used'],
                'reset_in_seconds': max(0, reset_in),
                'percentage_used': (limit_info['used'] / limit_info['limit']) * 100 if limit_info['limit'] > 0 else 0
            }
        
        return status
    
    def should_slow_down(self) -> bool:
        """Check if we should slow down requests"""
        current_time = time.time()
        
        # Check if in backoff
        if self.backoff_until and current_time < self.backoff_until:
            return True
        
        # Check core API usage
        core_usage = (self.limits['core']['used'] / self.limits['core']['limit']) * 100
        
        if core_usage > 80:  # Above 80% usage
            return True
        
        # Check request frequency
        recent_requests = [t for t in self.request_history if t > current_time - 300]  # Last 5 minutes
        
        if len(recent_requests) > 200:  # More than 200 requests in 5 minutes
            return True
        
        return False
    
    def get_recommended_delay(self) -> float:
        """Get recommended delay between requests"""
        if self.should_slow_down():
            return 2.0  # 2 seconds between requests when slowing down
        
        core_usage = (self.limits['core']['used'] / self.limits['core']['limit']) * 100
        
        if core_usage > 60:
            return 1.0  # 1 second delay above 60% usage
        elif core_usage > 40:
            return 0.5  # 0.5 second delay above 40% usage
        else:
            return 0.1  # Minimal delay under 40% usage
    
    def wait_if_needed(self, api_type: str = 'core'):
        """Wait if rate limit requires it"""
        current_time = time.time()
        
        # Check if we're in backoff mode
        if self.backoff_until and current_time < self.backoff_until:
            wait_time = self.backoff_until - current_time
            self.logger.warning(f"Rate limit backoff active, waiting {wait_time:.1f} seconds")
            time.sleep(wait_time)
            self.backoff_until = None
        
        # Check specific API limits
        limit_info = self.limits.get(api_type, self.limits['core'])
        
        if limit_info['remaining'] <= 1:
            reset_time = limit_info['reset']
            wait_time = max(0, reset_time - current_time)
            if wait_time > 0:
                self.logger.warning(f"Rate limit for {api_type} exhausted, waiting {wait_time:.1f} seconds")
                time.sleep(wait_time)
    
    def update_from_headers(self, headers: Dict):
        """Update rate limits from HTTP response headers"""
        try:
            # Core API limits
            if 'x-ratelimit-limit' in headers:
                self.limits['core']['limit'] = int(headers['x-ratelimit-limit'])
            if 'x-ratelimit-remaining' in headers:
                self.limits['core']['remaining'] = int(headers['x-ratelimit-remaining'])
            if 'x-ratelimit-reset' in headers:
                self.limits['core']['reset'] = int(headers['x-ratelimit-reset'])
            
            # Search API limits
            if 'x-ratelimit-limit' in headers and 'search' in headers.get('x-ratelimit-resource', ''):
                self.limits['search']['limit'] = int(headers['x-ratelimit-limit'])
                self.limits['search']['remaining'] = int(headers.get('x-ratelimit-remaining', 0))
                self.limits['search']['reset'] = int(headers.get('x-ratelimit-reset', time.time() + 60))
            
            self.save_state()
            
        except Exception as e:
            self.logger.warning(f"Failed to update rate limits from headers: {e}")