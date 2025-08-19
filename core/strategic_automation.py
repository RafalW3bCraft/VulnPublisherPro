#!/usr/bin/env python3
"""
Strategic Follower Growth Automation Engine
Advanced automation for strategic follower growth with intelligence and tracking
"""

import time
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Set
import random
from pathlib import Path
import json

from .github_api import GitHubAPI
from .database import DatabaseManager
from .logger import Logger
from .rate_limiter import RateLimiter
from .ban_manager import BanManager


class StrategicAutomation:
    """100% Reliable Strategic Follower Growth Automation Engine
    
    Implements continuous cycling: Follow → Wait → Unfollow if no follow-back → Repeat
    with moon-symbol tracking and intelligent blacklisting.
    """
    
    def __init__(self, github_api: GitHubAPI, database: DatabaseManager, 
                 ban_manager: BanManager):
        self.github_api = github_api
        self.database = database
        self.ban_manager = ban_manager
        self.logger = Logger()
        self.rate_limiter = RateLimiter()
        
        # Enhanced strategic settings for 100% reliability
        self.settings = {
            'daily_follow_limit': 75,  # Increased for better growth
            'daily_unfollow_limit': 100,  # Higher unfollow capacity
            'min_stars_for_high_value': 179,  # Threshold for extended wait
            'standard_wait_days': 15,  # Default follow-back wait period
            'high_value_wait_days': 90,  # Extended wait for valuable users
            'max_moon_symbols': 3,  # Moon limit before blacklisting
            'activity_lookback_days': 30,
            'target_follower_growth': 150,  # Monthly growth target
            'follow_back_check_interval': 4,  # Hours - more frequent checks
            'automation_cycle_interval': 3,  # Hours - consistent cycling
            'retry_failed_actions': True,  # Retry failed API calls
            'max_retries': 3,  # Maximum retry attempts
        }
        
        self.load_settings()
        
        # Continuous automation state
        self.automation_active = False
        self.cycle_count = 0
        self.total_followed = 0
        self.total_unfollowed = 0
        self.current_session_stats = {
            'session_start': datetime.now(),
            'follows_sent': 0,
            'unfollows_executed': 0,
            'followbacks_received': 0,
            'users_blacklisted': 0,
            'moon_symbols_assigned': 0,
            'api_errors': 0
        }
    
    def load_settings(self):
        """Load automation settings from database or config"""
        try:
            # This would normally load from database settings table
            settings_file = Path("data/automation_settings.json")
            if settings_file.exists():
                with open(settings_file, 'r', encoding='utf-8') as f:
                    stored_settings = json.load(f)
                    self.settings.update(stored_settings)
                    self.logger.info("Loaded automation settings from file")
        except Exception as e:
            self.logger.warning(f"Could not load settings: {e}, using defaults")
    
    def save_settings(self):
        """Save current settings"""
        try:
            settings_file = Path("data/automation_settings.json")
            settings_file.parent.mkdir(exist_ok=True)
            
            with open(settings_file, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=2)
                self.logger.info("Saved automation settings")
        except Exception as e:
            self.logger.error(f"Failed to save settings: {e}")
    
    def discover_strategic_targets(self, limit: int = 100) -> List[Dict]:
        """Discover strategic follow targets based on recent activity"""
        self.logger.info("🎯 Discovering strategic follow targets...")
        
        targets = []
        seen_users = set()
        
        try:
            # Get current followers and following for context
            current_followers = set(self.github_api.get_followers())
            current_following = set(self.github_api.get_following())
            damaged_users = set()
            
            # Load damaged users to avoid
            ban_list = self.ban_manager.load_ban_list("followers")
            for username in ban_list:
                if self.database.is_damaged_user(username):
                    damaged_users.add(username)
            
            # Strategy 1: Analyze followers of similar users in your domain
            similar_users = self._find_similar_users_in_domain()
            
            for similar_user in similar_users[:20]:  # Limit to avoid rate limits
                try:
                    followers = self.github_api.get_followers(similar_user)
                    
                    for follower in followers:
                        if (len(targets) >= limit or 
                            follower in current_following or 
                            follower in current_followers or
                            follower in damaged_users or
                            follower in seen_users):
                            continue
                        
                        # Get user profile for analysis
                        user_info = self.github_api.get_user_info(follower)
                        if not user_info:
                            continue
                        
                        # Calculate user value
                        user_analysis = self._analyze_user_value(user_info)
                        
                        if user_analysis['is_valuable']:
                            targets.append({
                                'username': follower,
                                'stars_count': user_analysis['total_stars'],
                                'is_high_value': user_analysis['is_high_value'],
                                'activity_score': user_analysis['activity_score'],
                                'discovery_method': f'followers_of_{similar_user}',
                                'analysis': user_analysis
                            })
                            seen_users.add(follower)
                        
                        # Rate limiting
                        time.sleep(0.1)
                    
                except Exception as e:
                    self.logger.warning(f"Error analyzing {similar_user}: {e}")
                    continue
                
                if len(targets) >= limit:
                    break
            
            # Strategy 2: Find users who starred popular repositories in your domain
            if len(targets) < limit:
                popular_repos = self._find_popular_repositories_in_domain()
                
                for repo_full_name in popular_repos[:10]:
                    try:
                        stargazers = self.github_api.get_repository_stargazers(repo_full_name)
                        
                        for stargazer in stargazers[:50]:  # Limit per repo
                            if (len(targets) >= limit or 
                                stargazer in current_following or 
                                stargazer in current_followers or
                                stargazer in damaged_users or
                                stargazer in seen_users):
                                continue
                            
                            user_info = self.github_api.get_user_info(stargazer)
                            if not user_info:
                                continue
                            
                            user_analysis = self._analyze_user_value(user_info)
                            
                            if user_analysis['is_valuable']:
                                targets.append({
                                    'username': stargazer,
                                    'stars_count': user_analysis['total_stars'],
                                    'is_high_value': user_analysis['is_high_value'],
                                    'activity_score': user_analysis['activity_score'],
                                    'discovery_method': f'stargazer_of_{repo_full_name}',
                                    'analysis': user_analysis
                                })
                                seen_users.add(stargazer)
                            
                            time.sleep(0.1)
                        
                    except Exception as e:
                        self.logger.warning(f"Error analyzing stargazers of {repo_full_name}: {e}")
                        continue
                    
                    if len(targets) >= limit:
                        break
            
            # Sort targets by strategic value
            targets.sort(key=lambda x: (
                x['is_high_value'],
                x['activity_score'],
                x['stars_count']
            ), reverse=True)
            
            self.logger.info(f"✅ Discovered {len(targets)} strategic targets")
            return targets[:limit]
            
        except Exception as e:
            self.logger.error(f"Failed to discover strategic targets: {e}")
            return []
    
    def _find_similar_users_in_domain(self) -> List[str]:
        """Find users similar to you in your domain"""
        try:
            # This is a simplified version - in production you'd use more sophisticated analysis
            similar_users = []
            
            # Get your repositories to understand your domain
            your_repos = self.github_api.get_repositories(per_page=20)
            
            # Extract languages and topics
            languages = set()
            topics = set()
            
            for repo in your_repos:
                if repo.get('language'):
                    languages.add(repo['language'])
                
                repo_topics = repo.get('topics', [])
                topics.update(repo_topics)
            
            # Search for users with similar repositories
            # This would be expanded with more sophisticated GitHub API searches
            search_terms = list(languages)[:3] + list(topics)[:3]
            
            for term in search_terms:
                try:
                    # Use GitHub search API to find users
                    search_results = self.github_api.search_users(f"{term} followers:>100")
                    
                    for user in search_results[:10]:
                        if user['login'] != self.github_api.username:
                            similar_users.append(user['login'])
                    
                    time.sleep(1)  # Rate limiting for search API
                    
                except Exception as e:
                    self.logger.warning(f"Search error for term {term}: {e}")
                    continue
            
            return list(set(similar_users))[:50]  # Remove duplicates and limit
            
        except Exception as e:
            self.logger.error(f"Failed to find similar users: {e}")
            return []
    
    def _find_popular_repositories_in_domain(self) -> List[str]:
        """Find popular repositories in your domain"""
        try:
            # This would normally use more sophisticated analysis
            popular_repos = []
            
            # Get your repositories to understand your domain
            your_repos = self.github_api.get_repositories(per_page=20)
            
            # Extract main language/topic
            languages = {}
            for repo in your_repos:
                lang = repo.get('language')
                if lang:
                    languages[lang] = languages.get(lang, 0) + 1
            
            # Find most used language
            if languages:
                main_language = max(languages.keys(), key=lambda k: languages[k])
                
                # Search for popular repositories in this language
                try:
                    search_results = self.github_api.search_repositories(
                        f"language:{main_language} stars:>500"
                    )
                    
                    for repo in search_results[:20]:
                        popular_repos.append(repo['full_name'])
                    
                except Exception as e:
                    self.logger.warning(f"Repository search error: {e}")
            
            return popular_repos
            
        except Exception as e:
            self.logger.error(f"Failed to find popular repositories: {e}")
            return []
    
    def _analyze_user_value(self, user_info: Dict) -> Dict:
        """Analyze user value for strategic following"""
        try:
            followers_count = user_info.get('followers', 0)
            following_count = user_info.get('following', 0)
            public_repos = user_info.get('public_repos', 0)
            created_at = user_info.get('created_at', '')
            
            # Calculate account age in days
            account_age_days = 0
            if created_at:
                try:
                    created_date = datetime.strptime(created_at[:10], '%Y-%m-%d')
                    account_age_days = (datetime.now() - created_date).days
                except:
                    account_age_days = 0
            
            # Get user's repositories to count total stars
            total_stars = 0
            try:
                user_repos = self.github_api.get_repositories(user_info['login'], per_page=100)
                total_stars = sum(repo.get('stargazers_count', 0) for repo in user_repos)
            except:
                total_stars = 0
            
            # Calculate activity score
            activity_score = 0
            
            # Positive indicators
            if followers_count > 10:
                activity_score += min(followers_count / 10, 50)
            
            if public_repos > 0:
                activity_score += min(public_repos * 2, 20)
            
            if total_stars > 0:
                activity_score += min(total_stars / 5, 30)
            
            if account_age_days > 30:
                activity_score += min(account_age_days / 30, 20)
            
            # Bio and company indicators
            if user_info.get('bio'):
                activity_score += 10
            
            if user_info.get('company'):
                activity_score += 15
            
            if user_info.get('blog'):
                activity_score += 10
            
            # Negative indicators
            if following_count > followers_count * 3 and followers_count > 0:
                activity_score -= 20  # Likely follow-for-follow account
            
            if followers_count > 10000 and following_count < 100:
                activity_score -= 10  # Might not follow back
            
            # Determine if valuable
            is_valuable = (
                activity_score >= 30 and
                followers_count >= 5 and
                account_age_days >= 7 and
                public_repos > 0
            )
            
            # Determine if high value
            is_high_value = total_stars > self.settings['min_stars_for_high_value']
            
            return {
                'is_valuable': is_valuable,
                'is_high_value': is_high_value,
                'activity_score': round(activity_score, 2),
                'total_stars': total_stars,
                'followers_count': followers_count,
                'following_count': following_count,
                'account_age_days': account_age_days,
                'public_repos': public_repos
            }
            
        except Exception as e:
            self.logger.error(f"Failed to analyze user value: {e}")
            return {
                'is_valuable': False,
                'is_high_value': False,
                'activity_score': 0,
                'total_stars': 0,
                'followers_count': 0,
                'following_count': 0,
                'account_age_days': 0,
                'public_repos': 0
            }
    
    def execute_strategic_follow_cycle(self) -> Dict:
        """Execute a 100% reliable strategic follow cycle with comprehensive tracking"""
        self.cycle_count += 1
        cycle_start_time = datetime.now()
        
        self.logger.info(f"🚀 Starting strategic follow cycle #{self.cycle_count}...")
        
        results = {
            'cycle_number': self.cycle_count,
            'cycle_start': cycle_start_time.isoformat(),
            'followed': 0,
            'unfollowed': 0,
            'blacklisted': 0,
            'followback_confirmed': 0,
            'moon_symbols_added': 0,
            'errors': 0,
            'reliability_score': 0.0
        }
        
        try:
            # Phase 1: Comprehensive followback verification
            self.logger.info("🔍 Phase 1: Checking for followbacks...")
            self._comprehensive_followback_check(results)
            
            # Phase 2: Process expired follow requests with moon tracking
            self.logger.info("⏰ Phase 2: Processing expired follow requests...")
            self._process_expired_with_moon_tracking(results)
            
            # Phase 3: Strategic target discovery and following
            self.logger.info("🎯 Phase 3: Discovering and following strategic targets...")
            self._execute_strategic_follows(results)
            
            # Phase 4: Update comprehensive statistics and blacklist management
            self.logger.info("📊 Phase 4: Updating statistics and managing blacklists...")
            self._update_comprehensive_stats(results)
            
            # Calculate reliability score
            results['reliability_score'] = self._calculate_reliability_score(results)
            
            # Update session statistics
            self._update_session_stats(results)
            
            cycle_duration = (datetime.now() - cycle_start_time).total_seconds()
            results['cycle_duration_seconds'] = cycle_duration
            
            self.logger.info(f"✅ Cycle #{self.cycle_count} complete in {cycle_duration:.1f}s: {results}")
            
            # Log comprehensive cycle summary
            self._log_cycle_summary(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Strategic follow cycle #{self.cycle_count} failed: {e}")
            results['errors'] += 1
            results['error_message'] = str(e)
            
            # Attempt error recovery
            self._attempt_error_recovery(e)
            
            return results
    
    def _comprehensive_followback_check(self, results: Dict):
        """Check for users who have followed back"""
        try:
            current_followers = set(self.github_api.get_followers())
            
            # Get all pending follow requests
            cursor = self.database.connection.cursor()
            
            if self.database.use_postgresql:
                cursor.execute("""
                    SELECT username FROM follow_requests 
                    WHERE status = 'pending'
                """)
            else:
                cursor.execute("""
                    SELECT username FROM follow_requests 
                    WHERE status = 'pending'
                """)
            
            pending_users = [row[0] for row in cursor.fetchall()]
            
            for username in pending_users:
                if username in current_followers:
                    if self.database.update_followback_status(username, True):
                        results['followback_confirmed'] += 1
                        self.logger.info(f"✅ {username} followed back!")
            
        except Exception as e:
            self.logger.error(f"Error checking followbacks: {e}")
            results['errors'] += 1
    
    def _process_expired_with_moon_tracking(self, results: Dict):
        """Process expired follow requests for unfollowing"""
        try:
            expired_requests = self.database.get_expired_follow_requests()
            
            for request in expired_requests:
                username = request['username']
                retry_count = request['retry_count']
                moon_symbols = request['moon_symbols']
                
                try:
                    # Unfollow the user
                    if self.github_api.unfollow_user(username):
                        # Add moon symbol for the retry
                        self.database.mark_unfollowed(username, add_moon=True)
                        results['unfollowed'] += 1
                        
                        # Check if user should be blacklisted
                        # Enhanced moon tracking with detailed logging
                        new_moon_count = moon_symbols + 1
                        results['moon_symbols_added'] += 1
                        
                        if new_moon_count >= self.settings['max_moon_symbols']:
                            self._add_to_comprehensive_blacklist(
                                username, retry_count, new_moon_count,
                                f"Reached {new_moon_count} moon symbols - No follow-back after {retry_count} attempts"
                            )
                            results['blacklisted'] += 1
                            self.logger.info(f"🌙💀 {username} PERMANENTLY BLACKLISTED with {new_moon_count} moon symbols")
                            
                            # Update damaged.txt with comprehensive info
                            self._update_damaged_file(username, new_moon_count, retry_count)
                        else:
                            self.logger.info(f"🌙 {username} unfollowed, assigned {new_moon_count} moon symbols (retry #{retry_count})")
                        
                        # Rate limiting
                        time.sleep(random.uniform(1, 3))
                    
                except Exception as e:
                    self.logger.error(f"Failed to unfollow {username}: {e}")
                    results['errors'] += 1
            
        except Exception as e:
            self.logger.error(f"Error processing expired requests: {e}")
            results['errors'] += 1
    
    def _execute_strategic_follows(self, results: Dict):
        """Execute new strategic follows"""
        try:
            # Calculate how many we can follow today
            daily_limit = self.settings['daily_follow_limit']
            
            # Check how many we've already followed today
            cursor = self.database.connection.cursor()
            today = datetime.now().date()
            
            if self.database.use_postgresql:
                cursor.execute("""
                    SELECT COUNT(*) FROM automation_logs 
                    WHERE action = 'follow_request' AND DATE(timestamp) = %s
                """, (today,))
            else:
                cursor.execute("""
                    SELECT COUNT(*) FROM automation_logs 
                    WHERE action = 'follow_request' AND DATE(timestamp) = ?
                """, (today,))
            
            result = cursor.fetchone()
            today_follows = result[0] if result else 0
            remaining_follows = max(0, daily_limit - today_follows)
            
            if remaining_follows == 0:
                self.logger.info(f"Daily follow limit ({daily_limit}) already reached")
                return
            
            # Get strategic targets
            targets = self.discover_strategic_targets(remaining_follows * 2)  # Get extra for filtering
            
            followed_count = 0
            for target in targets:
                if followed_count >= remaining_follows:
                    break
                
                username = target['username']
                
                try:
                    # Double-check we're not already following
                    if self.github_api.is_following(username):
                        continue
                    
                    # Follow the user
                    if self.github_api.follow_user(username):
                        # Record in database
                        if self.database.record_follow_request(
                            username=username,
                            stars_count=target['stars_count'],
                            is_high_value=target['is_high_value'],
                            notes=f"Discovery: {target['discovery_method']}, Score: {target['activity_score']}"
                        ):
                            followed_count += 1
                            results['followed'] += 1
                            self.logger.info(f"✅ Followed strategic target: {username} "
                                           f"(⭐{target['stars_count']}, 📊{target['activity_score']})")
                        
                        # Strategic rate limiting
                        time.sleep(random.uniform(2, 5))
                    else:
                        self.logger.warning(f"❌ Failed to follow {username}")
                    
                except Exception as e:
                    self.logger.error(f"Error following {username}: {e}")
                    results['errors'] += 1
            
            self.logger.info(f"Followed {followed_count} new strategic targets")
            
        except Exception as e:
            self.logger.error(f"Error executing new follows: {e}")
            results['errors'] += 1
    
    def run_continuous_automation(self, check_interval_hours: int = 2):
        """Run continuous strategic automation"""
        self.logger.info("🔄 Starting continuous strategic automation...")
        self.logger.info(f"Check interval: {check_interval_hours} hours")
        
        cycle_count = 0
        
        try:
            while True:
                cycle_count += 1
                self.logger.info(f"\n--- Strategic Automation Cycle #{cycle_count} ---")
                
                # Execute strategic cycle
                results = self.execute_strategic_follow_cycle()
                
                # Display results
                self.logger.info(f"Cycle {cycle_count} Results:")
                self.logger.info(f"  ✅ Followed: {results['followed']}")
                self.logger.info(f"  ↩️ Unfollowed: {results['unfollowed']}")
                self.logger.info(f"  🌙 Blacklisted: {results['blacklisted']}")
                self.logger.info(f"  💚 Followbacks: {results['followback_confirmed']}")
                self.logger.info(f"  ❌ Errors: {results['errors']}")
                
                # Wait for next cycle
                wait_seconds = check_interval_hours * 3600
                self.logger.info(f"⏰ Next cycle in {check_interval_hours} hours...")
                
                time.sleep(wait_seconds)
                
        except KeyboardInterrupt:
            self.logger.info("🛑 Continuous automation stopped by user")
        except Exception as e:
            self.logger.error(f"Continuous automation error: {e}")
    
    def get_comprehensive_stats(self) -> Dict:
        """Get comprehensive automation statistics"""
        stats = self.database.get_automation_stats()
        
        # Add calculated metrics
        follow_requests = stats.get('follow_requests', {})
        total_requests = sum(follow_requests.values())
        
        if total_requests > 0:
            success_rate = (follow_requests.get('followed_back', 0) / total_requests) * 100
            stats['success_rate'] = round(success_rate, 2)
        
        # Add current follower count
        try:
            current_followers = len(self.github_api.get_followers())
            stats['current_followers'] = current_followers
        except:
            stats['current_followers'] = 0
        
        return stats
    
    def _add_to_comprehensive_blacklist(self, username: str, retry_count: int, 
                                      moon_count: int, reason: str):
        """Add user to comprehensive blacklist with detailed tracking"""
        try:
            # Add to database damaged list
            self.database.add_to_damaged_list(username, retry_count, moon_count, reason)
            
            # Also add to ban manager for immediate protection
            self.ban_manager.add_to_ban_list([username], "followers")
            
            # Log comprehensive blacklist action
            self.database.log_action(
                "permanent_blacklist", username, True,
                f"BLACKLISTED: {moon_count} moons, {retry_count} retries - {reason}"
            )
            
            self.logger.info(f"🚫 {username} added to comprehensive blacklist")
            
        except Exception as e:
            self.logger.error(f"Failed to add {username} to comprehensive blacklist: {e}")
    
    def _update_damaged_file(self, username: str, moon_count: int, retry_count: int):
        """Update damaged.txt file with comprehensive tracking"""
        try:
            damaged_file = Path("data/damaged.txt")
            damaged_file.parent.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            moon_symbols = '🌙' * moon_count
            
            with open(damaged_file, "a", encoding="utf-8") as f:
                f.write(f"{username} # {moon_symbols} ({moon_count} moons) - {retry_count} retries - {timestamp}\n")
            
            self.logger.info(f"📝 Updated damaged.txt with {username} ({moon_count} moons)")
            
        except Exception as e:
            self.logger.error(f"Failed to update damaged.txt for {username}: {e}")
    
    def _calculate_reliability_score(self, results: Dict) -> float:
        """Calculate reliability score for the automation cycle"""
        try:
            total_actions = (
                results['followed'] + results['unfollowed'] + 
                results['followback_confirmed'] + results['blacklisted']
            )
            
            if total_actions == 0:
                return 100.0
            
            successful_actions = total_actions - results['errors']
            reliability_score = (successful_actions / total_actions) * 100
            
            return round(reliability_score, 2)
            
        except Exception as e:
            self.logger.error(f"Failed to calculate reliability score: {e}")
            return 0.0
    
    def _update_session_stats(self, results: Dict):
        """Update current session statistics"""
        try:
            self.current_session_stats['follows_sent'] += results.get('followed', 0)
            self.current_session_stats['unfollows_executed'] += results.get('unfollowed', 0)
            self.current_session_stats['followbacks_received'] += results.get('followback_confirmed', 0)
            self.current_session_stats['users_blacklisted'] += results.get('blacklisted', 0)
            self.current_session_stats['moon_symbols_assigned'] += results.get('moon_symbols_added', 0)
            self.current_session_stats['api_errors'] += results.get('errors', 0)
            
        except Exception as e:
            self.logger.error(f"Failed to update session stats: {e}")
    
    def _log_cycle_summary(self, results: Dict):
        """Log comprehensive cycle summary for monitoring"""
        try:
            summary = f"""
╔══════════════════════════════════════════════════════════════════╗
║                   STRATEGIC AUTOMATION CYCLE #{results['cycle_number']:03d}                     ║
╠══════════════════════════════════════════════════════════════════╣
║ 📊 CYCLE PERFORMANCE:                                            ║
║   • Duration: {results.get('cycle_duration_seconds', 0):.1f} seconds                                    ║
║   • Reliability Score: {results.get('reliability_score', 0):.1f}%                              ║
║                                                                  ║
║ 🎯 ACTIONS EXECUTED:                                             ║
║   • New Follows: {results.get('followed', 0):3d}                                        ║
║   • Unfollows: {results.get('unfollowed', 0):3d}                                          ║
║   • Followbacks Confirmed: {results.get('followback_confirmed', 0):3d}                           ║
║   • Users Blacklisted: {results.get('blacklisted', 0):3d}                               ║
║   • Moon Symbols Added: {results.get('moon_symbols_added', 0):3d}                            ║
║                                                                  ║
║ 📈 SESSION TOTALS:                                               ║
║   • Total Follows: {self.current_session_stats['follows_sent']:3d}                                    ║
║   • Total Unfollows: {self.current_session_stats['unfollows_executed']:3d}                                ║
║   • Total Followbacks: {self.current_session_stats['followbacks_received']:3d}                              ║
║   • Total Blacklisted: {self.current_session_stats['users_blacklisted']:3d}                             ║
║   • Total Errors: {self.current_session_stats['api_errors']:3d}                                    ║
╚══════════════════════════════════════════════════════════════════╝
            """.strip()
            
            self.logger.info(summary)
            
        except Exception as e:
            self.logger.error(f"Failed to log cycle summary: {e}")
    
    def _attempt_error_recovery(self, error: Exception):
        """Attempt to recover from errors and maintain automation reliability"""
        try:
            self.logger.warning(f"🔧 Attempting error recovery from: {error}")
            
            # Reset rate limiter if needed
            if "rate limit" in str(error).lower():
                self.logger.info("🔄 Resetting rate limiter due to rate limit error")
                self.rate_limiter = RateLimiter()
                time.sleep(5)  # Brief pause
            
            # Check API connection
            if "connection" in str(error).lower():
                self.logger.info("🔄 Testing GitHub API connection...")
                if self.github_api.validate_token():
                    self.logger.info("✅ API connection restored")
                else:
                    self.logger.error("❌ API connection still failed")
            
            # Log recovery attempt
            self.database.log_action(
                "error_recovery", "system", True,
                f"Recovery attempted for: {str(error)[:100]}"
            )
            
        except Exception as recovery_error:
            self.logger.error(f"Error recovery failed: {recovery_error}")
    
    def _update_comprehensive_stats(self, results: Dict):
        """Update comprehensive automation statistics"""
        try:
            # Get current stats
            stats = self.database.get_automation_stats()
            
            # Log current state
            self.logger.info(f"📊 Current automation stats: {stats}")
            
            # Update totals
            self.total_followed += results.get('followed', 0)
            self.total_unfollowed += results.get('unfollowed', 0)
            
            # Log comprehensive statistics update
            self.database.log_action(
                "stats_update", "automation", True,
                f"Cycle #{results['cycle_number']}: F:{results.get('followed', 0)} U:{results.get('unfollowed', 0)} FB:{results.get('followback_confirmed', 0)} B:{results.get('blacklisted', 0)}"
            )
            
        except Exception as e:
            self.logger.error(f"Failed to update comprehensive stats: {e}")
    
    def get_automation_status(self) -> Dict:
        """Get comprehensive automation status"""
        try:
            current_time = datetime.now()
            session_duration = current_time - self.current_session_stats['session_start']
            
            return {
                'active': self.automation_active,
                'cycle_count': self.cycle_count,
                'session_duration': str(session_duration),
                'session_start': self.current_session_stats['session_start'].isoformat(),
                'current_stats': self.current_session_stats.copy(),
                'settings': self.settings.copy(),
                'database_stats': self.database.get_automation_stats()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get automation status: {e}")
            return {'active': False, 'error': str(e)}
    
    def increase_follow_limits(self, daily_follow_increase: int = 25, daily_unfollow_increase: int = 25) -> Dict:
        """Increase daily follow and unfollow limits for aggressive growth"""
        try:
            old_follow_limit = self.settings['daily_follow_limit']
            old_unfollow_limit = self.settings['daily_unfollow_limit']
            
            # Apply increases
            self.settings['daily_follow_limit'] += daily_follow_increase
            self.settings['daily_unfollow_limit'] += daily_unfollow_increase
            
            # Cap at reasonable maximums to avoid API abuse
            self.settings['daily_follow_limit'] = min(self.settings['daily_follow_limit'], 200)
            self.settings['daily_unfollow_limit'] = min(self.settings['daily_unfollow_limit'], 300)
            
            # Save updated settings
            self.save_settings()
            
            # Log the change
            self.database.log_action(
                "limits_increased", "system", True,
                f"Follow: {old_follow_limit}→{self.settings['daily_follow_limit']}, Unfollow: {old_unfollow_limit}→{self.settings['daily_unfollow_limit']}"
            )
            
            result = {
                'action': 'limits_increased',
                'old_follow_limit': old_follow_limit,
                'new_follow_limit': self.settings['daily_follow_limit'],
                'old_unfollow_limit': old_unfollow_limit,
                'new_unfollow_limit': self.settings['daily_unfollow_limit'],
                'follow_increase': daily_follow_increase,
                'unfollow_increase': daily_unfollow_increase
            }
            
            self.logger.info(f"📈 Increased follow limits - Follow: {old_follow_limit}→{self.settings['daily_follow_limit']}, Unfollow: {old_unfollow_limit}→{self.settings['daily_unfollow_limit']}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to increase follow limits: {e}")
            return {'error': str(e)}
    
    def decrease_follow_limits(self, daily_follow_decrease: int = 25, daily_unfollow_decrease: int = 25) -> Dict:
        """Decrease daily follow and unfollow limits for conservative growth"""
        try:
            old_follow_limit = self.settings['daily_follow_limit']
            old_unfollow_limit = self.settings['daily_unfollow_limit']
            
            # Apply decreases
            self.settings['daily_follow_limit'] -= daily_follow_decrease
            self.settings['daily_unfollow_limit'] -= daily_unfollow_decrease
            
            # Floor at minimum reasonable values
            self.settings['daily_follow_limit'] = max(self.settings['daily_follow_limit'], 10)
            self.settings['daily_unfollow_limit'] = max(self.settings['daily_unfollow_limit'], 15)
            
            # Save updated settings
            self.save_settings()
            
            # Log the change
            self.database.log_action(
                "limits_decreased", "system", True,
                f"Follow: {old_follow_limit}→{self.settings['daily_follow_limit']}, Unfollow: {old_unfollow_limit}→{self.settings['daily_unfollow_limit']}"
            )
            
            result = {
                'action': 'limits_decreased',
                'old_follow_limit': old_follow_limit,
                'new_follow_limit': self.settings['daily_follow_limit'],
                'old_unfollow_limit': old_unfollow_limit,
                'new_unfollow_limit': self.settings['daily_unfollow_limit'],
                'follow_decrease': daily_follow_decrease,
                'unfollow_decrease': daily_unfollow_decrease
            }
            
            self.logger.info(f"📉 Decreased follow limits - Follow: {old_follow_limit}→{self.settings['daily_follow_limit']}, Unfollow: {old_unfollow_limit}→{self.settings['daily_unfollow_limit']}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to decrease follow limits: {e}")
            return {'error': str(e)}
    
    def adjust_follow_limits_by_performance(self) -> Dict:
        """Automatically adjust follow limits based on system performance"""
        try:
            # Get recent performance metrics
            stats = self.database.get_automation_stats()
            follow_back_rate = stats.get('success_rate', 0)
            
            result = {'action': 'performance_adjustment', 'follow_back_rate': follow_back_rate}
            
            if follow_back_rate > 35:  # High success rate - increase limits
                adjustment = self.increase_follow_limits(15, 20)
                result.update(adjustment)
                result['reason'] = f'High follow-back rate ({follow_back_rate}%) - increasing limits for aggressive growth'
                
            elif follow_back_rate < 15:  # Low success rate - decrease limits
                adjustment = self.decrease_follow_limits(15, 10)
                result.update(adjustment)
                result['reason'] = f'Low follow-back rate ({follow_back_rate}%) - decreasing limits for quality focus'
                
            else:  # Normal range - maintain current limits
                result['reason'] = f'Normal follow-back rate ({follow_back_rate}%) - maintaining current limits'
                result['action'] = 'no_adjustment'
            
            self.logger.info(f"🎯 Performance-based adjustment: {result['reason']}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to adjust limits by performance: {e}")
            return {'error': str(e)}
    
    def set_custom_follow_limits(self, daily_follow_limit: int, daily_unfollow_limit: int) -> Dict:
        """Set custom daily follow and unfollow limits"""
        try:
            old_follow_limit = self.settings['daily_follow_limit']
            old_unfollow_limit = self.settings['daily_unfollow_limit']
            
            # Validate limits
            if daily_follow_limit < 5 or daily_follow_limit > 300:
                raise ValueError("Daily follow limit must be between 5 and 300")
            if daily_unfollow_limit < 10 or daily_unfollow_limit > 500:
                raise ValueError("Daily unfollow limit must be between 10 and 500")
            
            # Set new limits
            self.settings['daily_follow_limit'] = daily_follow_limit
            self.settings['daily_unfollow_limit'] = daily_unfollow_limit
            
            # Save updated settings
            self.save_settings()
            
            # Log the change
            self.database.log_action(
                "custom_limits_set", "system", True,
                f"Custom limits - Follow: {old_follow_limit}→{daily_follow_limit}, Unfollow: {old_unfollow_limit}→{daily_unfollow_limit}"
            )
            
            result = {
                'action': 'custom_limits_set',
                'old_follow_limit': old_follow_limit,
                'new_follow_limit': daily_follow_limit,
                'old_unfollow_limit': old_unfollow_limit,
                'new_unfollow_limit': daily_unfollow_limit
            }
            
            self.logger.info(f"⚙️ Set custom limits - Follow: {daily_follow_limit}, Unfollow: {daily_unfollow_limit}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to set custom follow limits: {e}")
            return {'error': str(e)}
    
    def execute_quarterly_data_purge(self) -> Dict:
        """Execute comprehensive 3-month data purge to optimize performance"""
        try:
            self.logger.info("🗑️ Starting quarterly data purge (3-month cleanup)...")
            
            purge_start_time = datetime.now()
            three_months_ago = purge_start_time - timedelta(days=90)
            
            purge_results = {
                'purge_date': purge_start_time.isoformat(),
                'cutoff_date': three_months_ago.isoformat(),
                'follow_requests_purged': 0,
                'automation_logs_purged': 0,
                'old_reports_purged': 0,
                'damaged_users_reviewed': 0,
                'database_optimized': False,
                'errors': 0
            }
            
            cursor = self.database.connection.cursor()
            
            # 1. Purge old follow requests that are completed/unfollowed
            try:
                if self.database.use_postgresql:
                    cursor.execute("""
                        DELETE FROM follow_requests 
                        WHERE (status IN ('unfollowed', 'followed_back') 
                               OR unfollow_date < %s) 
                              AND follow_date < %s
                    """, (three_months_ago, three_months_ago))
                else:
                    cursor.execute("""
                        DELETE FROM follow_requests 
                        WHERE (status IN ('unfollowed', 'followed_back') 
                               OR unfollow_date < ?) 
                              AND follow_date < ?
                    """, (three_months_ago, three_months_ago))
                
                purge_results['follow_requests_purged'] = cursor.rowcount
                self.database.connection.commit()
                
            except Exception as e:
                self.logger.error(f"Failed to purge follow requests: {e}")
                purge_results['errors'] += 1
            
            # 2. Purge old automation logs (keep last 30 days only)
            try:
                thirty_days_ago = purge_start_time - timedelta(days=30)
                
                if self.database.use_postgresql:
                    cursor.execute("""
                        DELETE FROM automation_logs 
                        WHERE timestamp < %s
                    """, (thirty_days_ago,))
                else:
                    cursor.execute("""
                        DELETE FROM automation_logs 
                        WHERE timestamp < ?
                    """, (thirty_days_ago,))
                
                purge_results['automation_logs_purged'] = cursor.rowcount
                self.database.connection.commit()
                
            except Exception as e:
                self.logger.error(f"Failed to purge automation logs: {e}")
                purge_results['errors'] += 1
            
            # 3. Clean up old daily/weekly reports
            try:
                reports_purged = 0
                
                # Clean old daily reports
                daily_reports_dir = Path("data/daily_reports")
                if daily_reports_dir.exists():
                    for report_file in daily_reports_dir.glob("*.json"):
                        if report_file.stat().st_mtime < three_months_ago.timestamp():
                            report_file.unlink()
                            reports_purged += 1
                
                # Clean old weekly reports
                weekly_reports_dir = Path("data/weekly_reports")
                if weekly_reports_dir.exists():
                    for report_file in weekly_reports_dir.glob("*.json"):
                        if report_file.stat().st_mtime < three_months_ago.timestamp():
                            report_file.unlink()
                            reports_purged += 1
                
                purge_results['old_reports_purged'] = reports_purged
                
            except Exception as e:
                self.logger.error(f"Failed to clean report files: {e}")
                purge_results['errors'] += 1
            
            # 4. Review and optimize damaged users list (remove very old entries)
            try:
                if self.database.use_postgresql:
                    cursor.execute("""
                        SELECT COUNT(*) FROM damaged_users 
                        WHERE created_date < %s
                    """, (three_months_ago,))
                else:
                    cursor.execute("""
                        SELECT COUNT(*) FROM damaged_users 
                        WHERE created_date < ?
                    """, (three_months_ago,))
                
                old_damaged_count = cursor.fetchone()
                if old_damaged_count:
                    purge_results['damaged_users_reviewed'] = old_damaged_count[0]
                
                # Keep damaged users but clean up damaged.txt file
                damaged_file = Path("data/damaged.txt")
                if damaged_file.exists() and damaged_file.stat().st_size > 1024 * 1024:  # If > 1MB
                    # Keep only recent entries in damaged.txt
                    with open(damaged_file, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                    
                    # Keep only last 1000 entries
                    recent_lines = lines[-1000:] if len(lines) > 1000 else lines
                    
                    with open(damaged_file, 'w', encoding='utf-8') as f:
                        f.writelines(recent_lines)
                
            except Exception as e:
                self.logger.error(f"Failed to review damaged users: {e}")
                purge_results['errors'] += 1
            
            # 5. Optimize database (if PostgreSQL)
            try:
                if self.database.use_postgresql:
                    cursor.execute("VACUUM ANALYZE")
                    cursor.execute("REINDEX DATABASE github_automation")
                    purge_results['database_optimized'] = True
                    
            except Exception as e:
                self.logger.warning(f"Database optimization failed (non-critical): {e}")
            
            # Calculate purge duration and log results
            purge_duration = (datetime.now() - purge_start_time).total_seconds()
            purge_results['purge_duration_seconds'] = purge_duration
            
            # Log comprehensive purge results
            self.database.log_action(
                "quarterly_data_purge", "system", purge_results['errors'] == 0,
                f"Purged: {purge_results['follow_requests_purged']} requests, {purge_results['automation_logs_purged']} logs, {purge_results['old_reports_purged']} reports in {purge_duration:.1f}s"
            )
            
            self.logger.info(f"🗑️ Quarterly data purge completed in {purge_duration:.1f}s")
            self.logger.info(f"Purged: {purge_results['follow_requests_purged']} follow requests, {purge_results['automation_logs_purged']} logs, {purge_results['old_reports_purged']} reports")
            
            if purge_results['errors'] == 0:
                self.logger.info("✅ Quarterly purge completed successfully - System optimized!")
            else:
                self.logger.warning(f"⚠️ Quarterly purge completed with {purge_results['errors']} errors")
            
            return purge_results
            
        except Exception as e:
            self.logger.error(f"Critical failure in quarterly data purge: {e}")
            return {'error': str(e), 'purge_failed': True}
    
    def get_follow_limits_status(self) -> Dict:
        """Get current follow limits and performance metrics"""
        try:
            stats = self.database.get_automation_stats()
            
            return {
                'current_follow_limit': self.settings['daily_follow_limit'],
                'current_unfollow_limit': self.settings['daily_unfollow_limit'],
                'follow_back_success_rate': stats.get('success_rate', 0),
                'recommended_adjustment': self._get_limit_recommendation(stats),
                'limits_last_updated': self.settings.get('limits_last_updated', 'Never'),
                'performance_status': self._get_performance_status(stats)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get follow limits status: {e}")
            return {'error': str(e)}
    
    def _get_limit_recommendation(self, stats: Dict) -> str:
        """Get recommendation for limit adjustment based on performance"""
        success_rate = stats.get('success_rate', 0)
        
        if success_rate > 35:
            return "INCREASE - High success rate allows for more aggressive growth"
        elif success_rate < 15:
            return "DECREASE - Low success rate suggests need for quality over quantity"
        else:
            return "MAINTAIN - Success rate is in optimal range"
    
    def _get_performance_status(self, stats: Dict) -> str:
        """Get current performance status"""
        success_rate = stats.get('success_rate', 0)
        
        if success_rate > 30:
            return "EXCELLENT"
        elif success_rate > 20:
            return "GOOD"
        elif success_rate > 15:
            return "AVERAGE"
        else:
            return "NEEDS_IMPROVEMENT"