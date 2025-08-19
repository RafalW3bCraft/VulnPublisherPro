"""
Promotion Engine for GitHub Automation Suite
Handles follower-of-follower discovery and time-based tracking
"""

import time
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Set, Tuple, Dict, Optional
import logging
from tqdm import tqdm

from .github_api import GitHubAPI
from .ban_manager import BanManager

class PromotionEngine:
    """Manages promotion system for expanding network reach"""
    
    def __init__(self, github_api: GitHubAPI, ban_manager: BanManager, data_dir: str = "data"):
        self.github_api = github_api
        self.ban_manager = ban_manager
        self.data_dir = Path(data_dir)
        self.promoted_users_file = self.data_dir / "promoted_users.txt"
        
        # Ensure data directory exists
        self.data_dir.mkdir(exist_ok=True)
    
    def discover_promotion_candidates(self, 
                                    follower_list: List[str], 
                                    count: int,
                                    min_followers: int = 0,
                                    filter_verified: bool = False) -> List[str]:
        """
        Discover users to promote by finding followers of your followers
        
        Args:
            follower_list: List of your current followers
            count: Number of users to promote
            min_followers: Minimum follower count for candidates
            filter_verified: Only include verified users
            
        Returns:
            List of usernames to promote
        """
        promotion_users = []
        ban_list = self.ban_manager.load_ban_list("followers")
        current_following = set(self.github_api.get_following())
        processed_count = 0
        
        print(f"🔍 Discovering promotion candidates from {len(follower_list)} followers...")
        
        with tqdm(total=min(len(follower_list), 50), desc="Analyzing followers") as pbar:
            for follower in follower_list[:50]:  # Limit to avoid rate limits
                if len(promotion_users) >= count:
                    break
                
                try:
                    # Get followers of this follower
                    followers_of_follower = self.github_api.get_followers(follower)
                    
                    for candidate in followers_of_follower:
                        if len(promotion_users) >= count:
                            break
                        
                        # Skip if already following, banned, or self
                        if (candidate in current_following or 
                            candidate in ban_list or 
                            candidate == self.github_api.username or
                            candidate in promotion_users):
                            continue
                        
                        # Apply filters if specified
                        if min_followers > 0 or filter_verified:
                            user_info = self.github_api.get_user_info(candidate)
                            if user_info:
                                # Check follower count
                                if user_info.get('followers', 0) < min_followers:
                                    continue
                                
                                # Check verification (company or verified status)
                                if filter_verified:
                                    is_verified = bool(user_info.get('company') or 
                                                     user_info.get('twitter_username'))
                                    if not is_verified:
                                        continue
                        
                        promotion_users.append(candidate)
                    
                    pbar.update(1)
                    processed_count += 1
                    
                    # Rate limiting
                    time.sleep(0.5)
                    
                except Exception as e:
                    logging.warning(f"Error processing follower {follower}: {e}")
                    continue
        
        # Save promoted users with timestamp
        self._save_promoted_users(promotion_users)
        
        print(f"✅ Found {len(promotion_users)} promotion candidates")
        return promotion_users
    
    def _save_promoted_users(self, users: List[str]) -> None:
        """Save promoted users with current timestamp"""
        current_date = datetime.now().strftime("%Y-%m-%d")
        
        # Append to file
        with open(self.promoted_users_file, 'a', encoding='utf-8') as file:
            for user in users:
                file.write(f"{user} {current_date}\n")
    
    def check_promotion_expiry(self, days_period: int = 7) -> Tuple[List[str], List[str]]:
        """
        Check promoted users and return active vs expired
        
        Args:
            days_period: Days after which promotion expires
            
        Returns:
            Tuple of (active_users, expired_users)
        """
        if not self.promoted_users_file.exists():
            return [], []
        
        active_users = []
        expired_users = []
        updated_entries = []
        
        cutoff_date = datetime.now() - timedelta(days=days_period)
        
        with open(self.promoted_users_file, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        
        print(f"🔄 Checking {len(lines)} promoted users for expiry...")
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            try:
                username, date_str = line.rsplit(' ', 1)
                entry_date = datetime.strptime(date_str, "%Y-%m-%d")
                
                if entry_date >= cutoff_date:
                    active_users.append(username)
                    updated_entries.append(line)
                else:
                    expired_users.append(username)
            except ValueError:
                # Invalid format, skip
                continue
        
        # Update file with only active entries
        with open(self.promoted_users_file, 'w', encoding='utf-8') as file:
            for entry in updated_entries:
                file.write(f"{entry}\n")
        
        print(f"📊 Active: {len(active_users)}, Expired: {len(expired_users)}")
        return active_users, expired_users
    
    def get_promotion_stats(self) -> Dict[str, any]:
        """Get promotion system statistics"""
        if not self.promoted_users_file.exists():
            return {
                "total_promoted": 0,
                "active_promotions": 0,
                "expired_promotions": 0,
                "promotion_dates": []
            }
        
        promotion_dates = []
        total_count = 0
        
        with open(self.promoted_users_file, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    username, date_str = line.rsplit(' ', 1)
                    promotion_dates.append(date_str)
                    total_count += 1
                except ValueError:
                    continue
        
        # Get current active vs expired
        active_users, expired_users = self.check_promotion_expiry()
        
        return {
            "total_promoted": total_count,
            "active_promotions": len(active_users),
            "expired_promotions": len(expired_users),
            "promotion_dates": promotion_dates,
            "recent_activity": len([d for d in promotion_dates 
                                  if (datetime.now() - datetime.strptime(d, "%Y-%m-%d")).days <= 7])
        }
    
    def cleanup_expired_promotions(self, days_period: int = 7) -> int:
        """Remove expired promotions and return count of removed users"""
        active_users, expired_users = self.check_promotion_expiry(days_period)
        
        if expired_users:
            print(f"🧹 Cleaned up {len(expired_users)} expired promotions")
        
        return len(expired_users)