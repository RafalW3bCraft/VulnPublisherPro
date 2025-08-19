"""
Ban List Management for GitHub Automation Suite
Handles blacklisted users for different operations
"""

from pathlib import Path
from typing import Set, List
import logging

class BanManager:
    """Manages ban lists for different GitHub operations"""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.followers_ban_file = self.data_dir / "ban_list_followers.txt"
        self.following_ban_file = self.data_dir / "ban_list_following.txt"
        
        # Ensure data directory exists
        self.data_dir.mkdir(exist_ok=True)
        
        # Ensure ban list files exist
        self._ensure_ban_files_exist()
    
    def _ensure_ban_files_exist(self) -> None:
        """Create ban list files if they don't exist"""
        for ban_file in [self.followers_ban_file, self.following_ban_file]:
            if not ban_file.exists():
                ban_file.touch()
    
    def load_ban_list(self, list_type: str = "followers") -> Set[str]:
        """
        Load ban list from file
        
        Args:
            list_type: Either 'followers' or 'following'
            
        Returns:
            Set of banned usernames
        """
        if list_type == "followers":
            file_path = self.followers_ban_file
        elif list_type == "following":
            file_path = self.following_ban_file
        else:
            raise ValueError("list_type must be 'followers' or 'following'")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                return set(line.strip() for line in file if line.strip())
        except FileNotFoundError:
            return set()
    
    def add_to_ban_list(self, usernames: List[str], list_type: str = "followers") -> None:
        """
        Add usernames to ban list
        
        Args:
            usernames: List of usernames to ban
            list_type: Either 'followers' or 'following'
        """
        current_bans = self.load_ban_list(list_type)
        current_bans.update(usernames)
        self._save_ban_list(current_bans, list_type)
        
        logging.info(f"Added {len(usernames)} users to {list_type} ban list")
    
    def remove_from_ban_list(self, usernames: List[str], list_type: str = "followers") -> None:
        """
        Remove usernames from ban list
        
        Args:
            usernames: List of usernames to remove from ban
            list_type: Either 'followers' or 'following'
        """
        current_bans = self.load_ban_list(list_type)
        current_bans.difference_update(usernames)
        self._save_ban_list(current_bans, list_type)
        
        logging.info(f"Removed {len(usernames)} users from {list_type} ban list")
    
    def _save_ban_list(self, ban_set: Set[str], list_type: str) -> None:
        """Save ban list to file"""
        if list_type == "followers":
            file_path = self.followers_ban_file
        elif list_type == "following":
            file_path = self.following_ban_file
        else:
            raise ValueError("list_type must be 'followers' or 'following'")
        
        with open(file_path, 'w', encoding='utf-8') as file:
            for username in sorted(ban_set):
                file.write(f"{username}\n")
    
    def is_banned(self, username: str, list_type: str = "followers") -> bool:
        """
        Check if a username is banned
        
        Args:
            username: Username to check
            list_type: Either 'followers' or 'following'
            
        Returns:
            True if username is banned, False otherwise
        """
        ban_list = self.load_ban_list(list_type)
        return username in ban_list
    
    def get_ban_stats(self) -> dict:
        """Get statistics about ban lists"""
        followers_bans = self.load_ban_list("followers")
        following_bans = self.load_ban_list("following")
        
        return {
            "followers_banned": len(followers_bans),
            "following_banned": len(following_bans),
            "total_banned": len(followers_bans | following_bans),
            "overlap": len(followers_bans & following_bans)
        }