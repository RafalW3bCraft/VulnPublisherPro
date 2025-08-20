#!/usr/bin/env python3
"""
Database management for GitHub Repository Manager
Handles follower tracking, automation history, and strategic growth data
"""

import os
import sqlite3
import psycopg2
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import json
from .logger import Logger


class DatabaseManager:
    """Advanced database manager for follower growth automation"""
    
    def __init__(self, use_postgresql: Optional[bool] = None):
        self.logger = Logger()
        self.use_postgresql = use_postgresql if use_postgresql is not None else bool(os.getenv('DATABASE_URL'))
        self.connection = None
        
        self._ensure_connection()
        self._initialize_tables()
    
    def _ensure_connection(self):
        """Ensure database connection is active, reconnect if necessary"""
        try:
            if self.connection is None or self._is_connection_closed():
                if self.use_postgresql:
                    self.connection = self._connect_postgresql()
                else:
                    self.connection = self._connect_sqlite()
        except Exception as e:
            self.logger.error(f"Failed to ensure connection: {e}")
            raise
    
    def _is_connection_closed(self):
        """Check if current connection is closed"""
        try:
            if self.connection is None:
                return True
            
            if self.use_postgresql:
                return self.connection.closed != 0
            else:
                # For SQLite, try a simple query
                cursor = self.connection.cursor()
                cursor.execute("SELECT 1")
                return False
        except Exception:
            return True
    
    def _connect_postgresql(self):
        """Connect to PostgreSQL database"""
        try:
            database_url = os.getenv('DATABASE_URL')
            if not database_url:
                raise ValueError("DATABASE_URL not found for PostgreSQL connection")
            
            connection = psycopg2.connect(database_url)
            connection.autocommit = True
            self.logger.info("Connected to PostgreSQL database")
            return connection
        except Exception as e:
            self.logger.error(f"Failed to connect to PostgreSQL: {e}")
            raise
    
    def _connect_sqlite(self):
        """Connect to SQLite database as fallback"""
        try:
            db_path = Path("data/github_automation.db")
            db_path.parent.mkdir(exist_ok=True)
            
            connection = sqlite3.connect(str(db_path))
            connection.execute("PRAGMA foreign_keys = ON")
            self.logger.info("Connected to SQLite database")
            return connection
        except Exception as e:
            self.logger.error(f"Failed to connect to SQLite: {e}")
            raise
    
    def _initialize_tables(self):
        """Initialize database tables for automation tracking"""
        cursor = self.connection.cursor()
        
        try:
            # Follow requests tracking table
            if self.use_postgresql:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS follow_requests (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(100) NOT NULL,
                        follow_date TIMESTAMP NOT NULL,
                        expected_followback_date TIMESTAMP NOT NULL,
                        actual_followback_date TIMESTAMP NULL,
                        unfollow_date TIMESTAMP NULL,
                        status VARCHAR(20) NOT NULL DEFAULT 'pending',
                        stars_count INTEGER DEFAULT 0,
                        retry_count INTEGER DEFAULT 0,
                        moon_symbols INTEGER DEFAULT 0,
                        is_high_value BOOLEAN DEFAULT FALSE,
                        notes TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_follow_requests_username ON follow_requests(username);
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_follow_requests_status ON follow_requests(status);
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_follow_requests_expected_date ON follow_requests(expected_followback_date);
                """)
            else:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS follow_requests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        follow_date TIMESTAMP NOT NULL,
                        expected_followback_date TIMESTAMP NOT NULL,
                        actual_followback_date TIMESTAMP NULL,
                        unfollow_date TIMESTAMP NULL,
                        status TEXT NOT NULL DEFAULT 'pending',
                        stars_count INTEGER DEFAULT 0,
                        retry_count INTEGER DEFAULT 0,
                        moon_symbols INTEGER DEFAULT 0,
                        is_high_value BOOLEAN DEFAULT 0,
                        notes TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_follow_requests_username ON follow_requests(username);
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_follow_requests_status ON follow_requests(status);
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_follow_requests_expected_date ON follow_requests(expected_followback_date);
                """)
            
            # Automation logs table
            if self.use_postgresql:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS automation_logs (
                        id SERIAL PRIMARY KEY,
                        action VARCHAR(50) NOT NULL,
                        username VARCHAR(100) NOT NULL,
                        success BOOLEAN NOT NULL,
                        details TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            else:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS automation_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        action TEXT NOT NULL,
                        username TEXT NOT NULL,
                        success BOOLEAN NOT NULL,
                        details TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            
            # Damaged users blacklist
            if self.use_postgresql:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS damaged_users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(100) NOT NULL UNIQUE,
                        reason TEXT NOT NULL,
                        retry_count INTEGER NOT NULL,
                        final_moon_symbols INTEGER NOT NULL,
                        blacklisted_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            else:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS damaged_users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        reason TEXT NOT NULL,
                        retry_count INTEGER NOT NULL,
                        final_moon_symbols INTEGER NOT NULL,
                        blacklisted_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            
            # Automation settings table
            if self.use_postgresql:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS automation_settings (
                        id SERIAL PRIMARY KEY,
                        setting_name VARCHAR(100) NOT NULL UNIQUE,
                        setting_value TEXT NOT NULL,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            else:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS automation_settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        setting_name TEXT NOT NULL UNIQUE,
                        setting_value TEXT NOT NULL,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            
            if not self.use_postgresql:
                self.connection.commit()
            
            self.logger.info("Database tables initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database tables: {e}")
            raise
    
    def record_follow_request(self, username: str, stars_count: int = 0, 
                            is_high_value: bool = False, notes: Optional[str] = None) -> bool:
        """Record a new follow request"""
        cursor = self.connection.cursor()
        
        try:
            follow_date = datetime.now()
            # High value users (>179 stars) get 90 days, others get 15 days
            wait_days = 90 if is_high_value else 15
            expected_followback_date = follow_date + timedelta(days=wait_days)
            
            if self.use_postgresql:
                cursor.execute("""
                    INSERT INTO follow_requests 
                    (username, follow_date, expected_followback_date, stars_count, is_high_value, notes)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (username) DO UPDATE SET
                        follow_date = EXCLUDED.follow_date,
                        expected_followback_date = EXCLUDED.expected_followback_date,
                        status = 'pending',
                        retry_count = follow_requests.retry_count + 1,
                        updated_at = CURRENT_TIMESTAMP
                """, (username, follow_date, expected_followback_date, stars_count, is_high_value, notes))
            else:
                cursor.execute("""
                    INSERT OR REPLACE INTO follow_requests 
                    (username, follow_date, expected_followback_date, stars_count, is_high_value, notes, retry_count)
                    VALUES (?, ?, ?, ?, ?, ?, 
                            COALESCE((SELECT retry_count + 1 FROM follow_requests WHERE username = ?), 0))
                """, (username, follow_date, expected_followback_date, stars_count, is_high_value, notes, username))
                self.connection.commit()
            
            self.log_action("follow_request", username, True, 
                          f"Recorded follow request, wait period: {wait_days} days")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to record follow request for {username}: {e}")
            return False
    
    def update_followback_status(self, username: str, followed_back: bool) -> bool:
        """Update followback status for a user"""
        cursor = self.connection.cursor()
        
        try:
            if followed_back:
                if self.use_postgresql:
                    cursor.execute("""
                        UPDATE follow_requests 
                        SET actual_followback_date = %s, status = 'followed_back', updated_at = %s
                        WHERE username = %s AND status = 'pending'
                    """, (datetime.now(), datetime.now(), username))
                else:
                    cursor.execute("""
                        UPDATE follow_requests 
                        SET actual_followback_date = ?, status = 'followed_back', updated_at = ?
                        WHERE username = ? AND status = 'pending'
                    """, (datetime.now(), datetime.now(), username))
                    self.connection.commit()
                
                self.log_action("followback_confirmed", username, True, "User followed back")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update followback status for {username}: {e}")
            return False
    
    def get_expired_follow_requests(self) -> List[Dict]:
        """Get follow requests that have expired and need unfollowing"""
        cursor = self.connection.cursor()
        
        try:
            current_time = datetime.now()
            
            if self.use_postgresql:
                cursor.execute("""
                    SELECT username, follow_date, expected_followback_date, stars_count, 
                           is_high_value, retry_count, moon_symbols
                    FROM follow_requests 
                    WHERE status = 'pending' AND expected_followback_date <= %s
                    ORDER BY expected_followback_date ASC
                """, (current_time,))
            else:
                cursor.execute("""
                    SELECT username, follow_date, expected_followback_date, stars_count, 
                           is_high_value, retry_count, moon_symbols
                    FROM follow_requests 
                    WHERE status = 'pending' AND expected_followback_date <= ?
                    ORDER BY expected_followback_date ASC
                """, (current_time,))
            
            results = cursor.fetchall()
            
            if self.use_postgresql:
                columns = [desc[0] for desc in cursor.description] if cursor.description else []
                return [dict(zip(columns, row)) for row in results]
            else:
                return [
                    {
                        'username': row[0],
                        'follow_date': row[1],
                        'expected_followback_date': row[2],
                        'stars_count': row[3],
                        'is_high_value': row[4],
                        'retry_count': row[5],
                        'moon_symbols': row[6]
                    }
                    for row in results
                ]
            
        except Exception as e:
            self.logger.error(f"Failed to get expired follow requests: {e}")
            return []
    
    def mark_unfollowed(self, username: str, add_moon: bool = False) -> bool:
        """Mark a user as unfollowed and optionally add moon symbol"""
        cursor = self.connection.cursor()
        
        try:
            moon_increment = 1 if add_moon else 0
            
            if self.use_postgresql:
                cursor.execute("""
                    UPDATE follow_requests 
                    SET unfollow_date = %s, status = 'unfollowed', 
                        moon_symbols = moon_symbols + %s, updated_at = %s
                    WHERE username = %s
                """, (datetime.now(), moon_increment, datetime.now(), username))
            else:
                cursor.execute("""
                    UPDATE follow_requests 
                    SET unfollow_date = ?, status = 'unfollowed', 
                        moon_symbols = moon_symbols + ?, updated_at = ?
                    WHERE username = ?
                """, (datetime.now(), moon_increment, datetime.now(), username))
                self.connection.commit()
            
            self.log_action("unfollowed", username, True, 
                          f"Unfollowed user, moon added: {add_moon}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to mark {username} as unfollowed: {e}")
            return False
    
    def add_to_damaged_list(self, username: str, retry_count: int, moon_symbols: int, 
                          reason: str = "Multiple unsuccessful follow attempts") -> bool:
        """Add user to damaged/blacklist"""
        cursor = self.connection.cursor()
        
        try:
            if self.use_postgresql:
                cursor.execute("""
                    INSERT INTO damaged_users (username, reason, retry_count, final_moon_symbols)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (username) DO UPDATE SET
                        retry_count = EXCLUDED.retry_count,
                        final_moon_symbols = EXCLUDED.final_moon_symbols,
                        blacklisted_date = CURRENT_TIMESTAMP
                """, (username, reason, retry_count, moon_symbols))
            else:
                cursor.execute("""
                    INSERT OR REPLACE INTO damaged_users (username, reason, retry_count, final_moon_symbols)
                    VALUES (?, ?, ?, ?)
                """, (username, reason, retry_count, moon_symbols))
                self.connection.commit()
            
            # Also write to damaged.txt file for backward compatibility
            damaged_file = Path("data/damaged.txt")
            damaged_file.parent.mkdir(exist_ok=True)
            
            with open(damaged_file, "a", encoding="utf-8") as f:
                f.write(f"{username} # {moon_symbols}🌙 - {reason} - {datetime.now().strftime('%Y-%m-%d')}\n")
            
            self.log_action("blacklisted", username, True, 
                          f"Added to damaged list: {moon_symbols} moon symbols")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add {username} to damaged list: {e}")
            return False
    
    def is_damaged_user(self, username: str) -> bool:
        """Check if user is in damaged/blacklist"""
        cursor = self.connection.cursor()
        
        try:
            if self.use_postgresql:
                cursor.execute("SELECT 1 FROM damaged_users WHERE username = %s", (username,))
            else:
                cursor.execute("SELECT 1 FROM damaged_users WHERE username = ?", (username,))
            
            return cursor.fetchone() is not None
            
        except Exception as e:
            self.logger.error(f"Failed to check damaged status for {username}: {e}")
            return False
    
    def log_action(self, action: str, username: str, success: bool, details: Optional[str] = None):
        """Log automation actions"""
        self._ensure_connection()
        cursor = self.connection.cursor()
        
        try:
            if self.use_postgresql:
                cursor.execute("""
                    INSERT INTO automation_logs (action, username, success, details)
                    VALUES (%s, %s, %s, %s)
                """, (action, username, success, details))
            else:
                cursor.execute("""
                    INSERT INTO automation_logs (action, username, success, details)
                    VALUES (?, ?, ?, ?)
                """, (action, username, success, details))
                self.connection.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to log action {action} for {username}: {e}")
    
    def get_automation_stats(self) -> Dict:
        """Get comprehensive automation statistics"""
        self._ensure_connection()
        cursor = self.connection.cursor()
        
        try:
            stats = {}
            
            # Follow requests stats
            if self.use_postgresql:
                cursor.execute("""
                    SELECT status, COUNT(*) as count 
                    FROM follow_requests 
                    GROUP BY status
                """)
            else:
                cursor.execute("""
                    SELECT status, COUNT(*) as count 
                    FROM follow_requests 
                    GROUP BY status
                """)
            
            follow_stats = {row[0]: row[1] for row in cursor.fetchall()}
            stats['follow_requests'] = follow_stats
            
            # Damaged users count
            if self.use_postgresql:
                cursor.execute("SELECT COUNT(*) FROM damaged_users")
            else:
                cursor.execute("SELECT COUNT(*) FROM damaged_users")
            
            result = cursor.fetchone()
            stats['damaged_users'] = result[0] if result else 0
            
            # Recent actions (last 7 days)
            week_ago = datetime.now() - timedelta(days=7)
            
            if self.use_postgresql:
                cursor.execute("""
                    SELECT action, COUNT(*) as count 
                    FROM automation_logs 
                    WHERE timestamp >= %s 
                    GROUP BY action
                """, (week_ago,))
            else:
                cursor.execute("""
                    SELECT action, COUNT(*) as count 
                    FROM automation_logs 
                    WHERE timestamp >= ? 
                    GROUP BY action
                """, (week_ago,))
            
            recent_actions = {row[0]: row[1] for row in cursor.fetchall()}
            stats['recent_actions'] = recent_actions
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get automation stats: {e}")
            return {}
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.logger.info("Database connection closed")