#!/usr/bin/env python3
"""
Database Connection Fix for Render Deployment
Adds robust connection handling and automatic reconnection
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
    """Advanced database manager with robust connection handling for follower growth automation"""
    
    def __init__(self, use_postgresql: Optional[bool] = None):
        self.logger = Logger()
        self.use_postgresql = use_postgresql if use_postgresql is not None else bool(os.getenv('DATABASE_URL'))
        self.connection = None
        self.database_url = os.getenv('DATABASE_URL') if self.use_postgresql else None
        
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
            # Fallback to SQLite if PostgreSQL fails
            if self.use_postgresql:
                self.logger.warning("Falling back to SQLite due to PostgreSQL connection failure")
                self.use_postgresql = False
                self.connection = self._connect_sqlite()
            else:
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
            if not self.database_url:
                raise ValueError("DATABASE_URL not found for PostgreSQL connection")
            
            connection = psycopg2.connect(self.database_url)
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
            
            connection = sqlite3.connect(str(db_path), timeout=30.0)
            connection.execute("PRAGMA foreign_keys = ON")
            self.logger.info("Connected to SQLite database")
            return connection
        except Exception as e:
            self.logger.error(f"Failed to connect to SQLite: {e}")
            raise
    
    def _execute_with_retry(self, query, params=None, fetch='none'):
        """Execute query with automatic retry on connection failure"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self._ensure_connection()
                cursor = self.connection.cursor()
                
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                if fetch == 'one':
                    return cursor.fetchone()
                elif fetch == 'all':
                    return cursor.fetchall()
                elif fetch == 'none':
                    if not self.use_postgresql:
                        self.connection.commit()
                    return True
                    
            except Exception as e:
                self.logger.warning(f"Database query failed (attempt {attempt + 1}/{max_retries}): {e}")
                self.connection = None  # Force reconnection
                if attempt == max_retries - 1:
                    raise
        return None
    
    def _initialize_tables(self):
        """Initialize database tables for automation tracking"""
        try:
            # Follow requests tracking table
            if self.use_postgresql:
                self._execute_with_retry("""
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
                
                self._execute_with_retry("CREATE INDEX IF NOT EXISTS idx_follow_requests_username ON follow_requests(username)")
                self._execute_with_retry("CREATE INDEX IF NOT EXISTS idx_follow_requests_status ON follow_requests(status)")
                self._execute_with_retry("CREATE INDEX IF NOT EXISTS idx_follow_requests_expected_date ON follow_requests(expected_followback_date)")
            else:
                self._execute_with_retry("""
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
                
                self._execute_with_retry("CREATE INDEX IF NOT EXISTS idx_follow_requests_username ON follow_requests(username)")
                self._execute_with_retry("CREATE INDEX IF NOT EXISTS idx_follow_requests_status ON follow_requests(status)")
                self._execute_with_retry("CREATE INDEX IF NOT EXISTS idx_follow_requests_expected_date ON follow_requests(expected_followback_date)")
            
            # Automation logs table
            if self.use_postgresql:
                self._execute_with_retry("""
                    CREATE TABLE IF NOT EXISTS automation_logs (
                        id SERIAL PRIMARY KEY,
                        action VARCHAR(50) NOT NULL,
                        username VARCHAR(100),
                        success BOOLEAN NOT NULL,
                        details TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                self._execute_with_retry("CREATE INDEX IF NOT EXISTS idx_automation_logs_timestamp ON automation_logs(timestamp)")
                self._execute_with_retry("CREATE INDEX IF NOT EXISTS idx_automation_logs_action ON automation_logs(action)")
            else:
                self._execute_with_retry("""
                    CREATE TABLE IF NOT EXISTS automation_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        action TEXT NOT NULL,
                        username TEXT,
                        success BOOLEAN NOT NULL,
                        details TEXT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                self._execute_with_retry("CREATE INDEX IF NOT EXISTS idx_automation_logs_timestamp ON automation_logs(timestamp)")
                self._execute_with_retry("CREATE INDEX IF NOT EXISTS idx_automation_logs_action ON automation_logs(action)")
            
            # Damaged users table  
            if self.use_postgresql:
                self._execute_with_retry("""
                    CREATE TABLE IF NOT EXISTS damaged_users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(100) NOT NULL UNIQUE,
                        reason TEXT NOT NULL,
                        retry_count INTEGER DEFAULT 0,
                        final_moon_symbols INTEGER DEFAULT 0,
                        blacklisted_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                self._execute_with_retry("CREATE INDEX IF NOT EXISTS idx_damaged_users_username ON damaged_users(username)")
            else:
                self._execute_with_retry("""
                    CREATE TABLE IF NOT EXISTS damaged_users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        reason TEXT NOT NULL,
                        retry_count INTEGER DEFAULT 0,
                        final_moon_symbols INTEGER DEFAULT 0,
                        blacklisted_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                self._execute_with_retry("CREATE INDEX IF NOT EXISTS idx_damaged_users_username ON damaged_users(username)")
            
            self.logger.info("Database tables initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database tables: {e}")
            raise
    
    def get_automation_stats(self) -> Dict:
        """Get comprehensive automation statistics"""
        try:
            stats = {}
            
            # Follow requests stats
            if self.use_postgresql:
                result = self._execute_with_retry("""
                    SELECT status, COUNT(*) as count 
                    FROM follow_requests 
                    GROUP BY status
                """, fetch='all')
            else:
                result = self._execute_with_retry("""
                    SELECT status, COUNT(*) as count 
                    FROM follow_requests 
                    GROUP BY status
                """, fetch='all')
            
            follow_stats = {row[0]: row[1] for row in (result or [])}
            stats['follow_requests'] = follow_stats
            
            # Damaged users count
            if self.use_postgresql:
                result = self._execute_with_retry("SELECT COUNT(*) FROM damaged_users", fetch='one')
            else:
                result = self._execute_with_retry("SELECT COUNT(*) FROM damaged_users", fetch='one')
            
            stats['damaged_users'] = result[0] if result else 0
            
            # Recent actions (last 7 days)
            week_ago = datetime.now() - timedelta(days=7)
            
            if self.use_postgresql:
                result = self._execute_with_retry("""
                    SELECT action, COUNT(*) as count 
                    FROM automation_logs 
                    WHERE timestamp >= %s 
                    GROUP BY action
                """, (week_ago,), fetch='all')
            else:
                result = self._execute_with_retry("""
                    SELECT action, COUNT(*) as count 
                    FROM automation_logs 
                    WHERE timestamp >= ? 
                    GROUP BY action
                """, (week_ago,), fetch='all')
            
            recent_actions = {row[0]: row[1] for row in (result or [])}
            stats['recent_actions'] = recent_actions
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Failed to get automation stats: {e}")
            return {}
    
    def log_action(self, action: str, username: str, success: bool, details: Optional[str] = None):
        """Log automation actions"""
        try:
            if self.use_postgresql:
                self._execute_with_retry("""
                    INSERT INTO automation_logs (action, username, success, details)
                    VALUES (%s, %s, %s, %s)
                """, (action, username, success, details))
            else:
                self._execute_with_retry("""
                    INSERT INTO automation_logs (action, username, success, details)
                    VALUES (?, ?, ?, ?)
                """, (action, username, success, details))
            
        except Exception as e:
            self.logger.error(f"Failed to log action {action} for {username}: {e}")
    
    def is_damaged_user(self, username: str) -> bool:
        """Check if user is in damaged/blacklist"""
        try:
            if self.use_postgresql:
                result = self._execute_with_retry("SELECT 1 FROM damaged_users WHERE username = %s", (username,), fetch='one')
            else:
                result = self._execute_with_retry("SELECT 1 FROM damaged_users WHERE username = ?", (username,), fetch='one')
            
            return result is not None
            
        except Exception as e:
            self.logger.error(f"Failed to check damaged status for {username}: {e}")
            return False
    
    def close(self):
        """Close database connection"""
        try:
            if self.connection:
                self.connection.close()
                self.connection = None
                self.logger.info("Database connection closed")
        except Exception as e:
            self.logger.error(f"Error closing database connection: {e}")