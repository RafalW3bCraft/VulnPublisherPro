"""
Database management for VulnPublisherPro
"""

import sqlite3
import json
import logging
import hashlib
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path
import threading

try:
    import psycopg2
    import psycopg2.extras
    POSTGRES_AVAILABLE = True
except ImportError:
    psycopg2 = None
    POSTGRES_AVAILABLE = False

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages database operations for vulnerability data - supports both SQLite and PostgreSQL"""
    
    def __init__(self, db_connection: str = "vulnpublisher.db"):
        self.db_connection = db_connection
        self.is_postgres = db_connection.startswith(('postgresql://', 'postgres://'))
        self._local = threading.local()
        
        if self.is_postgres and not POSTGRES_AVAILABLE:
            raise ImportError("PostgreSQL support requires psycopg2-binary package")
        
        self.init_database()
    
    def get_connection(self):
        """Get thread-local database connection"""
        if not hasattr(self._local, 'connection'):
            if self.is_postgres:
                if psycopg2 is None:
                    raise ImportError("PostgreSQL support requires psycopg2-binary package")
                self._local.connection = psycopg2.connect(
                    self.db_connection,
                    cursor_factory=psycopg2.extras.RealDictCursor
                )
                self._local.connection.autocommit = False
            else:
                Path(self.db_connection).parent.mkdir(parents=True, exist_ok=True)
                self._local.connection = sqlite3.connect(
                    self.db_connection,
                    timeout=30.0,
                    check_same_thread=False
                )
                self._local.connection.row_factory = sqlite3.Row
                # Enable WAL mode for better concurrency
                self._local.connection.execute("PRAGMA journal_mode=WAL")
                self._local.connection.execute("PRAGMA synchronous=NORMAL")
                self._local.connection.execute("PRAGMA cache_size=10000")
                self._local.connection.execute("PRAGMA temp_store=memory")
        
        return self._local.connection
    
    def init_database(self):
        """Initialize database schema"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Vulnerabilities table
        if self.is_postgres:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id SERIAL PRIMARY KEY,
                    cve_id TEXT UNIQUE,
                    vulnerability_id TEXT,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    cwe_id TEXT,
                    affected_products TEXT, -- JSON array
                    reference_urls TEXT, -- JSON array
                    technical_details TEXT,
                    impact TEXT,
                    mitigation TEXT,
                    exploit_available BOOLEAN DEFAULT FALSE,
                    poc_available BOOLEAN DEFAULT FALSE,
                    source TEXT NOT NULL,
                    source_url TEXT,
                    published_date TEXT,
                    updated_date TEXT,
                    discovered_date TEXT,
                    disclosure_date TEXT,
                    vendor_response TEXT,
                    tags TEXT, -- JSON array
                    raw_data TEXT, -- JSON of original data
                    hash TEXT UNIQUE, -- For deduplication
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT UNIQUE,
                    vulnerability_id TEXT,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    cwe_id TEXT,
                    affected_products TEXT, -- JSON array
                    reference_urls TEXT, -- JSON array
                    technical_details TEXT,
                    impact TEXT,
                    mitigation TEXT,
                    exploit_available BOOLEAN DEFAULT FALSE,
                    poc_available BOOLEAN DEFAULT FALSE,
                    source TEXT NOT NULL,
                    source_url TEXT,
                    published_date TEXT,
                    updated_date TEXT,
                    discovered_date TEXT,
                    disclosure_date TEXT,
                    vendor_response TEXT,
                    tags TEXT, -- JSON array
                    raw_data TEXT, -- JSON of original data
                    hash TEXT UNIQUE, -- For deduplication
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
        
        # Publications table - tracks where vulnerabilities have been published
        if self.is_postgres:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS publications (
                    id SERIAL PRIMARY KEY,
                    vulnerability_id INTEGER,
                    platform TEXT NOT NULL,
                    platform_post_id TEXT,
                    content_type TEXT,
                    content TEXT,
                    status TEXT DEFAULT 'published',
                    published_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metrics TEXT, -- JSON of engagement metrics
                    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id)
                )
            """)
        else:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS publications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vulnerability_id INTEGER,
                    platform TEXT NOT NULL,
                    platform_post_id TEXT,
                    content_type TEXT,
                    content TEXT,
                    status TEXT DEFAULT 'published',
                    published_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    metrics TEXT, -- JSON of engagement metrics
                    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id)
                )
            """)
        
        # Scraping history table
        if self.is_postgres:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scraping_history (
                    id SERIAL PRIMARY KEY,
                    source TEXT NOT NULL,
                    scrape_type TEXT,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    new_vulnerabilities INTEGER DEFAULT 0,
                    updated_vulnerabilities INTEGER DEFAULT 0,
                    errors TEXT, -- JSON array of errors
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    duration_seconds REAL,
                    status TEXT DEFAULT 'completed'
                )
            """)
        else:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scraping_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    scrape_type TEXT,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    new_vulnerabilities INTEGER DEFAULT 0,
                    updated_vulnerabilities INTEGER DEFAULT 0,
                    errors TEXT, -- JSON array of errors
                    started_at TEXT,
                    completed_at TEXT,
                    duration_seconds REAL,
                    status TEXT DEFAULT 'completed'
                )
            """)
        
        # Configuration table for persistent settings
        if self.is_postgres:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS configuration (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS configuration (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
        
        # Create indexes for better performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_source ON vulnerabilities(source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published_date ON vulnerabilities(published_date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_hash ON vulnerabilities(hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_publications_vulnerability_id ON publications(vulnerability_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_publications_platform ON publications(platform)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scraping_history_source ON scraping_history(source)")
        
        conn.commit()
        logger.info("Database initialized successfully")
    
    def _generate_hash(self, vulnerability: Dict[str, Any]) -> str:
        """Generate a hash for deduplication"""
        # Use key fields to generate a unique hash
        key_data = {
            'cve_id': vulnerability.get('cve_id', ''),
            'title': vulnerability.get('title', ''),
            'description': vulnerability.get('description', ''),
            'source': vulnerability.get('source', '')
        }
        
        content = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def store_vulnerability(self, vulnerability: Dict[str, Any]) -> bool:
        """
        Store a vulnerability in the database
        Returns True if it's a new vulnerability, False if updated
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Generate hash for deduplication
        vuln_hash = self._generate_hash(vulnerability)
        
        # Check if vulnerability already exists  
        if self.is_postgres:
            cursor.execute("SELECT id, updated_at FROM vulnerabilities WHERE hash = %s", (vuln_hash,))
        else:
            cursor.execute("SELECT id, updated_at FROM vulnerabilities WHERE hash = ?", (vuln_hash,))
        existing = cursor.fetchone()
        
        # Prepare data for insertion/update
        data = {
            'cve_id': vulnerability.get('cve_id'),
            'vulnerability_id': vulnerability.get('vulnerability_id'),
            'title': vulnerability.get('title', ''),
            'description': vulnerability.get('description', ''),
            'severity': vulnerability.get('severity', '').lower() if vulnerability.get('severity') else None,
            'cvss_score': vulnerability.get('cvss_score'),
            'cvss_vector': vulnerability.get('cvss_vector'),
            'cwe_id': vulnerability.get('cwe_id'),
            'affected_products': json.dumps(vulnerability.get('affected_products', [])),
            'reference_urls': json.dumps(vulnerability.get('references', [])),
            'technical_details': vulnerability.get('technical_details'),
            'impact': vulnerability.get('impact'),
            'mitigation': vulnerability.get('mitigation'),
            'exploit_available': vulnerability.get('exploit_available', False),
            'poc_available': vulnerability.get('poc_available', False),
            'source': vulnerability.get('source', ''),
            'source_url': vulnerability.get('source_url'),
            'published_date': vulnerability.get('published_date'),
            'updated_date': vulnerability.get('updated_date'),
            'discovered_date': vulnerability.get('discovered_date'),
            'disclosure_date': vulnerability.get('disclosure_date'),
            'vendor_response': vulnerability.get('vendor_response'),
            'tags': json.dumps(vulnerability.get('tags', [])),
            'raw_data': json.dumps(vulnerability),
            'hash': vuln_hash,
            'updated_at': datetime.now().isoformat()
        }
        
        if existing:
            # Update existing vulnerability
            data['id'] = dict(existing)['id']
            
            if self.is_postgres:
                update_sql = """
                    UPDATE vulnerabilities SET
                        cve_id = %s,
                        vulnerability_id = %s,
                        title = %s,
                        description = %s,
                        severity = %s,
                        cvss_score = %s,
                        cvss_vector = %s,
                        cwe_id = %s,
                        affected_products = %s,
                        reference_urls = %s,
                        technical_details = %s,
                        impact = %s,
                        mitigation = %s,
                        exploit_available = %s,
                        poc_available = %s,
                        source = %s,
                        source_url = %s,
                        published_date = %s,
                        updated_date = %s,
                        discovered_date = %s,
                        disclosure_date = %s,
                        vendor_response = %s,
                        tags = %s,
                        raw_data = %s,
                        updated_at = %s
                    WHERE id = %s
                """
                
                cursor.execute(update_sql, (
                    data['cve_id'], data['vulnerability_id'], data['title'], data['description'],
                    data['severity'], data['cvss_score'], data['cvss_vector'], data['cwe_id'],
                    data['affected_products'], data['reference_urls'], data['technical_details'],
                    data['impact'], data['mitigation'], data['exploit_available'], data['poc_available'],
                    data['source'], data['source_url'], data['published_date'], data['updated_date'],
                    data['discovered_date'], data['disclosure_date'], data['vendor_response'],
                    data['tags'], data['raw_data'], data['updated_at'], data['id']
                ))
            else:
                update_sql = """
                    UPDATE vulnerabilities SET
                        cve_id = :cve_id,
                        vulnerability_id = :vulnerability_id,
                        title = :title,
                        description = :description,
                        severity = :severity,
                        cvss_score = :cvss_score,
                        cvss_vector = :cvss_vector,
                        cwe_id = :cwe_id,
                        affected_products = :affected_products,
                        reference_urls = :reference_urls,
                        technical_details = :technical_details,
                        impact = :impact,
                        mitigation = :mitigation,
                        exploit_available = :exploit_available,
                        poc_available = :poc_available,
                        source = :source,
                        source_url = :source_url,
                        published_date = :published_date,
                        updated_date = :updated_date,
                        discovered_date = :discovered_date,
                        disclosure_date = :disclosure_date,
                        vendor_response = :vendor_response,
                        tags = :tags,
                        raw_data = :raw_data,
                        updated_at = :updated_at
                    WHERE id = :id
                """
                
                cursor.execute(update_sql, data)
            conn.commit()
            logger.debug(f"Updated vulnerability: {vulnerability.get('cve_id', 'Unknown')}")
            return False
        else:
            # Insert new vulnerability
            if self.is_postgres:
                insert_sql = """
                    INSERT INTO vulnerabilities (
                        cve_id, vulnerability_id, title, description, severity,
                        cvss_score, cvss_vector, cwe_id, affected_products, reference_urls,
                        technical_details, impact, mitigation, exploit_available, poc_available,
                        source, source_url, published_date, updated_date, discovered_date,
                        disclosure_date, vendor_response, tags, raw_data, hash, updated_at
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s
                    )
                """
                
                cursor.execute(insert_sql, (
                    data['cve_id'], data['vulnerability_id'], data['title'], data['description'],
                    data['severity'], data['cvss_score'], data['cvss_vector'], data['cwe_id'],
                    data['affected_products'], data['reference_urls'], data['technical_details'],
                    data['impact'], data['mitigation'], data['exploit_available'], data['poc_available'],
                    data['source'], data['source_url'], data['published_date'], data['updated_date'],
                    data['discovered_date'], data['disclosure_date'], data['vendor_response'],
                    data['tags'], data['raw_data'], data['hash'], data['updated_at']
                ))
            else:
                insert_sql = """
                    INSERT INTO vulnerabilities (
                        cve_id, vulnerability_id, title, description, severity,
                        cvss_score, cvss_vector, cwe_id, affected_products, reference_urls,
                        technical_details, impact, mitigation, exploit_available, poc_available,
                        source, source_url, published_date, updated_date, discovered_date,
                        disclosure_date, vendor_response, tags, raw_data, hash, updated_at
                    ) VALUES (
                        :cve_id, :vulnerability_id, :title, :description, :severity,
                        :cvss_score, :cvss_vector, :cwe_id, :affected_products, :reference_urls,
                        :technical_details, :impact, :mitigation, :exploit_available, :poc_available,
                        :source, :source_url, :published_date, :updated_date, :discovered_date,
                        :disclosure_date, :vendor_response, :tags, :raw_data, :hash, :updated_at
                    )
                """
                
                cursor.execute(insert_sql, data)
            conn.commit()
            logger.debug(f"Stored new vulnerability: {vulnerability.get('cve_id', 'Unknown')}")
            return True
    
    def get_vulnerability(self, vulnerability_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific vulnerability by ID or CVE ID"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Try by database ID first, then by CVE ID
        if self.is_postgres:
            if vulnerability_id.isdigit():
                cursor.execute("SELECT * FROM vulnerabilities WHERE id = %s", (vulnerability_id,))
            else:
                cursor.execute("SELECT * FROM vulnerabilities WHERE cve_id = %s", (vulnerability_id,))
        else:
            if vulnerability_id.isdigit():
                cursor.execute("SELECT * FROM vulnerabilities WHERE id = ?", (vulnerability_id,))
            else:
                cursor.execute("SELECT * FROM vulnerabilities WHERE cve_id = ?", (vulnerability_id,))
        
        row = cursor.fetchone()
        if row:
            return self._row_to_dict(row)
        return None
    
    def get_vulnerabilities(self, 
                          severity: Optional[List[str]] = None,
                          sources: Optional[List[str]] = None,
                          limit: int = 100,
                          offset: int = 0,
                          published_since: Optional[datetime] = None,
                          published_until: Optional[datetime] = None,
                          has_exploit: Optional[bool] = None,
                          has_poc: Optional[bool] = None,
                          cve_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Get vulnerabilities with various filters"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        where_clauses = []
        params = []
        
        placeholder = "%s" if self.is_postgres else "?"
        
        if severity:
            severity_placeholders = ','.join([placeholder for _ in severity])
            where_clauses.append(f"severity IN ({severity_placeholders})")
            params.extend(severity)
        
        if sources:
            source_placeholders = ','.join([placeholder for _ in sources])
            where_clauses.append(f"source IN ({source_placeholders})")
            params.extend(sources)
        
        if published_since:
            where_clauses.append(f"published_date >= {placeholder}")
            params.append(published_since.isoformat())
        
        if published_until:
            where_clauses.append(f"published_date <= {placeholder}")
            params.append(published_until.isoformat())
        
        if has_exploit is not None:
            where_clauses.append(f"exploit_available = {placeholder}")
            params.append(has_exploit)
        
        if has_poc is not None:
            where_clauses.append(f"poc_available = {placeholder}")
            params.append(has_poc)
        
        if cve_ids:
            cve_placeholders = ','.join([placeholder for _ in cve_ids])
            where_clauses.append(f"cve_id IN ({cve_placeholders})")
            params.extend(cve_ids)
        
        where_clause = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        sql = f"""
            SELECT * FROM vulnerabilities
            {where_clause}
            ORDER BY published_date DESC, created_at DESC
            LIMIT {placeholder} OFFSET {placeholder}
        """
        
        params.extend([limit, offset])
        cursor.execute(sql, params)
        
        return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    def store_publication(self, vulnerability_id: int, platform: str, 
                         publication_data: Dict[str, Any]):
        """Store publication record"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if self.is_postgres:
            cursor.execute("""
                INSERT INTO publications (
                    vulnerability_id, platform, platform_post_id, content_type,
                    content, status, metrics
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                vulnerability_id,
                platform,
                publication_data.get('post_id'),
                publication_data.get('content_type'),
                publication_data.get('content'),
                publication_data.get('status', 'published'),
                json.dumps(publication_data.get('metrics', {}))
            ))
        else:
            cursor.execute("""
                INSERT INTO publications (
                    vulnerability_id, platform, platform_post_id, content_type,
                    content, status, metrics
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                vulnerability_id,
                platform,
                publication_data.get('post_id'),
                publication_data.get('content_type'),
                publication_data.get('content'),
                publication_data.get('status', 'published'),
                json.dumps(publication_data.get('metrics', {}))
            ))
        
        conn.commit()
    
    def get_publications(self, vulnerability_id: Optional[int] = None, 
                        platform: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get publication records"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        where_clauses = []
        params = []
        
        if vulnerability_id:
            where_clauses.append("vulnerability_id = ?")
            params.append(vulnerability_id)
        
        if platform:
            where_clauses.append("platform = ?")
            params.append(platform)
        
        where_clause = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        sql = f"""
            SELECT p.*, v.cve_id, v.title 
            FROM publications p
            LEFT JOIN vulnerabilities v ON p.vulnerability_id = v.id
            {where_clause}
            ORDER BY published_at DESC
        """
        
        cursor.execute(sql, params)
        return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    def store_scraping_history(self, source: str, scrape_data: Dict[str, Any]):
        """Store scraping history record"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if self.is_postgres:
            cursor.execute("""
                INSERT INTO scraping_history (
                    source, scrape_type, vulnerabilities_found, new_vulnerabilities,
                    updated_vulnerabilities, errors, started_at, completed_at,
                    duration_seconds, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                source,
                scrape_data.get('scrape_type'),
                scrape_data.get('vulnerabilities_found', 0),
                scrape_data.get('new_vulnerabilities', 0),
                scrape_data.get('updated_vulnerabilities', 0),
                json.dumps(scrape_data.get('errors', [])),
                scrape_data.get('started_at'),
                scrape_data.get('completed_at'),
                scrape_data.get('duration_seconds'),
                scrape_data.get('status', 'completed')
            ))
        else:
            cursor.execute("""
                INSERT INTO scraping_history (
                    source, scrape_type, vulnerabilities_found, new_vulnerabilities,
                    updated_vulnerabilities, errors, started_at, completed_at,
                    duration_seconds, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                source,
                scrape_data.get('scrape_type'),
                scrape_data.get('vulnerabilities_found', 0),
                scrape_data.get('new_vulnerabilities', 0),
                scrape_data.get('updated_vulnerabilities', 0),
                json.dumps(scrape_data.get('errors', [])),
                scrape_data.get('started_at'),
                scrape_data.get('completed_at'),
                scrape_data.get('duration_seconds'),
                scrape_data.get('status', 'completed')
            ))
        
        conn.commit()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        stats = {}
        
        # Total vulnerabilities
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        result = cursor.fetchone()
        stats['total_vulnerabilities'] = result[0] if result else 0
        
        # Vulnerabilities by severity
        cursor.execute("""
            SELECT severity, COUNT(*) 
            FROM vulnerabilities 
            WHERE severity IS NOT NULL 
            GROUP BY severity
        """)
        stats['by_severity'] = dict(cursor.fetchall())
        
        # Vulnerabilities by source
        cursor.execute("""
            SELECT source, COUNT(*) 
            FROM vulnerabilities 
            GROUP BY source 
            ORDER BY COUNT(*) DESC
        """)
        stats['by_source'] = dict(cursor.fetchall())
        
        # Recent activity (last 7 days)
        week_ago = (datetime.now() - timedelta(days=7)).isoformat()
        if self.is_postgres:
            cursor.execute("""
                SELECT DATE(created_at) as date, COUNT(*) 
                FROM vulnerabilities 
                WHERE created_at >= %s 
                GROUP BY DATE(created_at) 
                ORDER BY date
            """, (week_ago,))
        else:
            cursor.execute("""
                SELECT DATE(created_at) as date, COUNT(*) 
                FROM vulnerabilities 
                WHERE created_at >= ? 
                GROUP BY DATE(created_at) 
                ORDER BY date
            """, (week_ago,))
        stats['recent_activity'] = dict(cursor.fetchall())
        
        # Publications by platform
        cursor.execute("""
            SELECT platform, COUNT(*) 
            FROM publications 
            GROUP BY platform 
            ORDER BY COUNT(*) DESC
        """)
        stats['publications_by_platform'] = dict(cursor.fetchall())
        
        return stats
    
    def cleanup_old_data(self, days_to_keep: int = 365):
        """Clean up old data to maintain database size"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cutoff_date = (datetime.now() - timedelta(days=days_to_keep)).isoformat()
        
        # Clean up old scraping history
        cursor.execute("DELETE FROM scraping_history WHERE completed_at < ?", (cutoff_date,))
        scraping_deleted = cursor.rowcount
        
        # Clean up old publications for vulnerabilities that no longer exist
        cursor.execute("""
            DELETE FROM publications 
            WHERE vulnerability_id NOT IN (SELECT id FROM vulnerabilities)
        """)
        publications_deleted = cursor.rowcount
        
        conn.commit()
        
        logger.info(f"Cleaned up {scraping_deleted} old scraping records and {publications_deleted} orphaned publications")
        
        return {
            'scraping_records_deleted': scraping_deleted,
            'publications_deleted': publications_deleted
        }
    
    def reset_database(self):
        """Reset the entire database (WARNING: Deletes all data)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        tables = ['publications', 'vulnerabilities', 'scraping_history', 'configuration']
        
        for table in tables:
            cursor.execute(f"DELETE FROM {table}")
        
        conn.commit()
        logger.warning("Database has been reset - all data deleted")
    
    def _row_to_dict(self, row: Any) -> Dict[str, Any]:
        """Convert SQLite row to dictionary"""
        result = dict(row)
        
        # Parse JSON fields
        json_fields = ['affected_products', 'reference_urls', 'tags', 'raw_data', 'metrics']
        for field in json_fields:
            if field in result and result[field]:
                try:
                    result[field] = json.loads(result[field])
                except (json.JSONDecodeError, TypeError):
                    result[field] = []
        
        # Map database column names to expected API names
        if 'reference_urls' in result:
            result['references'] = result['reference_urls']
            del result['reference_urls']
        
        return result
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        stats = {}
        
        try:
            # Get vulnerability count
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            stats['total_vulnerabilities'] = cursor.fetchone()[0]
            
            # Get vulnerabilities by severity
            cursor.execute("SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity")
            severity_stats = {}
            for row in cursor.fetchall():
                severity_stats[row[0] or 'unknown'] = row[1]
            stats['by_severity'] = severity_stats
            
            # Get vulnerabilities by source
            cursor.execute("SELECT source, COUNT(*) FROM vulnerabilities GROUP BY source ORDER BY COUNT(*) DESC")
            source_stats = {}
            for row in cursor.fetchall():
                source_stats[row[0]] = row[1]
            stats['by_source'] = source_stats
            
            # Get publication count
            cursor.execute("SELECT COUNT(*) FROM publications")
            stats['total_publications'] = cursor.fetchone()[0]
            
            # Get recent activity (last 7 days)
            if self.is_postgres:
                cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE created_at >= NOW() - INTERVAL '7 days'")
            else:
                cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE created_at >= datetime('now', '-7 days')")
            stats['recent_vulnerabilities'] = cursor.fetchone()[0]
            
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            stats['error'] = str(e)
        
        return stats
    
    def backup_database(self, backup_path: str):
        """Create a backup of the database"""
        import shutil
        
        try:
            if self.is_postgres:
                logger.error("PostgreSQL database backup not supported via this method")
                return False
            shutil.copy2(self.db_connection, backup_path)
            logger.info(f"Database backed up to {backup_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to backup database: {e}")
            return False
    
    def close(self):
        """Close database connections"""
        if hasattr(self._local, 'connection'):
            self._local.connection.close()
