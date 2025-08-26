"""
PostgreSQL database management for VulnPublisherPro
"""

import json
import logging
import hashlib
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path
import threading

import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages PostgreSQL database operations for vulnerability data"""
    
    def __init__(self, db_connection: str):
        if not db_connection.startswith(('postgresql://', 'postgres://')):
            raise ValueError("Only PostgreSQL databases are supported. Please provide a PostgreSQL connection string.")
        
        self.db_connection = db_connection
        self._local = threading.local()
        
        self.init_database()
    
    def get_connection(self):
        """Get thread-local PostgreSQL database connection"""
        if not hasattr(self._local, 'connection'):
            self._local.connection = psycopg2.connect(
                self.db_connection,
                cursor_factory=psycopg2.extras.RealDictCursor
            )
            self._local.connection.autocommit = False
        
        return self._local.connection
    
    def init_database(self):
        """Initialize PostgreSQL database schema"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Vulnerabilities table
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
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                review_status TEXT DEFAULT 'pending'
            )
        """)
        
        # Publications table
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
        
        # Scraping history table
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
        
        # Configuration table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS configuration (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Content drafts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS content_drafts (
                id SERIAL PRIMARY KEY,
                vulnerability_id INTEGER,
                platform TEXT NOT NULL,
                content_type TEXT NOT NULL,
                content TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id)
            )
        """)
        
        # Add review_status column if it doesn't exist
        cursor.execute("""
            ALTER TABLE vulnerabilities 
            ADD COLUMN IF NOT EXISTS review_status TEXT DEFAULT 'pending'
        """)
        
        # Create indexes for better performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_source ON vulnerabilities(source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published_date ON vulnerabilities(published_date)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_hash ON vulnerabilities(hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vulnerabilities_review_status ON vulnerabilities(review_status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_publications_vulnerability_id ON publications(vulnerability_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_publications_platform ON publications(platform)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scraping_history_source ON scraping_history(source)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_content_drafts_status ON content_drafts(status)")
        
        conn.commit()
        logger.info("PostgreSQL database schema initialized successfully")
    
    def _create_tables(self):
        """Ensure all tables exist (alias for init_database)"""
        self.init_database()
    
    def _generate_hash(self, vulnerability: Dict[str, Any]) -> str:
        """Generate a hash for deduplication"""
        key_data = {
            'cve_id': vulnerability.get('cve_id', ''),
            'title': vulnerability.get('title', ''),
            'description': vulnerability.get('description', ''),
            'source': vulnerability.get('source', '')
        }
        
        content = json.dumps(key_data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
    
    def store_vulnerability(self, vulnerability: Dict[str, Any]) -> bool:
        """Store a vulnerability in the database. Returns True if new, False if updated"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        vuln_hash = self._generate_hash(vulnerability)
        
        # Check if vulnerability already exists
        cursor.execute("SELECT id, updated_at FROM vulnerabilities WHERE hash = %s", (vuln_hash,))
        existing = cursor.fetchone()
        
        # Prepare data
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
            update_sql = """
                UPDATE vulnerabilities SET
                    cve_id = %(cve_id)s, vulnerability_id = %(vulnerability_id)s, title = %(title)s,
                    description = %(description)s, severity = %(severity)s, cvss_score = %(cvss_score)s,
                    cvss_vector = %(cvss_vector)s, cwe_id = %(cwe_id)s, affected_products = %(affected_products)s,
                    reference_urls = %(reference_urls)s, technical_details = %(technical_details)s,
                    impact = %(impact)s, mitigation = %(mitigation)s, exploit_available = %(exploit_available)s,
                    poc_available = %(poc_available)s, source = %(source)s, source_url = %(source_url)s,
                    published_date = %(published_date)s, updated_date = %(updated_date)s,
                    discovered_date = %(discovered_date)s, disclosure_date = %(disclosure_date)s,
                    vendor_response = %(vendor_response)s, tags = %(tags)s, raw_data = %(raw_data)s,
                    hash = %(hash)s, updated_at = %(updated_at)s
                WHERE id = %(id)s
            """
            cursor.execute(update_sql, data)
            conn.commit()
            logger.debug(f"Updated vulnerability: {vulnerability.get('cve_id', 'Unknown')}")
            return False
        else:
            # Insert new vulnerability
            insert_sql = """
                INSERT INTO vulnerabilities (
                    cve_id, vulnerability_id, title, description, severity, cvss_score,
                    cvss_vector, cwe_id, affected_products, reference_urls, technical_details,
                    impact, mitigation, exploit_available, poc_available, source, source_url,
                    published_date, updated_date, discovered_date, disclosure_date,
                    vendor_response, tags, raw_data, hash, updated_at
                ) VALUES (
                    %(cve_id)s, %(vulnerability_id)s, %(title)s, %(description)s, %(severity)s, %(cvss_score)s,
                    %(cvss_vector)s, %(cwe_id)s, %(affected_products)s, %(reference_urls)s, %(technical_details)s,
                    %(impact)s, %(mitigation)s, %(exploit_available)s, %(poc_available)s, %(source)s, %(source_url)s,
                    %(published_date)s, %(updated_date)s, %(discovered_date)s, %(disclosure_date)s,
                    %(vendor_response)s, %(tags)s, %(raw_data)s, %(hash)s, %(updated_at)s
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
        
        if vulnerability_id.isdigit():
            cursor.execute("SELECT * FROM vulnerabilities WHERE id = %s", (vulnerability_id,))
        else:
            cursor.execute("SELECT * FROM vulnerabilities WHERE cve_id = %s", (vulnerability_id,))
        
        row = cursor.fetchone()
        if row:
            return self._row_to_dict(row)
        return None
    
    def get_vulnerabilities(self, severity: Optional[List[str]] = None,
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
        
        if severity:
            severity_placeholders = ','.join(['%s' for _ in severity])
            where_clauses.append(f"severity IN ({severity_placeholders})")
            params.extend(severity)
        
        if sources:
            source_placeholders = ','.join(['%s' for _ in sources])
            where_clauses.append(f"source IN ({source_placeholders})")
            params.extend(sources)
        
        if published_since:
            where_clauses.append("published_date >= %s")
            params.append(published_since.isoformat())
        
        if published_until:
            where_clauses.append("published_date <= %s")
            params.append(published_until.isoformat())
        
        if has_exploit is not None:
            where_clauses.append("exploit_available = %s")
            params.append(has_exploit)
        
        if has_poc is not None:
            where_clauses.append("poc_available = %s")
            params.append(has_poc)
        
        if cve_ids:
            cve_placeholders = ','.join(['%s' for _ in cve_ids])
            where_clauses.append(f"cve_id IN ({cve_placeholders})")
            params.extend(cve_ids)
        
        where_clause = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        sql = f"""
            SELECT * FROM vulnerabilities
            {where_clause}
            ORDER BY published_date DESC, created_at DESC
            LIMIT %s OFFSET %s
        """
        
        params.extend([limit, offset])
        cursor.execute(sql, params)
        
        return [self._row_to_dict(row) for row in cursor.fetchall()]
    
    def store_publication(self, vulnerability_id: int, platform: str, 
                         publication_data: Dict[str, Any]):
        """Store publication record"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
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
        
        conn.commit()
    
    def get_publications(self, vulnerability_id: Optional[int] = None, 
                        platform: Optional[str] = None,
                        limit: int = 100) -> List[Dict[str, Any]]:
        """Get publication records with optional filters"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        where_clauses = []
        params = []
        
        if vulnerability_id:
            where_clauses.append("vulnerability_id = %s")
            params.append(vulnerability_id)
        
        if platform:
            where_clauses.append("platform = %s")
            params.append(platform)
        
        where_clause = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
        
        sql = f"""
            SELECT * FROM publications 
            {where_clause}
            ORDER BY published_at DESC 
            LIMIT %s
        """
        params.append(limit)
        
        cursor.execute(sql, params)
        
        publications = []
        for row in cursor.fetchall():
            pub = dict(row)
            if pub.get('metrics'):
                try:
                    pub['metrics'] = json.loads(pub['metrics'])
                except (json.JSONDecodeError, TypeError):
                    pub['metrics'] = {}
            publications.append(pub)
        
        return publications
    
    def store_scraping_history(self, history_data: Dict[str, Any]):
        """Store scraping history record"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO scraping_history (
                source, scrape_type, vulnerabilities_found, new_vulnerabilities,
                updated_vulnerabilities, errors, started_at, completed_at,
                duration_seconds, status
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            history_data.get('source'),
            history_data.get('scrape_type'),
            history_data.get('vulnerabilities_found', 0),
            history_data.get('new_vulnerabilities', 0),
            history_data.get('updated_vulnerabilities', 0),
            json.dumps(history_data.get('errors', [])),
            history_data.get('started_at'),
            history_data.get('completed_at'),
            history_data.get('duration_seconds'),
            history_data.get('status', 'completed')
        ))
        
        conn.commit()
    
    def get_scraping_history(self, source: Optional[str] = None,
                           limit: int = 100) -> List[Dict[str, Any]]:
        """Get scraping history records"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        if source:
            cursor.execute("""
                SELECT * FROM scraping_history 
                WHERE source = %s 
                ORDER BY completed_at DESC 
                LIMIT %s
            """, (source, limit))
        else:
            cursor.execute("""
                SELECT * FROM scraping_history 
                ORDER BY completed_at DESC 
                LIMIT %s
            """, (limit,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_pending_review_vulnerabilities(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get vulnerabilities that are pending review"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT * FROM vulnerabilities 
                WHERE review_status = 'pending' OR review_status IS NULL
                ORDER BY 
                    CASE severity 
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2  
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    created_at DESC
                LIMIT %s
            """, (limit,))
            
            vulnerabilities = []
            for row in cursor.fetchall():
                vuln = self._row_to_dict(row)
                vulnerabilities.append(vuln)
                
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error getting pending review vulnerabilities: {e}")
            return []
    
    def update_vulnerability_review_status(self, vuln_id: int, status: str, notes: str = None) -> bool:
        """Update vulnerability review status"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                UPDATE vulnerabilities 
                SET review_status = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            """, (status, vuln_id))
            
            conn.commit()
            logger.info(f"Updated vulnerability {vuln_id} review status to {status}")
            return cursor.rowcount > 0
            
        except Exception as e:
            logger.error(f"Error updating vulnerability review status: {e}")
            conn.rollback()
            return False

    def store_generated_content(self, vulnerability_id: int, platform: str, content_type: str, 
                              content: str, status: str = 'pending') -> int:
        """Store generated content for review"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO content_drafts 
                (vulnerability_id, platform, content_type, content, status)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            """, (vulnerability_id, platform, content_type, content, status))
            
            draft_id = cursor.fetchone()[0]
            conn.commit()
            
            logger.info(f"Stored content draft {draft_id} for vulnerability {vulnerability_id}")
            return draft_id
            
        except Exception as e:
            logger.error(f"Error storing generated content: {e}")
            conn.rollback()
            return 0

    def get_content_drafts(self, vulnerability_id: int = None, status: str = None) -> List[Dict[str, Any]]:
        """Get content drafts for review"""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        try:
            query = "SELECT * FROM content_drafts"
            params = []
            conditions = []
            
            if vulnerability_id:
                conditions.append("vulnerability_id = %s")
                params.append(vulnerability_id)
            
            if status:
                conditions.append("status = %s")
                params.append(status)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            query += " ORDER BY created_at DESC"
            
            cursor.execute(query, params)
            
            drafts = []
            for row in cursor.fetchall():
                draft = dict(row)
                drafts.append(draft)
            
            return drafts
            
        except Exception as e:
            logger.error(f"Error getting content drafts: {e}")
            return []
    
    def _row_to_dict(self, row: Any) -> Dict[str, Any]:
        """Convert PostgreSQL row to dictionary"""
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
            result = cursor.fetchone()
            stats['total_vulnerabilities'] = result[0] if result else 0
            
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
            result = cursor.fetchone()
            stats['total_publications'] = result[0] if result else 0
            
            # Get recent activity (last 7 days)
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE created_at >= NOW() - INTERVAL '7 days'")
            result = cursor.fetchone()
            stats['recent_vulnerabilities'] = result[0] if result else 0
            
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            stats['error'] = str(e)
        
        return stats
    
    def backup_database(self, backup_path: str):
        """PostgreSQL database backup not supported via this method"""
        logger.error("PostgreSQL database backup not supported via this method. Use pg_dump instead.")
        return False
    
    def close(self):
        """Close database connections"""
        if hasattr(self._local, 'connection'):
            self._local.connection.close()