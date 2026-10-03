#!/usr/bin/env python3
"""
CYBERSPLOI - Advanced Payloads Database Module
Database abstraction layer for 5,000+ pentesting payloads
Handles persistence, optimization, analytics, and evolution
"""

import json
import os
import sqlite3
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set
from collections import Counter
import hashlib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PayloadsDatabase")


class PayloadsDatabase:
    """Advanced database abstraction for pentesting payloads"""
    
    def __init__(self, json_file: str = "pentesting_payloads_5k.json", db_file: str = "payloads.db"):
        """Initialize payloads database"""
        self.json_file = json_file
        self.db_file = db_file
        self.cache = {}
        self.stats_cache = None
        self.stats_timestamp = None
        self.stats_ttl = 3600  # Cache stats for 1 hour
        
        # Initialize database
        self._init_db()
        self._load_from_json()
        
    def _init_db(self):
        """Initialize SQLite database with proper schema"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Create payloads table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY,
                category TEXT NOT NULL,
                payload_text TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hash TEXT UNIQUE NOT NULL,
                effectiveness_score REAL DEFAULT 0.0,
                executed_count INTEGER DEFAULT 0
            )
        """)
        
        # Create category cache table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS category_cache (
                category TEXT PRIMARY KEY,
                total_count INTEGER,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create statistics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY,
                total_payloads INTEGER,
                total_categories INTEGER,
                avg_cvss REAL,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indices
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_category ON payloads(category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_severity ON payloads(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cvss ON payloads(cvss_score)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hash ON payloads(hash)")
        
        conn.commit()
        conn.close()
    
    def _load_from_json(self):
        """Load payloads from JSON file into database"""
        if not os.path.exists(self.json_file):
            logger.error(f"JSON file not found: {self.json_file}")
            return
        
        with open(self.json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Clear existing data
        cursor.execute("DELETE FROM payloads")
        
        total_loaded = 0
        for category, category_data in data.items():
            if category == "metadata":
                continue
            
            if not isinstance(category_data, dict) or 'payloads' not in category_data:
                continue
            
            severity = category_data.get('severity', 'MEDIUM').upper()
            cvss = category_data.get('cvss_base', 5.0)
            description = category_data.get('description', '')
            
            for payload_text in category_data['payloads']:
                payload_hash = hashlib.sha256(f"{category}{payload_text}".encode()).hexdigest()
                
                try:
                    cursor.execute("""
                        INSERT INTO payloads 
                        (category, payload_text, severity, cvss_score, description, hash)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (category, payload_text, severity, cvss, description, payload_hash))
                    total_loaded += 1
                except sqlite3.IntegrityError:
                    # Payload already exists
                    pass
        
        conn.commit()
        
        # Update statistics
        self._update_statistics(conn, cursor)
        conn.close()
        
        logger.info(f"✓ Loaded {total_loaded} payloads into database")
    
    def _update_statistics(self, conn=None, cursor=None):
        """Update database statistics"""
        close_conn = conn is None
        if close_conn:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM payloads")
        total_payloads = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT category) FROM payloads")
        total_categories = cursor.fetchone()[0]
        
        cursor.execute("SELECT AVG(cvss_score) FROM payloads")
        avg_cvss = cursor.fetchone()[0] or 0.0
        
        cursor.execute("DELETE FROM statistics")
        cursor.execute("""
            INSERT INTO statistics (total_payloads, total_categories, avg_cvss)
            VALUES (?, ?, ?)
        """, (total_payloads, total_categories, avg_cvss))
        
        if close_conn:
            conn.commit()
            conn.close()
        
        self.stats_cache = {
            'total_payloads': total_payloads,
            'total_categories': total_categories,
            'avg_cvss': avg_cvss,
            'timestamp': datetime.now()
        }
    
    def get_payload_by_id(self, payload_id: int) -> Optional[Dict]:
        """Get payload by ID"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, category, payload_text, severity, cvss_score, description
            FROM payloads WHERE id = ?
        """, (payload_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return {
                'id': row[0],
                'category': row[1],
                'payload': row[2],
                'severity': row[3],
                'cvss': row[4],
                'description': row[5]
            }
        return None
    
    def get_payloads_by_category(self, category: str, limit: int = None) -> List[Dict]:
        """Get payloads by category"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        if limit:
            cursor.execute("""
                SELECT id, payload_text, severity, cvss_score
                FROM payloads WHERE category = ? LIMIT ?
            """, (category, limit))
        else:
            cursor.execute("""
                SELECT id, payload_text, severity, cvss_score
                FROM payloads WHERE category = ?
            """, (category,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': row[0],
                'payload': row[1],
                'severity': row[2],
                'cvss': row[3],
                'category': category
            }
            for row in rows
        ]
    
    def get_payloads_by_severity(self, severity: str) -> List[Dict]:
        """Get payloads by severity level"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, category, payload_text, cvss_score
            FROM payloads WHERE UPPER(severity) = UPPER(?)
        """, (severity,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': row[0],
                'category': row[1],
                'payload': row[2],
                'cvss': row[3],
                'severity': severity
            }
            for row in rows
        ]
    
    def get_payloads_by_cvss_range(self, min_cvss: float, max_cvss: float) -> List[Dict]:
        """Get payloads within CVSS range"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, category, payload_text, cvss_score, severity
            FROM payloads WHERE cvss_score BETWEEN ? AND ?
            ORDER BY cvss_score DESC
        """, (min_cvss, max_cvss))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': row[0],
                'category': row[1],
                'payload': row[2],
                'cvss': row[3],
                'severity': row[4]
            }
            for row in rows
        ]
    
    def get_high_impact_payloads(self, min_cvss: float = 8.0) -> List[Dict]:
        """Get high-impact payloads (CVSS >= 8.0)"""
        return self.get_payloads_by_cvss_range(min_cvss, 10.0)
    
    def search_payloads(self, query: str) -> List[Dict]:
        """Search payloads by text pattern"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, category, payload_text, severity, cvss_score
            FROM payloads WHERE payload_text LIKE ? OR description LIKE ?
        """, (f"%{query}%", f"%{query}%"))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': row[0],
                'category': row[1],
                'payload': row[2],
                'severity': row[3],
                'cvss': row[4]
            }
            for row in rows
        ]
    
    def record_execution(self, payload_id: int, success: bool):
        """Record payload execution result"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE payloads 
            SET executed_count = executed_count + 1,
                effectiveness_score = effectiveness_score + ?
            WHERE id = ?
        """, (1.0 if success else 0.0, payload_id))
        
        conn.commit()
        conn.close()
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        # Check cache
        if self.stats_cache and (datetime.now() - self.stats_cache['timestamp']).seconds < self.stats_ttl:
            return self.stats_cache
        
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        self._update_statistics(conn, cursor)
        conn.close()
        
        return self.stats_cache
    
    def get_category_statistics(self) -> Dict[str, Dict]:
        """Get statistics per category"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT category, COUNT(*) as total, AVG(cvss_score) as avg_cvss, 
                   MAX(severity) as max_severity
            FROM payloads GROUP BY category ORDER BY total DESC
        """)
        
        rows = cursor.fetchall()
        conn.close()
        
        return {
            row[0]: {
                'total': row[1],
                'avg_cvss': round(row[2], 2) if row[2] else 0,
                'max_severity': row[3]
            }
            for row in rows
        }
    
    def get_effectiveness_report(self, limit: int = 20) -> List[Dict]:
        """Get most effective payloads (by execution success rate)"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, category, payload_text, effectiveness_score, executed_count
            FROM payloads 
            WHERE executed_count > 0
            ORDER BY effectiveness_score DESC, executed_count DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': row[0],
                'category': row[1],
                'payload': row[2],
                'effectiveness': round(row[3], 3),
                'executions': row[4]
            }
            for row in rows
        ]
    
    def export_payloads(self, output_file: str, category: str = None, severity: str = None):
        """Export payloads to file"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        query = "SELECT category, payload_text, severity, cvss_score FROM payloads WHERE 1=1"
        params = []
        
        if category:
            query += " AND category = ?"
            params.append(category)
        
        if severity:
            query += " AND UPPER(severity) = UPPER(?)"
            params.append(severity)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        export_data = {}
        for row in rows:
            cat = row[0]
            if cat not in export_data:
                export_data[cat] = []
            export_data[cat].append({
                'payload': row[1],
                'severity': row[2],
                'cvss': row[3]
            })
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"✓ Exported {sum(len(v) for v in export_data.values())} payloads to {output_file}")
    
    def get_summary(self) -> Dict:
        """Get comprehensive database summary"""
        stats = self.get_statistics()
        category_stats = self.get_category_statistics()
        
        severity_breakdown = {}
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT severity, COUNT(*) FROM payloads GROUP BY severity
        """)
        
        for row in cursor.fetchall():
            severity_breakdown[row[0]] = row[1]
        
        conn.close()
        
        return {
            'total_payloads': stats['total_payloads'],
            'total_categories': stats['total_categories'],
            'avg_cvss': round(stats['avg_cvss'], 2),
            'categories': category_stats,
            'severity_breakdown': severity_breakdown,
            'last_updated': datetime.now().isoformat()
        }


class PayloadAnalytics:
    """Analytics engine for payload performance and insights"""
    
    def __init__(self, db: PayloadsDatabase):
        """Initialize analytics engine"""
        self.db = db
    
    def get_top_payloads_by_category(self, category: str, limit: int = 10) -> List[Dict]:
        """Get top performing payloads in category"""
        payloads = self.db.get_payloads_by_category(category, limit=limit)
        return sorted(payloads, key=lambda x: x['cvss'], reverse=True)[:limit]
    
    def get_category_coverage(self) -> Dict:
        """Get coverage across all categories"""
        stats = self.db.get_category_statistics()
        total = self.db.get_statistics()['total_payloads']
        
        return {
            category: {
                'count': data['total'],
                'percentage': round((data['total'] / total * 100), 1),
                'avg_cvss': data['avg_cvss']
            }
            for category, data in stats.items()
        }
    
    def get_risk_distribution(self) -> Dict:
        """Get distribution of risk levels"""
        conn = sqlite3.connect(self.db.db_file)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN cvss_score >= 9.0 THEN 'CRITICAL'
                    WHEN cvss_score >= 7.0 THEN 'HIGH'
                    WHEN cvss_score >= 4.0 THEN 'MEDIUM'
                    ELSE 'LOW'
                END as risk_level,
                COUNT(*) as count
            FROM payloads
            GROUP BY risk_level
            ORDER BY risk_level DESC
        """)
        
        result = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()
        
        return result
    
    def get_recommendations(self) -> Dict:
        """Get testing recommendations"""
        stats = self.db.get_statistics()
        high_impact = self.db.get_high_impact_payloads()
        
        return {
            'total_payloads': stats['total_payloads'],
            'recommended_test_count': min(100, stats['total_payloads'] // 50),
            'high_impact_count': len(high_impact),
            'avg_cvss': round(stats['avg_cvss'], 2),
            'recommendation': 'Start with high-impact payloads (CVSS >= 8.0) before running full test suite'
        }


def main():
    """Test the database module"""
    print("CYBERSPLOI - Payloads Database Test")
    print("=" * 50)
    
    db = PayloadsDatabase()
    
    print("\n📊 Database Summary:")
    summary = db.get_summary()
    print(f"  Total Payloads: {summary['total_payloads']}")
    print(f"  Categories: {summary['total_categories']}")
    print(f"  Avg CVSS: {summary['avg_cvss']}")
    
    print("\n🎯 Severity Breakdown:")
    for severity, count in summary['severity_breakdown'].items():
        print(f"  {severity}: {count} payloads")
    
    print("\n🔥 Top 5 Categories:")
    categories = sorted(summary['categories'].items(), 
                       key=lambda x: x[1]['total'], reverse=True)[:5]
    for cat, data in categories:
        print(f"  {cat}: {data['total']} payloads (CVSS: {data['avg_cvss']})")
    
    print("\n✅ Database initialized successfully")


if __name__ == "__main__":
    main()
