import sqlite3
import datetime
import os
from typing import List, Dict, Any, Optional

DB_FILE = os.path.join(os.path.dirname(__file__), "phishing_extension.db")

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables for logs, whitelist, and reports."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Scan Logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            risk_score REAL NOT NULL,
            classification TEXT NOT NULL,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 2. Whitelist table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            added_by TEXT DEFAULT 'user',
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 3. Phishing Reports table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT NOT NULL,
            user_comments TEXT,
            status TEXT DEFAULT 'pending',
            reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Populate default whitelisted top domains if empty
    cursor.execute("SELECT COUNT(*) FROM whitelist")
    count = cursor.fetchone()[0]
    if count == 0:
        default_whitelist = [
            "google.com", "github.com", "microsoft.com", "apple.com",
            "youtube.com", "wikipedia.org", "amazon.com", "stackoverflow.com"
        ]
        for domain in default_whitelist:
            cursor.execute("INSERT OR IGNORE INTO whitelist (domain, added_by) VALUES (?, ?)", (domain, "system"))

    conn.commit()
    conn.close()

# Log dynamic scans
def log_scan(url: str, domain: str, risk_score: float, classification: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_logs (url, domain, risk_score, classification) VALUES (?, ?, ?, ?)",
        (url, domain, risk_score, classification)
    )
    conn.commit()
    conn.close()

def get_scan_history(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, url, domain, risk_score, classification, scanned_at FROM scan_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

# Whitelist CRUD operations
def is_whitelisted(domain: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    # Check exact domain or root domain match
    cursor.execute("SELECT id FROM whitelist WHERE domain = ? OR ? LIKE '%.' || domain", (domain.lower(), domain.lower()))
    row = cursor.fetchone()
    conn.close()
    return row is not None

def get_whitelist() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, domain, added_by, added_at FROM whitelist ORDER BY added_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def add_to_whitelist(domain: str, added_by: str = "user") -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO whitelist (domain, added_by) VALUES (?, ?)", (domain.lower().strip(), added_by))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    finally:
        conn.close()
    return success

def remove_from_whitelist(domain: str) -> bool:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM whitelist WHERE domain = ?", (domain.lower().strip(),))
    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()
    return rows_affected > 0

# Phishing Report functions
def create_report(url: str, domain: str, user_comments: Optional[str] = None) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO reports (url, domain, user_comments) VALUES (?, ?, ?)", (url, domain, user_comments))
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return report_id

def get_reports(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, url, domain, user_comments, status, reported_at FROM reports ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM scan_logs")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE classification = 'Phishing'")
    phishing_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE classification = 'Suspicious'")
    suspicious_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM whitelist")
    whitelist_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM reports")
    reports_count = cursor.fetchone()[0]

    conn.close()
    return {
        "total_scans": total_scans,
        "phishing_detected": phishing_count,
        "suspicious_detected": suspicious_count,
        "whitelisted_domains": whitelist_count,
        "user_reports": reports_count
    }
