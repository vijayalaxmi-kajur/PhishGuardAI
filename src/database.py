"""PhishGuardAI - SQLite Scan History Database Interface

Manages persistent storage of URL scan results, verdicts, probabilities, and timestamps.
Uses Python's standard library sqlite3 module with strict parameterization and safe
connection lifecycles.
"""

import os
import sqlite3
import datetime
from contextlib import contextmanager
from typing import Optional, List, Dict, Any, Generator

# Project Root resolution
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
DEFAULT_DB_PATH = os.path.join(PROJECT_ROOT, "data", "scan_history.db")


def get_db_path(db_path: Optional[str] = None) -> str:
    """Resolve database path, defaulting to data/scan_history.db in project root."""
    if db_path is not None:
        return os.path.abspath(db_path)
    return DEFAULT_DB_PATH


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Create a new SQLite connection with sqlite3.Row factory and timeout.
    
    Args:
        db_path: Optional path to SQLite database.
        
    Returns:
        sqlite3.Connection object.
    """
    resolved_path = get_db_path(db_path)
    os.makedirs(os.path.dirname(resolved_path), exist_ok=True)
    conn = sqlite3.connect(resolved_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def get_db_connection(db_path: Optional[str] = None) -> Generator[sqlite3.Connection, None, None]:
    """Context manager that ensures the SQLite connection is committed and strictly closed.
    
    Args:
        db_path: Optional path to SQLite database.
        
    Yields:
        Open sqlite3.Connection object.
    """
    conn = get_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()


def initialize_database(db_path: Optional[str] = None) -> bool:
    """Initialize the scans table and necessary indices if they do not exist.
    
    Args:
        db_path: Optional custom database path.
        
    Returns:
        True if initialization succeeded, False otherwise.
    """
    try:
        resolved_path = get_db_path(db_path)
        os.makedirs(os.path.dirname(resolved_path), exist_ok=True)
        with get_db_connection(resolved_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    phishing_probability REAL NOT NULL,
                    confidence_percent REAL NOT NULL,
                    scanned_at TEXT NOT NULL
                );
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_id_desc ON scans(id DESC);
            """)
            conn.commit()
        return True
    except sqlite3.Error:
        return False


def save_scan(
    url: str,
    verdict: str,
    phishing_probability: float,
    confidence_percent: float,
    scanned_at: Optional[str] = None,
    db_path: Optional[str] = None
) -> int:
    """Persist a URL scan record into the database using parameterized queries.
    
    Args:
        url: The submitted URL.
        verdict: 'phishing' or 'legitimate'.
        phishing_probability: Numeric probability (0.0 to 1.0).
        confidence_percent: Percentage value (0.0 to 100.0).
        scanned_at: UTC ISO timestamp string. If None, current UTC time is used.
        db_path: Optional custom database path.
        
    Returns:
        The integer primary key (id) of the inserted record.
        
    Raises:
        ValueError: If input values violate schema constraints.
        sqlite3.Error: If a database error occurs.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string.")
    if verdict not in ("phishing", "legitimate"):
        raise ValueError("Verdict must be either 'phishing' or 'legitimate'.")
    if not (0.0 <= phishing_probability <= 1.0):
        raise ValueError("phishing_probability must be between 0.0 and 1.0.")
    if not (0.0 <= confidence_percent <= 100.0):
        raise ValueError("confidence_percent must be between 0.0 and 100.0.")

    if scanned_at is None:
        scanned_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    resolved_path = get_db_path(db_path)
    with get_db_connection(resolved_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (url, verdict, phishing_probability, confidence_percent, scanned_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (url.strip(), verdict, float(phishing_probability), float(confidence_percent), scanned_at)
        )
        conn.commit()
        record_id = cursor.lastrowid
        if record_id is None:
            raise sqlite3.Error("Failed to retrieve lastrowid after INSERT.")
        return int(record_id)


def get_scan_history(
    limit: int = 50,
    offset: int = 0,
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve scan history ordered newest first (descending id) with pagination.
    
    Args:
        limit: Maximum records to return (1 to 100, default 50).
        offset: Offset for pagination (>= 0, default 0).
        db_path: Optional custom database path.
        
    Returns:
        List of dictionaries representing scan records.
        
    Raises:
        ValueError: If limit or offset are invalid.
    """
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("Limit must be an integer >= 1.")
    if not isinstance(offset, int) or offset < 0:
        raise ValueError("Offset must be an integer >= 0.")
    
    # Cap limit to sensible max
    enforced_limit = min(limit, 100)

    resolved_path = get_db_path(db_path)
    with get_db_connection(resolved_path) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, url, verdict, phishing_probability, confidence_percent, scanned_at
            FROM scans
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (enforced_limit, offset)
        )
        rows = cursor.fetchall()
        return [
            {
                "id": int(row["id"]),
                "url": str(row["url"]),
                "verdict": str(row["verdict"]),
                "phishing_probability": float(row["phishing_probability"]),
                "confidence_percent": float(row["confidence_percent"]),
                "scanned_at": str(row["scanned_at"])
            }
            for row in rows
        ]


def get_scan_count(db_path: Optional[str] = None) -> int:
    """Return total number of scan records stored.
    
    Args:
        db_path: Optional custom database path.
        
    Returns:
        Total scan count integer.
    """
    resolved_path = get_db_path(db_path)
    with get_db_connection(resolved_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans")
        row = cursor.fetchone()
        return int(row[0]) if row else 0


def delete_scan_history(db_path: Optional[str] = None) -> int:
    """Delete all records from the scans table without deleting the database file.
    
    Args:
        db_path: Optional custom database path.
        
    Returns:
        Integer count of deleted records.
    """
    resolved_path = get_db_path(db_path)
    with get_db_connection(resolved_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans")
        deleted_count = cursor.rowcount
        conn.commit()
        return max(0, int(deleted_count))
