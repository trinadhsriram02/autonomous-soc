import sqlite3
import json
from datetime import datetime

DB_PATH = "src/data/investigations.db"


def init_db():
    """Create the investigations table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            alert_type TEXT,
            verdict TEXT,
            confidence INTEGER,
            priority TEXT,
            message TEXT,
            timestamp TEXT,
            actions_taken TEXT,
            analyst_id INTEGER
        )
    """)
    conn.commit()
    conn.close()


def init_users_table():
    """Create users table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'readonly',
            created_at TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()


def save_investigation(alert: dict, verdict: str,
                       confidence: int, priority: str,
                       actions: list):
    """Save a completed investigation to the database."""
    init_db()
    import re
    ip_match = re.search(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        alert.get("message", "")
    )
    ip = ip_match.group() if ip_match else "unknown"

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO investigations
        (ip_address, alert_type, verdict, confidence,
         priority, message, timestamp, actions_taken)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        ip,
        alert.get("type"),
        verdict,
        confidence,
        priority,
        alert.get("message"),
        datetime.now().isoformat(),
        json.dumps(actions)
    ))
    conn.commit()
    conn.close()


def get_ip_history(ip: str) -> dict:
    """Get all past investigations for a specific IP."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT verdict, confidence, timestamp, alert_type
        FROM investigations
        WHERE ip_address = ?
        ORDER BY timestamp DESC
        LIMIT 5
    """, (ip,))
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return {"found": False, "message": "No prior history for this IP"}

    return {
        "found": True,
        "total_incidents": len(rows),
        "last_verdict": rows[0][0],
        "last_seen": rows[0][2],
        "history": [
            {
                "verdict": r[0],
                "confidence": r[1],
                "timestamp": r[2],
                "type": r[3]
            }
            for r in rows
        ]
    }


def safe_get_ip_history(ip: str) -> dict:
    """
    Uses parameterized queries — completely prevents SQL injection.
    The ? placeholder means user input NEVER touches the SQL string.
    """
    import re

    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(ip_pattern, ip):
        return {"error": "Invalid IP format", "found": False}

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT verdict, confidence, timestamp FROM investigations WHERE ip_address = ?",
        (ip,)
    )
    rows = cursor.fetchall()
    conn.close()

    return {
        "found": bool(rows),
        "total": len(rows),
        "history": [
            {
                "verdict": r[0],
                "confidence": r[1],
                "timestamp": r[2]
            }
            for r in rows
        ]
    }


def get_all_investigations(limit: int = 50) -> list:
    """Get recent investigations for the dashboard."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT ip_address, alert_type, verdict, confidence,
               priority, timestamp
        FROM investigations
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "ip": r[0],
            "type": r[1],
            "verdict": r[2],
            "confidence": r[3],
            "priority": r[4],
            "timestamp": r[5]
        }
        for r in rows
    ]


def create_user(username: str, email: str,
                hashed_password: str, role: str,
                first_name: str = "", last_name: str = "") -> dict:
    """Save a new user to the database."""
    init_users_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO users
            (username, email, hashed_password, role, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            username, email, hashed_password,
            role, datetime.now().isoformat()
        ))
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return {
            "id": user_id,
            "username": username,
            "role": role,
            "first_name": first_name,
            "last_name": last_name
        }
    except sqlite3.IntegrityError:
        conn.close()
        return {"error": "Username or email already exists"}


def get_user_by_username(username: str) -> dict:
    """Get user from database by username."""
    init_users_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, email, hashed_password, role, is_active
        FROM users WHERE username = ?
    """, (username,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "username": row[1],
        "email": row[2],
        "hashed_password": row[3],
        "role": row[4],
        "is_active": row[5]
    }


def get_all_users() -> list:
    """Get all users — admin only."""
    init_users_table()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, username, email, role, created_at, is_active
        FROM users ORDER BY created_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": r[0],
            "username": r[1],
            "email": r[2],
            "role": r[3],
            "created_at": r[4],
            "is_active": r[5]
        }
        for r in rows
    ]