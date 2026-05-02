def safe_get_ip_history(ip: str) -> dict:
    """
    Uses parameterized queries — completely prevents SQL injection.
    The ? placeholder means user input NEVER touches the SQL string.
    """
    import re
    # Validate IP format before any DB call
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(ip_pattern, ip):
        return {"error": "Invalid IP format", "found": False}
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Parameterized query — safe from injection
    cursor.execute(
        "SELECT verdict, confidence, timestamp FROM investigations WHERE ip_address = ?",
        (ip,)  # tuple, not string concatenation
    )
    rows = cursor.fetchall()
    conn.close()
    return {"found": bool(rows), "history": rows}

def safe_get_ip_history(ip: str) -> dict:
    """
    Uses parameterized queries — completely prevents SQL injection.
    The ? placeholder means user input NEVER touches the SQL string.
    """
    import re
    import sqlite3

    # Validate IP format before any DB call
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(ip_pattern, ip):
        return {"error": "Invalid IP format", "found": False}

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Parameterized query — safe from injection
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