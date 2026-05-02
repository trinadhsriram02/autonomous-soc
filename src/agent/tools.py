import requests
import json
import os
from langchain_core.tools import tool

# ─────────────────────────────────────────
# TOOL 1 — IP Reputation Checker
# Uses AbuseIPDB free API to check if an
# IP address is known to be malicious
# ─────────────────────────────────────────

@tool
def check_ip_reputation(ip_address: str) -> str:
    """
    Check if an IP address is malicious using AbuseIPDB.
    Returns reputation score, country, ISP, and threat reports.
    Use this when an alert contains an IP address.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        # Fallback: simulate result for testing without API key
        known_bad_ips = [
            "185.220.101.42",
            "192.168.1.45",
            "45.33.32.156"
        ]
        if ip_address in known_bad_ips:
            return json.dumps({
                "ip": ip_address,
                "abuse_score": 95,
                "country": "Unknown",
                "isp": "Known Tor Exit Node",
                "total_reports": 847,
                "threat_level": "CRITICAL",
                "assessment": "This IP is heavily flagged — known malicious actor"
            })
        return json.dumps({
            "ip": ip_address,
            "abuse_score": 2,
            "country": "US",
            "isp": "Internal Network",
            "total_reports": 0,
            "threat_level": "LOW",
            "assessment": "IP appears clean — no significant threat history"
        })

    # Real API call to AbuseIPDB
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        data = response.json()["data"]
        return json.dumps({
            "ip": ip_address,
            "abuse_score": data["abuseConfidenceScore"],
            "country": data["countryCode"],
            "isp": data["isp"],
            "total_reports": data["totalReports"],
            "threat_level": "CRITICAL" if data["abuseConfidenceScore"] > 80
                           else "HIGH" if data["abuseConfidenceScore"] > 50
                           else "LOW",
            "assessment": f"Reported {data['totalReports']} times in last 90 days"
        })
    except Exception as e:
        return json.dumps({"error": f"IP lookup failed: {str(e)}"})


# ─────────────────────────────────────────
# TOOL 2 — CVE Vulnerability Search
# Searches NIST National Vulnerability
# Database (completely free, no key needed)
# ─────────────────────────────────────────

@tool
def search_cve_database(search_term: str) -> str:
    """
    Search the NIST CVE database for known vulnerabilities.
    Use this when an alert mentions software, services, or attack types.
    Example inputs: 'SSH brute force', 'Apache Log4j', 'Windows RDP'
    """
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": search_term,
        "resultsPerPage": 3  # get top 3 most relevant
    }

    try:
        response = requests.get(url, params=params, timeout=8)
        data = response.json()

        if not data.get("vulnerabilities"):
            return json.dumps({
                "search_term": search_term,
                "result": "No CVEs found for this search term",
                "risk_level": "UNKNOWN"
            })

        cves = []
        for item in data["vulnerabilities"][:3]:
            cve = item["cve"]
            # get severity score safely
            metrics = cve.get("metrics", {})
            score = "N/A"
            severity = "UNKNOWN"
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                severity = "HIGH" if float(score) >= 7 else "MEDIUM"

            cves.append({
                "id": cve["id"],
                "description": cve["descriptions"][0]["value"][:200],
                "severity": severity,
                "score": score
            })

        return json.dumps({
            "search_term": search_term,
            "cves_found": len(cves),
            "top_results": cves,
            "risk_level": cves[0]["severity"] if cves else "UNKNOWN"
        })

    except Exception as e:
        return json.dumps({"error": f"CVE search failed: {str(e)}"})


# ─────────────────────────────────────────
# TOOL 3 — Alert History Checker
# Simulates checking if we have seen
# similar alerts before in our system
# ─────────────────────────────────────────
@tool
def check_alert_history(alert_type: str) -> str:
    """
    Check real database for similar past alerts.
    Queries SQLite database — returns actual historical patterns.
    Use this for every alert to find recurring attack patterns.
    Input should be the alert type like brute_force or malware.
    """
    import sqlite3
    import json

    DB_PATH = "src/data/investigations.db"

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Create table if it doesnt exist yet
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
                actions_taken TEXT
            )
        """)
        conn.commit()

        # Query real historical data using parameterized query
        cursor.execute("""
            SELECT verdict, confidence, timestamp, ip_address
            FROM investigations
            WHERE alert_type = ?
            ORDER BY timestamp DESC
            LIMIT 5
        """, (alert_type,))

        rows = cursor.fetchall()

        # Count total occurrences
        cursor.execute(
            "SELECT COUNT(*) FROM investigations WHERE alert_type = ?",
            (alert_type,)
        )
        total = cursor.fetchone()[0]
        conn.close()

        if not rows:
            return json.dumps({
                "seen_before": False,
                "count": 0,
                "pattern": "First occurrence in database",
                "note": "No prior history — treat as high priority"
            })

        verdicts = [r[0] for r in rows]
        real_threats = verdicts.count("REAL THREAT")

        return json.dumps({
            "seen_before": True,
            "total_occurrences": total,
            "recent_count": len(rows),
            "real_threat_rate": f"{(real_threats/len(rows)*100):.0f}%",
            "last_seen": rows[0][2],
            "last_verdict": rows[0][0],
            "pattern": "Recurring attack" if total > 3 else "Occasional",
            "note": f"Seen {total} times. Last verdict was {rows[0][0]}"
        })

    except Exception as e:
        return json.dumps({
            "error": str(e),
            "seen_before": False,
            "note": "Database error — treating as first occurrence"
        })

# ─────────────────────────────────────────
# TOOL 4 — MITRE ATT&CK Knowledge Base
# Searches your local vector database for
# matching attack techniques and threat groups
# ─────────────────────────────────────────

from src.agent.knowledge_base import search_mitre

@tool
def search_mitre_attack(query: str) -> str:
    """
    Search the MITRE ATT&CK knowledge base for attack techniques.
    Use this for EVERY alert to find matching techniques, threat groups,
    and what the attacker is likely to do next.
    Input should describe the attack behavior you observed.
    Example: 'PowerShell encoded command execution from svchost'
    """
    return search_mitre(query, k=2)