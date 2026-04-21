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
    Check if we have seen similar alerts recently in our system.
    Use this to determine if this is a repeated pattern or first occurrence.
    Input should be the type of attack like 'brute_force', 'data_exfiltration'
    """
    # Simulated alert history database
    history = {
        "brute_force": {
            "seen_before": True,
            "count_last_7_days": 12,
            "last_seen": "2024-01-14 22:15:00",
            "pattern": "Increasing frequency — 3x more than last week",
            "previous_verdict": "REAL THREAT",
            "note": "Active campaign detected — multiple source IPs targeting root"
        },
        "data_exfiltration": {
            "seen_before": True,
            "count_last_7_days": 2,
            "last_seen": "2024-01-13 08:30:00",
            "pattern": "Rare — only 2 occurrences",
            "previous_verdict": "REAL THREAT",
            "note": "Previous incident involved same Tor exit node range"
        },
        "malware": {
            "seen_before": False,
            "count_last_7_days": 0,
            "last_seen": None,
            "pattern": "First occurrence",
            "previous_verdict": None,
            "note": "No prior history — treat as high priority"
        },
        "normal_traffic": {
            "seen_before": True,
            "count_last_7_days": 1520,
            "last_seen": "2024-01-15 10:00:00",
            "pattern": "Normal baseline activity",
            "previous_verdict": "FALSE POSITIVE",
            "note": "This is expected daily activity"
        }
    }

    result = history.get(alert_type, {
        "seen_before": False,
        "count_last_7_days": 0,
        "pattern": "No history found",
        "note": "Unknown alert type"
    })

    return json.dumps(result)