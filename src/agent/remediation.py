import os
import json
import requests
from datetime import datetime


# ─────────────────────────────────────────
# Confidence thresholds — these decide
# what action the agent takes automatically
# ─────────────────────────────────────────
THRESHOLDS = {
    "AUTO_BLOCK": 85,      # above this → act automatically
    "ESCALATE": 50,        # above this → alert human
    "DISMISS": 50          # below this → dismiss as false positive
}


def parse_confidence(analysis: str) -> int:
    """Extract confidence score from agent's analysis text."""
    import re
    match = re.search(r'CONFIDENCE:\s*(\d+)', analysis)
    if match:
        return int(match.group(1))
    return 0


def parse_verdict(analysis: str) -> str:
    """Extract verdict from agent's analysis text."""
    if "REAL THREAT" in analysis.upper():
        return "REAL THREAT"
    elif "FALSE POSITIVE" in analysis.upper():
        return "FALSE POSITIVE"
    return "NEEDS INVESTIGATION"


def parse_priority(analysis: str) -> str:
    """Extract priority level from agent's analysis."""
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if level in analysis.upper():
            return level
    return "MEDIUM"


# ─────────────────────────────────────────
# Remediation Actions
# In production these would call real APIs
# For now they simulate the actions clearly
# ─────────────────────────────────────────

def block_ip(ip_address: str, reason: str) -> dict:
    """
    Block a malicious IP address.
    Production: would call firewall API or AWS Security Group API
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    action = {
        "action": "IP_BLOCKED",
        "ip": ip_address,
        "reason": reason,
        "timestamp": timestamp,
        "status": "SUCCESS",
        "details": f"IP {ip_address} added to blocklist. All traffic dropped."
    }
    print(f"\n  [ACTION] BLOCKING IP: {ip_address}")
    print(f"  [ACTION] Reason: {reason}")
    print(f"  [ACTION] Status: BLOCKED at {timestamp}")
    return action


def quarantine_host(hostname: str, reason: str) -> dict:
    """
    Isolate a compromised host from the network.
    Production: would call EDR API like CrowdStrike or SentinelOne
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    action = {
        "action": "HOST_QUARANTINED",
        "hostname": hostname,
        "reason": reason,
        "timestamp": timestamp,
        "status": "SUCCESS",
        "details": f"Host {hostname} isolated from network. Awaiting forensic analysis."
    }
    print(f"\n  [ACTION] QUARANTINING HOST: {hostname}")
    print(f"  [ACTION] Reason: {reason}")
    print(f"  [ACTION] Status: ISOLATED at {timestamp}")
    return action


def create_ticket(alert_id: str, analysis: str, priority: str) -> dict:
    """
    Create an incident ticket for human review.
    Production: would call Jira, ServiceNow, or PagerDuty API
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ticket_id = f"INC-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    action = {
        "action": "TICKET_CREATED",
        "ticket_id": ticket_id,
        "alert_id": alert_id,
        "priority": priority,
        "timestamp": timestamp,
        "status": "OPEN",
        "details": f"Incident {ticket_id} created for human review"
    }
    print(f"\n  [ACTION] TICKET CREATED: {ticket_id}")
    print(f"  [ACTION] Priority: {priority}")
    print(f"  [ACTION] Assigned to: SOC Team")
    return action


def send_slack_alert(alert_id: str, verdict: str,
                     confidence: int, analysis: str, priority: str) -> dict:
    """
    Send a Slack notification to the security team.
    Falls back to console print if no webhook configured.
    """
    webhook_url = os.getenv("SLACK_WEBHOOK_URL")

    message = {
        "text": f"*AutonomousSOC Alert* — {priority} Priority",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Security Alert: {verdict}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Alert ID:*\n{alert_id}"},
                    {"type": "mrkdwn", "text": f"*Priority:*\n{priority}"},
                    {"type": "mrkdwn", "text": f"*Confidence:*\n{confidence}%"},
                    {"type": "mrkdwn", "text": f"*Verdict:*\n{verdict}"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Analysis Summary:*\n{analysis[:300]}..."
                }
            }
        ]
    }

    if webhook_url:
        try:
            response = requests.post(webhook_url, json=message, timeout=5)
            if response.status_code == 200:
                print(f"\n  [ACTION] SLACK ALERT SENT to security team")
                return {"action": "SLACK_SENT", "status": "SUCCESS"}
        except Exception as e:
            print(f"\n  [ACTION] Slack failed: {e} — printing instead")

    # Fallback — print to console
    print(f"\n  [SLACK SIMULATION] Message that would be sent:")
    print(f"  Alert {alert_id} | {verdict} | {confidence}% confidence | {priority} priority")
    return {"action": "SLACK_SIMULATED", "status": "SUCCESS"}


# ─────────────────────────────────────────
# Main Decision Engine
# This is the brain that decides what to do
# based on confidence score and verdict
# ─────────────────────────────────────────

def decide_and_act(alert: dict, analysis: str) -> dict:
    """
    Read the agent's analysis and take the right action automatically.
    This is the confidence-gating logic.
    """
    confidence = parse_confidence(analysis)
    verdict = parse_verdict(analysis)
    priority = parse_priority(analysis)

    print(f"\n{'─'*55}")
    print(f"REMEDIATION ENGINE")
    print(f"Verdict: {verdict} | Confidence: {confidence}% | Priority: {priority}")
    print(f"{'─'*55}")

    actions_taken = []

    # ── FALSE POSITIVE ──────────────────────────────
    if verdict == "FALSE POSITIVE":
        print(f"  [DECISION] False positive — no action needed")
        actions_taken.append({
            "action": "DISMISSED",
            "reason": "False positive — confidence below threat threshold"
        })

    # ── REAL THREAT — HIGH CONFIDENCE → AUTO ACT ────
    elif verdict == "REAL THREAT" and confidence >= THRESHOLDS["AUTO_BLOCK"]:
        print(f"  [DECISION] High confidence threat — taking automatic action")

        # Extract IP from alert message if present
        import re
        ip_match = re.search(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            alert.get("message", "")
        )

        if ip_match:
            ip = ip_match.group()
            action = block_ip(ip, f"Auto-blocked: {alert['type']} detected")
            actions_taken.append(action)

        # If malware type — quarantine the host too
        if alert.get("type") == "malware":
            host_match = re.search(r'host\s+(\S+)', alert.get("message", ""), re.IGNORECASE)
            hostname = host_match.group(1) if host_match else "UNKNOWN-HOST"
            action = quarantine_host(hostname, "Malware detected — auto-quarantine")
            actions_taken.append(action)

        # Always create a ticket for real threats
        ticket = create_ticket(alert["id"], analysis, priority)
        actions_taken.append(ticket)

        # Send Slack alert
        slack = send_slack_alert(alert["id"], verdict, confidence, analysis, priority)
        actions_taken.append(slack)

    # ── REAL THREAT — LOW CONFIDENCE → ESCALATE ─────
    elif verdict == "REAL THREAT" and confidence < THRESHOLDS["AUTO_BLOCK"]:
        print(f"  [DECISION] Moderate confidence — escalating to human analyst")

        ticket = create_ticket(alert["id"], analysis, priority)
        actions_taken.append(ticket)

        slack = send_slack_alert(alert["id"], verdict, confidence, analysis, priority)
        actions_taken.append(slack)

    # ── NEEDS INVESTIGATION ──────────────────────────
    else:
        print(f"  [DECISION] Needs investigation — creating ticket")
        ticket = create_ticket(alert["id"], analysis, priority)
        actions_taken.append(ticket)

    return {
        "alert_id": alert["id"],
        "verdict": verdict,
        "confidence": confidence,
        "priority": priority,
        "actions_taken": actions_taken
    }