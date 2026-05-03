import streamlit as st
import requests
from datetime import datetime

# ─────────────────────────────────────────
# Page config — MUST be first line
# ─────────────────────────────────────────
st.set_page_config(
    page_title="AutonomousSOC",
    page_icon="🛡️",
    layout="wide"
)

# ─────────────────────────────────────────
# Auth check — stop if not logged in
# ─────────────────────────────────────────
from src.ui.auth_forms import show_auth_page, logout, get_auth_headers

if not show_auth_page():
    st.stop()

# ─────────────────────────────────────────
# Styling
# ─────────────────────────────────────────
st.markdown("""
<style>
.big-title {
    font-size: 2.5rem;
    font-weight: 600;
    color: #00D4FF;
}
.subtitle {
    font-size: 1.1rem;
    color: #CCCCCC;
    margin-bottom: 2rem;
}
.verdict-real {
    background: #4a0000;
    border-left: 4px solid #ff4444;
    padding: 1rem;
    border-radius: 0 8px 8px 0;
    margin: 1rem 0;
    color: #ffffff;
}
.verdict-false {
    background: #004a1a;
    border-left: 4px solid #44ff88;
    padding: 1rem;
    border-radius: 0 8px 8px 0;
    margin: 1rem 0;
    color: #ffffff;
}
.verdict-investigate {
    background: #4a3a00;
    border-left: 4px solid #ffd700;
    padding: 1rem;
    border-radius: 0 8px 8px 0;
    margin: 1rem 0;
    color: #ffffff;
}
.action-card {
    background: #1e2a3a;
    border-radius: 8px;
    padding: 0.75rem 1rem;
    margin: 0.5rem 0;
    border: 1px solid #3a4a5a;
    font-size: 0.9rem;
    color: #ffffff;
}
</style>
""", unsafe_allow_html=True)

import os
API_URL = os.environ.get("SOC_API_URL", "http://localhost:8000")


# ─────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────

def check_api_health():
    try:
        response = requests.get(f"{API_URL}/health", timeout=3)
        return response.status_code == 200
    except:
        return False


def analyze_alert(alert_type, message, severity):
    payload = {
        "type": alert_type,
        "message": message,
        "severity": severity,
        "timestamp": datetime.now().isoformat()
    }
    response = requests.post(
        f"{API_URL}/analyze",
        json=payload,
        headers=get_auth_headers(),
        timeout=60
    )
    return response.json()


def get_verdict_color(verdict):
    if "REAL" in verdict.upper():
        return "verdict-real"
    elif "FALSE" in verdict.upper():
        return "verdict-false"
    return "verdict-investigate"


def get_priority_color(priority):
    colors = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢"
    }
    return colors.get(priority.upper(), "⚪")


# ─────────────────────────────────────────
# Header
# ─────────────────────────────────────────
col1, col2 = st.columns([3, 1])

with col1:
    st.markdown('<div class="big-title">🛡️ AutonomousSOC</div>',
                unsafe_allow_html=True)
    st.markdown('<div class="subtitle">AI-powered Security Operations Center — real-time threat analysis and auto-remediation</div>',
                unsafe_allow_html=True)

with col2:
    api_status = check_api_health()
    if api_status:
        st.success("API Online ✓")
    else:
        st.error("API Offline ✗")
        st.info("Run: python -m src.api.main")

    st.markdown(
        f"👤 **{st.session_state.get('username', '')}** "
        f"— {st.session_state.get('role', '').upper()}"
    )
    if st.button("Logout"):
        logout()

st.divider()

# ─────────────────────────────────────────
# Role banner
# ─────────────────────────────────────────
role = st.session_state.get("role", "readonly")
if role == "admin":
    st.info("👑 Admin — full access to all features")
elif role == "analyst":
    st.info("🔍 Analyst — can analyze alerts and submit feedback")
else:
    st.warning("👁️ Read-Only — viewing dashboard only")

can_analyze = role in ["admin", "analyst"]

# ─────────────────────────────────────────
# Main layout
# ─────────────────────────────────────────
left_col, right_col = st.columns([1, 1])

with left_col:
    st.subheader("Submit Security Alert")

    alert_type = st.selectbox(
        "Alert Type",
        options=[
            "brute_force",
            "data_exfiltration",
            "malware",
            "normal_traffic",
            "ransomware",
            "phishing",
            "lateral_movement"
        ]
    )

    severity = st.select_slider(
        "Severity",
        options=["low", "medium", "high", "critical"],
        value="medium"
    )

    message = st.text_area(
        "Alert Message",
        height=150,
        placeholder="Paste your security alert here..."
    )

    st.markdown("**Quick test alerts:**")
    sample_col1, sample_col2 = st.columns(2)

    with sample_col1:
        if st.button("SSH Brute Force", use_container_width=True):
            st.session_state.sample_message = "Failed SSH login attempts: 847 failures in 60 seconds from IP 192.168.1.45 targeting user root"
            st.session_state.sample_type = "brute_force"
            st.session_state.sample_severity = "high"
            st.rerun()

        if st.button("Data Exfiltration", use_container_width=True):
            st.session_state.sample_message = "Unusual outbound traffic: 4.7GB transferred to external IP 185.220.101.42 known Tor exit node in 10 minutes"
            st.session_state.sample_type = "data_exfiltration"
            st.session_state.sample_severity = "critical"
            st.rerun()

    with sample_col2:
        if st.button("Malware Detected", use_container_width=True):
            st.session_state.sample_message = "Process svchost.exe spawned child process powershell.exe with encoded payload on host DESKTOP-XK29"
            st.session_state.sample_type = "malware"
            st.session_state.sample_severity = "critical"
            st.rerun()

        if st.button("Normal Traffic", use_container_width=True):
            st.session_state.sample_message = "User john.doe logged in successfully from IP 10.0.0.12 at 09:15 AM"
            st.session_state.sample_type = "normal_traffic"
            st.session_state.sample_severity = "low"
            st.rerun()

    if "sample_message" in st.session_state:
        message = st.session_state.sample_message
        st.info("Sample loaded — click Analyze to run")

    st.divider()

    analyze_clicked = st.button(
        "Analyze Alert",
        type="primary",
        use_container_width=True,
        disabled=not api_status or not can_analyze
    )

    if not can_analyze:
        st.caption("Read-only users cannot run analysis")


# ─────────────────────────────────────────
# Results column
# ─────────────────────────────────────────
with right_col:
    st.subheader("AI Analysis Results")

    if analyze_clicked:
        if not message or message.strip() == "":
            st.warning("Please enter an alert message first")
        else:
            with st.spinner("AI agent is investigating..."):
                try:
                    actual_type = st.session_state.get("sample_type", alert_type)
                    actual_severity = st.session_state.get("sample_severity", severity)
                    actual_message = st.session_state.get("sample_message", message)

                    result = analyze_alert(actual_type, actual_message, actual_severity)

                    for key in ["sample_message", "sample_type", "sample_severity"]:
                        if key in st.session_state:
                            del st.session_state[key]

                    verdict = result.get("verdict", "UNKNOWN")
                    confidence = result.get("confidence", 0)
                    priority = result.get("priority", "MEDIUM")
                    processing_time = result.get("processing_time_seconds", 0)

                    verdict_class = get_verdict_color(verdict)
                    priority_icon = get_priority_color(priority)

                    st.markdown(f"""
                    <div class="{verdict_class}">
                        <strong style="font-size: 1.2rem;">{verdict}</strong><br>
                        {priority_icon} Priority: {priority} &nbsp;|&nbsp;
                        Confidence: {confidence}% &nbsp;|&nbsp;
                        Analyzed in {processing_time}s
                    </div>
                    """, unsafe_allow_html=True)

                    st.markdown("**Confidence Score**")
                    st.progress(confidence / 100)

                    m1, m2, m3 = st.columns(3)
                    with m1:
                        st.metric("Verdict", verdict.split()[0])
                    with m2:
                        st.metric("Confidence", f"{confidence}%")
                    with m3:
                        st.metric("Priority", priority)

                    st.divider()

                    with st.expander("Full AI Analysis", expanded=True):
                        st.text(result.get("analysis", "No analysis available"))

                    actions = result.get("actions_taken", [])
                    if actions:
                        st.markdown(f"**Actions Taken ({len(actions)})**")
                        for action in actions:
                            action_type = action.get("action", "UNKNOWN")
                            if action_type == "IP_BLOCKED":
                                st.markdown(f"""
                                <div class="action-card">
                                🚫 <strong>IP Blocked:</strong> {action.get('ip')} — {action.get('details')}
                                </div>
                                """, unsafe_allow_html=True)
                            elif action_type == "HOST_QUARANTINED":
                                st.markdown(f"""
                                <div class="action-card">
                                🔒 <strong>Host Quarantined:</strong> {action.get('hostname')} — {action.get('details')}
                                </div>
                                """, unsafe_allow_html=True)
                            elif action_type == "TICKET_CREATED":
                                st.markdown(f"""
                                <div class="action-card">
                                🎫 <strong>Ticket Created:</strong> {action.get('ticket_id')} — Priority: {action.get('priority')}
                                </div>
                                """, unsafe_allow_html=True)
                            elif action_type in ["SLACK_SENT", "SLACK_SIMULATED"]:
                                st.markdown(f"""
                                <div class="action-card">
                                💬 <strong>Slack Alert:</strong> Security team notified
                                </div>
                                """, unsafe_allow_html=True)
                            elif action_type == "DISMISSED":
                                st.markdown(f"""
                                <div class="action-card">
                                ✅ <strong>Dismissed:</strong> {action.get('reason')}
                                </div>
                                """, unsafe_allow_html=True)

                    # Save to history
                    if "history" not in st.session_state:
                        st.session_state.history = []
                    st.session_state.history.append({
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "type": actual_type,
                        "verdict": verdict,
                        "confidence": confidence,
                        "priority": priority
                    })

                except requests.exceptions.ConnectionError:
                    st.error("Cannot connect to API.")
                    st.code("python -m src.api.main")
                except Exception as e:
                    st.error(f"Error: {str(e)}")
    else:
        st.info("Submit an alert on the left to see AI analysis here")
        st.markdown("""
        **How it works:**
        1. Select alert type and severity
        2. Paste the alert message or use a quick test button
        3. Click Analyze Alert
        4. AI investigates using 4 tools + MITRE ATT&CK
        5. See verdict, confidence score, and actions taken
        """)

st.divider()

# ─────────────────────────────────────────
# Alert history
# ─────────────────────────────────────────
st.subheader("Alert History")

if "history" not in st.session_state:
    st.session_state.history = []

if st.session_state.history:
    for item in reversed(st.session_state.history[-10:]):
        icon = "🔴" if "REAL" in item["verdict"] else "🟢" if "FALSE" in item["verdict"] else "🟡"
        st.markdown(
            f"{icon} `{item['time']}` — **{item['type']}** → "
            f"{item['verdict']} ({item['confidence']}% confidence) — {item['priority']}"
        )
else:
    st.caption("No alerts analyzed yet in this session")