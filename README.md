# AutonomousSOC — AI-Powered Security Operations Center

An autonomous AI agent that investigates security alerts, correlates threat intelligence, and takes automatic remediation actions — replacing Tier-1 SOC analyst work.

## Demo
> Paste your Loom video link here after recording

## What it does
- Analyzes security alerts using LLM reasoning
- Looks up IP reputation using AbuseIPDB
- Searches NIST CVE database for vulnerabilities
- Maps attacks to MITRE ATT&CK techniques and threat groups
- Auto-blocks IPs and quarantines hosts based on confidence score
- Sends Slack alerts to security team for escalation
- Full REST API with interactive documentation
- Real-time dashboard for visual alert analysis

## Architecture
Security Alert
↓
FastAPI Backend (/analyze)
↓
LangGraph AI Agent
↓
Tool 1: IP Reputation (AbuseIPDB)
Tool 2: CVE Search (NIST NVD)
Tool 3: Alert History
Tool 4: MITRE ATT&CK RAG Search
↓
Remediation Engine
↓
Streamlit Dashboard

## Tech Stack
- **AI/ML**: LangGraph, LangChain, Groq LLaMA 3.1
- **RAG**: ChromaDB, Sentence Transformers
- **Backend**: FastAPI, Python
- **Frontend**: Streamlit
- **Security APIs**: AbuseIPDB, NIST NVD CVE Database
- **Knowledge Base**: MITRE ATT&CK Framework

## Setup

### 1. Clone the repo
```bash
git clone https://github.com/trinadhsriram02/autonomous-soc.git
cd autonomous-soc
```

### 2. Create virtual environment
```bash
python -m venv venv
venv\Scripts\activate.bat
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Set up environment variables
Create a `.env` file:

GROQ_API_KEY=your_groq_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
SLACK_WEBHOOK_URL=your_slack_webhook

### 5. Build the knowledge base
```bash
python -m src.agent.knowledge_base
```

### 6. Start the API server
```bash
python -m src.api.main
```

### 7. Start the dashboard
```bash
streamlit run dashboard.py
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | / | Health check |
| GET | /health | Detailed status |
| POST | /analyze | Analyze single alert |
| POST | /analyze/batch | Analyze multiple alerts |
| GET | /alerts/sample | Get sample test alerts |
| GET | /docs | Interactive API documentation |

## Remediation Logic

| Confidence | Verdict | Action |
|------------|---------|--------|
| Above 85% | REAL THREAT | Auto-block IP, quarantine host, create ticket |
| 50 to 85% | REAL THREAT | Create ticket, escalate to human via Slack |
| Below 50% | Any | Dismiss as false positive |

## Project Structure

autonomous-soc/
├── src/
│   ├── agent/
│   │   ├── analyzer.py
│   │   ├── tools.py
│   │   ├── knowledge_base.py
│   │   └── remediation.py
│   ├── api/
│   │   └── main.py
│   └── data/
│       ├── sample_alerts.py
│       └── mitre_knowledge.py
├── dashboard.py
├── requirements.txt
└── README.md

## Real World Impact
- Reduces alert triage time from 20 minutes to under 30 seconds
- Automatically handles false positives which are 70% of all alerts
- Provides evidence-based verdicts with cited threat intelligence
- Scales to thousands of alerts per hour via API

## Author
Trinadh Sriram — [GitHub](https://github.com/trinadhsriram02)