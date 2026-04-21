from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage
from dotenv import load_dotenv

from src.agent.tools import check_ip_reputation, search_cve_database, check_alert_history

load_dotenv()

model = ChatGroq(model="llama-3.1-8b-instant")

tools = [check_ip_reputation, search_cve_database, check_alert_history]

executor = create_react_agent(model, tools)


def analyze_alert(alert: dict) -> dict:
    """Run the agent on a single alert and return structured result."""

    print(f"\n{'='*60}")
    print(f"ALERT ID  : {alert['id']}")
    print(f"TYPE      : {alert['type']}")
    print(f"MESSAGE   : {alert['message'][:80]}...")
    print(f"{'='*60}")

    query = f"""Analyze this security alert and use your tools to investigate.

Alert ID: {alert['id']}
Timestamp: {alert['timestamp']}
Alert Type: {alert['type']}
Severity: {alert['severity']}
Message: {alert['message']}

Steps:
1. If there is an IP address in the message, call check_ip_reputation
2. Search for CVEs related to this attack type using search_cve_database
3. Call check_alert_history with the alert type
4. Give your final verdict in this format:

VERDICT: REAL THREAT / FALSE POSITIVE / NEEDS INVESTIGATION
CONFIDENCE: 0-100%
ATTACK TYPE: name of attack
TOOLS USED: what tools returned
REASONING: 2-3 sentences
RECOMMENDED ACTION: what to do right now
PRIORITY: CRITICAL / HIGH / MEDIUM / LOW"""

    result = executor.invoke({
        "messages": [HumanMessage(content=query)]
    })

    final_answer = result["messages"][-1].content

    print(f"\n--- FINAL ANALYSIS ---")
    print(final_answer)

    return {
        "alert_id": alert["id"],
        "analysis": final_answer
    }


if __name__ == "__main__":
    from src.data.sample_alerts import SAMPLE_ALERTS

    print("AutonomousSOC — Agentic Security Analyzer")
    print("The AI will now use tools to investigate each alert\n")

    results = []
    for alert in SAMPLE_ALERTS:
        result = analyze_alert(alert)
        results.append(result)

    print(f"\n{'='*60}")
    print(f"COMPLETE — Analyzed {len(results)} alerts with tool-assisted reasoning")