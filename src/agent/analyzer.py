from src.agent.remediation import decide_and_act
from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage
from dotenv import load_dotenv

from src.agent.tools import check_ip_reputation, search_cve_database, check_alert_history, search_mitre_attack

load_dotenv()

model = ChatGroq(model="llama-3.1-8b-instant")

tools = [check_ip_reputation, search_cve_database, check_alert_history, search_mitre_attack]

executor = create_react_agent(model, tools)


def analyze_alert(alert: dict) -> dict:
    """Run the agent on a single alert and return structured result."""

    print(f"\n{'='*60}")
    print(f"ALERT ID  : {alert['id']}")
    print(f"TYPE      : {alert['type']}")
    print(f"MESSAGE   : {alert['message'][:80]}...")
    print(f"{'='*60}")

    query = (
        f"Analyze this security alert and use your tools to investigate.\n\n"
        f"Alert ID: {alert['id']}\n"
        f"Timestamp: {alert['timestamp']}\n"
        f"Alert Type: {alert['type']}\n"
        f"Severity: {alert['severity']}\n"
        f"Message: {alert['message']}\n\n"
        "Steps:\n"
        "1. If there is an IP address in the message, call check_ip_reputation\n"
        "2. Search for CVEs using search_cve_database\n"
        "3. Call check_alert_history with the alert type\n"
        "4. Call search_mitre_attack to find matching techniques\n\n"
        "Give your final verdict in this exact format:\n"
        "VERDICT: REAL THREAT / FALSE POSITIVE / NEEDS INVESTIGATION\n"
        "CONFIDENCE: 0-100%\n"
        "ATTACK TYPE: name of attack\n"
        "TOOLS USED: what tools returned\n"
        "REASONING: 2-3 sentences\n"
        "RECOMMENDED ACTION: what to do right now\n"
        "PRIORITY: CRITICAL / HIGH / MEDIUM / LOW"
    )

    result = executor.invoke({
        "messages": [HumanMessage(content=query)]
    })

    final_answer = result["messages"][-1].content

    print(f"\n--- FINAL ANALYSIS ---")
    print(final_answer)

    remediation_result = decide_and_act(alert, final_answer)

    return {
        "alert_id": alert["id"],
        "analysis": final_answer,
        "remediation": remediation_result
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