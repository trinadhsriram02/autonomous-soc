import requests
import json
from datetime import datetime

def fetch_latest_mitre():
    """
    Pulls latest MITRE ATT&CK data directly from MITRE's 
    official STIX repository — always up to date.
    """
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    print("Fetching latest MITRE ATT&CK data from official source...")
    response = requests.get(url, timeout=30)
    data = response.json()
    
    techniques = []
    for obj in data["objects"]:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked"):
            technique = {
                "id": obj.get("external_references", [{}])[0].get("external_id", ""),
                "name": obj.get("name", ""),
                "description": obj.get("description", "")[:500],
                "tactic": str(obj.get("kill_chain_phases", [{}])[0].get("phase_name", "")),
            }
            if technique["id"].startswith("T"):
                techniques.append(technique)
    
    print(f"Fetched {len(techniques)} techniques from MITRE")
    return techniques


def rebuild_knowledge_base():
    """Rebuild vector DB with latest MITRE data."""
    from src.agent.knowledge_base import build_knowledge_base
    techniques = fetch_latest_mitre()
    build_knowledge_base(techniques)
    print(f"Knowledge base rebuilt at {datetime.now()}")


if __name__ == "__main__":
    rebuild_knowledge_base()