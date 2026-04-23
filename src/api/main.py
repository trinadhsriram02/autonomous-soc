from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn
from datetime import datetime

from src.agent.analyzer import analyze_alert

app = FastAPI(
    title="AutonomousSOC API",
    description="AI-powered security alert analysis and auto-remediation",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class AlertRequest(BaseModel):
    id: Optional[str] = None
    type: str
    message: str
    severity: str = "medium"
    timestamp: Optional[str] = None


class AlertResponse(BaseModel):
    alert_id: str
    verdict: str
    confidence: int
    priority: str
    analysis: str
    actions_taken: list
    processing_time_seconds: float


@app.get("/")
def root():
    return {
        "status": "running",
        "service": "AutonomousSOC",
        "version": "1.0.0",
        "message": "AI-powered security operations center is active"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "ai_model": "groq/llama-3.1-8b-instant",
            "knowledge_base": "MITRE ATT&CK (10 techniques)",
            "tools": [
                "ip_reputation",
                "cve_search",
                "alert_history",
                "mitre_search"
            ]
        }
    }


@app.post("/analyze")
def analyze(request: AlertRequest):
    start_time = datetime.now()

    alert = {
        "id": request.id or f"alert_{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "type": request.type,
        "message": request.message,
        "severity": request.severity,
        "timestamp": request.timestamp or datetime.now().isoformat()
    }

    try:
        result = analyze_alert(alert)
        processing_time = (datetime.now() - start_time).total_seconds()

        return {
            "alert_id": result["alert_id"],
            "verdict": result["remediation"]["verdict"],
            "confidence": result["remediation"]["confidence"],
            "priority": result["remediation"]["priority"],
            "analysis": result["analysis"],
            "actions_taken": result["remediation"]["actions_taken"],
            "processing_time_seconds": round(processing_time, 2)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/alerts/sample")
def get_sample_alerts():
    from src.data.sample_alerts import SAMPLE_ALERTS
    return {
        "total": len(SAMPLE_ALERTS),
        "alerts": SAMPLE_ALERTS
    }


@app.post("/analyze/batch")
def analyze_batch(alerts: list[AlertRequest]):
    if len(alerts) > 10:
        raise HTTPException(
            status_code=400,
            detail="Maximum 10 alerts per batch"
        )

    results = []
    for request in alerts:
        alert = {
            "id": request.id or f"alert_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "type": request.type,
            "message": request.message,
            "severity": request.severity,
            "timestamp": request.timestamp or datetime.now().isoformat()
        }
        result = analyze_alert(alert)
        results.append(result)

    return {
        "total_analyzed": len(results),
        "results": results
    }


if __name__ == "__main__":
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )