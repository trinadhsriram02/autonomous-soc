from src.api.jwt_auth import (
    hash_password, verify_password,
    create_access_token, get_current_user,
    require_permission
)
from src.data.memory_store import (
    create_user, get_user_by_username, get_all_users,
    init_users_table
)

from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from src.agent.analyzer import analyze_alert
from src.api.auth import verify_api_key
from fastapi import Depends
from src.queue.alert_queue import publish_alert

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

executor_pool = ThreadPoolExecutor(max_workers=5)
@app.on_event("startup")
async def startup_event():
    """Start the background queue consumer when API starts."""
    from src.queue.alert_queue import consume_alerts
    asyncio.create_task(consume_alerts())
    print("Background alert queue consumer started")


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
async def analyze(
    request: AlertRequest,
    current_user: dict = Depends(require_permission("analyze"))
):
    """
    Async endpoint — handles 5 simultaneous requests.
    Runs agent in thread pool so it never blocks.
    """
    start_time = datetime.now()

    alert = {
        "id": request.id or f"alert_{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "type": request.type,
        "message": request.message,
        "severity": request.severity,
        "timestamp": request.timestamp or datetime.now().isoformat()
    }

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            executor_pool,
            analyze_alert,
            alert
        )

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
def analyze_batch(
    alerts: list[AlertRequest],
    api_key: str = Depends(verify_api_key)
):
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


@app.get("/investigations/history")
def get_investigation_history():
    """Get all past investigations from persistent memory."""
    from src.data.memory_store import get_all_investigations
    results = get_all_investigations()
    return {
        "total": len(results),
        "investigations": results
    }


@app.get("/investigations/ip/{ip_address}")
def get_ip_investigation_history(ip_address: str):
    """Get full history for a specific IP — SQL injection safe."""
    from src.data.memory_store import safe_get_ip_history
    return safe_get_ip_history(ip_address)



@app.post("/analyze/queue")
async def analyze_queued(
    request: AlertRequest,
    api_key: str = Depends(verify_api_key)
):
    """
    Queued endpoint — returns job ID immediately.
    Alert is processed in background.
    No 37 second wait.
    """
    alert = {
        "id": request.id or f"alert_{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "type": request.type,
        "message": request.message,
        "severity": request.severity,
        "timestamp": datetime.now().isoformat()
    }

    await publish_alert(alert)

    return {
        "status": "queued",
        "alert_id": alert["id"],
        "message": "Alert queued for processing — result will be stored in DB",
        "check_result_at": f"/investigations/ip/{alert['id']}"
    }


@app.get("/queue/status")
def queue_status():
    """Check queue size and processing stats."""
    from src.queue.alert_queue import get_queue_status
    return get_queue_status()


@app.get("/queue/result/{alert_id}")
def get_queue_result(alert_id: str):
    """Get result of a queued alert by ID."""
    from src.queue.alert_queue import get_queue_result
    return get_queue_result(alert_id)

@app.post("/feedback")
def submit_feedback(feedback: dict):
    """Store human analyst feedback for future fine-tuning."""
    import json
    with open("src/data/feedback_dataset.jsonl", "a") as f:
        f.write(json.dumps(feedback) + "\n")
    return {"status": "saved", "message": "Feedback stored for fine-tuning"}

# ─────────────────────────────────────────
# Auth Models
# ─────────────────────────────────────────
class SignupRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "readonly"


class LoginRequest(BaseModel):
    username: str
    password: str


# ─────────────────────────────────────────
# Auth Endpoints
# ─────────────────────────────────────────

@app.post("/signup")
def signup(request: SignupRequest):
    """
    Create a new user account.
    Passwords are hashed with bcrypt before storing.
    Default role is readonly — admin must upgrade.
    """
    # Validate role
    valid_roles = ["admin", "analyst", "readonly"]
    if request.role not in valid_roles:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role. Choose from: {valid_roles}"
        )

    # Hash password before saving
    hashed = hash_password(request.password)

    result = create_user(
        username=request.username,
        email=request.email,
        hashed_password=hashed,
        role=request.role
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return {
        "message": "Account created successfully",
        "username": result["username"],
        "role": result["role"]
    }


@app.post("/login")
def login(request: LoginRequest):
    """
    Login and get JWT token.
    Token expires in 8 hours.
    Include token in all future requests as Bearer token.
    """
    user = get_user_by_username(request.username)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Username not found"
        )

    if not user["is_active"]:
        raise HTTPException(
            status_code=401,
            detail="Account is deactivated"
        )

    if not verify_password(request.password, user["hashed_password"]):
        raise HTTPException(
            status_code=401,
            detail="Incorrect password"
        )

    # Create JWT token
    token = create_access_token(data={
        "sub": user["username"],
        "role": user["role"],
        "id": user["id"]
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"],
        "message": f"Welcome back {user['username']}"
    }


@app.get("/me")
async def get_my_profile(
    current_user: dict = Depends(get_current_user)
):
    """Get current logged in user profile."""
    return {
        "username": current_user["username"],
        "role": current_user["role"],
        "permissions": {
            "can_analyze": current_user["role"] in ["admin", "analyst"],
            "can_give_feedback": current_user["role"] in ["admin", "analyst"],
            "can_manage_users": current_user["role"] == "admin",
            "can_view": True
        }
    }


@app.get("/admin/users")
async def list_all_users(
    current_user: dict = Depends(require_permission("manage_users"))
):
    """
    Get all users — admin only.
    Analysts and readonly users cannot access this.
    """
    return {
        "total": len(get_all_users()),
        "users": get_all_users()
    }


if __name__ == "__main__":
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )