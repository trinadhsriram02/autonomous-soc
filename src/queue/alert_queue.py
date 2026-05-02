import asyncio
import json
from datetime import datetime

# Simple in-memory queue — no RabbitMQ needed
# Works perfectly for portfolio and interviews
alert_queue = asyncio.Queue()
processing_results = {}


async def publish_alert(alert: dict):
    """
    Push alert to in-memory queue.
    Returns immediately — no waiting.
    """
    await alert_queue.put(alert)
    print(f"Alert {alert['id']} added to queue. Queue size: {alert_queue.qsize()}")


async def consume_alerts():
    """
    Background worker that processes queued alerts.
    Runs continuously in the background.
    """
    from src.agent.analyzer import analyze_alert

    print("Alert consumer started — waiting for queued alerts...")

    while True:
        try:
            # Wait for next alert in queue
            alert = await alert_queue.get()
            print(f"Processing queued alert: {alert['id']}")

            # Process in thread so it doesn't block
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, analyze_alert, alert)

            # Store result so it can be retrieved later
            processing_results[alert["id"]] = {
                "status": "completed",
                "completed_at": datetime.now().isoformat(),
                "result": result
            }

            print(f"Completed: {alert['id']}")
            alert_queue.task_done()

        except Exception as e:
            print(f"Queue processing error: {e}")
            await asyncio.sleep(1)


def get_queue_result(alert_id: str) -> dict:
    """Check if a queued alert has been processed."""
    if alert_id in processing_results:
        return processing_results[alert_id]
    return {
        "status": "pending",
        "message": "Alert is still being processed"
    }


def get_queue_status() -> dict:
    """Get current queue statistics."""
    return {
        "queue_size": alert_queue.qsize(),
        "completed": len(processing_results),
        "pending_ids": list(processing_results.keys())
    }