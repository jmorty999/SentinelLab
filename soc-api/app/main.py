from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="SentinelLab SOC")

# stockage temporaire en mémoire (sera remplacé par la DB plus tard)
EVENTS: list[dict] = []


class IngestEvent(BaseModel):
    ts: datetime = Field(..., description="timestamp ISO")
    host: str = Field(..., min_length=1)
    event_type: Literal[
        "ssh_failed_login",
        "ssh_login_success",
        "generic",
    ]
    src_ip: Optional[str] = None
    user: Optional[str] = None
    message: str = Field(..., min_length=1)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ingest")
def ingest(event: IngestEvent):
    # normalisation légère
    ts = event.ts
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    normalized = {
        "ts": ts.isoformat(),
        "host": event.host,
        "event_type": event.event_type,
        "src_ip": event.src_ip,
        "user": event.user,
        "message": event.message,
        "received_at": datetime.now(timezone.utc).isoformat(),
    }

    EVENTS.append(normalized)

    return {"ok": True, "total_events": len(EVENTS)}


@app.get("/events")
def list_events():
    return {
        "count": len(EVENTS),
        "items": list(reversed(EVENTS)),
    }
