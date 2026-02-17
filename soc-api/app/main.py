from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import FastAPI, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from .db import SessionLocal, engine, Base
from .models import Event

app = FastAPI(title="SentinelLab SOC")

# MVP: crée les tables au démarrage (on fera Alembic plus tard)
Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class IngestEvent(BaseModel):
    ts: datetime = Field(..., description="timestamp ISO")
    host: str = Field(..., min_length=1, max_length=128)
    event_type: Literal["ssh_failed_login", "ssh_login_success", "generic"]
    src_ip: Optional[str] = Field(default=None, max_length=64)
    user: Optional[str] = Field(default=None, max_length=64)
    message: str = Field(..., min_length=1, max_length=2000)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ingest")
def ingest(event: IngestEvent, db: Session = Depends(get_db)):
    ts = event.ts
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    row = Event(
        ts=ts,
        host=event.host,
        event_type=event.event_type,
        src_ip=event.src_ip,
        user=event.user,
        message=event.message,
        received_at=datetime.now(timezone.utc),
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return {"ok": True, "event_id": row.id}


@app.get("/events")
def list_events(limit: int = 100, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 500))
    stmt = select(Event).order_by(desc(Event.received_at)).limit(limit)
    rows = db.execute(stmt).scalars().all()

    items = [
        {
            "id": r.id,
            "ts": r.ts.isoformat(),
            "host": r.host,
            "event_type": r.event_type,
            "src_ip": r.src_ip,
            "user": r.user,
            "message": r.message,
            "received_at": r.received_at.isoformat(),
        }
        for r in rows
    ]
    return {"count": len(items), "items": items}
