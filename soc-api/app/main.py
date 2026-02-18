from datetime import datetime, timezone, timedelta
from typing import Literal, Optional
from fastapi import FastAPI, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.orm import Session
from .db import SessionLocal, engine, Base
from .models import Event, Alert
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
    # Detection: SSH brute force (>= 5 fails / 2 min / same IP)
    if row.event_type == "ssh_failed_login" and row.src_ip:
        window_start = datetime.now(timezone.utc) - timedelta(minutes=2)

        # Compter les échecs récents depuis cette IP
        fail_count_stmt = (
            select(Event.id)
            .where(Event.event_type == "ssh_failed_login")
            .where(Event.src_ip == row.src_ip)
            .where(Event.received_at >= window_start)
        )
        fail_count = len(db.execute(fail_count_stmt).all())

        # Anti-spam : une seule alerte par IP toutes les 2 minutes
        recent_alert_stmt = (
            select(Alert.id)
            .where(Alert.rule == "ssh_bruteforce")
            .where(Alert.src_ip == row.src_ip)
            .where(Alert.created_at >= window_start)
            .limit(1)
        )
        recent_alert = db.execute(recent_alert_stmt).first()

        if fail_count >= 5 and not recent_alert:
            alert = Alert(
                created_at=datetime.now(timezone.utc),
                rule="ssh_bruteforce",
                severity="high",
                host=row.host,
                src_ip=row.src_ip,
                user=row.user,
                message=f"SSH brute force suspected: {fail_count} failures in 2 min from {row.src_ip}",
                is_active=True,
            )
            db.add(alert)
            db.commit()
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

@app.get("/alerts")
def list_alerts(limit: int = 50, db: Session = Depends(get_db)):
    limit = max(1, min(limit, 200))
    stmt = select(Alert).order_by(desc(Alert.created_at)).limit(limit)
    rows = db.execute(stmt).scalars().all()

    items = [
        {
            "id": a.id,
            "created_at": a.created_at.isoformat(),
            "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
            "rule": a.rule,
            "severity": a.severity,
            "host": a.host,
            "src_ip": a.src_ip,
            "user": a.user,
            "message": a.message,
            "is_active": a.is_active,
        }
        for a in rows
    ]
    return {"count": len(items), "items": items}

@app.patch("/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if not alert.is_active:
        return {"ok": True, "id": alert.id, "status": "already_resolved"}

    alert.is_active = False
    alert.resolved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(alert)

    return {
        "ok": True,
        "id": alert.id,
        "status": "resolved",
        "resolved_at": alert.resolved_at.isoformat(),
    }
@app.patch("/alerts/{alert_id}/reopen")
def reopen_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.is_active = True
    alert.resolved_at = None
    db.commit()
    db.refresh(alert)

    return {"ok": True, "id": alert.id, "status": "reopened"}

