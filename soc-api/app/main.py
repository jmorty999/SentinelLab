from datetime import datetime, timezone, timedelta
from typing import Literal, Optional

from fastapi import FastAPI, Depends, Query, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pydantic import BaseModel, Field
from sqlalchemy import select, desc, func
from sqlalchemy.orm import Session

from .db import SessionLocal, engine, Base
from .models import Event, Alert

app = FastAPI(title="SentinelLab SOC")

# Static + templates
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# (MVP) tables au démarrage
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

        fail_count_stmt = (
            select(func.count())
            .select_from(Event)
            .where(Event.event_type == "ssh_failed_login")
            .where(Event.src_ip == row.src_ip)
            .where(Event.received_at >= window_start)
        )
        fail_count = int(db.execute(fail_count_stmt).scalar_one())

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
    alert.is_active = False
    db.add(alert)
    db.commit()
    return {"ok": True, "id": alert.id, "status": "resolved"}


# ---- Dashboard HTML ----
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


# ---- Dashboard data (JSON pour le JS) ----
@app.get("/dashboard/data")
def dashboard_data(
    db: Session = Depends(get_db),
    alerts_limit: int = Query(25, ge=1, le=200),
    events_limit: int = Query(25, ge=1, le=200),
    active_only: bool = Query(True),
    severity: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
):
    now = datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)

    active_alerts_count = int(
        db.execute(
            select(func.count()).select_from(Alert).where(Alert.is_active.is_(True))
        ).scalar_one()
    )
    total_alerts_count = int(
        db.execute(select(func.count()).select_from(Alert)).scalar_one()
    )
    events_last_hour = int(
        db.execute(
            select(func.count()).select_from(Event).where(Event.received_at >= hour_ago)
        ).scalar_one()
    )
    total_events = int(
        db.execute(select(func.count()).select_from(Event)).scalar_one()
    )

    alerts_stmt = select(Alert)
    if active_only:
        alerts_stmt = alerts_stmt.where(Alert.is_active.is_(True))
    if severity:
        alerts_stmt = alerts_stmt.where(Alert.severity == severity)
    if src_ip:
        alerts_stmt = alerts_stmt.where(Alert.src_ip == src_ip)

    alerts = db.execute(
        alerts_stmt.order_by(desc(Alert.created_at)).limit(alerts_limit)
    ).scalars().all()

    events = db.execute(
        select(Event).order_by(desc(Event.received_at)).limit(events_limit)
    ).scalars().all()

    return JSONResponse(
        {
            "kpi": {
                "active_alerts": active_alerts_count,
                "total_alerts": total_alerts_count,
                "events_last_hour": events_last_hour,
                "total_events": total_events,
            },
            "alerts": [
                {
                    "id": a.id,
                    "created_at": a.created_at.isoformat(),
                    "rule": a.rule,
                    "severity": a.severity,
                    "host": a.host,
                    "src_ip": a.src_ip,
                    "user": a.user,
                    "message": a.message,
                    "is_active": a.is_active,
                }
                for a in alerts
            ],
            "events": [
                {
                    "id": e.id,
                    "received_at": e.received_at.isoformat(),
                    "event_type": e.event_type,
                    "host": e.host,
                    "src_ip": e.src_ip,
                    "user": e.user,
                    "message": e.message,
                }
                for e in events
            ],
        }
    )

