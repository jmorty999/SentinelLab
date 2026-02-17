from datetime import datetime, timezone, timedelta
from typing import Literal, Optional

import os
import hmac
import hashlib
import json
import time

from fastapi import FastAPI, Depends, Request, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from .db import SessionLocal, engine, Base
from .models import Event, Alert


app = FastAPI(title="SentinelLab SOC")

# Création automatique des tables (MVP)
Base.metadata.create_all(bind=engine)


# =========================
# HMAC CONFIG
# =========================

HMAC_SECRET = os.getenv("INGEST_HMAC_SECRET", "")
MAX_SKEW = int(os.getenv("INGEST_MAX_SKEW_SECONDS", "120"))
NONCE_TTL = int(os.getenv("INGEST_NONCE_TTL_SECONDS", "300"))

NONCE_CACHE: dict[str, int] = {}


def _prune_nonces(now: int) -> None:
    expired = [n for n, t in NONCE_CACHE.items() if now - t > NONCE_TTL]
    for n in expired:
        NONCE_CACHE.pop(n, None)


def verify_ingest_signature(request: Request, body_bytes: bytes) -> None:
    if not HMAC_SECRET:
        raise HTTPException(status_code=500, detail="INGEST_HMAC_SECRET not configured")

    ts_str = request.headers.get("X-Timestamp")
    nonce = request.headers.get("X-Nonce")
    sig = request.headers.get("X-Signature")

    if not ts_str or not nonce or not sig:
        raise HTTPException(status_code=401, detail="Missing auth headers")

    try:
        ts = int(ts_str)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid timestamp")

    now = int(time.time())

    if abs(now - ts) > MAX_SKEW:
        raise HTTPException(status_code=401, detail="Timestamp out of range")

    _prune_nonces(now)

    if nonce in NONCE_CACHE:
        raise HTTPException(status_code=401, detail="Replay detected")

    NONCE_CACHE[nonce] = now

    msg = str(ts).encode() + b"\n" + nonce.encode() + b"\n" + body_bytes
    expected = hmac.new(HMAC_SECRET.encode(), msg, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, sig):
        NONCE_CACHE.pop(nonce, None)
        raise HTTPException(status_code=401, detail="Invalid signature")


# =========================
# DB DEPENDENCY
# =========================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================
# MODELS
# =========================

class IngestEvent(BaseModel):
    ts: datetime = Field(..., description="timestamp ISO")
    host: str = Field(..., min_length=1, max_length=128)
    event_type: Literal["ssh_failed_login", "ssh_login_success", "generic"]
    src_ip: Optional[str] = Field(default=None, max_length=64)
    user: Optional[str] = Field(default=None, max_length=64)
    message: str = Field(..., min_length=1, max_length=2000)


# =========================
# ROUTES
# =========================

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/ingest")
async def ingest(request: Request, db: Session = Depends(get_db)):
    body_bytes = await request.body()

    # 🔐 Vérification HMAC
    verify_ingest_signature(request, body_bytes)

    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    event = IngestEvent(**payload)

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

    # =========================
    # Detection: SSH brute force
    # =========================
    if row.event_type == "ssh_failed_login" and row.src_ip:
        window_start = datetime.now(timezone.utc) - timedelta(minutes=2)

        fail_count_stmt = (
            select(Event.id)
            .where(Event.event_type == "ssh_failed_login")
            .where(Event.src_ip == row.src_ip)
            .where(Event.received_at >= window_start)
        )

        fail_count = len(db.execute(fail_count_stmt).all())

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

