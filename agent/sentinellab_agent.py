#!/usr/bin/env python3
import argparse
import hmac
import hashlib
import json
import os
import re
import secrets
import socket
import time
from datetime import datetime, timezone
from urllib import request as urlrequest
from urllib.error import URLError, HTTPError


# --- SSH parsing (auth.log) ---
# Exemples typiques:
# Feb 17 10:20:28 ubuntu sshd[1234]: Failed password for root from 10.0.0.5 port 54321 ssh2
# Feb 17 10:20:30 ubuntu sshd[1234]: Accepted password for ubuntu from 10.0.0.5 port 54321 ssh2

RE_FAILED = re.compile(r"Failed password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_ACCEPTED = re.compile(r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_SYSLOG_TS = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$")

MONTHS = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,"Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}


def syslog_ts_to_iso(line: str) -> str:
    """
    Convertit un timestamp syslog sans année (ex: 'Feb 17 10:20:28') en ISO UTC.
    Hypothèse: année courante. C’est ok pour un lab.
    """
    m = RE_SYSLOG_TS.match(line)
    if not m:
        return datetime.now(timezone.utc).isoformat()

    mon = MONTHS.get(m.group("mon"), datetime.now().month)
    day = int(m.group("day"))
    h, mi, s = map(int, m.group("hms").split(":"))
    now = datetime.now()
    dt_local = datetime(now.year, mon, day, h, mi, s)  # naive (local)
    # On force en UTC pour rester cohérent avec ton backend
    return dt_local.replace(tzinfo=timezone.utc).isoformat()


def parse_auth_line(host: str, line: str):
    # On ne traite que sshd
    if "sshd" not in line:
        return None

    event_type = None
    user = None
    src_ip = None

    m = RE_FAILED.search(line)
    if m:
        event_type = "ssh_failed_login"
        user = m.group("user")
        src_ip = m.group("ip")

    m = RE_ACCEPTED.search(line)
    if m:
        event_type = "ssh_login_success"
        user = m.group("user")
        src_ip = m.group("ip")

    if not event_type:
        return None

    return {
        "ts": syslog_ts_to_iso(line),
        "host": host,
        "event_type": event_type,
        "src_ip": src_ip,
        "user": user,
        "message": line.strip(),
    }


def sign_hmac(secret: str, body_bytes: bytes):
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    msg = ts.encode() + b"\n" + nonce.encode() + b"\n" + body_bytes
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    return ts, nonce, sig


def post_json(url: str, secret: str, payload: dict, timeout: int = 5):
    body_bytes = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ts, nonce, sig = sign_hmac(secret, body_bytes)

    req = urlrequest.Request(
        url,
        data=body_bytes,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Timestamp": ts,
            "X-Nonce": nonce,
            "X-Signature": sig,
        },
    )
    with urlrequest.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", errors="replace")


def follow_file(path: str):
    """
    Tail -F simple en Python:
    - lit la fin du fichier
    - attend les nouvelles lignes
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="/var/log/auth.log")
    ap.add_argument("--url", default=os.getenv("SENTINELLAB_INGEST_URL", "http://127.0.0.1:8000/ingest"))
    ap.add_argument("--secret", default=os.getenv("SENTINELLAB_HMAC_SECRET", ""))
    ap.add_argument("--host", default=os.getenv("SENTINELLAB_HOST", socket.gethostname()))
    ap.add_argument("--retry-seconds", type=int, default=2)
    args = ap.parse_args()

    if not args.secret:
        print("ERROR: missing secret. Set SENTINELLAB_HMAC_SECRET or --secret")
        raise SystemExit(2)

    print(f"[agent] following {args.file}")
    print(f"[agent] sending to {args.url} as host={args.host}")

    for line in follow_file(args.file):
        evt = parse_auth_line(args.host, line)
        if not evt:
            continue

        # Retry simple
        while True:
            try:
                status, body = post_json(args.url, args.secret, evt)
                if status >= 200 and status < 300:
                    break
                print(f"[agent] server error {status}: {body}")
                time.sleep(args.retry_seconds)
            except HTTPError as e:
                print(f"[agent] HTTPError {e.code}: {e.read().decode(errors='replace')}")
                time.sleep(args.retry_seconds)
            except URLError as e:
                print(f"[agent] URLError: {e}")
                time.sleep(args.retry_seconds)
            except Exception as e:
                print(f"[agent] error: {e}")
                time.sleep(args.retry_seconds)


if __name__ == "__main__":
    main()

