# SentinelLab

SentinelLab is a mini Security Operations Center (SOC) developed from scratch.

The project collects system events from endpoints, normalizes them, detects suspicious behavior, and generates alerts.

Objective: to gain a deep understanding of how detection tools (EDR/SIEM) work by rebuilding the core components yourself.

---

## Features

- Log collection from Linux machines
- Secure ingestion API
- Event normalization
- Database storage
- Rule-based detection engine
- Web interface for exploring events and alerts
- Attack lab for testing detections

---

## Architecture

Agent (Linux VM) → SOC API → Database → Detection → Dashboard

---

## Technical Stack

- Backend: FastAPI (Python)
- Database: PostgreSQL
- Deployment: Docker Compose
- Agent: Python

---

## Why this project?

Off-the-shelf tools often mask the true complexity.

SentinelLab aims to demonstrate:

- Telemetry collection
- Data transformation
- Correlation
- Noise reduction
- Generation of actionable alerts

---

## Roadmap

- [ ] Ingestion API
- [ ] Event storage
- [ ] Initial detection rules (SSH brute force)
- [ ] Dashboard
- [ ] Event signing (HMAC)
- [ ] IP enrichment / threat intelligence
- [ ] Attack replay

---

## Disclaimer

Educational project. No offensive tools or malware are included.

project finished
