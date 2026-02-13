from fastapi import FastAPI

app = FastAPI(title="SentinelLab SOC")

@app.get("/health")
def health():
    return {"status": "ok"}

