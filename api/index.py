from fastapi import FastAPI

app = FastAPI(
    title="CyberShield API",
    version="1.0.0",
)


@app.get("/api")
def api_root():
    return {
        "ok": True,
        "service": "CyberShield",
        "status": "online",
        "web_deployment": "health-api",
    }


@app.get("/api/health")
def health():
    return {
        "ok": True,
        "status": "healthy",
    }


@app.get("/api/version")
def version():
    return {
        "service": "CyberShield",
        "version": "19",
        "desktop": "python -m app.main",
    }