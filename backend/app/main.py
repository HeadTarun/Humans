from fastapi import FastAPI
from app.api.router import api_router
from app.core.config import settings

app = FastAPI(title="Humans", version="1.0.0")

app.include_router(api_router, prefix="/api")

@app.get("/health")
def health_check():
    return {"status": "ok"}
