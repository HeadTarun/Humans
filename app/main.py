"""
app/main.py

FastAPI application entry point.

Startup order:
  1. Logging configured
  2. DB schema initialised (create_all — idempotent)
  3. ML models loaded into memory
  4. Provider diagnostic logged

Middleware stack (outermost → innermost):
  RequestIDMiddleware  →  CORSMiddleware  →  routes

Global exception handler catches any unhandled exception and returns a
structured JSON error so raw tracebacks / SQL errors never reach clients.
"""

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.router import api_router
from app.core.config import settings
from app.middleware.request_id import RequestIDMiddleware

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Application lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Provider diagnostics (logs warnings, never logs values)
    from app.core.config import log_optional_provider_diagnostics
    log_optional_provider_diagnostics()

    # 2. Database initialisation — run ONCE at startup, not per-request.
    #    Uses async engine when DATABASE_URL is asyncpg/aiosqlite;
    #    falls back to the synchronous engine for other drivers.
    try:
        from app.repositories.async_persistence import (
            ASYNC_PERSISTENCE_ENABLED,
            init_async_db,
        )
        if ASYNC_PERSISTENCE_ENABLED:
            await init_async_db()
            logger.info("Async database schema initialised.")
        else:
            from app.repositories.db import init_db
            init_db()
            logger.info("Sync database schema initialised.")
    except Exception as db_exc:
        # Non-fatal at startup: log clearly and continue.
        # Investigation results can still be computed; only persistence will fail.
        logger.error(
            "DATABASE_INIT_FAILED type=%s detail=%s — persistence unavailable",
            type(db_exc).__name__,
            db_exc,
        )

    # 3. Eagerly load ML models so the first request is not slow.
    try:
        from app.services.ml.m2_intent_classifier import M2IntentClassifier
        from app.services.ml.m4_lighturlnet_inference import M4LightUrlNetInference

        logger.info("Initializing ML models...")
        m2 = M2IntentClassifier()
        if m2.is_available():
            logger.info("M2IntentClassifier runtime loaded successfully. Warming up...")
            m2.process({"module": "M1", "status": "success", "normalized_text": "warmup text", "language": "en"})
            logger.info("M2IntentClassifier warm-up complete.")
        else:
            logger.warning("M2IntentClassifier runtime unavailable.")

        m4 = M4LightUrlNetInference()
        if m4.is_available():
            logger.info("M4LightUrlNetInference runtime loaded successfully. Warming up...")
            m4.predict_risk("http://example.com/warmup")
            logger.info("M4LightUrlNetInference warm-up complete.")
        else:
            logger.warning("M4LightUrlNetInference runtime unavailable.")
    except Exception as exc:
        logger.error(f"ML model initialization failed: {exc}", exc_info=True)

    yield
    # Shutdown cleanup (add resource teardown here if needed)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

app = FastAPI(
    title="ASHIELDER — Email Threat Investigation API",
    version="1.0.0",
    description=(
        "Adaptive, evidence-grounded email threat investigation. "
        "All endpoints except /health require X-API-Key authentication."
    ),
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Middleware stack
# ---------------------------------------------------------------------------

# 1. Request ID — outermost so every request/error has an ID
app.add_middleware(RequestIDMiddleware)

# 2. CORS — origins come from environment; never hardcoded to "*"
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "X-Request-ID", "Authorization"],
)

# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Catch-all for unhandled exceptions.

    Returns a structured JSON error — never exposes:
      - stack traces
      - SQL error messages
      - database credentials
      - internal file paths
      - provider API keys
    """
    request_id = getattr(request.state, "request_id", uuid.uuid4().hex)
    logger.error(
        "UNHANDLED_EXCEPTION request_id=%s method=%s path=%s type=%s",
        request_id,
        request.method,
        request.url.path,
        type(exc).__name__,
        exc_info=True,  # full traceback in server logs only
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An internal server error occurred. Check server logs for details.",
                "request_id": request_id,
            }
        },
        headers={"X-Request-ID": request_id},
    )

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

app.include_router(api_router, prefix="/api")


@app.get("/health", tags=["Health"])
def health_check():
    return {"status": "ok"}

@app.get("/healthz", tags=["Health"])
def liveness_probe():
    """Liveness probe for Kubernetes/Docker."""
    return {"status": "ok"}

@app.get("/readyz", tags=["Health"])
async def readiness_probe():
    """Readiness probe checking DB connectivity and ML models."""
    try:
        from app.repositories.async_persistence import ASYNC_PERSISTENCE_ENABLED
        if ASYNC_PERSISTENCE_ENABLED:
            from app.repositories.async_persistence import get_async_session
            async for session in get_async_session():
                from sqlalchemy import text
                await session.execute(text("SELECT 1"))
                break
        else:
            from app.repositories.db import SessionLocal
            from sqlalchemy import text
            with SessionLocal() as db:
                db.execute(text("SELECT 1"))
                
        # Check ML models
        from app.services.ml.m2_intent_classifier import M2IntentClassifier
        from app.services.ml.m4_lighturlnet_inference import M4LightUrlNetInference
        
        models_status = {
            "M2IntentClassifier": M2IntentClassifier.is_available(),
            "M4LightUrlNetInference": M4LightUrlNetInference.is_available()
        }
        
        # If models are fundamentally missing, the demo is not ready
        if not all(models_status.values()):
            from fastapi import HTTPException
            logger.error(f"Readiness probe failed, missing models: {models_status}")
            raise HTTPException(status_code=503, detail=f"ML models unavailable: {models_status}")
            
        return {"status": "ready", "models": models_status}
    except Exception as e:
        logger.error(f"Readiness probe failed: {e}")
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail="Service unavailable")
