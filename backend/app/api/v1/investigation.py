"""
api/v1/investigation.py

POST /api/v1/investigations/analyze

Accepts a raw .eml file and runs the full deterministic investigation pipeline:

    Raw .eml
        ↓ EmailParser
    ParsedEmail
        ↓ EvidenceNormalizer
    EmailEvidencePackage
        ↓ InvestigationDecisionEngine.run_stage1()
    Stage1Result
        ↓ to_investigation_result()
    InvestigationResult ← returned to client

The response_model=InvestigationResult enforces the contract at the
FastAPI serialization boundary. If the result cannot be serialized
(e.g., a validator fails), FastAPI will return a 422, not silently
return incorrect data.

Security guarantees:
    - resource exhaustion → status=INCONCLUSIVE, not BENIGN
    - all evidence collected before stop is preserved
    - audit hash included in every response
"""

from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.contracts.result import InvestigationResult
from app.services.evidence import EvidenceNormalizer
from app.services.ingestion.parser import EmailParser
from app.services.investigation import (
    InvestigationDecisionEngine,
    to_investigation_result,
)

router = APIRouter()

# Stateless, safe to share across requests
_parser = EmailParser()
_normalizer = EvidenceNormalizer()
_engine = InvestigationDecisionEngine()


@router.post(
    "/analyze",
    response_model=InvestigationResult,
    summary="Analyze a raw email for threats",
    description=(
        "Upload a raw .eml file. Returns a fully structured InvestigationResult "
        "including verdict, risk score, confidence, hypotheses, evidence IDs, "
        "budget usage, and audit chain hash. "
        "Budget exhaustion → status=INCONCLUSIVE (never BENIGN). "
        "All evidence collected before stopping is preserved in the response."
    ),
    tags=["Investigations"],
)
async def analyze_email(
    file: UploadFile = File(..., description="Raw .eml file to investigate"),
) -> InvestigationResult:
    """
    Full investigation pipeline for a single email.

    Steps:
        1. Parse raw .eml → ParsedEmail
        2. Normalize → EmailEvidencePackage
        3. Stage 1 investigation → Stage1Result
        4. Risk assessment → InvestigationResult

    Returns a contract-validated InvestigationResult.
    All fields are deterministic for the same input.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename not provided")

    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Empty file")

    try:
        # Stage 1: Parse
        parsed_email = _parser.parse(raw_bytes)

        # Stage 2: Normalize
        package = _normalizer.normalize(parsed_email)

        # Stage 3: Investigate
        stage1_result = _engine.run_stage1(package)

        # Stage 4: Risk assessment → final result
        result = to_investigation_result(stage1_result)

        return result

    except ValueError as exc:
        # Contract validation failures are 422 by convention
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Investigation failed: {type(exc).__name__}: {exc}",
        ) from exc
