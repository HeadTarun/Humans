"""
api/v1/evidence_api.py

Evidence annotation and verification endpoints.

Design principles:
  - Raw forensic evidence (raw_json) is NEVER modified — immutable.
  - Annotations are stored in a separate JSON column and appended-only.
  - Verification state (UNVERIFIED / VERIFIED / DISPUTED) is analyst-controlled.
  - All endpoints are tenant-scoped via JWT.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.api.auth import verify_api_key_or_jwt

logger = logging.getLogger(__name__)
router = APIRouter()


class AnnotateRequest(BaseModel):
    note: str = Field(..., min_length=1, max_length=2000, description="Analyst annotation text")
    author: str = Field(..., min_length=1, max_length=255, description="Analyst identifier")


class VerifyRequest(BaseModel):
    state: str = Field(..., pattern="^(VERIFIED|DISPUTED|UNVERIFIED)$")
    author: str = Field(..., min_length=1, max_length=255)


def _auth_context(auth):
    """Extract tenant_id, user_id, is_admin from auth dependency result."""
    if isinstance(auth, str):
        return None, None, True  # API-key
    return auth.tenant_id, auth.id, auth.can_read_all()


def _check_evidence_access(ev, case, tenant_id, user_id, is_admin):
    """Raise 404 if the caller cannot access this evidence item."""
    if ev is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if case is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    if tenant_id and not is_admin and case.user_id != user_id:
        raise HTTPException(status_code=404, detail="Evidence not found")


@router.post(
    "/{evidence_id}/annotate",
    summary="Add an analyst annotation to an evidence item",
    description=(
        "Appends an analyst note to the evidence item. "
        "Raw forensic evidence (raw_json) is NEVER modified. "
        "Annotations are append-only — they cannot be deleted."
    ),
)
async def annotate_evidence(
    evidence_id: str,
    body: AnnotateRequest,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository
    from app.models.schema import CaseModel
    from sqlalchemy import select as _select

    tenant_id, user_id, is_admin = _auth_context(auth)

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        ev = repo.get_evidence_item(evidence_id, tenant_id) if tenant_id else None
        if ev is None:
            # Fallback for API-key (no tenant_id)
            from app.models.schema import EvidenceModel
            ev = db.execute(_select(EvidenceModel).where(EvidenceModel.evidence_id == evidence_id)).scalar_one_or_none()

        if ev is None:
            raise HTTPException(status_code=404, detail="Evidence not found")

        case = repo.get_case(ev.case_id, tenant_id=tenant_id)
        _check_evidence_access(ev, case, tenant_id, user_id, is_admin)

        annotation = {
            "note": body.note,
            "author": body.author,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        import json as _json
        raw = ev.raw_json or {}
        if isinstance(raw, str):
            try:
                raw = _json.loads(raw)
            except _json.JSONDecodeError:
                raw = {}

        ev = repo.update_evidence_annotation(evidence_id, tenant_id or "", annotation)
        if ev is None:
            raise HTTPException(status_code=404, detail="Evidence not found after update")

        return {
            **raw,
            "annotations": ev.annotations or [],
            "verification_state": ev.verification_state or "UNVERIFIED",
        }


@router.post(
    "/{evidence_id}/verify",
    summary="Set verification state on an evidence item",
    description=(
        "Set the verification state to VERIFIED or DISPUTED. "
        "Only analysts and admins can verify evidence. "
        "Raw forensic evidence is NEVER modified."
    ),
)
async def verify_evidence(
    evidence_id: str,
    body: VerifyRequest,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository
    from sqlalchemy import select as _select

    tenant_id, user_id, is_admin = _auth_context(auth)

    # Viewers cannot verify evidence
    if not isinstance(auth, str) and auth.role == "viewer":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Viewers cannot verify evidence",
        )

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        ev = repo.get_evidence_item(evidence_id, tenant_id) if tenant_id else None
        if ev is None:
            from app.models.schema import EvidenceModel
            ev = db.execute(_select(EvidenceModel).where(EvidenceModel.evidence_id == evidence_id)).scalar_one_or_none()

        if ev is None:
            raise HTTPException(status_code=404, detail="Evidence not found")

        case = repo.get_case(ev.case_id, tenant_id=tenant_id)
        _check_evidence_access(ev, case, tenant_id, user_id, is_admin)

        import json as _json
        raw = ev.raw_json or {}
        if isinstance(raw, str):
            try:
                raw = _json.loads(raw)
            except _json.JSONDecodeError:
                raw = {}

        ev = repo.update_evidence_verification(evidence_id, tenant_id or "", body.state)
        if ev is None:
            raise HTTPException(status_code=404, detail="Evidence not found after update")

        # Log the verification action
        logger.info(
            "Evidence verified evidence_id=%s state=%s author=%s",
            evidence_id, body.state, body.author,
        )

        return {
            **raw,
            "annotations": ev.annotations or [],
            "verification_state": ev.verification_state or "UNVERIFIED",
        }
