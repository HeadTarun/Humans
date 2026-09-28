"""
app/api/v1/cases.py

Case management endpoints.

Cases are the top-level investigation records. Every investigation
produces a Case with a unique case_id. Cases are tenant-scoped
and RBAC-enforced.

Endpoints:
  GET  /cases/                  List cases for the authenticated user's tenant
  GET  /cases/{case_id}         Get a single case summary
  PATCH /cases/{case_id}/status Update case status (admin/analyst only)
  GET  /cases/{case_id}/audit   Retrieve audit trail for a case
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.auth import verify_api_key_or_jwt
from app.api.jwt_auth import require_role

logger = logging.getLogger(__name__)
router = APIRouter()


def _auth_context(auth):
    """Extract tenant_id, user_id, is_admin from dual-auth result."""
    is_api_key = isinstance(auth, str)
    if is_api_key:
        return None, None, True  # API key = admin-level, no tenant filter
    return auth.tenant_id, auth.id, auth.can_read_all()


@router.get("/", summary="List cases for tenant")
async def list_cases(
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """
    Return a paginated list of cases for the authenticated user's tenant.
    Admins see all cases in the tenant. Analysts see only their own cases.
    API-key callers see all cases (service-to-service, no tenant filter).
    """
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository

    tenant_id, user_id, is_admin = _auth_context(auth)

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        if is_admin and tenant_id is None:
            # API-key path: cross-tenant admin (service-to-service)
            # For safety, require tenant_id query param for cross-tenant queries
            tenant_qp = request.query_params.get("tenant_id")
            if tenant_qp:
                cases = repo.list_cases_for_tenant(tenant_qp)
            else:
                # Without explicit tenant, return empty to avoid data leakage
                cases = []
        elif is_admin:
            cases = repo.list_cases_for_tenant(tenant_id)
        else:
            cases = repo.list_cases_for_user(tenant_id, user_id)

        paginated = cases[offset : offset + limit]
        return {
            "total": len(cases),
            "offset": offset,
            "limit": limit,
            "cases": [
                {
                    "case_id": c.case_id,
                    "tenant_id": c.tenant_id,
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                    "status": c.status,
                    "verdict": c.verdict,
                    "risk_score": c.risk_score,
                    "confidence": c.confidence,
                    "original_case_id": c.original_case_id,
                    "user_id": c.user_id,
                }
                for c in paginated
            ],
        }


@router.get("/{case_id}", summary="Get case details")
async def get_case(
    case_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """Return a single case. Tenant-scoped, RBAC-enforced."""
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository

    tenant_id, user_id, is_admin = _auth_context(auth)

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        case = repo.get_case(case_id, tenant_id=tenant_id)
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        if tenant_id and not is_admin and case.user_id != user_id:
            raise HTTPException(status_code=404, detail="Case not found")

        return {
            "case_id": case.case_id,
            "tenant_id": case.tenant_id,
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "status": case.status,
            "verdict": case.verdict,
            "risk_score": case.risk_score,
            "confidence": case.confidence,
            "original_case_id": case.original_case_id,
            "eml_sha256": case.eml_sha256,
            "eml_storage_path": case.eml_storage_path,
            "user_id": case.user_id,
        }


@router.patch("/{case_id}/status", summary="Update case status")
async def update_case_status(
    case_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Update the status of a case (e.g., CLOSED, ESCALATED, FALSE_POSITIVE).
    Only admins and analysts can update status.
    """
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository
    from sqlalchemy import update as sa_update
    from app.models.schema import CaseModel

    tenant_id, user_id, is_admin = _auth_context(auth)

    body = await request.json()
    new_status = body.get("status")
    if not new_status:
        raise HTTPException(status_code=422, detail="'status' field required in request body")

    ALLOWED_STATUSES = {
        "COMPLETED", "INCONCLUSIVE", "CLOSED", "ESCALATED",
        "FALSE_POSITIVE", "TRUE_POSITIVE", "UNDER_REVIEW",
    }
    if new_status.upper() not in ALLOWED_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status. Must be one of: {sorted(ALLOWED_STATUSES)}",
        )

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        case = repo.get_case(case_id, tenant_id=tenant_id)
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        if tenant_id and not is_admin and case.user_id != user_id:
            raise HTTPException(status_code=403, detail="Permission denied")

        db.execute(
            sa_update(CaseModel)
            .where(CaseModel.case_id == case_id)
            .values(status=new_status.upper())
        )
        db.commit()

    logger.info(
        "CASE_STATUS_UPDATED case_id=%s new_status=%s user_id=%s",
        case_id, new_status.upper(), user_id or "api_key",
    )
    return {"case_id": case_id, "status": new_status.upper()}


@router.get("/{case_id}/audit", summary="Get audit trail for a case")
async def get_case_audit(
    case_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Return the full audit trail for a case.
    The audit trail is an append-only, hash-chained sequence of events
    recording every decision made during investigation.
    """
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository

    tenant_id, user_id, is_admin = _auth_context(auth)

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        case = repo.get_case(case_id, tenant_id=tenant_id)
        if not case:
            raise HTTPException(status_code=404, detail="Case not found")
        if tenant_id and not is_admin and case.user_id != user_id:
            raise HTTPException(status_code=404, detail="Case not found")

        audit_records = repo.get_audit_records_by_case(case_id)

    return {
        "case_id": case_id,
        "audit_record_count": len(audit_records),
        "audit_trail": [
            {
                "hash_self": rec.hash_self,
                "hash_prev": rec.hash_prev,
                "step": rec.step,
                "timestamp": rec.timestamp.isoformat() if rec.timestamp else None,
                "event": rec.raw_json,
            }
            for rec in audit_records
        ],
    }
