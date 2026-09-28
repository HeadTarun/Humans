"""
app/api/v1/reports.py

Forensic report management endpoints.

These endpoints manage the persisted report records that are generated
during investigation. The actual report generation logic lives in
GET /investigations/{id}/report — this router provides:
  - Listing and retrieving saved reports
  - Report export (JSON format)
  - Report deletion (admin only)
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.auth import verify_api_key_or_jwt

logger = logging.getLogger(__name__)
router = APIRouter()


def _auth_context(auth):
    """Extract tenant_id, user_id, is_admin from dual-auth result."""
    is_api_key = isinstance(auth, str)
    if is_api_key:
        return None, None, True
    return auth.tenant_id, auth.id, auth.can_read_all()


@router.get("/", summary="List all reports for tenant")
async def list_reports(
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Return all forensic reports available to the authenticated tenant.
    Each report is associated with an investigation case.
    """
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository
    from sqlalchemy import select
    from app.models.schema import ReportModel, CaseModel

    tenant_id, user_id, is_admin = _auth_context(auth)

    with SessionLocal() as db:
        repo = HistoricalRepository(db)

        # Get cases visible to this user/tenant
        if tenant_id:
            if is_admin:
                cases = repo.list_cases_for_tenant(tenant_id)
            else:
                cases = repo.list_cases_for_user(tenant_id, user_id)
        else:
            cases = []

        visible_case_ids = {c.case_id for c in cases}

        if not visible_case_ids:
            return {"total": 0, "reports": []}

        # Fetch reports for visible cases
        reports_q = db.execute(
            select(ReportModel).where(ReportModel.case_id.in_(visible_case_ids))
        ).scalars().all()

        return {
            "total": len(reports_q),
            "reports": [
                {
                    "report_id": r.report_id,
                    "case_id": r.case_id,
                    "generated_at": r.generated_at.isoformat() if r.generated_at else None,
                }
                for r in reports_q
            ],
        }


@router.get("/{case_id}", summary="Get forensic report for a case")
async def get_report(
    case_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Retrieve the persisted forensic report for an investigation.

    This returns the stored report JSON. For a freshly generated report,
    use GET /api/v1/investigations/{investigation_id}/report instead.
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

        report = repo.get_report(case_id)
        if not report:
            raise HTTPException(
                status_code=404,
                detail=(
                    "No report found for this case. "
                    "Use GET /api/v1/investigations/{case_id}/report to generate one."
                ),
            )

        return {
            "report_id": report.report_id,
            "case_id": report.case_id,
            "generated_at": report.generated_at.isoformat() if report.generated_at else None,
            "report": report.raw_json,
        }


@router.get("/{case_id}/export", summary="Export report as JSON")
async def export_report(
    case_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Export the forensic report as a downloadable JSON file.
    Returns the report with Content-Disposition header for download.
    """
    from fastapi.responses import JSONResponse
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

        report = repo.get_report(case_id)
        if not report:
            raise HTTPException(status_code=404, detail="No report found for this case")

        export_data = {
            "export_version": "1.0",
            "case_id": case_id,
            "generated_at": report.generated_at.isoformat() if report.generated_at else None,
            "report": report.raw_json,
        }

    return JSONResponse(
        content=export_data,
        headers={
            "Content-Disposition": f'attachment; filename="ashielder_report_{case_id}.json"',
        },
    )
