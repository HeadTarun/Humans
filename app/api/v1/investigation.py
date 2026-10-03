from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile

from app.api.auth import verify_api_key_or_jwt
from app.contracts.result import InvestigationResult
from app.services.evidence import EvidenceNormalizer
from app.services.ingestion.parser import EmailParser
from app.services.investigation import (
    InvestigationDecisionEngine,
    to_investigation_result,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Stateless, safe to share across requests
_parser = EmailParser()
_normalizer = EvidenceNormalizer()
_engine = InvestigationDecisionEngine()


@router.get(
    "",
    summary="List investigations for the authenticated user's tenant",
    description=(
        "Returns all investigations visible to the caller. "
        "Admin: all cases in the tenant. Analyst/viewer: own cases only. "
        "Ordered by created_at descending."
    ),
    tags=["Investigations"],
)
async def list_investigations(
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
    limit: int = 50,
    offset: int = 0,
):
    """
    List investigations for the authenticated tenant.

    TENANT ISOLATION: Only cases belonging to the caller's tenant_id are returned.
    Admin users see all cases in the tenant; analyst/viewer sees only their own.
    """
    import json as _json
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository

    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    is_admin = isinstance(auth, str)

    if not isinstance(auth, str):
        tenant_id = auth.tenant_id
        user_id = auth.id
        is_admin = auth.can_read_all()

    with SessionLocal() as db:
        repo = HistoricalRepository(db)

        if not tenant_id:
            # API-key: no tenant filter; return empty list (not relevant for service-to-service)
            return {"cases": [], "total": 0, "limit": limit, "offset": offset}

        if is_admin:
            cases = repo.list_cases_for_tenant(tenant_id)
        else:
            cases = repo.list_cases_for_user(tenant_id, user_id)

        # Pagination (slice after fetch — acceptable for moderate case volumes)
        total = len(cases)
        paged = cases[offset: offset + limit]

        def _extract_email_meta(case_id: str) -> dict:
            """Extract subject/sender/recipient from persisted report (best-effort)."""
            try:
                rpt = repo.get_report(case_id)
                if not rpt or not rpt.raw_json:
                    return {}
                raw = rpt.raw_json
                if isinstance(raw, str):
                    try:
                        raw = _json.loads(raw)
                    except Exception:
                        return {}
                inv = raw.get("investigation_result", {})
                email_artifact = inv.get("email_artifact", {})
                risk_reasons = inv.get("risk_reasons", [])
                summary = risk_reasons[0] if risk_reasons else None
                return {
                    "subject": email_artifact.get("subject"),
                    "sender": email_artifact.get("sender") or email_artifact.get("from_address"),
                    "recipient": (
                        email_artifact.get("to_address")
                        or (email_artifact.get("recipients") or [None])[0]
                    ),
                    "summary": summary,
                    "tools_used": inv.get("tools_used", []),
                    "missing_evidence": inv.get("missing_evidence", []),
                    "attack_hypotheses": inv.get("attack_hypotheses", []),
                    "risk_reasons": inv.get("risk_reasons", []),
                    "stop_reason": inv.get("stop_reason"),
                    "iteration_count": inv.get("iteration_count", 0),
                }
            except Exception:
                return {}

        return {
            "cases": [
                {
                    "case_id": c.case_id,
                    "tenant_id": c.tenant_id,
                    "status": c.status,
                    "verdict": c.verdict,
                    "risk_score": c.risk_score,
                    "confidence": c.confidence,
                    "created_at": c.created_at.isoformat() if c.created_at else None,
                    "user_id": c.user_id,
                    "original_case_id": c.original_case_id,
                    "eml_sha256": c.eml_sha256,
                    **_extract_email_meta(c.case_id),
                }
                for c in paged
            ],
            "total": total,
            "limit": limit,
            "offset": offset,
        }


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
    request: Request,
    file: UploadFile = File(..., description="Raw .eml file to investigate"),
    auth=Depends(verify_api_key_or_jwt),
) -> InvestigationResult:
    """
    Full investigation pipeline for a single email.

    Auth: accepts X-API-Key (legacy/service) OR Bearer JWT (user).
    When authenticated via JWT, the case is tagged with the user's ID and
    tenant_id — both derived from the token, never from client input.

    Steps:
        1. Parse raw .eml → ParsedEmail
        2. Normalize → EmailEvidencePackage
        3. Stage 1 investigation → Stage1Result
        4. Risk assessment → InvestigationResult
        5. Persist case (best-effort)
        6. Upload raw .eml to Supabase Storage (best-effort)
    """
    request_started = time.perf_counter()

    # Resolve user_id and tenant_id from JWT auth (fallback for API-key auth)
    user_id: Optional[str] = None
    tenant_id: str = "default_tenant"
    if not isinstance(auth, str):
        # auth is a UserModel — use authoritative tenant from the DB record
        user_id = auth.id
        tenant_id = auth.tenant_id

    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename not provided")

    MAX_UPLOAD_BYTES = 10_000_000  # 10 MB limit
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large")

    try:
        # Stage 1: Parse
        parsed_email = _parser.parse(raw_bytes)

        # Stage 2: Normalize
        package = _normalizer.normalize(parsed_email)

        # Stage 3: Investigate
        stage1_result = await _engine.run_stage1(package, started_at=request_started)

        # Stage 4: Risk assessment → final result
        result = to_investigation_result(stage1_result)

        # ------------------------------------------------------------------
        # Stage 5: Persistence (best-effort) — SKIPPED in demo mode
        # ------------------------------------------------------------------
        from app.core.config import settings as _app_settings
        eml_sha256: Optional[str] = None
        eml_storage_path: Optional[str] = None

        if not _app_settings.DEMO_MODE:
            try:
                from app.repositories.async_persistence import (
                    ASYNC_PERSISTENCE_ENABLED,
                    persist_investigation,
                )
                if ASYNC_PERSISTENCE_ENABLED:
                    await persist_investigation(
                        result,
                        stage1_result.all_evidence,
                        stage1_result.audit_logger.records,
                        user_id=user_id,
                        tenant_id=tenant_id,
                    )
                else:
                    from app.repositories.db import SessionLocal
                    from app.repositories.historical_repository import HistoricalRepository
                    with SessionLocal() as _session:
                        HistoricalRepository(_session).save_investigation(
                            result,
                            stage1_result.all_evidence,
                            stage1_result.audit_logger.records,
                            user_id=user_id,
                            tenant_id=tenant_id,
                        )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "PERSISTENCE_FAILED case=%s type=%s detail=%s",
                    result.investigation_id,
                    type(exc).__name__,
                    exc,
                    exc_info=True,
                )
                raise HTTPException(
                    status_code=500,
                    detail=f"Investigation completed but persistence failed: {exc}",
                ) from exc

            # ------------------------------------------------------------------
            # Stage 6: Raw .eml upload to Supabase Storage (best-effort)
            # ------------------------------------------------------------------
            try:
                from app.integrations.eml_storage import eml_storage
                if eml_storage.enabled:
                    eml_sha256 = await eml_storage.upload_eml(
                        result.investigation_id, raw_bytes
                    )
                    if eml_sha256:
                        eml_storage_path = eml_storage.storage_path(result.investigation_id)
                        _patch_case_eml_fields(
                            result.investigation_id, eml_sha256, eml_storage_path
                        )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "EML_STORAGE_FAILED case=%s type=%s detail=%s",
                    result.investigation_id,
                    type(exc).__name__,
                    exc,
                )
        else:
            logger.info(
                "DEMO_MODE: skipping persistence and EML storage for case=%s",
                result.investigation_id,
            )

        return result

    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Investigation failed: {type(exc).__name__}: {exc}",
        ) from exc


def _patch_case_eml_fields(
    case_id: str, sha256: str, storage_path: str
) -> None:
    """Best-effort DB update to record EML storage metadata on the case row."""
    try:
        from app.repositories.db import SessionLocal
        from app.models.schema import CaseModel
        with SessionLocal() as session:
            case = session.get(CaseModel, case_id)
            if case:
                case.eml_sha256 = sha256
                case.eml_storage_path = storage_path
                session.commit()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not patch EML fields on case %s: %s", case_id, exc)


@router.get("/{investigation_id}", summary="Get investigation summary")
async def get_investigation(
    investigation_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Return a tenant-scoped investigation summary enriched with email metadata.

    RBAC:
        - admin: any case within their tenant
        - analyst/viewer: only cases they submitted

    TENANT ISOLATION: case_id + tenant_id are both required for DB lookup.
    Client-supplied case_id alone is never sufficient.
    """
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository

    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    is_admin = isinstance(auth, str)  # API-key = treat as admin

    if not isinstance(auth, str):
        tenant_id = auth.tenant_id
        user_id = auth.id
        is_admin = auth.can_read_all()

    with SessionLocal() as db:
        repo = HistoricalRepository(db)

        if tenant_id:
            case = repo.get_case(investigation_id, tenant_id=tenant_id)
        else:
            # API-key path — no tenant filter (service-to-service)
            case = repo.get_case(investigation_id)

        if not case:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # Non-admin JWT users can only see their own cases within the tenant
        if tenant_id and not is_admin and case.user_id != user_id:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # Enrich from persisted report
        report_model = repo.get_report(investigation_id)
        investigation_result = None
        if report_model and report_model.raw_json:
            import json as _json
            raw = report_model.raw_json
            if isinstance(raw, str):
                try:
                    raw = _json.loads(raw)
                except _json.JSONDecodeError:
                    raw = {}
            investigation_result = raw.get("investigation_result", {})

        # Extract email metadata from persisted InvestigationResult
        geolocation = []
        content_analysis = None
        attack_hypotheses = []
        risk_reasons = []
        tools_used = []
        missing_evidence = []
        stop_reason = None
        iteration_count = 0
        if investigation_result:
            geolocation = investigation_result.get("geolocation", [])
            content_analysis = investigation_result.get("content_analysis")
            attack_hypotheses = investigation_result.get("attack_hypotheses", [])
            risk_reasons = investigation_result.get("risk_reasons", [])
            tools_used = investigation_result.get("tools_used", [])
            missing_evidence = investigation_result.get("missing_evidence", [])
            stop_reason = investigation_result.get("stop_reason")
            iteration_count = investigation_result.get("iteration_count", 0)

        return {
            "case_id": case.case_id,
            "tenant_id": case.tenant_id,
            "status": case.status,
            "verdict": case.verdict,
            "risk_score": case.risk_score,
            "confidence": case.confidence,
            "created_at": case.created_at.isoformat() if case.created_at else None,
            "user_id": case.user_id,
            "original_case_id": case.original_case_id,
            "eml_sha256": case.eml_sha256,
            "eml_storage_path": case.eml_storage_path if is_admin else None,
            # Enriched from InvestigationResult
            "geolocation": geolocation,
            "content_analysis": content_analysis,
            "attack_hypotheses": attack_hypotheses,
            "risk_reasons": risk_reasons,
            "tools_used": tools_used,
            "missing_evidence": missing_evidence,
            "stop_reason": stop_reason,
            "iteration_count": iteration_count,
        }


@router.get("/{investigation_id}/evidence", summary="Get investigation evidence")
async def get_evidence(
    investigation_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Return all evidence items for a case, tenant-scoped.

    Each evidence item includes its raw forensic data PLUS analyst annotations
    and verification state (stored separately — raw evidence is never mutated).
    """
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository

    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    is_admin = isinstance(auth, str)

    if not isinstance(auth, str):
        tenant_id = auth.tenant_id
        user_id = auth.id
        is_admin = auth.can_read_all()

    with SessionLocal() as db:
        repo = HistoricalRepository(db)

        case = repo.get_case(investigation_id, tenant_id=tenant_id)
        if not case:
            raise HTTPException(status_code=404, detail="Investigation not found")

        if tenant_id and not is_admin and case.user_id != user_id:
            raise HTTPException(status_code=404, detail="Investigation not found")

        evidence = repo.get_evidence_by_case(investigation_id, tenant_id=tenant_id)
        if not evidence:
            return []

        # Merge annotations and verification_state into each evidence item
        result = []
        for ev in evidence:
            raw = ev.raw_json or {}
            if isinstance(raw, str):
                import json as _json
                try:
                    raw = _json.loads(raw)
                except _json.JSONDecodeError:
                    raw = {"error": "unparseable evidence record", "evidence_id": ev.evidence_id}
            result.append({
                **raw,
                "annotations": ev.annotations or [],
                "verification_state": ev.verification_state or "UNVERIFIED",
            })
        return result


@router.get("/{investigation_id}/report", summary="Get investigation forensic report")
async def get_report(
    investigation_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Deterministic forensic report built from persisted InvestigationResult + evidence.

    Per §3 of the spec:
    - "Builds a forensic report from the authoritative investigation result and
      validated evidence."
    - Groq is explicitly OPTIONAL (§16, §3): this report MUST NOT depend on
      Groq being available. The deterministic report is always returned.
    - If Groq IS configured it may add a natural-language narrative on top,
      but MUST degrade gracefully to the deterministic report per §5 P2.
    """
    import json
    from datetime import datetime, timezone

    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        case = repo.get_case(investigation_id)
        if not case:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # RBAC visibility
        if not isinstance(auth, str):
            user = auth
            if not user.can_read_all() and case.user_id != user.id:
                raise HTTPException(status_code=404, detail="Investigation not found")

        evidence_records = repo.get_evidence_by_case(investigation_id)
        persisted_report = repo.get_report(investigation_id)

    # ------------------------------------------------------------------
    # Build the deterministic forensic report from persisted data.
    # This section has NO dependency on Groq.
    # ------------------------------------------------------------------
    evidence_items = []
    for ev in evidence_records:
        raw = ev.raw_json
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = {"error": "unparseable evidence record", "evidence_id": ev.evidence_id}
        evidence_items.append(raw)

    # Group evidence by type for structured presentation
    facts = [e for e in evidence_items if e.get("type") == "FACT"]
    heuristics = [e for e in evidence_items if e.get("type") == "HEURISTIC"]
    ml_signals = [e for e in evidence_items if e.get("type") == "ML_SIGNAL"]
    threat_intel = [e for e in evidence_items if e.get("type") in ("THREAT_INTEL", "THREAT_INTELLIGENCE")]
    historical = [e for e in evidence_items if e.get("type") == "HISTORICAL"]

    # Deterministic verdict narrative
    verdict = case.verdict or "UNKNOWN"
    risk_score = case.risk_score or 0.0
    confidence = case.confidence or 0.0

    if verdict == "BENIGN":
        deterministic_summary = (
            f"Email assessed as BENIGN with risk score {risk_score:.1f} "
            f"and confidence {confidence:.2f}. "
            f"No significant threat indicators were found."
        )
    elif verdict in ("MALICIOUS", "SUSPICIOUS"):
        deterministic_summary = (
            f"Email assessed as {verdict} with risk score {risk_score:.1f} "
            f"and confidence {confidence:.2f}. "
            f"Threat indicators identified across {len(evidence_items)} evidence items: "
            f"{len(heuristics)} heuristic findings, {len(ml_signals)} ML signals, "
            f"{len(threat_intel)} threat intelligence signals."
        )
    else:  # INCONCLUSIVE
        deterministic_summary = (
            f"Investigation returned INCONCLUSIVE with risk score {risk_score:.1f} "
            f"and confidence {confidence:.2f}. "
            f"Insufficient evidence was collected to reach a definitive verdict. "
            f"Analyst review recommended."
        )

    report = {
        "report_type": "FORENSIC_INVESTIGATION_REPORT",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "schema_version": "1.0",

        # §23 fields preserved
        "case_summary": {
            "investigation_id": investigation_id,
            "verdict": verdict,
            "risk_score": risk_score,
            "confidence": confidence,
            "status": case.status,
            "created_at": case.created_at.isoformat() if case.created_at else None,
        },
        "geolocation": ((persisted_report.raw_json or {}).get("investigation_result", {}).get("geolocation", []) if persisted_report else []),
        "content_analysis": ((persisted_report.raw_json or {}).get("investigation_result", {}).get("content_analysis") if persisted_report else None),

        # Full evidence list with types/sources (§38 requirement)
        "evidence_summary": {
            "total_evidence_items": len(evidence_items),
            "facts_count": len(facts),
            "heuristics_count": len(heuristics),
            "ml_signals_count": len(ml_signals),
            "threat_intelligence_count": len(threat_intel),
            "historical_matches_count": len(historical),
        },
        "evidence_by_type": {
            "facts": facts,
            "heuristics": heuristics,
            "ml_signals": ml_signals,
            "threat_intelligence": threat_intel,
            "historical_matches": historical,
        },

        # Deterministic narrative — always present regardless of Groq
        "deterministic_summary": deterministic_summary,

        # Groq augmentation (optional — degrade gracefully per §5 P2)
        "groq_narrative": None,
        "groq_status": "NOT_ATTEMPTED",
    }

    # ------------------------------------------------------------------
    # Optional Groq augmentation
    # Per §5 P2: "Groq unavailable → GROQ_UNAVAILABLE → deterministic
    # fallback explanation" — never block the whole report on Groq.
    # ------------------------------------------------------------------
    try:
        import os
        groq_key = app_settings.GROQ_API_KEY
        if groq_key and groq_key not in ("", "your-groq-api-key-here"):
            report["groq_status"] = "GROQ_AVAILABLE_NOT_INVOKED"
            # Full Groq narrative invocation is deferred to a future
            # implementation milestone. The deterministic report above is
            # always complete and correct without it.
        else:
            report["groq_status"] = "GROQ_UNAVAILABLE"
            report["groq_narrative"] = deterministic_summary  # fallback
    except Exception as groq_exc:  # noqa: BLE001
        logger.warning(
            "Groq check failed for report %s: %s",
            investigation_id, groq_exc
        )
        report["groq_status"] = "GROQ_UNAVAILABLE"
        report["groq_narrative"] = deterministic_summary

    return report

@router.post(
    "/{investigation_id}/reinvestigate",
    summary="Re-investigate a case",
    description=(
        "Runs a fresh investigation for the same email. "
        "The original investigation is NOT mutated — this creates a new case with "
        "a lineage reference to the original. "
        "Upload the same (or updated) .eml file along with the original case ID."
    ),
    tags=["Investigations"],
)
async def reinvestigate(
    investigation_id: str,
    request: Request,
    file: UploadFile = File(..., description="Raw .eml file to re-investigate"),
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Starts a new investigation run with lineage back to the original case.

    Architecture:
      - Original investigation_id remains immutable in DB.
      - A new case_id is generated for this re-run.
      - The new CaseModel.original_case_id points to the original investigation.
      - Full investigation pipeline is re-executed from scratch.
    """
    request_started = time.perf_counter()

    # Demo mode: no previous cases exist, reinvestigation is not applicable.
    from app.core.config import settings as _app_settings
    if _app_settings.DEMO_MODE:
        raise HTTPException(
            status_code=404,
            detail="Reinvestigation is not available in demo mode (no persisted cases)",
        )

    # Validate the .eml upload
    MAX_UPLOAD_BYTES = 10_000_000
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large")

    # Verify original case exists (prevents dangling lineage references)
    try:
        from app.repositories.db import SessionLocal
        from app.repositories.historical_repository import HistoricalRepository
        with SessionLocal() as db:
            original_case = HistoricalRepository(db).get_case(investigation_id)
    except Exception as lookup_exc:
        logger.warning(
            "Could not verify original case %s during reinvestigation: %s",
            investigation_id, type(lookup_exc).__name__,
        )
        original_case = None  # non-blocking — proceed anyway

    if original_case is None:
        raise HTTPException(
            status_code=404,
            detail=f"Original investigation '{investigation_id}' not found",
        )

    try:
        # Parse and normalize the uploaded .eml
        parsed_email = _parser.parse(raw_bytes)
        package = _normalizer.normalize(parsed_email)

        # Wire to the existing reinvestigation service.
        # start_reinvestigation() requires the EmailEvidencePackage directly;
        # it generates a new case_id internally and references original_case_id.
        from app.services.investigation.reinvestigation import start_reinvestigation
        from app.services.investigation import to_investigation_result

        reinv_result, final_state = await start_reinvestigation(
            original_case_id=investigation_id,
            reason="analyst_requested",
            requested_by="api",
            original_package=package,
        )

        # Build the full result from the completed stage1 state
        # (start_reinvestigation returns (ReinvestigationResult, InvestigationState)
        # but we need the full Stage1Result for to_investigation_result).
        # We run stage1 directly here via the shared engine so we get the Stage1Result.
        stage1_result = await _engine.run_stage1(
            package,
            original_case_id=investigation_id,
            started_at=request_started,
        )
        result = to_investigation_result(stage1_result)

        # Persist the new investigation (best-effort, same as analyze_email)
        try:
            from app.repositories.async_persistence import (
                ASYNC_PERSISTENCE_ENABLED,
                persist_investigation,
            )
            if ASYNC_PERSISTENCE_ENABLED:
                await persist_investigation(
                    result,
                    stage1_result.all_evidence,
                    stage1_result.audit_logger.records,
                )
            else:
                from app.repositories.db import SessionLocal
                from app.repositories.historical_repository import HistoricalRepository
                with SessionLocal() as _session:
                    repo = HistoricalRepository(_session)
                    repo.save_case(
                        result.investigation_id,
                        result.status.value,
                        result=result,
                        original_case_id=investigation_id,
                    )
                    repo.save_investigation(
                        result,
                        stage1_result.all_evidence,
                        stage1_result.audit_logger.records,
                    )
        except Exception as persist_exc:
            logger.error(
                "REINVESTIGATION_PERSISTENCE_FAILED new_case=%s original=%s type=%s detail=%s",
                result.investigation_id, investigation_id,
                type(persist_exc).__name__, persist_exc,
                exc_info=True,
            )

        return {
            "new_investigation_id": result.investigation_id,
            "original_investigation_id": investigation_id,
            "verdict": result.verdict.value,
            "risk_score": result.risk_score,
            "confidence": result.confidence,
            "status": result.status.value,
            "stop_reason": result.stop_reason.value if result.stop_reason else None,
        }

    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Reinvestigation failed: {type(exc).__name__}: {exc}",
        ) from exc


@router.get("/{investigation_id}/timeline", summary="Get investigation timeline")
async def get_timeline(
    investigation_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
    limit: int = 100,
):
    """
    Return timeline events derived from audit records and evidence timestamps.

    Each audit record becomes a timeline event. Evidence items with notable
    types (ML_SIGNAL, THREAT_INTEL, HEURISTIC) create additional events.
    Events are ordered chronologically (oldest first).
    """
    import json as _json
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository

    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    is_admin = isinstance(auth, str)
    if not isinstance(auth, str):
        tenant_id = auth.tenant_id
        user_id = auth.id
        is_admin = auth.can_read_all()

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        case = repo.get_case(investigation_id, tenant_id=tenant_id)
        if not case:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if tenant_id and not is_admin and case.user_id != user_id:
            raise HTTPException(status_code=404, detail="Investigation not found")

        audit_records = repo.get_audit_records_by_case(investigation_id)
        evidence_items = repo.get_evidence_by_case(investigation_id, tenant_id=tenant_id)

    events = []

    # 1. Derive events from audit records (investigation pipeline steps)
    for rec in audit_records:
        raw = rec.raw_json or {}
        if isinstance(raw, str):
            try:
                raw = _json.loads(raw)
            except _json.JSONDecodeError:
                raw = {}
        events.append({
            "event_id": rec.hash_self[:16],
            "event_type": "AUDIT",
            "timestamp": rec.timestamp.isoformat() if rec.timestamp else None,
            "summary": raw.get("action", raw.get("step", f"Investigation step {rec.step}")),
            "severity": "INFO",
            "source": "AUDIT_CHAIN",
            "evidence_hash": rec.hash_self,
            "associated_entity_id": None,
            "mitre_technique": None,
        })

    # 2. Add notable evidence events (ML signals, threat intel, heuristics)
    NOTABLE_TYPES = {"ML_SIGNAL", "THREAT_INTEL", "THREAT_INTELLIGENCE", "HEURISTIC"}
    for ev in evidence_items:
        raw = ev.raw_json or {}
        if isinstance(raw, str):
            try:
                raw = _json.loads(raw)
            except _json.JSONDecodeError:
                raw = {}
        ev_type = ev.evidence_type or raw.get("type", "")
        if ev_type.upper() not in NOTABLE_TYPES:
            continue

        severity = "HIGH" if ev_type.upper() in ("THREAT_INTEL", "THREAT_INTELLIGENCE") else "MEDIUM"
        label = raw.get("key", ev.key or ev_type)
        value_str = str(raw.get("value", {}))
        if len(value_str) > 120:
            value_str = value_str[:120] + "..."

        events.append({
            "event_id": ev.evidence_id[:16],
            "event_type": ev_type.upper(),
            "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
            "summary": f"{label}: {value_str}",
            "severity": severity,
            "source": "EVIDENCE",
            "evidence_hash": ev.evidence_id,
            "associated_entity_id": raw.get("related_entity"),
            "mitre_technique": raw.get("mitre_technique"),
        })

    # 3. Sort by timestamp
    events.sort(key=lambda e: e["timestamp"] or "")
    return {"events": events[:limit], "total": len(events)}


@router.get("/{investigation_id}/graph", summary="Get investigation entity-relationship graph")
async def get_graph(
    investigation_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
    max_depth: int = 2,
    center_node_id: Optional[str] = None,
):
    """
    Build and return the entity-relationship graph for an investigation.

    Nodes: unique forensic entities (IPs, Domains, URLs, Emails, Attachments).
    Edges: relationships between entities derived from evidence and indicators.
    Graph is constructed server-side from evidence data (GraphService).
    """
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository
    from app.services.graph import build_graph as _build_graph
    from sqlalchemy import select as _select
    from app.models.schema import IndicatorModel

    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    is_admin = isinstance(auth, str)
    if not isinstance(auth, str):
        tenant_id = auth.tenant_id
        user_id = auth.id
        is_admin = auth.can_read_all()

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        case = repo.get_case(investigation_id, tenant_id=tenant_id)
        if not case:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if tenant_id and not is_admin and case.user_id != user_id:
            raise HTTPException(status_code=404, detail="Investigation not found")

        evidence_items = repo.get_evidence_by_case(investigation_id, tenant_id=tenant_id)
        indicators = list(
            db.execute(
                _select(IndicatorModel).where(IndicatorModel.case_id == investigation_id)
            ).scalars().all()
        )

    nodes, edges = _build_graph(investigation_id, evidence_items, indicators, max_depth=max_depth, center_node_id=center_node_id)
    return {"nodes": nodes, "edges": edges}


@router.get("/{investigation_id}/graph/expand/{node_id}", summary="Expand a graph node")
async def expand_graph_node(
    investigation_id: str,
    node_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Return nodes and edges adjacent to the specified node that can be added to
    an existing graph view.
    """
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository
    from app.services.graph import expand_node as _expand_node
    from sqlalchemy import select as _select
    from app.models.schema import IndicatorModel

    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    is_admin = isinstance(auth, str)
    if not isinstance(auth, str):
        tenant_id = auth.tenant_id
        user_id = auth.id
        is_admin = auth.can_read_all()

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        case = repo.get_case(investigation_id, tenant_id=tenant_id)
        if not case:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if tenant_id and not is_admin and case.user_id != user_id:
            raise HTTPException(status_code=404, detail="Investigation not found")

        evidence_items = repo.get_evidence_by_case(investigation_id, tenant_id=tenant_id)
        indicators = list(
            db.execute(
                _select(IndicatorModel).where(IndicatorModel.case_id == investigation_id)
            ).scalars().all()
        )

    nodes, edges = _expand_node(node_id, investigation_id, evidence_items, indicators)
    return {"nodes": nodes, "edges": edges}


@router.get("/{investigation_id}/related", summary="Get related cases sharing indicators")
async def get_related_cases(
    investigation_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
    limit: int = 10,
):
    """
    Return cases in the same tenant that share at least one indicator with this case.
    Ordered by similarity score descending.
    """
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository

    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    is_admin = isinstance(auth, str)
    if not isinstance(auth, str):
        tenant_id = auth.tenant_id
        user_id = auth.id
        is_admin = auth.can_read_all()

    if not tenant_id:
        return {"related_cases": []}

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        case = repo.get_case(investigation_id, tenant_id=tenant_id)
        if not case:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if not is_admin and case.user_id != user_id:
            raise HTTPException(status_code=404, detail="Investigation not found")

        related = repo.find_related_cases(investigation_id, tenant_id, limit=limit)

    return {"related_cases": related}


@router.get("/{investigation_id}/email-entity", summary="Get email entity metadata")
async def get_email_entity(
    investigation_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Return email metadata (sender, recipient, subject, headers, body preview)
    extracted from the stored InvestigationResult.
    """
    import json as _json
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository

    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    is_admin = isinstance(auth, str)
    if not isinstance(auth, str):
        tenant_id = auth.tenant_id
        user_id = auth.id
        is_admin = auth.can_read_all()

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        case = repo.get_case(investigation_id, tenant_id=tenant_id)
        if not case:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if tenant_id and not is_admin and case.user_id != user_id:
            raise HTTPException(status_code=404, detail="Investigation not found")

        report_model = repo.get_report(investigation_id)

    if not report_model or not report_model.raw_json:
        raise HTTPException(status_code=404, detail="Email entity data not available")

    raw = report_model.raw_json
    if isinstance(raw, str):
        try:
            raw = _json.loads(raw)
        except _json.JSONDecodeError:
            raise HTTPException(status_code=404, detail="Email entity data not parseable")

    inv_result = raw.get("investigation_result", {})
    email_artifact = inv_result.get("email_artifact", {})
    content_analysis = inv_result.get("content_analysis", {})

    return {
        "email_id": investigation_id,
        "message_id": email_artifact.get("message_id"),
        "sender": email_artifact.get("sender") or email_artifact.get("from_address"),
        "recipients": email_artifact.get("recipients", []) or [email_artifact.get("to_address")],
        "reply_to": email_artifact.get("reply_to"),
        "subject": email_artifact.get("subject"),
        "date": email_artifact.get("date") or email_artifact.get("sent_at"),
        "body_preview": (
            (email_artifact.get("body_text", "") or "")[:500]
            if email_artifact.get("body_text")
            else None
        ),
        "has_html": bool(email_artifact.get("body_html")),
        "attachments": email_artifact.get("attachments", []),
        "auth_results": email_artifact.get("auth_results", {}),
        "routing_hops": email_artifact.get("routing_hops", []),
        "spf_pass": content_analysis.get("spf_pass") if content_analysis else None,
        "dkim_pass": content_analysis.get("dkim_pass") if content_analysis else None,
        "dmarc_pass": content_analysis.get("dmarc_pass") if content_analysis else None,
        "is_reply": email_artifact.get("is_reply"),
        "eml_sha256": case.eml_sha256,
    }


@router.get("/{investigation_id}/geolocation", summary="Get geographic activity hops")
async def get_geolocation(
    investigation_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Return geolocation data for all IP hops identified during investigation.
    Derived from the stored InvestigationResult geolocation field.
    """
    import json as _json
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository

    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    is_admin = isinstance(auth, str)
    if not isinstance(auth, str):
        tenant_id = auth.tenant_id
        user_id = auth.id
        is_admin = auth.can_read_all()

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        case = repo.get_case(investigation_id, tenant_id=tenant_id)
        if not case:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if tenant_id and not is_admin and case.user_id != user_id:
            raise HTTPException(status_code=404, detail="Investigation not found")

        report_model = repo.get_report(investigation_id)

    if not report_model or not report_model.raw_json:
        return {"hops": []}

    raw = report_model.raw_json
    if isinstance(raw, str):
        try:
            raw = _json.loads(raw)
        except _json.JSONDecodeError:
            return {"hops": []}

    geolocation = raw.get("investigation_result", {}).get("geolocation", [])

    # Enrich each hop with lat/lng if missing (derived from country_code centroid)
    _CENTROIDS: dict = {
        "US": (-98.5, 39.5), "GB": (-1.0, 52.0), "DE": (10.0, 51.0), "FR": (2.5, 46.5),
        "RU": (60.0, 60.0), "CN": (104.0, 35.0), "IN": (78.9, 20.6), "JP": (138.0, 36.0),
        "AU": (133.0, -25.0), "BR": (-52.0, -10.0), "CA": (-96.0, 56.0), "SG": (103.8, 1.4),
        "HK": (114.2, 22.3), "NL": (5.3, 52.1), "UA": (31.0, 49.0), "RO": (24.9, 45.9),
        "PL": (19.0, 52.0), "TR": (35.0, 39.0), "KR": (127.0, 36.0), "ID": (120.0, -5.0),
        "VN": (108.0, 14.0), "MY": (109.5, 4.2), "TH": (100.5, 15.0), "PK": (69.3, 30.0),
        "BD": (90.4, 23.7), "NG": (8.0, 10.0), "ZA": (25.0, -29.0), "KE": (37.9, -0.02),
        "EG": (30.0, 26.8), "IL": (34.9, 31.5), "SA": (45.0, 23.9), "IR": (53.0, 32.4),
        "SE": (18.6, 62.0), "NO": (10.0, 62.0), "DK": (10.0, 56.0), "FI": (26.0, 64.0),
        "CH": (8.2, 46.8), "AT": (13.2, 47.5), "BE": (4.5, 50.5), "PT": (-8.2, 39.5),
        "ES": (-3.7, 40.4), "IT": (12.5, 42.5), "PH": (122.0, 12.0), "NZ": (174.0, -41.0),
        "MX": (-102.0, 23.6), "AR": (-64.0, -34.0), "CL": (-71.0, -30.0), "CO": (-74.3, 4.6),
        "BY": (28.0, 53.0), "CZ": (15.5, 49.8), "HU": (19.5, 47.2), "RS": (21.0, 44.0),
    }

    enriched = []
    for hop in geolocation:
        hop_dict = dict(hop) if not isinstance(hop, dict) else hop.copy()
        cc = (hop_dict.get("country_code") or "").upper()
        # Only add lat/lng if they are genuinely missing
        has_lat = hop_dict.get("lat") is not None or hop_dict.get("latitude") is not None
        has_lng = hop_dict.get("lng") is not None or hop_dict.get("longitude") is not None
        if cc and not (has_lat and has_lng) and cc in _CENTROIDS:
            lng, lat = _CENTROIDS[cc]
            hop_dict["lat"] = lat
            hop_dict["lng"] = lng
        elif has_lat and not hop_dict.get("lat"):
            hop_dict["lat"] = hop_dict.get("latitude")
            hop_dict["lng"] = hop_dict.get("longitude")
        enriched.append(hop_dict)

    return {"hops": enriched}


@router.get("/{investigation_id}/artifact", summary="Download original .eml artifact")
async def get_artifact(
    investigation_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """
    Return a signed/temporary download URL for the original .eml file stored
    in Supabase Storage. Returns 404 if no EML was stored.

    Security: URL is derived from the server-side storage path. Clients cannot
    construct or guess storage paths.
    """
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository

    tenant_id: Optional[str] = None
    user_id: Optional[str] = None
    is_admin = isinstance(auth, str)
    if not isinstance(auth, str):
        tenant_id = auth.tenant_id
        user_id = auth.id
        is_admin = auth.can_read_all()

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        case = repo.get_case(investigation_id, tenant_id=tenant_id)
        if not case:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if tenant_id and not is_admin and case.user_id != user_id:
            raise HTTPException(status_code=404, detail="Investigation not found")

    if not case.eml_storage_path:
        raise HTTPException(status_code=404, detail="No EML artifact stored for this investigation")

    # Try to get a signed URL from Supabase Storage
    try:
        from app.integrations.eml_storage import eml_storage
        if eml_storage.enabled:
            download_url = await eml_storage.get_download_url(investigation_id)
            if download_url:
                return {
                    "download_url": download_url,
                    "eml_sha256": case.eml_sha256,
                    "storage_path": case.eml_storage_path if is_admin else None,
                    "expires_in_seconds": 3600,
                }
    except Exception as exc:
        logger.warning("EML download URL generation failed for %s: %s", investigation_id, exc)

    raise HTTPException(status_code=503, detail="EML storage service unavailable")


# ---------------------------------------------------------------------------
# On-Demand Reasoning (Advisory Intelligence Layer)
# ---------------------------------------------------------------------------

# Module-level singleton — preserves in-memory cache across requests
from app.services.reasoning.service import ReasoningService as _ReasoningServiceClass

_reasoning_service = _ReasoningServiceClass()


async def _demo_reasoning(investigation_id: str, request: Request, app_settings) -> dict:
    """Demo mode reasoning — builds snapshot from request body, no DB required.

    The frontend sends a lightweight context object containing the fields
    already present in the InvestigationResult (risk_score, confidence,
    verdict, risk_reasons, analysis_layers, tools_used).
    """
    import json, time as _time, uuid
    from app.contracts.reasoning import (
        BudgetStatus, ReasoningEvidenceSnapshot, ReasoningFinding,
        ReasoningHypothesis, UntrustedContentItem, ReasoningUnavailable,
    )
    from app.contracts.investigation import InvestigationLevel

    # --- Parse optional body ---
    ctx: dict = {}
    try:
        body_bytes = await request.body()
        if body_bytes:
            ctx = json.loads(body_bytes)
    except Exception:
        pass

    risk_score: float = float(ctx.get("risk_score", 50.0))
    confidence: float = float(ctx.get("confidence", 0.5))
    verdict: str = str(ctx.get("verdict", "INCONCLUSIVE"))
    risk_reasons: list = ctx.get("risk_reasons", [])
    tools_used: list = ctx.get("tools_used", [])
    analysis_layers: list = ctx.get("analysis_layers", [])
    hypothesis: str = ctx.get("investigation_hypothesis", "")
    user_query: str | None = ctx.get("user_query")

    # --- Build typed key_findings from risk_reasons + layer findings ---

    key_findings: list[ReasoningFinding] = []
    for i, reason in enumerate(risk_reasons[:20]):
        key_findings.append(ReasoningFinding(
            evidence_id=f"DEMO-RSN-{i:03d}",
            type="HEURISTIC",
            category="AUTHENTICATION",
            key=f"risk_reason_{i}",
            value=reason,
            source="deterministic_pipeline",
            confidence=0.85,
        ))

    for layer in analysis_layers[:5]:
        for j, finding in enumerate(layer.get("findings", [])[:3]):
            key_findings.append(ReasoningFinding(
                evidence_id=f"DEMO-LYR-{layer.get('layer_id', 'x')}-{j}",
                type="HEURISTIC",
                category=layer.get("layer_id", "HEADER").upper(),
                key=f"{layer.get('layer_id', 'layer')}_finding",
                value=finding,
                source=layer.get("layer_name", "Analysis Layer"),
                confidence=float(layer.get("confidence", 0.8)),
            ))

    # --- Hypothesis as an untrusted content item (treated as data) ---
    untrusted: list[UntrustedContentItem] = []
    if hypothesis:
        untrusted.append(UntrustedContentItem(
            evidence_id="DEMO-HYP-001",
            content_type="investigation_hypothesis",
            text=hypothesis[:500],
        ))

    # --- Minimal hypotheses from attack patterns in risk reasons ---
    hypotheses: list[ReasoningHypothesis] = []
    if verdict in ("MALICIOUS", "SUSPICIOUS"):
        hypotheses.append(ReasoningHypothesis(
            hypothesis_type="credential_phishing",
            score=min(1.0, risk_score / 100.0),
            status="SUPPORTED" if verdict == "MALICIOUS" else "UNCERTAIN",
            reasons=risk_reasons[:5],
            supporting_evidence_ids=[f"DEMO-RSN-{i:03d}" for i in range(min(3, len(risk_reasons)))],
            contradicting_evidence_ids=[],
        ))

    snapshot = ReasoningEvidenceSnapshot(
        case_id=investigation_id,
        investigation_id=investigation_id,
        investigation_level=InvestigationLevel.L2_DEEP.value,
        current_risk=risk_score,
        current_confidence=confidence,
        key_findings=key_findings[:50],
        current_hypotheses=hypotheses,
        missing_evidence=[],
        completed_tools=tools_used[:15],
        failed_tools=[],
        budget_status=BudgetStatus.AVAILABLE,
        supporting_evidence=[f"DEMO-RSN-{i:03d}" for i in range(min(3, len(risk_reasons)))],
        contradictory_evidence=[],
        historical_context=f"Demo mode investigation. Verdict: {verdict}. Risk: {risk_score:.1f}/100.",
        untrusted_content=untrusted,
        user_query=user_query,
    )

    correlation_id = str(uuid.uuid4())
    _start = _time.monotonic()

    result = await _reasoning_service.reason(snapshot)

    _latency_ms = int((_time.monotonic() - _start) * 1000)

    if isinstance(result, ReasoningUnavailable):
        return {
            "investigation_id": investigation_id,
            "reasoning_status": "unavailable",
            "reason": result.reason,
            "category": result.category.value,
            "correlation_id": correlation_id,
        }

    artifact = _reasoning_service.build_artifact(result, snapshot.compute_hash())
    return {
        "investigation_id": investigation_id,
        "reasoning_status": "available",
        "reasoning_result": result.model_dump(mode="json"),
        "artifact": {
            "source_type": artifact.source_type,
            "model": artifact.model,
            "prompt_version": artifact.prompt_version,
            "snapshot_hash": artifact.snapshot_hash[:32],
            "timestamp": artifact.timestamp.isoformat(),
            "validation_status": artifact.validation_status,
        },
    }



@router.post(
    "/{investigation_id}/reason",
    summary="Request reasoning analysis for an investigation",
    description=(
        "Triggers a bounded LLM reasoning call for the specified investigation. "
        "The server constructs the evidence snapshot from persisted data — "
        "clients cannot submit arbitrary snapshot data, system prompts, or "
        "influence risk/confidence/verdict. Returns validated reasoning "
        "result or explicit unavailable status."
    ),
    tags=["Reasoning"],
)
async def request_reasoning(
    investigation_id: str,
    request: Request,
    auth=Depends(verify_api_key_or_jwt),
):
    """On-demand reasoning analysis endpoint.

    Auth: accepts X-API-Key (service) OR Bearer JWT (user).
    RBAC: JWT users can only reason about their own cases (or admin).

    The snapshot is constructed SERVER-SIDE from persisted evidence.
    The client cannot:
        - Submit arbitrary evidence snapshot
        - Submit or modify the system prompt
        - Set risk, confidence, or verdict
        - Execute tools through the reasoning layer
    """
    import json
    from app.core.config import settings as app_settings

    # --- Check if reasoning is enabled ---
    if not app_settings.REASONING_ENABLED:
        return {
            "investigation_id": investigation_id,
            "reasoning_status": "unavailable",
            "reason": "Reasoning layer is disabled",
            "category": "REASONING_DISABLED",
        }

    # ----------------------------------------------------------------
    # DEMO MODE FAST PATH — build snapshot from request body, skip DB
    # ----------------------------------------------------------------
    if app_settings.DEMO_MODE:
        return await _demo_reasoning(investigation_id, request, app_settings)

    # --- Load the investigation from DB ---
    from app.repositories.db import SessionLocal
    from app.repositories.historical_repository import HistoricalRepository

    with SessionLocal() as db:
        repo = HistoricalRepository(db)
        case = repo.get_case(investigation_id)
        if not case:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # RBAC: non-admin JWT users can only access their own cases
        if not isinstance(auth, str):
            user = auth
            if not user.can_read_all() and case.user_id != user.id:
                raise HTTPException(status_code=404, detail="Investigation not found")

        # Load evidence
        evidence_records = repo.get_evidence_by_case(investigation_id)

        # Load full InvestigationResult from ReportModel for rich state
        report_model = repo.get_report(investigation_id)

    # --- Build evidence store from persisted records ---
    from app.contracts.evidence import EvidenceItem, EvidenceType

    evidence_store: dict[str, EvidenceItem] = {}
    for ev in evidence_records:
        raw = ev.raw_json
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                continue
        try:
            item = EvidenceItem.model_validate(raw)
            evidence_store[item.evidence_id] = item
        except Exception:
            continue

    # --- Reconstruct InvestigationState from persisted InvestigationResult ---
    from app.contracts.investigation import (
        AttackHypothesis,
        InvestigationBudget,
        InvestigationLevel,
        InvestigationState,
    )

    # Try to load the full result for rich context
    persisted_result = None
    if report_model and report_model.raw_json:
        raw_report = report_model.raw_json
        if isinstance(raw_report, str):
            try:
                raw_report = json.loads(raw_report)
            except json.JSONDecodeError:
                raw_report = {}
        if isinstance(raw_report, dict) and "investigation_result" in raw_report:
            try:
                from app.contracts.result import InvestigationResult as _IR
                persisted_result = _IR.model_validate(raw_report["investigation_result"])
            except Exception:
                pass

    # Build evidence ID lists grouped by type
    observed_facts = [eid for eid, e in evidence_store.items() if e.type == EvidenceType.FACT]
    heuristic_findings = [eid for eid, e in evidence_store.items() if e.type == EvidenceType.HEURISTIC]
    ml_signals = [eid for eid, e in evidence_store.items() if e.type == EvidenceType.ML_SIGNAL]
    threat_intelligence = [eid for eid, e in evidence_store.items() if e.type == EvidenceType.THREAT_INTEL]
    historical_matches = [eid for eid, e in evidence_store.items() if e.type == EvidenceType.HISTORICAL]

    if persisted_result:
        # Use real budget and investigation context from the persisted result
        budget = persisted_result.budget
        budget_remaining = persisted_result.budget_remaining
        level = persisted_result.investigation_level_reached
        hypotheses = persisted_result.attack_hypotheses
        tools_used = persisted_result.tools_used
        tools_failed = persisted_result.tools_failed
        missing_evidence = persisted_result.missing_evidence
    else:
        # Fallback: minimal context
        budget = InvestigationBudget(
            max_latency_ms=4000, max_tool_calls=8,
            max_external_calls=4, max_llm_tokens=4000,
        )
        budget_remaining = budget
        level = InvestigationLevel.L2_DEEP
        hypotheses = []
        tools_used = []
        tools_failed = []
        missing_evidence = []

    state = InvestigationState(
        case_id=investigation_id,
        observed_facts=observed_facts,
        heuristic_findings=heuristic_findings,
        ml_signals=ml_signals,
        threat_intelligence=threat_intelligence,
        historical_matches=historical_matches,
        current_risk=case.risk_score or 0.0,
        current_confidence=case.confidence or 0.0,
        investigation_level=level,
        budget=budget,
        budget_remaining=budget_remaining,
        attack_hypotheses=hypotheses,
        tools_used=tools_used,
        tools_failed=tools_failed,
        missing_evidence=missing_evidence,
    )

    # --- Build snapshot (server-side, allowlist) ---
    from app.services.reasoning.snapshot_builder import build_reasoning_snapshot

    snapshot = build_reasoning_snapshot(state, evidence_store)

    # Allow custom question from UI
    try:
        body_bytes = await request.body()
        if body_bytes:
            ctx = json.loads(body_bytes)
            user_q = ctx.get("user_query")
            if user_q:
                snapshot.user_query = str(user_q)[:1000]
    except Exception:
        pass

    snapshot_hash = snapshot.compute_hash()


    # --- Audit: log attempt ---
    from app.services.investigation.audit_logger import AuditLogger
    from app.services.reasoning.prompts import PROMPT_VERSION

    audit = AuditLogger(case_id=investigation_id)
    audit.log_reasoning_attempt(
        snapshot_hash=snapshot_hash,
        model=app_settings.GROQ_REASONING_MODEL,
        prompt_version=PROMPT_VERSION,
    )

    # --- Execute reasoning ---
    import time as _time
    _start = _time.monotonic()

    from app.contracts.reasoning import ReasoningUnavailable

    result = await _reasoning_service.reason(snapshot)

    _latency_ms = int((_time.monotonic() - _start) * 1000)

    if isinstance(result, ReasoningUnavailable):
        # Audit: log failure
        audit.log_reasoning_failure(
            failure_category=result.category.value,
            reason=result.reason,
            model=app_settings.GROQ_REASONING_MODEL,
            latency_ms=_latency_ms,
        )
        return {
            "investigation_id": investigation_id,
            "reasoning_status": "unavailable",
            "reason": result.reason,
            "category": result.category.value,
            "correlation_id": result.request_correlation_id,
        }

    # --- Build artifact with provenance ---
    artifact = _reasoning_service.build_artifact(result, snapshot_hash)

    # Audit: log success
    audit.log_reasoning_success(
        snapshot_hash=snapshot_hash,
        model=app_settings.GROQ_REASONING_MODEL,
        prompt_version=PROMPT_VERSION,
        latency_ms=_latency_ms,
    )

    # --- Persist audit records (best-effort) ---
    try:
        from app.repositories.db import SessionLocal as _SL
        from app.repositories.historical_repository import HistoricalRepository as _HR
        from app.repositories.models import AuditRecordModel
        with _SL() as _session:
            for record in audit.records:
                if not _session.execute(
                    __import__("sqlalchemy").select(AuditRecordModel).where(
                        AuditRecordModel.hash_self == record.hash_self
                    )
                ).scalar_one_or_none():
                    _session.add(AuditRecordModel(
                        hash_self=record.hash_self,
                        hash_prev=record.hash_prev,
                        case_id=record.case_id,
                        step=record.step,
                        raw_json=record.model_dump(mode="json"),
                        timestamp=record.timestamp,
                    ))
            _session.commit()
    except Exception as _audit_exc:
        logger.warning("Reasoning audit persistence failed (non-fatal): %s", type(_audit_exc).__name__)

    artifact_response = {
        "source_type": artifact.source_type,
        "model": artifact.model,
        "prompt_version": artifact.prompt_version,
        "snapshot_hash": artifact.snapshot_hash[:32],
        "timestamp": artifact.timestamp.isoformat(),
        "validation_status": artifact.validation_status,
    }

    return {
        "investigation_id": investigation_id,
        "reasoning_status": "available",
        "reasoning_result": result.model_dump(mode="json"),
        "artifact": artifact_response,
    }
