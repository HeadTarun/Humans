"""
services/investigation/reinvestigation.py

Implements Stage 6.6 Re-investigation logic.
- Creates new case_id
- Leaves old case immutable
- Generates ReinvestigationRequest context
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from app.contracts.common import utcnow
from app.contracts.reinvestigation import ReinvestigationRequest, ReinvestigationResult
from app.contracts.investigation import InvestigationState
from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory, TrustLevel, SourceType
from app.contracts.common import Provenance
from app.services.evidence.models import EmailEvidencePackage
from app.services.investigation.decision_engine import InvestigationDecisionEngine

def start_reinvestigation(
    original_case_id: str,
    reason: str,
    requested_by: str,
    original_package: EmailEvidencePackage,
    additional_evidence: list[dict] = None
) -> tuple[ReinvestigationResult, InvestigationState]:
    """
    Starts a fresh investigation run against the original package, treating it as a new case.
    The original package is re-processed, but the state will hold the original_case_id.
    We inject the ReinvestigationRequest as a FACT evidence item.
    """
    if additional_evidence is None:
        additional_evidence = []
        
    req = ReinvestigationRequest(
        original_case_id=original_case_id,
        reason=reason,
        requested_by=requested_by,
        additional_evidence=additional_evidence
    )
    
    # Generate new case ID
    new_case_id = f"reinv_{uuid.uuid4().hex[:16]}"
    
    # We must not mutate the original package in-place if it's cached, 
    # but we need the new case to process it. 
    # We can create a deep copy and update the package_id.
    new_package = original_package.model_copy(update={
        "package_id": new_case_id,
        "case_id": new_case_id
    })
    
    # We can create the EvidenceItem for the request
    req_ev = EvidenceItem(
        evidence_id=f"ev_req_{uuid.uuid4().hex[:8]}",
        case_id=new_case_id,
        type=EvidenceType.FACT,
        category=EvidenceCategory.IOC,  # Or a new category
        key="reinvestigation_request",
        value=req.model_dump(),
        source="reinvestigation_api",
        source_type=SourceType.DETERMINISTIC,
        confidence=1.0,
        trust_level=TrustLevel.VERIFIED,
        timestamp=utcnow(),
        provenance=Provenance(
            producer_module="app.services.investigation.reinvestigation",
            extraction_method="analyst_request"
        )
    )
    
    # Run the engine
    engine = InvestigationDecisionEngine()
    
    # We pass original_case_id to run_stage1
    result = engine.run_stage1(new_package, original_case_id=original_case_id)
    
    # Manually inject the ReinvestigationRequest evidence into the final state facts
    # In a full system, this would be injected before hypotheses generation so rules could match it,
    # but for Stage 6 MVP, appending it to the final result is sufficient.
    result.l0_facts.append(req_ev)
    result.state = result.state.model_copy(update={
        "observed_facts": result.state.observed_facts + [req_ev.evidence_id]
    })
    
    return ReinvestigationResult(
        new_case_id=new_case_id,
        original_case_id=original_case_id,
        status="STARTED",
        message="Reinvestigation initiated and Stage 1 complete."
    ), result.state
