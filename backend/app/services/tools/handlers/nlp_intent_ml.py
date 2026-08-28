"""
services/tools/handlers/nlp_intent_ml.py

NLP Intent ML Handler (Level 1).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.evidence.models import EmailEvidencePackage
from app.services.ml.nlp_adapter import NLPModelAdapter
from app.services.ml.base import ModelFailureError
from app.services.ingestion.parser import EmailParser
from app.contracts.evidence import EvidenceItem

logger = logging.getLogger(__name__)

async def handle(
    request: ToolExecutionRequest, 
    state: InvestigationState,
    package: Optional[EmailEvidencePackage] = None
) -> dict[str, Any] | list[EvidenceItem]:
    
    if not package:
        raise ValueError("nlp_intent_ml requires the EmailEvidencePackage")

    parsed_text = ""
    artifact_ref = request.input.get("artifact_reference")
    if artifact_ref:
        try:
            with open(artifact_ref, "rb") as f_bin:
                parsed_email = EmailParser().parse(f_bin.read())
                parsed_text = parsed_email.plain_text or parsed_email.html or ""
        except Exception as e:
            logger.error(f"Failed to read artifact for nlp_intent_ml: {e}")
            
    if not parsed_text:
        return {"error": "No parsed text available for NLP ML", "status": "failed"}
        
    adapter = NLPModelAdapter()
    
    start_time = time.perf_counter()
    try:
        evidence_items = adapter.analyze(package, parsed_text)
    except ModelFailureError as e:
        logger.error(f"NLP ML failed: {e}")
        return {"error": str(e), "status": "failed"}
        
    latency_ms = (time.perf_counter() - start_time) * 1000.0
    
    # ToolExecutor can handle returning a list of EvidenceItem directly! Let's check this below.
    return evidence_items
