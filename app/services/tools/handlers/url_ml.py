"""
services/tools/handlers/url_ml.py

URL ML Handler (Level 1).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.evidence.models import EmailEvidencePackage
from app.services.ml.url_adapter import URLModelAdapter
from app.services.ml.base import ModelFailureError
from app.contracts.evidence import EvidenceItem

logger = logging.getLogger(__name__)

async def handle(
    request: ToolExecutionRequest, 
    state: InvestigationState,
    package: Optional[EmailEvidencePackage] = None
) -> list[EvidenceItem] | dict[str, Any]:
    
    canonical_url = request.input.get("canonical_url")
    if not canonical_url:
        return {"error": "url_ml requires canonical_url in input", "status": "failed"}

    adapter = URLModelAdapter()
    
    start_time = time.perf_counter()
    try:
        evidence_item = adapter.analyze(canonical_url, state.case_id)
    except ModelFailureError as e:
        logger.error(f"URL ML failed: {e}")
        return {"error": str(e), "status": "failed"}
        
    return [evidence_item.model_dump(mode="json")] if evidence_item else []
