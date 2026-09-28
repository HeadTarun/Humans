"""
services/tools/handlers/attachment_hasher.py

Attachment Hasher Tool (Level 0).
This tool extracts attachment hashes from the evidence package and packages them
as formal IOCs for the downstream threat intel tools. It does NOT re-hash files;
it just bridges the parser output into the intelligence pipeline.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.evidence.models import EmailEvidencePackage

logger = logging.getLogger(__name__)

async def handle(
    request: ToolExecutionRequest, 
    state: InvestigationState,
    package: Optional[EmailEvidencePackage] = None
) -> dict[str, Any]:
    """
    Input: none required (operates on package).
    Output: dict of extracted hashes.
    """
    if not package:
        raise ValueError("attachment_hasher requires the EmailEvidencePackage")
        
    hashes = []
    for att in package.attachments:
        if att.sha256_hash:
            hashes.append({
                "filename": att.filename,
                "sha256": att.sha256_hash,
                "size": att.size_bytes
            })
            
    return {
        "provider_name": "attachment_hasher",
        "indicator_value": package.email_sha256,
        "indicator_type": "HASH_SHA256",  # nominal
        "features": {
            "attachment_hashes": hashes,
            "attachment_count": len(hashes)
        }
    }
