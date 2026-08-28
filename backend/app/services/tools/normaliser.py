"""
services/tools/normaliser.py

EvidenceToolNormaliser converts ProviderResult (and other tool outputs)
into strictly typed EvidenceItems, preventing provider schema leakage.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from app.contracts.common import CaseId, Provenance, SourceType
from app.contracts.evidence import (
    EvidenceCategory,
    EvidenceItem,
    EvidenceStatus,
    EvidenceType,
    TrustLevel,
)
from app.contracts.provider_result import ProviderResult

class EvidenceToolNormaliser:
    """Converts tool outputs to EvidenceItems."""
    
    @staticmethod
    def _make_evidence_id(case_id: str, key: str, value: Any, source: str) -> str:
        raw = f"{case_id}:{key}:{str(value)}:{source}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]
        
    def from_provider_result(
        self, 
        case_id: CaseId, 
        result: ProviderResult, 
        module_path: str,
        confidence_override: float = 0.9
    ) -> list[EvidenceItem]:
        """Convert a ProviderResult to a list of EvidenceItems."""
        items: list[EvidenceItem] = []
        
        # 1. Generate THREAT_INTEL evidence if verdict exists
        if result.verdict:
            prov = Provenance(
                producer_module=module_path,
                extraction_method="api_lookup",
                api_provider=result.provider_name
            )
            
            # Key MUST be generic, not provider-specific (e.g. "url_reputation", not "virustotal_score")
            key_name = f"{result.indicator_type.value.lower()}_reputation"
            
            items.append(EvidenceItem(
                evidence_id=self._make_evidence_id(case_id, key_name, result.verdict.value, result.provider_name),
                case_id=case_id,
                type=EvidenceType.THREAT_INTEL,
                category=EvidenceCategory.THREAT_INTEL,
                key=key_name,
                value=result.verdict.value,
                source=result.provider_name,
                source_type=SourceType.THREAT_INTEL_API,
                confidence=confidence_override,
                trust_level=TrustLevel.REPORTED,
                provenance=prov,
                related_entity=result.indicator_value
            ))
            
        # 2. Generate FACT evidence for features
        for f_key, f_val in result.features.items():
            prov = Provenance(
                producer_module=module_path,
                extraction_method="api_feature_extraction",
                api_provider=result.provider_name
            )
            items.append(EvidenceItem(
                evidence_id=self._make_evidence_id(case_id, f_key, f_val, result.provider_name),
                case_id=case_id,
                type=EvidenceType.FACT,
                category=EvidenceCategory.IOC,  # Generic category for now
                key=f_key,
                value=f_val,
                source=result.provider_name,
                source_type=SourceType.THREAT_INTEL_API,
                confidence=confidence_override,
                trust_level=TrustLevel.REPORTED,
                provenance=prov,
                related_entity=result.indicator_value
            ))
            
        return items

