"""
services/tools/handlers/historical_correlation.py

Deep Historical Correlation Tool (Level 2).
Queries historical case database for multi-indicator matches and campaigns.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory, TrustLevel, SourceType
from app.contracts.common import Provenance, utcnow
from app.contracts.historical import MatchType, MatchStrength, HistoricalCorrelationResult, HistoricalMatch
from app.repositories.db import SessionLocal
from app.repositories.historical_repository import HistoricalRepository
from app.services.evidence.models import EmailEvidencePackage

logger = logging.getLogger(__name__)

async def handle(
    request: ToolExecutionRequest, 
    state: InvestigationState,
    package: EmailEvidencePackage = None
) -> list[dict[str, Any]]:
    """
    Finds structural similarities and groups matches into Campaigns.
    """
    if not package:
        return []
        
    db = SessionLocal()
    repo = HistoricalRepository(db)
    
    case_id = state.case_id
    
    # 1. Collect all deterministic indicators we can query on
    indicators_to_check = []
    
    for att in package.attachments:
        if att.sha256_hash:
            indicators_to_check.append(("EXACT_HASH", att.sha256_hash))
            
    for url in package.urls:
        if url.raw_url:
            indicators_to_check.append(("EXACT_URL", url.raw_url))
            
    for hop in package.received_hops:
        if hop.sending_ip:
            indicators_to_check.append(("EXACT_IP", hop.sending_ip))
            
    if package.sender and package.sender.domain:
        indicators_to_check.append(("EXACT_DOMAIN", package.sender.domain))
        
    # 2. Query historical database for matches
    # Maps previous case_id -> list of HistoricalMatch
    case_matches: dict[str, list[HistoricalMatch]] = {}
    
    for ind_type, ind_value in indicators_to_check:
        matches = repo.find_historical_indicators(ind_type, ind_value, case_id)
        for m in matches:
            prev_case_id = m.case_id
            if prev_case_id not in case_matches:
                case_matches[prev_case_id] = []
                
            case_ref = repo.get_case(prev_case_id)
            hm = HistoricalMatch(
                current_case_id=case_id,
                previous_case_id=prev_case_id,
                match_type=MatchType(ind_type),
                match_strength=MatchStrength.EXACT,
                matched_indicator=ind_value,
                first_seen=m.first_seen.isoformat(),
                last_seen=m.first_seen.isoformat(),
                historical_risk_score=case_ref.risk_score if case_ref else None,
                historical_verdict=case_ref.verdict if case_ref else None,
                similarity=1.0,
                reliability=0.9,
                explanation=f"Shared {ind_type}: {ind_value}"
            )
            case_matches[prev_case_id].append(hm)

    # 3. Analyze matches for deep correlation and campaigns
    # If a previous case shares > 1 indicator with us, it's a strong correlation
    # If > 2 previous cases share an indicator, it's a campaign
    
    # Track indicator frequencies across cases
    indicator_freq: dict[tuple[str, str], list[str]] = {}
    for p_cid, matches in case_matches.items():
        for hm in matches:
            key = (hm.match_type.value, hm.matched_indicator)
            if key not in indicator_freq:
                indicator_freq[key] = []
            indicator_freq[key].append(p_cid)
            
    campaign_indicators = {k: v for k, v in indicator_freq.items() if len(v) >= 2}
    
    evidence_items = []
    
    for prev_case_id, matches in case_matches.items():
        if len(matches) > 1:
            # Deep Correlation
            res = HistoricalCorrelationResult(
                case_id=case_id,
                matches=matches,
                correlation_reasons=[f"Shared {len(matches)} distinct indicators"],
                overall_strength=MatchStrength.STRONG,
                is_campaign=False
            )
            
            ev = EvidenceItem(
                evidence_id=f"ev_corr_{uuid.uuid4().hex[:8]}",
                case_id=case_id,
                type=EvidenceType.HISTORICAL,
                category=EvidenceCategory.HISTORICAL,
                key="deep_historical_correlation",
                value=res.model_dump(),
                source="historical_correlation",
                source_type=SourceType.HISTORICAL_CORRELATION,
                confidence=0.85,
                trust_level=TrustLevel.INFERRED,
                timestamp=utcnow(),
                provenance=Provenance(
                    producer_module="app.services.tools.handlers.historical_correlation",
                    extraction_method="multi_indicator_overlap"
                ),
                related_entity=prev_case_id
            )
            evidence_items.append(ev.model_dump(mode="json"))

    # Produce Campaign evidence
    for (ind_type, ind_val), p_cids in campaign_indicators.items():
        res = HistoricalCorrelationResult(
            case_id=case_id,
            matches=[], # We could put representative matches here
            correlation_reasons=[f"Indicator {ind_type}={ind_val} seen in {len(p_cids)} previous cases"],
            overall_strength=MatchStrength.STRONG,
            is_campaign=True
        )
        ev = EvidenceItem(
            evidence_id=f"ev_camp_{uuid.uuid4().hex[:8]}",
            case_id=case_id,
            type=EvidenceType.HISTORICAL,
            category=EvidenceCategory.HISTORICAL,
            key="campaign_detected",
            value=res.model_dump(),
            source="historical_correlation",
            source_type=SourceType.HISTORICAL_CORRELATION,
            confidence=0.9,
            trust_level=TrustLevel.INFERRED,
            timestamp=utcnow(),
            provenance=Provenance(
                producer_module="app.services.tools.handlers.historical_correlation",
                extraction_method="campaign_frequency_analysis"
            ),
            related_entity=ind_val
        )
        evidence_items.append(ev.model_dump(mode="json"))
        
    db.close()
    
    # The decision_engine accepts a list of dumped EvidenceItems 
    return evidence_items
