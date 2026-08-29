from typing import List, Optional
from datetime import datetime, timezone

from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory, TrustLevel, SourceType
from app.contracts.common import Provenance, utcnow
from app.contracts.historical import MatchType, MatchStrength, HistoricalMatch
from app.services.evidence.models import EmailEvidencePackage
from app.repositories.historical_repository import HistoricalRepository

class FastHistoricalLookup:
    def __init__(self, repo: HistoricalRepository):
        self.repo = repo
        
    def perform_lookup(self, package: EmailEvidencePackage) -> List[EvidenceItem]:
        """
        Fast lookup for EXACT matches on indicators present in the package.
        Returns a list of Historical EvidenceItems to seed into the investigation.
        """
        historical_evidence = []
        matches: List[HistoricalMatch] = []
        
        # We need a case ID for the current context. Since this is pre-investigation, 
        # the package_id is the case_id.
        case_id = package.package_id
        
        # 1. Attachment SHA-256
        for att in package.attachments:
            if att.sha256_hash:
                indicators = self.repo.find_historical_indicators("EXACT_HASH", att.sha256_hash, case_id)
                for ind in indicators:
                    case_ref = self.repo.get_case(ind.case_id)
                    matches.append(HistoricalMatch(
                        current_case_id=case_id,
                        previous_case_id=ind.case_id,
                        match_type=MatchType.EXACT_HASH,
                        match_strength=MatchStrength.EXACT,
                        matched_indicator=att.sha256_hash,
                        first_seen=ind.first_seen.isoformat(),
                        last_seen=ind.first_seen.isoformat(),
                        historical_risk_score=case_ref.risk_score if case_ref else None,
                        historical_verdict=case_ref.verdict if case_ref else None,
                        similarity=1.0,
                        reliability=1.0,
                        explanation=f"Exact attachment hash {att.sha256_hash} matches previous case {ind.case_id}"
                    ))
                    
        # 2. Canonical URL (if available, otherwise raw URL)
        for url in package.urls:
            url_val = url.raw_url # Assuming canonicalization happens later, but we use what we have
            indicators = self.repo.find_historical_indicators("EXACT_URL", url_val, case_id)
            for ind in indicators:
                case_ref = self.repo.get_case(ind.case_id)
                matches.append(HistoricalMatch(
                    current_case_id=case_id,
                    previous_case_id=ind.case_id,
                    match_type=MatchType.EXACT_URL,
                    match_strength=MatchStrength.EXACT,
                    matched_indicator=url_val,
                    first_seen=ind.first_seen.isoformat(),
                    last_seen=ind.first_seen.isoformat(),
                    historical_risk_score=case_ref.risk_score if case_ref else None,
                    historical_verdict=case_ref.verdict if case_ref else None,
                    similarity=1.0,
                    reliability=1.0,
                    explanation=f"Exact URL {url_val} matches previous case {ind.case_id}"
                ))

        # 3. IP Address (from headers/hops)
        for hop in package.received_hops:
            if hop.sending_ip:
                indicators = self.repo.find_historical_indicators("EXACT_IP", hop.sending_ip, case_id)
                for ind in indicators:
                    case_ref = self.repo.get_case(ind.case_id)
                    matches.append(HistoricalMatch(
                        current_case_id=case_id,
                        previous_case_id=ind.case_id,
                        match_type=MatchType.EXACT_IP,
                        match_strength=MatchStrength.EXACT,
                        matched_indicator=hop.sending_ip,
                        first_seen=ind.first_seen.isoformat(),
                        last_seen=ind.first_seen.isoformat(),
                        historical_risk_score=case_ref.risk_score if case_ref else None,
                        historical_verdict=case_ref.verdict if case_ref else None,
                        similarity=1.0,
                        reliability=0.8,
                        explanation=f"Exact sender IP {hop.sending_ip} matches previous case {ind.case_id}"
                    ))
                    
        # Map matches to EvidenceItems
        import uuid
        for i, match in enumerate(matches):
            ev_id = f"ev_hist_{uuid.uuid4().hex[:8]}"
            ev = EvidenceItem(
                evidence_id=ev_id,
                case_id=case_id,
                type=EvidenceType.HISTORICAL,
                category=EvidenceCategory.HISTORICAL,
                key=f"historical_match_{match.match_type.value.lower()}",
                value=match.model_dump(),
                source="fast_historical_lookup",
                source_type=SourceType.HISTORICAL_CORRELATION,
                confidence=1.0,
                trust_level=TrustLevel.INFERRED,
                timestamp=utcnow(),
                provenance=Provenance(
                    producer_module="app.services.investigation.historical_lookup",
                    extraction_method="database_exact_match"
                ),
                related_entity=match.matched_indicator
            )
            historical_evidence.append(ev)
            
        return historical_evidence
