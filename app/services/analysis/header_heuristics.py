import uuid
import weakref
from datetime import datetime
from typing import List, Optional

from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory, TrustLevel, EvidenceStatus
from app.contracts.common import SourceType, Provenance, utcnow
from app.services.evidence.models import EmailEvidencePackage, AuthProtocol


def create_heuristic_evidence(
    case_id: str, key: str, value: any, confidence: float, related_entity: str = None
) -> EvidenceItem:
    """Build one HEURISTIC EvidenceItem. Module-level so callers (including
    the three thin per-key tool wrappers below) don't need to instantiate
    HeaderHeuristicAnalyzer just to synthesize a placeholder/"complete"
    marker item."""
    return EvidenceItem(
        evidence_id=f"evd_{uuid.uuid4().hex[:12]}",
        case_id=case_id,
        type=EvidenceType.HEURISTIC,
        category=EvidenceCategory.HEADER,
        key=key,
        value=value,
        source="HeaderHeuristicAnalyzer",
        source_type=SourceType.DETERMINISTIC,
        confidence=confidence,
        trust_level=TrustLevel.INFERRED,
        provenance=Provenance(
            producer_module="app.services.analysis.header_heuristics",
            extraction_method="deterministic_rule"
        ),
        related_entity=related_entity,
        status=EvidenceStatus.ACTIVE
    )


class HeaderHeuristicAnalyzer:
    """
    Deterministic header analysis (NO ML).
    Produces HEURISTIC evidence based on RFC rules, auth alignments, and structural anomalies.
    """

    def analyze(self, package: EmailEvidencePackage, case_id: str = None) -> List[EvidenceItem]:
        case_id = case_id or getattr(package, "case_id", "unknown")
        evidence = []
        now = utcnow()

        # 1. From / Reply-To Mismatch
        if package.sender and package.sender.reply_to_email:
            from_addr = package.sender.email_address
            reply_to_addr = package.sender.reply_to_email
            if from_addr and reply_to_addr and from_addr.lower() != reply_to_addr.lower():
                evidence.append(
                    self._create_heuristic(
                        case_id,
                        key="from_replyto_mismatch",
                        value=True,
                        confidence=1.0,
                        related_entity=reply_to_addr,
                    )
                )

        # 2. Authentication Failures
        if package.authentication and package.authentication.results:
            results = package.authentication.results
            
            # SPF
            spf = next((r for r in results if r.protocol == AuthProtocol.SPF), None)
            if spf and spf.result.name.lower() in ("fail", "softfail", "none"):
                evidence.append(
                    self._create_heuristic(
                        case_id,
                        key="spf_failure",
                        value=spf.result.name,
                        confidence=1.0,
                        related_entity=package.sender.email_address if package.sender else None,
                    )
                )
                
            # DKIM
            dkim = next((r for r in results if r.protocol == AuthProtocol.DKIM), None)
            if not dkim:
                evidence.append(
                    self._create_heuristic(
                        case_id,
                        key="dkim_missing",
                        value=True,
                        confidence=1.0,
                    )
                )
            elif dkim.result.name.lower() in ("fail", "none"):
                evidence.append(
                    self._create_heuristic(
                        case_id,
                        key="dkim_failure",
                        value=dkim.result.name,
                        confidence=1.0,
                    )
                )
                
            # DMARC
            dmarc = next((r for r in results if r.protocol == AuthProtocol.DMARC), None)
            if dmarc and dmarc.result.name.lower() in ("fail", "none"):
                evidence.append(
                    self._create_heuristic(
                        case_id,
                        key="dmarc_failure",
                        value=dmarc.result.name,
                        confidence=1.0,
                    )
                )

        # 3. Message-ID Anomaly
        if package.headers and package.headers.message_id and package.sender and package.sender.domain:
            msg_id = package.headers.message_id
            if "@" in msg_id:
                msg_domain = msg_id.split("@")[1].strip(">").lower()
                if msg_domain != package.sender.domain.lower():
                    evidence.append(
                        self._create_heuristic(
                            case_id,
                            key="message_id_domain_mismatch",
                            value=msg_domain,
                            confidence=0.8,
                            related_entity=msg_id
                        )
                    )

        # 4. Received-chain anomalies
        # Removed too_few_hops logic (now handled by reconstruct_relay_path)
                
        return evidence

    def _create_heuristic(self, case_id: str, key: str, value: any, confidence: float, related_entity: str = None) -> EvidenceItem:
        return create_heuristic_evidence(case_id, key, value, confidence, related_entity)


# ---------------------------------------------------------------------------
# Shared, request-scoped cache.
#
# header_parse, spf_dkim_dmarc, and relay_reconstruction (see
# services/tools/handlers/) are all registered as separate MANDATORY tools
# in tool_registry.py, but every one of them just re-runs
# HeaderHeuristicAnalyzer.analyze() over the same package and then filters
# the result by a different set of evidence keys. Before this cache, that
# meant identical analysis work ran three times per email for zero
# additional information. EmailEvidencePackage is a frozen contract, so
# caching by object identity is safe: the same package instance can only
# ever produce the same analysis.
# ---------------------------------------------------------------------------
_ANALYSIS_CACHE: dict[int, list[EvidenceItem]] = {}
 
def get_header_heuristics(package: EmailEvidencePackage, case_id: Optional[str] = None) -> List[EvidenceItem]:
    """Shared entry point for every header-derived tool. Computes
    HeaderHeuristicAnalyzer().analyze() at most once per package instance."""
    key = id(package)
    cached = _ANALYSIS_CACHE.get(key)
    if cached is not None:
        return cached
    result = HeaderHeuristicAnalyzer().analyze(package, case_id)
    _ANALYSIS_CACHE[key] = result
    if len(_ANALYSIS_CACHE) > 1000:
        _ANALYSIS_CACHE.pop(next(iter(_ANALYSIS_CACHE)))
    return result
