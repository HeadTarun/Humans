"""
app/services/investigation/correlation.py

Evidence correlation engine.

Responsibilities:
  1. Build an entity graph from a list of EvidenceItems.
  2. Identify cross-entity relationships (shared infrastructure, etc.).
  3. Produce correlation EvidenceItems that feed into risk scoring.
  4. Detect potential campaign patterns (same IOCs across multiple cases).

DESIGN RULES:
  - No LLM. No external API calls. Pure in-memory graph traversal.
  - All output is EvidenceItem objects with EvidenceType.HEURISTIC.
  - Correlation must be explainable: every output includes a reason string.
  - Empty evidence list → empty correlation output (never raises).
  - Correlation failures must be logged and return [] (never crash the pipeline).
"""

import logging
import uuid
from typing import Any, Dict, List, Optional

from app.contracts.common import Provenance, SourceType
from app.contracts.evidence import EvidenceCategory, EvidenceItem, EvidenceType, TrustLevel

logger = logging.getLogger(__name__)

class CorrelationEngine:
    def correlate(self, evidence_items: List[EvidenceItem], case_id: str) -> List[EvidenceItem]:
        if not evidence_items:
            return []
            
        correlations: List[EvidenceItem] = []
        try:
            graph = self._build_entity_graph(evidence_items)
            
            # Rule 1: Shared ASN across multiple malicious IPs
            asn_to_malicious_ips: Dict[str, set] = {}
            for ip, data in graph.get("ips", {}).items():
                asn = data.get("asn")
                rep = data.get("reputation", "").upper()
                if asn and rep in ["MALICIOUS", "SUSPICIOUS"]:
                    asn_to_malicious_ips.setdefault(asn, set()).add(ip)
            
            for asn, ips in asn_to_malicious_ips.items():
                if len(ips) >= 2:
                    correlations.append(self._create_evidence(
                        case_id=case_id,
                        key="shared_malicious_infrastructure",
                        value=True,
                        confidence=0.8,
                        related_entity=f"ASN:{asn}",
                        metadata={
                            "correlation_type": "shared_asn",
                            "supporting_ips": list(ips),
                            "reason": f"Shared ASN {asn} across {len(ips)} malicious/suspicious IPs."
                        }
                    ))

            # Rule 2: Reply-to + DMARC fail pattern
            if graph.get("reply_to_domain_mismatch") and graph.get("dmarc_result", "").lower() == "fail":
                correlations.append(self._create_evidence(
                    case_id=case_id,
                    key="bec_authentication_pattern",
                    value=True,
                    confidence=0.9,
                    metadata={
                        "correlation_type": "bec_pattern",
                        "reason": "Reply-to domain mismatch combined with DMARC failure indicates potential BEC."
                    }
                ))

            # Rule 3: Sender domain = URL domain
            sender_domain = graph.get("sender_domain")
            if sender_domain:
                if sender_domain in graph.get("url_domains", {}):
                    correlations.append(self._create_evidence(
                        case_id=case_id,
                        key="sender_url_domain_match",
                        value=True,
                        confidence=0.7,
                        related_entity=sender_domain,
                        metadata={
                            "correlation_type": "domain_match",
                            "reason": f"Sender domain {sender_domain} matches a domain found in URLs."
                        }
                    ))

            # Rule 4: Punycode domain + MALICIOUS reputation
            for domain, data in graph.get("domains", {}).items():
                if data.get("has_punycode"):
                    url_rep = graph.get("url_domains", {}).get(domain, {}).get("reputation", "").upper()
                    if url_rep == "MALICIOUS":
                        correlations.append(self._create_evidence(
                            case_id=case_id,
                            key="homoglyph_confirmed_malicious",
                            value=True,
                            confidence=0.95,
                            related_entity=domain,
                            metadata={
                                "correlation_type": "punycode_malicious",
                                "reason": f"Punycode domain {domain} has a MALICIOUS reputation."
                            }
                        ))

            # Rule 5: All-pass authentication + suspicious content
            spf = graph.get("spf_result", "").lower()
            dkim = graph.get("dkim_result", "").lower()
            dmarc = graph.get("dmarc_result", "").lower()
            
            if spf == "pass" and dkim == "pass" and dmarc == "pass":
                has_malicious_url = any(
                    data.get("reputation", "").upper() == "MALICIOUS" 
                    for data in graph.get("url_domains", {}).values()
                )
                if has_malicious_url:
                    correlations.append(self._create_evidence(
                        case_id=case_id,
                        key="compromised_legitimate_sender",
                        value=True,
                        confidence=0.85,
                        metadata={
                            "correlation_type": "auth_pass_malicious_content",
                            "reason": "Authentication all passed, but content contains malicious URLs."
                        }
                    ))
                    
        except Exception as e:
            logger.error(f"Correlation engine failed: {e}", exc_info=True)
            return []
            
        return correlations

    def _build_entity_graph(self, evidence_items: List[EvidenceItem]) -> dict:
        graph: Dict[str, Any] = {
            "ips": {},
            "domains": {},
            "url_domains": {},
            "sender_domain": None,
            "reply_to_domain_mismatch": False,
            "dmarc_result": None,
            "spf_result": None,
            "dkim_result": None
        }

        for item in evidence_items:
            key = item.key
            value = item.value
            entity = item.related_entity
            
            if key == "ip_asn" and entity:
                graph["ips"].setdefault(entity, {})["asn"] = str(value)
            elif key == "ip_reputation" and entity:
                graph["ips"].setdefault(entity, {})["reputation"] = str(value)
            elif key == "domain_is_newly_registered" and entity:
                graph["domains"].setdefault(entity, {})["is_newly_registered"] = bool(value)
            elif key == "domain_has_punycode" and entity:
                graph["domains"].setdefault(entity, {})["has_punycode"] = bool(value)
            elif key == "auth_dmarc_result":
                graph["dmarc_result"] = str(value)
            elif key == "auth_spf_result":
                graph["spf_result"] = str(value)
            elif key == "auth_dkim_result":
                graph["dkim_result"] = str(value)
            elif key == "url_reputation" and entity:
                graph["url_domains"].setdefault(entity, {})["reputation"] = str(value)
            elif key == "sender_domain":
                graph["sender_domain"] = str(value)
            elif key == "reply_to_domain_mismatch":
                graph["reply_to_domain_mismatch"] = bool(value)
            
        return graph

    def _create_evidence(
        self,
        case_id: str,
        key: str,
        value: Any,
        confidence: float,
        metadata: dict,
        related_entity: Optional[str] = None
    ) -> EvidenceItem:
        return EvidenceItem(
            evidence_id=f"ev_{uuid.uuid4().hex[:8]}",
            case_id=case_id,
            type=EvidenceType.HEURISTIC,
            category=EvidenceCategory.CORRELATION,
            key=key,
            value=value,
            source="correlation_engine",
            source_type=SourceType.DETERMINISTIC,
            confidence=confidence,
            trust_level=TrustLevel.INFERRED,
            related_entity=related_entity,
            metadata=metadata,
            provenance=Provenance(
                producer_module="app.services.investigation.correlation",
                extraction_method="heuristic_correlation"
            )
        )
