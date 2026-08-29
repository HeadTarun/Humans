import uuid
from datetime import datetime
from typing import List

from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory, TrustLevel, EvidenceStatus
from app.contracts.common import SourceType, Provenance, utcnow
from app.services.evidence.models import EmailEvidencePackage, AuthProtocol

class HeaderHeuristicAnalyzer:
    """
    Deterministic header analysis (NO ML).
    Produces HEURISTIC evidence based on RFC rules, auth alignments, and structural anomalies.
    """

    def analyze(self, package: EmailEvidencePackage) -> List[EvidenceItem]:
        evidence = []
        now = utcnow()

        # 1. From / Reply-To Mismatch
        if package.sender and package.sender.reply_to_email:
            from_addr = package.sender.email_address
            reply_to_addr = package.sender.reply_to_email
            if from_addr and reply_to_addr and from_addr.lower() != reply_to_addr.lower():
                evidence.append(
                    self._create_heuristic(
                        package.case_id,
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
                        package.case_id,
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
                        package.case_id,
                        key="dkim_missing",
                        value=True,
                        confidence=1.0,
                    )
                )
            elif dkim.result.name.lower() in ("fail", "none"):
                evidence.append(
                    self._create_heuristic(
                        package.case_id,
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
                        package.case_id,
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
                            package.case_id,
                            key="message_id_domain_mismatch",
                            value=msg_domain,
                            confidence=0.8,
                            related_entity=msg_id
                        )
                    )

        # 4. Received-chain anomalies
        if package.received_hops is not None:
            if len(package.received_hops) < 2:
                evidence.append(
                    self._create_heuristic(
                        package.case_id,
                        key="suspicious_relay_structure",
                        value="too_few_hops",
                        confidence=0.6,
                    )
                )
                
        return evidence

    def _create_heuristic(self, case_id: str, key: str, value: any, confidence: float, related_entity: str = None) -> EvidenceItem:
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
