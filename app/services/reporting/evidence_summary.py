"""
app/services/reporting/evidence_summary.py

Evidence summarization for forensic reports.
"""
from __future__ import annotations
from typing import Any
from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory

class EvidenceSummarizer:
    def summarize(self, evidence_items: list[EvidenceItem]) -> dict[str, Any]:
        # Group by type
        by_type: dict[str, list[dict]] = {}
        for item in evidence_items:
            type_key = item.type.value if hasattr(item.type, "value") else str(item.type)
            if type_key not in by_type:
                by_type[type_key] = []
            by_type[type_key].append({
                "evidence_id": item.evidence_id,
                "key": item.key,
                "value": item.value.value if hasattr(item.value, "value") else item.value,
                "source": item.source,
                "category": item.category.value if hasattr(item.category, "value") else str(item.category),
                "confidence": item.confidence,
                "related_entity": item.related_entity,
            })

        # Build summary
        total = len(evidence_items)
        high_confidence = sum(1 for i in evidence_items if (i.confidence or 0) >= 0.7)
        return {
            "total_evidence_items": total,
            "high_confidence_items": high_confidence,
            "by_type": by_type,
            "type_counts": {k: len(v) for k, v in by_type.items()},
        }

    def generate_narrative(self, evidence_items: list[EvidenceItem], verdict: str, risk_score: float) -> str:
        """Generate a human-readable narrative from evidence."""
        facts = [i for i in evidence_items if i.type == EvidenceType.FACT]
        ml_signals = [i for i in evidence_items if i.type == EvidenceType.ML_SIGNAL]
        threat_intel = [i for i in evidence_items if i.type == EvidenceType.THREAT_INTEL]
        heuristics = [i for i in evidence_items if i.type == EvidenceType.HEURISTIC]

        lines = [
            f"Verdict: {verdict} (Risk Score: {risk_score:.1f}/100)",
            f"Evidence collected: {len(evidence_items)} items "
            f"({len(facts)} facts, {len(heuristics)} heuristics, "
            f"{len(ml_signals)} ML signals, {len(threat_intel)} threat intel)",
        ]

        # Auth findings
        auth_facts = [f for f in facts if "auth_" in (f.key or "")]
        if auth_facts:
            auth_strs = [f"{f.key}={f.value.value if hasattr(f.value, 'value') else f.value}" for f in auth_facts]
            lines.append("Authentication: " + "; ".join(auth_strs))

        # Threat intel
        if threat_intel:
            malicious = [t for t in threat_intel if "MALICIOUS" in str(getattr(t.value, "value", t.value)).upper()]
            if malicious:
                lines.append(f"Threat intelligence: {len(malicious)} malicious indicators confirmed")

        return "\n".join(lines)
