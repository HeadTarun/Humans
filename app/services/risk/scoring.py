"""
services/risk/scoring.py

Deterministic evidence-weight scoring table.

DESIGN RULES:
    - All weights are configuration, not magic numbers scattered in code.
    - Positive weights increase risk. Negative weights decrease risk.
    - The table is the SINGLE SOURCE OF TRUTH for risk scoring.
    - Scores are additive and clipped to [0, 100].
    - Every contributing weight produces a RiskContribution (auditable).
    - No LLM. No ML. No external calls. No random numbers.

WEIGHT RATIONALE (briefly):
    Authentication failures are high-weight because they are machine-readable
    signals with low false-positive rates. Attachment executable signatures
    are very high-weight because they are a direct malware delivery vector.
    Negative weights represent positive authentication signals that reduce
    the overall risk but don't collapse it to zero (an attacker can still
    pass SPF while being malicious via URL/content).

FUTURE:
    Stage 3 will add weights for:
        "url_reputation:malicious"      +50.0
        "url_reputation:suspicious"     +25.0
        "attachment_av_result:malicious" +55.0
        "sender_reputation:poor"        +20.0
        "domain_age_days:young"         +15.0 (if < 30 days)
        "known_threat_actor"            +70.0
    These are left as placeholder comments below for visibility.
"""

from __future__ import annotations

from app.contracts.evidence import EvidenceItem, EvidenceType, EvidenceCategory
from app.contracts.risk import RiskContribution

# ---------------------------------------------------------------------------
# Evidence weight table — single source of truth
# ---------------------------------------------------------------------------
# Key format: "evidence_key:value" for value-specific weights,
#             "evidence_key"       for presence-based weights (any truthy value).
#
# Weights are on a 0–100 scale. The total is clipped to [0, 100].
# ---------------------------------------------------------------------------

EVIDENCE_WEIGHTS: dict[str, float] = {
    # ---- Authentication failures (high weight — machine-readable, reliable) ----
    "auth_dmarc_result:fail":      40.0,
    "auth_dmarc_result:softfail":  15.0,
    "auth_dmarc_result:none":       8.0,  # No policy — ambiguous, mild signal
    "auth_spf_result:fail":        20.0,
    "auth_spf_result:softfail":     8.0,
    "auth_dkim_result:fail":       15.0,

    # ---- Authentication passes (negative weight — reduce risk) ----
    "auth_dmarc_result:pass":     -15.0,
    "auth_spf_result:pass":        -8.0,
    "auth_dkim_result:pass":       -8.0,

    # ---- Header anomalies ----
    "reply_to_domain_mismatch":    20.0,  # Classic BEC signal
    "return_path_domain_mismatch": 12.0,

    # ---- Attachment signals ----
    "attachment_executable_signature": 35.0,  # Direct malware delivery vector
    "attachment_is_archive":           15.0,  # Often used to evade AV scanners
    # ---- NLP ML intents (M2) ----
    "intent:PHISHING":             30.0,  # Explicit classification of phishing intent by NLP model
    "intent:MALWARE":              35.0,  # Explicit classification of malware delivery intent by NLP model

    # ---- URL signals ----
    "url_http_scheme":              8.0,   # Non-HTTPS in email body

    # ---- Stage 6: Historical signals ----
    "historical_match_exact_hash": 65.0,
    "historical_match_exact_url":  45.0,
    "historical_match_exact_ip":   25.0,
    "historical_match_exact_domain": 20.0,
    
    "deep_historical_correlation": 60.0,
    "campaign_detected":           80.0,

    # ---- Stage 3: ML and API signals ----
    "url_ml_risk:MALICIOUS":       50.0,
    "url_ml_risk:SUSPICIOUS":      25.0,
    "url_ml_risk:BENIGN":         -10.0,

    # ---- Level-0 IOC intelligence ----
    # Values are enum names emitted by EvidenceToolNormaliser.
    "url_reputation:MALICIOUS":     50.0,
    "url_reputation:SUSPICIOUS":    25.0,
    "url_reputation:CLEAN":         -8.0,
    "ip_reputation:MALICIOUS":      35.0,
    "ip_reputation:SUSPICIOUS":     18.0,
    "ip_reputation:CLEAN":          -4.0,
    "domain_is_newly_registered":   15.0,
    "domain_has_punycode":           20.0,
}


def score_evidence_items(
    evidence_items: list[EvidenceItem],
    case_id: str,
) -> tuple[float, list[RiskContribution]]:
    """
    Compute a risk score from a list of EvidenceItem objects.

    Looks up each item in EVIDENCE_WEIGHTS using:
        1. "key:value" — value-specific match (for string values)
        2. "key"       — presence match (for boolean True values)

    Returns
    -------
    risk_score : float
        Clipped to [0, 100]. Sum of all matching weights.
    contributions : list[RiskContribution]
        One entry per matching evidence item, for full auditability.
    """
    # Multiple providers may describe the same indicator. Preserve all of
    # their evidence for audit/conflict review, but score only the most severe
    # reputation verdict for each (entity, semantic key). This prevents an
    # API fan-out from multiplying risk.
    reputation_rank = {"UNKNOWN": 0, "CLEAN": 1, "SUSPICIOUS": 2, "MALICIOUS": 3}
    strongest_reputation: dict[tuple[str, str], int] = {}
    for item in evidence_items:
        if item.type != EvidenceType.THREAT_INTEL or not item.related_entity:
            continue
        rank = reputation_rank.get(str(getattr(item.value, "value", item.value)).upper())
        if rank is not None:
            key = (item.related_entity, item.key)
            strongest_reputation[key] = max(strongest_reputation.get(key, -1), rank)

    total = 0.0
    contributions: list[RiskContribution] = []

    # Category caps
    CATEGORY_CAPS = {
        EvidenceCategory.URL: 50.0,
        EvidenceCategory.ATTACHMENT: 60.0,
        EvidenceCategory.HEADER: 40.0,
        EvidenceCategory.AUTHENTICATION: 50.0,
        EvidenceCategory.RELAY: 30.0,
        # Default cap for anything else is 100
    }
    
    category_totals: dict[EvidenceCategory, float] = {}

    for item in evidence_items:
        if item.type == EvidenceType.THREAT_INTEL and item.related_entity:
            rank = reputation_rank.get(str(getattr(item.value, "value", item.value)).upper())
            if rank is not None and rank < strongest_reputation[(item.related_entity, item.key)]:
                continue
        # Build lookup key variants
        val = item.value
        val_str = val.value if hasattr(val, "value") else str(val)

        # Try value-specific lookup first: "key:value"
        key_specific = f"{item.key}:{val_str}"
        key_presence = item.key

        weight = None
        reason_key = None

        if key_specific in EVIDENCE_WEIGHTS:
            weight = EVIDENCE_WEIGHTS[key_specific]
            reason_key = key_specific
        elif key_presence in EVIDENCE_WEIGHTS:
            # Presence match: fires when value is True (boolean) OR when it's a complex dict (like HISTORICAL)
            if val is True or isinstance(val, dict):
                weight = EVIDENCE_WEIGHTS[key_presence]
                reason_key = key_presence

        if weight is None:
            continue  # No weight defined for this evidence key/value
            
        cat = item.category
        if cat not in category_totals:
            category_totals[cat] = 0.0
            
        # Apply per-category capping
        cap = CATEGORY_CAPS.get(cat, 100.0)
        
        # Only cap positive weights
        if weight > 0:
            current_total = category_totals[cat]
            if current_total >= cap:
                continue # Skip this item, category is maxed out
            if current_total + weight > cap:
                weight = cap - current_total
                
        category_totals[cat] += weight

        total += weight
        contributions.append(
            RiskContribution(
                evidence_id=item.evidence_id,
                weight=weight,
                contribution=weight,  # Will be adjusted after clipping at total level
                reason_code=reason_key,
            )
        )

    # Clip total to [0, 100]
    clipped = max(0.0, min(100.0, total))

    # Adjust individual contributions proportionally if clipped
    if contributions and abs(total) > 0:
        scale = clipped / total if total != 0 else 0.0
        # Rebuild with scaled contributions to satisfy RiskAssessment validator
        contributions = [
            RiskContribution(
                evidence_id=c.evidence_id,
                weight=c.weight,
                contribution=round(c.contribution * scale, 4),
                reason_code=c.reason_code,
            )
            for c in contributions
        ]

    return clipped, contributions
