"""
services/investigation/layer_builder.py

Build the 5-layer intelligence correlation breakdown from existing evidence.

DESIGN RULES:
    - Pure function: same inputs → same outputs, no side-effects.
    - NO LLM, NO ML, NO external calls, NO DB access.
    - Scores are derived from EVIDENCE_WEIGHTS (reusing existing logic).
    - Unavailable layers are explicitly labelled — never fabricated.
    - The hypothesis references only layers that actually contributed
      evidence; it never invents signals.

LAYERS:
    1. header_analysis      — Authentication matrix (SPF/DKIM/DMARC),
                              Received-chain anomalies, sender field mismatches
    2. nlp_analysis         — NLP/ML intent classification (phishing, BEC,
                              social-engineering keywords)
    3. url_analysis         — URL ML signals, structural features, reputation
    4. threat_intelligence  — IP/domain/URL reputation lookups (TI providers)
    5. geolocation          — Geographic metadata for source IPs, routing anomalies
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.contracts.evidence import EvidenceCategory, EvidenceItem, EvidenceType
from app.contracts.result import AnalysisLayerSummary, GeoLocationSummary
from app.contracts.risk import Verdict
from app.services.risk.scoring import EVIDENCE_WEIGHTS

# ---------------------------------------------------------------------------
# Layer definitions — maps layer_id → (layer_name, category set, key prefixes)
# ---------------------------------------------------------------------------

_LAYER_AUTH_CATEGORIES = {EvidenceCategory.AUTHENTICATION}
_LAYER_HEADER_CATEGORIES = {EvidenceCategory.HEADER}
_LAYER_CONTENT_CATEGORIES = {EvidenceCategory.CONTENT}
_LAYER_URL_CATEGORIES = {EvidenceCategory.URL}
_LAYER_TI_CATEGORIES = {EvidenceCategory.THREAT_INTEL, EvidenceCategory.IOC}
_LAYER_RELAY_CATEGORIES = {EvidenceCategory.RELAY}

_AUTH_KEY_PREFIXES = ("auth_", "dkim_", "spf_", "dmarc_")
_NLP_KEY_PREFIXES = ("intent", "urgency", "se_flag_", "content_", "mentioned_")
_URL_KEY_PREFIXES = ("url_",)
_TI_KEY_PREFIXES = ("ip_reputation", "url_reputation", "domain_reputation",
                    "domain_is_newly", "domain_has_punycode",
                    "abuse_confidence", "historical_match")
_GEO_KEY_PREFIXES = ("geolocation_", "ip_country", "ip_city", "ip_region",
                     "ip_asn", "ip_is_")


@dataclass
class _LayerBucket:
    items: list[EvidenceItem] = field(default_factory=list)

    def add(self, ev: EvidenceItem) -> None:
        self.items.append(ev)

    def score(self) -> float:
        """Compute layer risk score reusing EVIDENCE_WEIGHTS, clipped to [0,100]."""
        total = 0.0
        for item in self.items:
            val = item.value
            val_str = val.value if hasattr(val, "value") else str(val)
            key_specific = f"{item.key}:{val_str}"
            weight = EVIDENCE_WEIGHTS.get(key_specific) or EVIDENCE_WEIGHTS.get(item.key, 0.0)
            if val is True or (isinstance(val, bool) and val):
                weight = EVIDENCE_WEIGHTS.get(item.key, 0.0)
            total += weight
        return max(0.0, min(100.0, total))

    def confidence(self) -> float:
        if not self.items:
            return 0.0
        return min(1.0, sum(i.confidence for i in self.items) / max(1, len(self.items)))

    def evidence_ids(self) -> list[str]:
        return [i.evidence_id for i in self.items]


def _classify(ev: EvidenceItem) -> str | None:
    """Return the layer_id this evidence item belongs to, or None."""
    cat = ev.category
    key = ev.key

    # Geolocation — check first (keys overlap with relay)
    if cat in _LAYER_RELAY_CATEGORIES or any(key.startswith(p) for p in _GEO_KEY_PREFIXES):
        return "geolocation"

    # Authentication / Header
    if cat in _LAYER_AUTH_CATEGORIES or any(key.startswith(p) for p in _AUTH_KEY_PREFIXES):
        return "header_analysis"
    if cat in _LAYER_HEADER_CATEGORIES:
        return "header_analysis"

    # NLP / Content
    if cat in _LAYER_CONTENT_CATEGORIES or any(key.startswith(p) for p in _NLP_KEY_PREFIXES):
        return "nlp_analysis"

    # URL
    if cat in _LAYER_URL_CATEGORIES or any(key.startswith(p) for p in _URL_KEY_PREFIXES):
        return "url_analysis"

    # Threat Intelligence (includes IOC + historical signals)
    if ev.type == EvidenceType.THREAT_INTEL:
        return "threat_intelligence"
    if cat in _LAYER_TI_CATEGORIES or any(key.startswith(p) for p in _TI_KEY_PREFIXES):
        return "threat_intelligence"
    if ev.type == EvidenceType.HISTORICAL:
        return "threat_intelligence"

    return None  # unclassified — skip


# ---------------------------------------------------------------------------
# Human-readable finding generators per layer
# ---------------------------------------------------------------------------

def _header_findings(items: list[EvidenceItem]) -> list[str]:
    findings = []
    for ev in items:
        val = ev.value
        val_str = val.value if hasattr(val, "value") else str(val)
        if ev.key == "auth_dmarc_result":
            findings.append(f"DMARC: {val_str.upper()}")
        elif ev.key == "auth_spf_result":
            findings.append(f"SPF: {val_str.upper()}")
        elif ev.key == "auth_dkim_result":
            findings.append(f"DKIM: {val_str.upper()}")
        elif ev.key == "reply_to_domain_mismatch" and val is True:
            findings.append("Reply-To domain mismatch detected")
        elif ev.key == "return_path_domain_mismatch" and val is True:
            findings.append("Return-Path domain mismatch detected")
        elif ev.key == "dkim_missing" and val is True:
            findings.append("No DKIM signature present")
    return findings[:4]  # cap for readability


def _nlp_findings(items: list[EvidenceItem]) -> list[str]:
    findings = []
    for ev in items:
        val = ev.value
        val_str = val.value if hasattr(val, "value") else str(val)
        if ev.key == "intent":
            findings.append(f"NLP intent classified as: {val_str} (conf {ev.confidence:.0%})")
        elif ev.key.startswith("se_flag_") and val is True:
            label = ev.key.replace("se_flag_", "").replace("_", " ").capitalize()
            findings.append(f"Social-engineering flag: {label}")
        elif ev.key == "urgency_score":
            try:
                score = float(val_str)
                if score > 0.5:
                    findings.append(f"Urgency score: {score:.2f} (elevated)")
            except (ValueError, TypeError):
                pass
    return findings[:4]


def _url_findings(items: list[EvidenceItem]) -> list[str]:
    findings = []
    seen_keys: set[str] = set()
    for ev in items:
        val = ev.value
        val_str = val.value if hasattr(val, "value") else str(val)
        if ev.key == "url_ml_risk" and ev.key not in seen_keys:
            findings.append(f"URL ML risk: {val_str} (conf {ev.confidence:.0%})")
            seen_keys.add(ev.key)
        elif ev.key == "url_http_scheme" and val is True and ev.key not in seen_keys:
            findings.append("Non-HTTPS URL detected in email body")
            seen_keys.add(ev.key)
        elif ev.key == "domain_has_punycode" and val is True and ev.key not in seen_keys:
            findings.append("Punycode/homoglyph domain detected")
            seen_keys.add(ev.key)
    return findings[:4]


def _ti_findings(items: list[EvidenceItem]) -> list[str]:
    findings = []
    for ev in items:
        val = ev.value
        val_str = val.value if hasattr(val, "value") else str(val)
        entity = ev.related_entity or ""
        if ev.key in ("ip_reputation", "url_reputation", "domain_reputation"):
            label = ev.key.replace("_reputation", "").upper()
            findings.append(f"{label} reputation: {val_str} ({entity})")
        elif ev.key == "domain_is_newly_registered" and val is True:
            findings.append(f"Domain newly registered (<30d): {entity}")
        elif ev.key.startswith("historical_match"):
            findings.append(f"Historical IOC match: {entity}")
    return findings[:4]


def _geo_findings(geo_summaries: list[GeoLocationSummary]) -> list[str]:
    findings = []
    for geo in geo_summaries:
        if not geo.success:
            continue
        parts = []
        if geo.country:
            parts.append(geo.country)
        if geo.city:
            parts.append(geo.city)
        if geo.asn:
            parts.append(f"ASN {geo.asn}")
        if parts:
            findings.append(f"Hop {geo.hop_position}: {geo.ip} — {', '.join(parts)}")
    return findings[:3]


def _geo_risk(geo_summaries: list[GeoLocationSummary]) -> float:
    """Simple heuristic geo risk: private/reserved = 0, success = small signal."""
    score = 0.0
    for geo in geo_summaries:
        if geo.is_private or geo.is_loopback or geo.is_reserved:
            continue
        if geo.success:
            score += 8.0  # Non-private routable hop with geo data
    return min(30.0, score)


# ---------------------------------------------------------------------------
# Hypothesis generator — deterministic string, never LLM
# ---------------------------------------------------------------------------

_LAYER_SIGNAL_LABELS: dict[str, str] = {
    "header_analysis": "authentication anomalies",
    "nlp_analysis": "NLP phishing/social-engineering indicators",
    "url_analysis": "suspicious URL patterns",
    "threat_intelligence": "high-risk threat intelligence signals",
    "geolocation": "anomalous geographic routing",
}

_VERDICT_PHRASES: dict[str, str] = {
    "MALICIOUS":    "is a high-confidence threat",
    "SUSPICIOUS":   "exhibits suspicious characteristics warranting investigation",
    "BENIGN":       "appears legitimate based on all available evidence",
    "INCONCLUSIVE": "requires further analysis — insufficient evidence for a definitive verdict",
}


def _generate_hypothesis(
    layers: list[AnalysisLayerSummary],
    verdict: Verdict,
    risk_score: float,
) -> str:
    contributing = [
        lay for lay in layers
        if lay.status == "analyzed" and lay.risk_score > 8.0
    ]
    verdict_phrase = _VERDICT_PHRASES.get(verdict.value, "has an indeterminate risk profile")

    if not contributing:
        return (
            f"The email {verdict_phrase}. "
            f"Insufficient individual layer signals to form a detailed hypothesis "
            f"(composite risk: {risk_score:.1f}/100)."
        )

    labels = [_LAYER_SIGNAL_LABELS[lay.layer_id] for lay in contributing
              if lay.layer_id in _LAYER_SIGNAL_LABELS]
    if len(labels) == 1:
        signals_text = labels[0]
    elif len(labels) == 2:
        signals_text = f"{labels[0]} and {labels[1]}"
    else:
        signals_text = ", ".join(labels[:-1]) + f", and {labels[-1]}"

    return (
        f"The email {verdict_phrase} because {signals_text} collectively "
        f"support this assessment. "
        f"(Composite risk: {risk_score:.1f}/100, "
        f"{len(contributing)}/5 layers contributed evidence)"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_analysis_layers(
    evidence: list[EvidenceItem],
    geolocation: list[GeoLocationSummary],
    risk_score: float,
    verdict: Verdict,
) -> tuple[list[AnalysisLayerSummary], str]:
    """
    Categorise existing evidence into 5 intelligence layers and generate
    a deterministic, evidence-backed investigation hypothesis.

    Parameters
    ----------
    evidence    : All EvidenceItem objects produced by the investigation.
    geolocation : GeoLocationSummary list from result_factory._geolocation_summaries().
    risk_score  : Overall composite risk score (0–100).
    verdict     : Final verdict from the Risk Engine.

    Returns
    -------
    (layers, hypothesis_text)
        layers          : list of 5 AnalysisLayerSummary objects (one per layer).
        hypothesis_text : Short evidence-backed hypothesis string.
    """
    buckets: dict[str, _LayerBucket] = {
        "header_analysis":    _LayerBucket(),
        "nlp_analysis":       _LayerBucket(),
        "url_analysis":       _LayerBucket(),
        "threat_intelligence": _LayerBucket(),
        "geolocation":        _LayerBucket(),
    }

    for ev in evidence:
        layer_id = _classify(ev)
        if layer_id and layer_id in buckets:
            buckets[layer_id].add(ev)

    def _make_layer(
        layer_id: str,
        layer_name: str,
        findings_fn,
        extra_score: float = 0.0,
        extra_confidence: float = 0.0,
    ) -> AnalysisLayerSummary:
        bucket = buckets[layer_id]
        items = bucket.items
        has_data = bool(items) or extra_score > 0

        raw_score = bucket.score() + extra_score
        score = max(0.0, min(100.0, raw_score))
        conf = max(bucket.confidence(), extra_confidence) if has_data else 0.0
        status = "analyzed" if has_data else "unavailable"
        findings = findings_fn(items) if items else []

        # Build one-line explanation
        if status == "unavailable":
            explanation = f"{layer_name}: No evidence collected for this layer."
        elif score >= 60:
            explanation = f"{layer_name}: High-risk signals detected ({score:.0f}/100)."
        elif score >= 25:
            explanation = f"{layer_name}: Moderate risk signals detected ({score:.0f}/100)."
        elif score > 0:
            explanation = f"{layer_name}: Low/negative risk signals ({score:.0f}/100)."
        else:
            explanation = f"{layer_name}: No risk-contributing signals found."

        return AnalysisLayerSummary(
            layer_id=layer_id,
            layer_name=layer_name,
            risk_score=round(score, 1),
            confidence=round(conf, 3),
            status=status,
            findings=findings,
            evidence_ids=bucket.evidence_ids(),
            explanation=explanation,
        )

    # Geolocation layer uses GeoLocationSummary directly for findings + score
    geo_score = _geo_risk(geolocation)
    geo_findings = _geo_findings(geolocation)
    geo_conf = 0.7 if any(g.success for g in geolocation) else 0.0

    layers = [
        _make_layer("header_analysis",    "Header Analysis",        _header_findings),
        _make_layer("nlp_analysis",       "NLP Analysis",           _nlp_findings),
        _make_layer("url_analysis",       "URL Analysis",           _url_findings),
        _make_layer("threat_intelligence","Threat Intelligence",     _ti_findings),
        AnalysisLayerSummary(
            layer_id="geolocation",
            layer_name="Geolocation Intelligence",
            risk_score=round(geo_score, 1),
            confidence=round(geo_conf, 3),
            status="analyzed" if geolocation else "unavailable",
            findings=geo_findings,
            evidence_ids=[],
            explanation=(
                f"Geolocation Intelligence: {len(geolocation)} relay hop(s) geolocated."
                if geolocation else
                "Geolocation Intelligence: No routing hops geolocated."
            ),
        ),
    ]

    hypothesis = _generate_hypothesis(layers, verdict, risk_score)
    return layers, hypothesis
