"""
services/investigation/hypothesis_rules.py

Configuration-driven hypothesis scoring rules for Stage 1.

DESIGN PRINCIPLES:
    - Every rule is a pure data record with no embedded logic.
    - The rule engine (case_manager.py) evaluates each rule deterministically.
    - No LLM, no random numbers, no external calls.
    - Scores are engineering-set, not statistically calibrated (documented).
    - All rules must be explainable: each carries a human-readable `reason`.

RULE SCHEMA:
    evidence_key   : key field to inspect from EmailEvidencePackage
    evidence_path  : dotted attribute path on the package (e.g. "authentication.dmarc")
    match_value    : expected value (str / bool). Use None to match "any non-None/truthy".
    target_hypothesis: AttackHypothesisType value
    score_delta    : amount to ADD to the hypothesis score (capped at 1.0)
    reason         : explainability string preserved in AttackHypothesis.reasons

NOTE on score calibration:
    These scores are ENGINEERING ESTIMATES, not probability distributions.
    They are intentionally conservative at Stage 1.
    Calibration against labeled datasets is a Stage 3 activity.
    Document all values with a rationale string in `reason`.

NOTE on evidence semantics:
    SPF/DKIM/DMARC PASS does NOT mean "email is safe."
    It means authentication checks passed per the reporting server.
    Evidence semantics are preserved exactly as the normalizer produced them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class HypothesisRule:
    """
    A single deterministic scoring rule.

    Attributes:
        rule_id         : Stable unique identifier for this rule. Never reuse an ID.
        evidence_path   : Dot-separated attribute path on EmailEvidencePackage.
                          Lists are supported: the engine iterates all elements.
                          Examples:
                            "authentication.dmarc"         → single AuthResult value
                            "headers.has_reply_to_mismatch"→ bool
                            "attachments"                  → list of AttachmentEvidence
                            "urls"                         → list of URLIndicator
        match_value     : The value to compare against. If None, the rule triggers
                          when the attribute is truthy (non-None, non-empty, True).
        target_hypothesis: AttackHypothesisType string value (matches the enum).
        score_delta     : Score contribution (0.0 – 1.0). Values are additive and
                          will be capped at 1.0 by the engine.
        reason          : Machine-readable + human-readable explanation string.
                          Stored in AttackHypothesis.reasons for audit trail.
        level           : Minimum investigation level at which this rule is evaluated.
                          "L0" = evaluated in Stage 1 triage. All Stage 1 rules are "L0".
    """

    rule_id: str
    evidence_path: str
    match_value: Optional[Any]
    target_hypothesis: str
    score_delta: float
    reason: str
    level: str = "L0"


# ---------------------------------------------------------------------------
# HYPOTHESIS_RULES — single source of truth for all deterministic scoring
#
# Engineering rationale per rule:
#
#   DMARC FAIL   → spoofing/BEC/exec-impersonation because DMARC failure
#                  is the single strongest low-cost authentication signal.
#                  (0.40 is conservative; an analyst would typically
#                  escalate a DMARC reject+fail combination immediately.)
#
#   SPF FAIL     → spoofing, moderate. SPF alone can fail for legitimate
#                  forwarding. Score is lower than DMARC.
#
#   Reply-To mismatch → BEC pattern: attacker redirects replies to their
#                       own mailbox. Low score because this is very common
#                       in newsletters too.
#
#   Return-Path mismatch → Similar to reply-to; more infrastructure-oriented.
#
#   Attachment present → malware_delivery / malicious_attachment (mild;
#                        need content analysis for strong signal).
#
#   Executable signature on attachment → strong malware/attachment signal.
#
#   Archive attachment → moderate malware delivery signal (archives hide
#                        executables from some gateway filters).
#
#   URL count > 0 → malicious_url (mild; any URL triggers minimal signal).
#
#   URL scheme http (not https) → mild phishing signal.
#
#   Subject matches urgency patterns → multiple BEC/social-engineering
#                                      hypotheses. NOT evaluated here because
#                                      subject is raw text requiring NLP —
#                                      that belongs to Level 1 ML analysis.
#                                      DO NOT add subject text rules here.
#
#   No authentication results → high spoofing uncertainty (missing evidence
#                                means we CANNOT conclude safe).
# ---------------------------------------------------------------------------

HYPOTHESIS_RULES: list[HypothesisRule] = [
    # ----------------------------------------------------------------
    # Authentication — DMARC
    # ----------------------------------------------------------------
    HypothesisRule(
        rule_id="AUTH_DMARC_FAIL_SPOOFING",
        evidence_path="authentication.results.result",
        match_value="fail",
        target_hypothesis="spoofing",
        score_delta=0.40,
        reason="DMARC fail: claimed sender domain authentication failed; spoofing is a primary hypothesis",
        level="L0",
    ),
    HypothesisRule(
        rule_id="AUTH_DMARC_FAIL_BEC",
        evidence_path="authentication.results.result",
        match_value="fail",
        target_hypothesis="bec",
        score_delta=0.20,
        reason="DMARC fail combined with email body indicators can indicate BEC; pre-scoring for further analysis",
        level="L0",
    ),
    HypothesisRule(
        rule_id="AUTH_DMARC_FAIL_EXEC_IMPERSONATION",
        evidence_path="authentication.results.result",
        match_value="fail",
        target_hypothesis="executive_impersonation",
        score_delta=0.15,
        reason="DMARC fail is consistent with executive impersonation attacks that spoof internal domains",
        level="L0",
    ),
    HypothesisRule(
        rule_id="AUTH_DMARC_SOFTFAIL_SPOOFING",
        evidence_path="authentication.results.result",
        match_value="softfail",
        target_hypothesis="spoofing",
        score_delta=0.15,
        reason="DMARC softfail: partial authentication failure; lower spoofing signal than hard fail",
        level="L0",
    ),
    HypothesisRule(
        rule_id="AUTH_DMARC_NONE_SPOOFING",
        evidence_path="authentication.results.result",
        match_value="none",
        target_hypothesis="spoofing",
        score_delta=0.10,
        reason="DMARC result=none: no DMARC policy defined; cannot verify sender domain authenticity",
        level="L0",
    ),

    # ----------------------------------------------------------------
    # Authentication — SPF
    # ----------------------------------------------------------------
    HypothesisRule(
        rule_id="AUTH_SPF_FAIL_SPOOFING",
        evidence_path="authentication.results.result",
        match_value="fail",
        target_hypothesis="spoofing",
        score_delta=0.20,
        reason="SPF hard fail: envelope sender not authorized to send from claimed IP",
        level="L0",
    ),
    HypothesisRule(
        rule_id="AUTH_SPF_SOFTFAIL_SPOOFING",
        evidence_path="authentication.results.result",
        match_value="softfail",
        target_hypothesis="spoofing",
        score_delta=0.10,
        reason="SPF softfail: envelope sender weakly unauthorized; common in misconfigured but legitimate domains",
        level="L0",
    ),

    # ----------------------------------------------------------------
    # Authentication — DKIM
    # ----------------------------------------------------------------
    HypothesisRule(
        rule_id="AUTH_DKIM_FAIL_SPOOFING",
        evidence_path="authentication.results.result",
        match_value="fail",
        target_hypothesis="spoofing",
        score_delta=0.15,
        reason="DKIM signature verification failed; message may have been tampered or spoofed",
        level="L0",
    ),

    # ----------------------------------------------------------------
    # Header anomalies
    # ----------------------------------------------------------------
    HypothesisRule(
        rule_id="HEADER_REPLY_TO_MISMATCH_BEC",
        evidence_path="headers.has_reply_to_mismatch",
        match_value=True,
        target_hypothesis="bec",
        score_delta=0.25,
        reason="Reply-To domain differs from From domain: classic BEC pattern to hijack reply chain",
        level="L0",
    ),
    HypothesisRule(
        rule_id="HEADER_REPLY_TO_MISMATCH_SOCIAL_ENGINEERING",
        evidence_path="headers.has_reply_to_mismatch",
        match_value=True,
        target_hypothesis="social_engineering",
        score_delta=0.15,
        reason="Reply-To mismatch is a common social engineering technique",
        level="L0",
    ),
    HypothesisRule(
        rule_id="HEADER_REPLY_TO_MISMATCH_EXEC_IMPERSONATION",
        evidence_path="headers.has_reply_to_mismatch",
        match_value=True,
        target_hypothesis="executive_impersonation",
        score_delta=0.15,
        reason="Reply-To mismatch with executive sender identity indicates possible impersonation",
        level="L0",
    ),
    HypothesisRule(
        rule_id="HEADER_RETURN_PATH_MISMATCH_SPOOFING",
        evidence_path="headers.has_return_path_mismatch",
        match_value=True,
        target_hypothesis="spoofing",
        score_delta=0.15,
        reason="Return-Path domain differs from From domain: may indicate envelope spoofing",
        level="L0",
    ),
    HypothesisRule(
        rule_id="HEADER_RETURN_PATH_MISMATCH_BEC",
        evidence_path="headers.has_return_path_mismatch",
        match_value=True,
        target_hypothesis="bec",
        score_delta=0.10,
        reason="Return-Path mismatch is a supporting indicator for BEC infrastructure patterns",
        level="L0",
    ),

    # ----------------------------------------------------------------
    # Attachment signals
    # ----------------------------------------------------------------
    HypothesisRule(
        rule_id="ATTACHMENT_PRESENT_MALWARE_DELIVERY",
        evidence_path="attachments",
        match_value=None,  # None = "any element in list" (truthy list)
        target_hypothesis="malware_delivery",
        score_delta=0.15,
        reason="Email contains attachment(s); malware delivery via attachment is possible; requires content analysis",
        level="L0",
    ),
    HypothesisRule(
        rule_id="ATTACHMENT_PRESENT_MALICIOUS_ATTACHMENT",
        evidence_path="attachments",
        match_value=None,
        target_hypothesis="malicious_attachment",
        score_delta=0.15,
        reason="Email contains attachment(s); malicious attachment hypothesis activated for content analysis",
        level="L0",
    ),
    HypothesisRule(
        rule_id="ATTACHMENT_EXECUTABLE_MALWARE_DELIVERY",
        evidence_path="attachments.is_executable_signature",
        match_value=True,
        target_hypothesis="malware_delivery",
        score_delta=0.35,
        reason="Attachment has executable file signature; strong malware delivery indicator",
        level="L0",
    ),
    HypothesisRule(
        rule_id="ATTACHMENT_EXECUTABLE_MALICIOUS_ATTACHMENT",
        evidence_path="attachments.is_executable_signature",
        match_value=True,
        target_hypothesis="malicious_attachment",
        score_delta=0.35,
        reason="Attachment has executable file signature; strong malicious attachment indicator",
        level="L0",
    ),
    HypothesisRule(
        rule_id="ATTACHMENT_ARCHIVE_MALWARE",
        evidence_path="attachments.is_archive",
        match_value=True,
        target_hypothesis="malware_delivery",
        score_delta=0.20,
        reason="Archive attachment detected; archives commonly used to obfuscate malware from gateway filters",
        level="L0",
    ),

    # ----------------------------------------------------------------
    # URL signals
    # ----------------------------------------------------------------
    HypothesisRule(
        rule_id="URL_PRESENT_MALICIOUS_URL",
        evidence_path="urls",
        match_value=None,  # any URL present
        target_hypothesis="malicious_url",
        score_delta=0.10,
        reason="Email contains URL(s); malicious URL hypothesis activated for URL intelligence analysis",
        level="L0",
    ),
    HypothesisRule(
        rule_id="URL_PRESENT_CREDENTIAL_PHISHING",
        evidence_path="urls",
        match_value=None,
        target_hypothesis="credential_phishing",
        score_delta=0.10,
        reason="URL(s) present; credential phishing via malicious link is possible; URL analysis required",
        level="L0",
    ),
    HypothesisRule(
        rule_id="URL_HTTP_SCHEME_PHISHING",
        evidence_path="urls.scheme",
        match_value="http",
        target_hypothesis="credential_phishing",
        score_delta=0.10,
        reason="Non-HTTPS URL found; HTTP-only URLs in email body are a mild phishing indicator",
        level="L0",
    ),
]
