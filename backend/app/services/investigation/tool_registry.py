"""
services/investigation/tool_registry.py

Static, versioned, configuration-driven Tool Registry.

DESIGN RULES:
    - TOOL_REGISTRY is a plain dict — no magic, no dynamic generation.
    - Tool names must match the constants in profile_registry.py exactly.
    - Tool definitions are METADATA ONLY in Stage 1. No execution occurs here.
    - Consumers (policy engine, budget engine) read this registry.
    - An LLM must NEVER be allowed to generate a new tool name or entry.
    - Tool availability comes ONLY from this registry + InvestigationProfile.
    - handler_ref is a string key for future executor resolution, not a callable.

VERSIONING:
    TOOL_REGISTRY_VERSION identifies the schema version of this registry.
    Bump it when adding/removing/changing tools so audit records can reference it.
"""

from __future__ import annotations

from app.contracts.investigation import InvestigationLevel
from app.contracts.policy import ToolEligibility
from app.contracts.tool import ToolDefinition

TOOL_REGISTRY_VERSION = "2.0.0"

# ---------------------------------------------------------------------------
# TOOL_REGISTRY — single source of truth for all tool metadata
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, ToolDefinition] = {

    # ----------------------------------------------------------------
    # Stage 3 Type A/C — Deterministic Preprocessors & Local Feeds
    # ----------------------------------------------------------------
    "url_canonicalizer": ToolDefinition(
        name="url_canonicalizer",
        description="Canonicalizes URLs and groups identical destinations to save external calls.",
        profiles=[],  # Meta-tool, runs automatically for URL extraction
        min_level=InvestigationLevel.L0_TRIAGE,
        tier=ToolEligibility.MANDATORY,
        input_contract="app.services.evidence.models.EmailEvidencePackage",
        output_contract="app.contracts.url_canonical.URLCanonicalSet",
        reliability=1.0, cost=0.01,
        handler_ref="investigation.tools.url_canonicalizer",
        estimated_latency_ms=5, external_api=False, enabled=True,
    ),
    "ip_classifier": ToolDefinition(
        name="ip_classifier",
        description="Checks if IP is private, TOR exit, or datacenter before allowing external lookups.",
        profiles=["spoofing", "campaign", "compromised_account"],
        min_level=InvestigationLevel.L0_TRIAGE,
        tier=ToolEligibility.MANDATORY,
        input_contract="app.contracts.ioc.IOC",
        output_contract="app.contracts.provider_result.ProviderResult",
        reliability=0.99, cost=0.01,
        handler_ref="investigation.tools.ip_classifier",
        estimated_latency_ms=5, external_api=False, enabled=True,
    ),
    "attachment_hasher": ToolDefinition(
        name="attachment_hasher",
        description="Packages attachment hashes as IOCs for intelligence lookups.",
        profiles=["malware_delivery", "malicious_attachment"],
        min_level=InvestigationLevel.L0_TRIAGE,
        tier=ToolEligibility.MANDATORY,
        input_contract="app.services.evidence.models.EmailEvidencePackage",
        output_contract="app.contracts.provider_result.ProviderResult",
        reliability=1.0, cost=0.01,
        handler_ref="investigation.tools.attachment_hasher",
        estimated_latency_ms=1, external_api=False, enabled=True,
    ),
    "dns_resolver": ToolDefinition(
        name="dns_resolver",
        description="Checks if domain resolves and fetches A/MX/TXT records.",
        profiles=["credential_phishing", "bec", "vendor_fraud", "spoofing"],
        min_level=InvestigationLevel.L1_TARGETED,
        tier=ToolEligibility.OPTIONAL,
        input_contract="app.contracts.ioc.IOC",
        output_contract="app.contracts.provider_result.ProviderResult",
        reliability=0.9, cost=0.05,
        handler_ref="investigation.tools.dns_resolver",
        estimated_latency_ms=200, external_api=False, enabled=True,
    ),
    "geoip_lookup": ToolDefinition(
        name="geoip_lookup",
        description="Local MaxMind GeoLite2 lookup for ASN and Country.",
        profiles=["spoofing", "campaign"],
        min_level=InvestigationLevel.L2_DEEP,
        tier=ToolEligibility.OPTIONAL,
        input_contract="app.contracts.ioc.IOC",
        output_contract="app.contracts.provider_result.ProviderResult",
        reliability=0.85, cost=0.05,
        handler_ref="investigation.tools.geoip_lookup",
        estimated_latency_ms=10, external_api=False, enabled=True,
    ),
    "urlhaus_feed_lookup": ToolDefinition(
        name="urlhaus_feed_lookup",
        description="Local lookup against URLhaus malware feed cache.",
        profiles=["malicious_url", "malware_delivery"],
        min_level=InvestigationLevel.L1_TARGETED,
        tier=ToolEligibility.OPTIONAL,
        input_contract="app.contracts.url_canonical.URLCanonical",
        output_contract="app.contracts.provider_result.ProviderResult",
        reliability=0.95, cost=0.05,
        handler_ref="investigation.tools.urlhaus_lookup",
        estimated_latency_ms=5, external_api=False, enabled=True,
    ),
    "virustotal_lookup": ToolDefinition(
        name="virustotal_lookup",
        description="VirusTotal v3 Reputation for URLs and Hashes.",
        profiles=["malicious_url", "malware_delivery", "malicious_attachment"],
        min_level=InvestigationLevel.L2_DEEP,
        tier=ToolEligibility.OPTIONAL,
        input_contract="app.contracts.ioc.IOC",
        output_contract="app.contracts.provider_result.ProviderResult",
        reliability=0.85, cost=0.45,
        handler_ref="investigation.tools.virustotal_lookup",
        estimated_latency_ms=600, external_api=True, estimated_api_cost=0.005, enabled=True,
    ),
    "abuseipdb_lookup": ToolDefinition(
        name="abuseipdb_lookup",
        description="AbuseIPDB reputation lookup for IPs.",
        profiles=["spoofing", "campaign"],
        min_level=InvestigationLevel.L2_DEEP,
        tier=ToolEligibility.OPTIONAL,
        input_contract="app.contracts.ioc.IOC",
        output_contract="app.contracts.provider_result.ProviderResult",
        reliability=0.85, cost=0.35,
        handler_ref="investigation.tools.abuseipdb_lookup",
        estimated_latency_ms=500, external_api=True, estimated_api_cost=0.003, enabled=True,
    ),
    "rdap_domain_lookup": ToolDefinition(
        name="rdap_domain_lookup",
        description="RDAP domain registration info.",
        profiles=["vendor_fraud", "bec", "credential_phishing"],
        min_level=InvestigationLevel.L2_DEEP,
        tier=ToolEligibility.OPTIONAL,
        input_contract="app.contracts.ioc.IOC",
        output_contract="app.contracts.domain_intel.DomainIntelResult",
        reliability=0.80, cost=0.30,
        handler_ref="investigation.tools.rdap_lookup",
        estimated_latency_ms=700, external_api=True, estimated_api_cost=0.0, enabled=True,
    ),

    # ----------------------------------------------------------------
    # Level 0 — Deterministic tools (no external API, no ML)
    # ----------------------------------------------------------------

    "spf_dkim_dmarc": ToolDefinition(
        name="spf_dkim_dmarc",
        description=(
            "Evaluates SPF, DKIM, and DMARC authentication results from the "
            "already-parsed Authentication-Results header. Deterministic. No external call."
        ),
        profiles=["spoofing", "compromised_account"],
        min_level=InvestigationLevel.L0_TRIAGE,
        tier=ToolEligibility.MANDATORY,
        input_contract="app.services.evidence.models.EmailEvidencePackage",
        output_contract="app.contracts.evidence.EvidenceItem",
        reliability=0.99,
        cost=0.01,
        handler_ref="investigation.tools.spf_dkim_dmarc",
        estimated_latency_ms=10,
        external_api=False,
        estimated_api_cost=0.0,
        enabled=True,
    ),

    "header_parse": ToolDefinition(
        name="header_parse",
        description=(
            "Structural analysis of email headers: From/Reply-To/Return-Path mismatches, "
            "received hop anomalies, message-id structure. Deterministic."
        ),
        profiles=["bec", "executive_impersonation", "vendor_fraud", "payment_diversion",
                  "invoice_fraud", "spoofing", "compromised_account", "campaign"],
        min_level=InvestigationLevel.L0_TRIAGE,
        tier=ToolEligibility.MANDATORY,
        input_contract="app.services.evidence.models.EmailEvidencePackage",
        output_contract="app.contracts.evidence.EvidenceItem",
        reliability=0.97,
        cost=0.01,
        handler_ref="investigation.tools.header_parse",
        estimated_latency_ms=15,
        external_api=False,
        estimated_api_cost=0.0,
        enabled=True,
    ),

    "relay_reconstruction": ToolDefinition(
        name="relay_reconstruction",
        description=(
            "Reconstructs the mail relay chain from Received headers. Identifies "
            "the candidate origin IP, hop order anomalies, and timestamp regressions."
        ),
        profiles=["spoofing", "compromised_account", "campaign"],
        min_level=InvestigationLevel.L0_TRIAGE,
        tier=ToolEligibility.MANDATORY,
        input_contract="app.services.evidence.models.EmailEvidencePackage",
        output_contract="app.contracts.relay.RelayPath",
        reliability=0.95,
        cost=0.02,
        handler_ref="investigation.tools.relay_reconstruction",
        estimated_latency_ms=20,
        external_api=False,
        estimated_api_cost=0.0,
        enabled=True,
    ),

    "deterministic_heuristics": ToolDefinition(
        name="deterministic_heuristics",
        description=(
            "Applies deterministic rule-based heuristics: display-name spoofing check, "
            "lookalike domain detection (edit distance), urgency keyword detection. "
            "No ML inference."
        ),
        profiles=["credential_phishing", "bec", "executive_impersonation",
                  "vendor_fraud", "payment_diversion", "invoice_fraud", "social_engineering"],
        min_level=InvestigationLevel.L0_TRIAGE,
        tier=ToolEligibility.MANDATORY,
        input_contract="app.services.evidence.models.EmailEvidencePackage",
        output_contract="app.contracts.evidence.EvidenceItem",
        reliability=0.90,
        cost=0.02,
        handler_ref="investigation.tools.deterministic_heuristics",
        estimated_latency_ms=30,
        external_api=False,
        estimated_api_cost=0.0,
        enabled=True,
    ),

    # ----------------------------------------------------------------
    # Level 1 — Targeted ML tools (no external network calls)
    # ----------------------------------------------------------------

    "url_ml": ToolDefinition(
        name="url_ml",
        description=(
            "ML model that classifies URLs as phishing/malicious based on structural "
            "and lexical features. No external reputation lookup in this tool."
        ),
        profiles=["credential_phishing", "malicious_url", "malware_delivery"],
        min_level=InvestigationLevel.L1_TARGETED,
        tier=ToolEligibility.MANDATORY,
        input_contract="app.contracts.ml.URLPrediction",
        output_contract="app.contracts.evidence.EvidenceItem",
        reliability=0.88,
        cost=0.15,
        handler_ref="investigation.tools.url_ml",
        estimated_latency_ms=120,
        external_api=False,
        estimated_api_cost=0.0,
        enabled=True,
    ),

    "header_ml": ToolDefinition(
        name="header_ml",
        description=(
            "ML model that scores header risk from structural features "
            "(hop patterns, authentication alignment, sender similarity). "
            "Outputs HeaderPrediction."
        ),
        profiles=["spoofing", "compromised_account"],
        min_level=InvestigationLevel.L1_TARGETED,
        tier=ToolEligibility.OPTIONAL,
        input_contract="app.contracts.ml.HeaderFeatures",
        output_contract="app.contracts.ml.HeaderPrediction",
        reliability=0.85,
        cost=0.15,
        handler_ref="investigation.tools.header_ml",
        estimated_latency_ms=100,
        external_api=False,
        estimated_api_cost=0.0,
        enabled=True,
    ),

    "nlp_intent_ml": ToolDefinition(
        name="nlp_intent_ml",
        description=(
            "Multi-label NLP model for BEC/phishing/social-engineering content signals. "
            "Outputs NLPAnalysisResult with per-label scores."
        ),
        profiles=["bec", "executive_impersonation", "vendor_fraud", "payment_diversion",
                  "invoice_fraud", "social_engineering"],
        min_level=InvestigationLevel.L1_TARGETED,
        tier=ToolEligibility.MANDATORY,
        input_contract="app.contracts.ml.NLPAnalysisResult",
        output_contract="app.contracts.evidence.EvidenceItem",
        reliability=0.86,
        cost=0.20,
        handler_ref="investigation.tools.nlp_intent_ml",
        estimated_latency_ms=200,
        external_api=False,
        estimated_api_cost=0.0,
        enabled=True,
    ),

    "html_analysis": ToolDefinition(
        name="html_analysis",
        description=(
            "Static analysis of HTML content: form detection, pixel tracking, "
            "obfuscated links, deceptive anchor text, hidden elements."
        ),
        profiles=["credential_phishing", "malicious_url"],
        min_level=InvestigationLevel.L1_TARGETED,
        tier=ToolEligibility.MANDATORY,
        input_contract="app.contracts.html.HTMLAnalysisResult",
        output_contract="app.contracts.evidence.EvidenceItem",
        reliability=0.87,
        cost=0.10,
        handler_ref="investigation.tools.html_analysis",
        estimated_latency_ms=80,
        external_api=False,
        estimated_api_cost=0.0,
        enabled=True,
    ),

    "attachment_static_analysis": ToolDefinition(
        name="attachment_static_analysis",
        description=(
            "Static analysis of attachment metadata and structure: MIME type mismatch, "
            "macro presence indicators, embedded executables, structural anomalies. "
            "Does NOT execute attachment content."
        ),
        profiles=["malware_delivery", "malicious_attachment"],
        min_level=InvestigationLevel.L1_TARGETED,
        tier=ToolEligibility.MANDATORY,
        input_contract="app.contracts.attachment.AttachmentRef",
        output_contract="app.contracts.evidence.EvidenceItem",
        reliability=0.88,
        cost=0.15,
        handler_ref="investigation.tools.attachment_static_analysis",
        estimated_latency_ms=150,
        external_api=False,
        estimated_api_cost=0.0,
        enabled=True,
    ),

    # ----------------------------------------------------------------
    # Level 2 — External enrichment tools (network calls)
    # ----------------------------------------------------------------

    "domain_intelligence": ToolDefinition(
        name="domain_intelligence",
        description=(
            "RDAP + passive DNS + registration age queries for extracted domains. "
            "External API call. Rate-limited."
        ),
        profiles=["credential_phishing", "bec", "executive_impersonation", "vendor_fraud",
                  "payment_diversion", "invoice_fraud", "malicious_url", "campaign"],
        min_level=InvestigationLevel.L2_DEEP,
        tier=ToolEligibility.OPTIONAL,
        input_contract="app.contracts.ioc.IOC",
        output_contract="app.contracts.evidence.EvidenceItem",
        reliability=0.82,
        cost=0.40,
        handler_ref="investigation.tools.domain_intelligence",
        estimated_latency_ms=800,
        external_api=True,
        estimated_api_cost=0.001,
        enabled=True,
    ),

    "url_reputation": ToolDefinition(
        name="url_reputation",
        description=(
            "URL reputation lookup via external threat-intelligence API. "
            "External call, returns ThreatIntelResult."
        ),
        profiles=["credential_phishing", "malicious_url", "malware_delivery"],
        min_level=InvestigationLevel.L2_DEEP,
        tier=ToolEligibility.OPTIONAL,
        input_contract="app.contracts.ioc.IOC",
        output_contract="app.contracts.threat_intel.ThreatIntelResult",
        reliability=0.85,
        cost=0.45,
        handler_ref="investigation.tools.url_reputation",
        estimated_latency_ms=600,
        external_api=True,
        estimated_api_cost=0.002,
        enabled=True,
    ),

    "ip_intelligence": ToolDefinition(
        name="ip_intelligence",
        description=(
            "GeoIP + ASN + abuse reputation for candidate origin IP addresses. "
            "External API call."
        ),
        profiles=["spoofing", "compromised_account", "campaign"],
        min_level=InvestigationLevel.L2_DEEP,
        tier=ToolEligibility.OPTIONAL,
        input_contract="app.contracts.ioc.IOC",
        output_contract="app.contracts.evidence.EvidenceItem",
        reliability=0.83,
        cost=0.35,
        handler_ref="investigation.tools.ip_intelligence",
        estimated_latency_ms=500,
        external_api=True,
        estimated_api_cost=0.001,
        enabled=True,
    ),

    "sender_history": ToolDefinition(
        name="sender_history",
        description=(
            "Historical case correlation for the sending address/domain. "
            "Queries internal historical store (not external API)."
        ),
        profiles=["bec", "executive_impersonation", "vendor_fraud", "spoofing",
                  "compromised_account", "social_engineering"],
        min_level=InvestigationLevel.L2_DEEP,
        tier=ToolEligibility.OPTIONAL,
        input_contract="app.contracts.ioc.IOC",
        output_contract="app.contracts.historical.HistoricalMatch",
        reliability=0.80,
        cost=0.30,
        handler_ref="investigation.tools.sender_history",
        estimated_latency_ms=400,
        external_api=False,
        estimated_api_cost=0.0,
        enabled=True,
    ),

    "historical_correlation": ToolDefinition(
        name="historical_correlation",
        description=(
            "Deep multi-indicator historical correlation across all known case IOCs. "
            "Resource-intensive. Expensive tier."
        ),
        profiles=["credential_phishing", "bec", "executive_impersonation", "vendor_fraud",
                  "payment_diversion", "invoice_fraud", "malicious_url", "malware_delivery",
                  "malicious_attachment", "spoofing", "compromised_account",
                  "social_engineering", "campaign"],
        min_level=InvestigationLevel.L2_DEEP,
        tier=ToolEligibility.EXPENSIVE,
        input_contract="app.contracts.investigation.InvestigationState",
        output_contract="app.contracts.historical.HistoricalMatch",
        reliability=0.78,
        cost=0.80,
        handler_ref="investigation.tools.historical_correlation",
        estimated_latency_ms=1500,
        external_api=False,
        estimated_api_cost=0.0,
        enabled=True,
    ),

    "rdap_domain": ToolDefinition(
        name="rdap_domain",
        description=(
            "RDAP registration data lookup for domains. External call. "
            "Returns creation date, registrar, registrant country."
        ),
        profiles=["vendor_fraud"],
        min_level=InvestigationLevel.L2_DEEP,
        tier=ToolEligibility.OPTIONAL,
        input_contract="app.contracts.ioc.IOC",
        output_contract="app.contracts.evidence.EvidenceItem",
        reliability=0.80,
        cost=0.30,
        handler_ref="investigation.tools.rdap_domain",
        estimated_latency_ms=700,
        external_api=True,
        estimated_api_cost=0.0,
        enabled=True,
    ),

    # ----------------------------------------------------------------
    # Level 3 — Groq bounded reasoning (Stage 5 only; disabled in Stage 1)
    # ----------------------------------------------------------------

    "groq_reasoning": ToolDefinition(
        name="groq_reasoning",
        description=(
            "Bounded Groq LLM reasoning over investigation state. "
            "DISABLED in Stage 1. Will only be enabled in Stage 5 after "
            "deterministic evidence has been collected and risk is still ambiguous."
        ),
        profiles=["credential_phishing", "bec", "executive_impersonation", "vendor_fraud",
                  "payment_diversion", "invoice_fraud", "malicious_url", "malware_delivery",
                  "malicious_attachment", "spoofing", "compromised_account",
                  "social_engineering", "campaign"],
        min_level=InvestigationLevel.L3_GROQ,
        tier=ToolEligibility.EXPENSIVE,
        input_contract="app.contracts.groq.GroqInvestigationRequest",
        output_contract="app.contracts.groq.GroqReasoningResponse",
        reliability=0.75,
        cost=1.0,
        handler_ref="investigation.tools.groq_reasoning",
        estimated_latency_ms=3000,
        external_api=True,
        estimated_api_cost=0.05,
        enabled=False,  # ← DISABLED in Stage 1
    ),
}


def get_tool(name: str) -> ToolDefinition:
    """
    Safe tool lookup. Raises KeyError if the tool does not exist.

    SECURITY: Do not allow callers to generate tool names dynamically
    from untrusted input (e.g., email content). All tool lookups must
    use constants from profile_registry.py or literal strings in
    policy code.
    """
    if name not in TOOL_REGISTRY:
        raise KeyError(
            f"Tool '{name}' is not registered. Tool selection must use "
            f"the static TOOL_REGISTRY — LLM-generated tool names are forbidden."
        )
    return TOOL_REGISTRY[name]


def get_enabled_tools() -> dict[str, ToolDefinition]:
    """Return only enabled tools. Disabled tools (e.g., groq_reasoning) are filtered out."""
    return {name: tool for name, tool in TOOL_REGISTRY.items() if tool.enabled}
