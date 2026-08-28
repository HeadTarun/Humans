"""
services/evidence/models.py

Evidence Normalization + IOC Preparation Layer (PS 26106 §2)

Transforms ParsedEmail → EmailEvidencePackage.

HARD RULES (from spec):
  - raw_value is NEVER overwritten
  - normalized_value is stored separately alongside raw_value
  - No verdict, no score, no malicious/benign decision
  - No external API calls
  - All indicators carry provenance, trust_level, extraction_confidence
  - Deterministic indicator_id for deduplication across cases

Schema version: "1.0"
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator

from app.contracts.common import BaseContract, utcnow


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ExtractionMethod(str, Enum):
    HEADER_PARSE = "header_parse"
    REGEX = "regex"
    HTML_HREF = "html_href"
    HTML_SRC = "html_src"
    MIME_WALK = "mime_walk"
    AUTH_RESULTS_PARSE = "auth_results_parse"
    RECEIVED_HEADER_PARSE = "received_header_parse"
    MANUAL = "manual"


class TrustLevel(str, Enum):
    """
    How much we should trust this indicator's value.

    VERIFIED   — confirmed by a cryptographic or authoritative source
    REPORTED   — claimed in a header but not independently verified
    EXTRACTED  — mechanically extracted from raw content
    INFERRED   — derived from reasoning over other evidence
    UNVERIFIABLE — we have no way to confirm this value
    """
    VERIFIED = "VERIFIED"
    REPORTED = "REPORTED"
    EXTRACTED = "EXTRACTED"
    INFERRED = "INFERRED"
    UNVERIFIABLE = "UNVERIFIABLE"


class IPVersion(str, Enum):
    V4 = "v4"
    V6 = "v6"
    UNKNOWN = "unknown"


class AuthProtocol(str, Enum):
    SPF = "spf"
    DKIM = "dkim"
    DMARC = "dmarc"
    ARC = "arc"
    UNKNOWN = "unknown"


class AuthResultValue(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"
    NEUTRAL = "neutral"
    SOFTFAIL = "softfail"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"


class ExtractionStatus(str, Enum):
    OK = "ok"
    INVALID = "invalid"          # malformed but preserved
    PARTIAL = "partial"          # partially parsed, some fields missing
    UNSUPPORTED = "unsupported"  # format not supported yet


class RelationshipType(str, Enum):
    URL_CONTAINS_DOMAIN = "url_contains_domain"
    HOP_CONTAINS_IP = "hop_contains_ip"
    SENDER_HAS_DOMAIN = "sender_has_domain"
    ATTACHMENT_HAS_HASH = "attachment_has_hash"
    AUTH_VALIDATES_DOMAIN = "auth_validates_domain"
    EMAIL_CONTAINS_URL = "email_contains_url"
    EMAIL_CONTAINS_IP = "email_contains_ip"
    EMAIL_CONTAINS_DOMAIN = "email_contains_domain"
    EMAIL_CONTAINS_ATTACHMENT = "email_contains_attachment"


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


class EvidenceMetadata(BaseContract):
    """
    Attached to every indicator. Answers: WHO extracted this? FROM WHERE?
    HOW? HOW CONFIDENT?
    """
    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source_module: str = Field(
        ..., description="Dotted module that produced this, e.g. 'services.evidence.normalizer'"
    )
    source_field: Optional[str] = Field(
        default=None,
        description="Exact header/field this was extracted from, e.g. 'Received[2]', 'From', 'html_href'"
    )
    raw_value: str = Field(..., description="Exact, unmodified string from the parser output")
    normalized_value: Optional[str] = Field(
        default=None,
        description="Canonicalized form. NEVER replaces raw_value — both coexist."
    )
    extraction_method: ExtractionMethod
    confidence: float = Field(..., ge=0.0, le=1.0)
    trust_level: TrustLevel
    timestamp: datetime = Field(default_factory=utcnow)
    normalization_status: ExtractionStatus = ExtractionStatus.OK
    normalization_notes: Optional[str] = Field(
        default=None,
        description="Human-readable note about why normalization was partial/invalid"
    )


# ---------------------------------------------------------------------------
# IP Indicator
# ---------------------------------------------------------------------------


class IPIndicator(BaseContract):
    """
    A candidate IP address extracted from email infrastructure.

    IMPORTANT: 'candidate_origin_ip' language used intentionally.
    Attribution is probabilistic. Do not call this 'attacker_ip'.
    """
    indicator_id: str = Field(
        ...,
        description="Deterministic: sha256('ip:' + normalized_ip). Stable across cases."
    )
    raw_ip: str
    normalized_ip: Optional[str] = Field(
        default=None,
        description="Canonical IP string. None if raw_ip was unparseable."
    )
    ip_version: IPVersion = IPVersion.UNKNOWN
    is_valid: bool
    source_header: str = Field(..., description="Header name this was extracted from, e.g. 'Received'")
    received_hop_id: Optional[str] = Field(
        default=None,
        description="hop_id of the ReceivedHopEvidence this came from"
    )
    position_in_chain: Optional[int] = Field(
        default=None,
        description="Index in the Received hop chain (0 = outermost/most recent)"
    )
    is_candidate_origin: bool = Field(
        default=False,
        description="Whether this is a candidate originating IP based on position only. "
                    "NOT a verified attribution claim. Downstream intelligence decides."
    )
    trust_level: TrustLevel
    extraction_confidence: float = Field(..., ge=0.0, le=1.0)
    meta: EvidenceMetadata


# ---------------------------------------------------------------------------
# Domain Indicator
# ---------------------------------------------------------------------------


class DomainIndicator(BaseContract):
    """
    A domain name extracted from any part of the email.
    Normalization: lowercased, trailing dot stripped.
    """
    indicator_id: str = Field(
        ...,
        description="Deterministic: sha256('domain:' + normalized_domain)"
    )
    raw_domain: str
    normalized_domain: Optional[str] = Field(
        default=None, description="Lowercase, trailing-dot-stripped form"
    )
    is_valid: bool
    source: str = Field(..., description="Where extracted from: 'from_header', 'url', 'received_hop', etc.")
    associated_email_address: Optional[str] = None
    associated_url_id: Optional[str] = None
    associated_hop_id: Optional[str] = None
    extraction_confidence: float = Field(..., ge=0.0, le=1.0)
    meta: EvidenceMetadata


# ---------------------------------------------------------------------------
# URL Indicator
# ---------------------------------------------------------------------------


class URLIndicator(BaseContract):
    """
    A URL extracted from body, HTML, or headers.

    No malicious/benign decision. No reputation check.
    The URL Intelligence layer consumes this.
    """
    indicator_id: str = Field(
        ...,
        description="Deterministic: sha256('url:' + raw_url)"
    )
    raw_url: str
    extracted_from: str = Field(
        ..., description="'plain_text', 'html_href', 'html_src', 'header'"
    )
    scheme: Optional[str] = None
    hostname: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    fragment: Optional[str] = None
    domain: Optional[str] = Field(
        default=None,
        description="Registrable domain if derivable. Null rather than guessing."
    )
    normalization_status: ExtractionStatus = ExtractionStatus.OK
    extraction_confidence: float = Field(..., ge=0.0, le=1.0)
    associated_domain_id: Optional[str] = None
    meta: EvidenceMetadata


# ---------------------------------------------------------------------------
# Received Hop Evidence
# ---------------------------------------------------------------------------


class ReceivedHopEvidence(BaseContract):
    """
    Structured representation of a single Received: header hop.

    IMPORTANT: the system determines a candidate_origin_ip separately
    based on relay trust boundary analysis, NOT merely by taking the
    last/first hop.
    """
    hop_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    position: int = Field(..., ge=0, description="0 = most recent (outermost) hop")
    raw_header: str
    sending_hostname: Optional[str] = None
    sending_ip: Optional[str] = None
    receiving_hostname: Optional[str] = None
    protocol: Optional[str] = None
    timestamp: Optional[datetime] = None
    trust_level: TrustLevel = TrustLevel.REPORTED
    extraction_status: ExtractionStatus = ExtractionStatus.OK
    ip_indicators: list[str] = Field(
        default_factory=list,
        description="indicator_ids of IPIndicators extracted from this hop"
    )


# ---------------------------------------------------------------------------
# Authentication Evidence
# ---------------------------------------------------------------------------


class SingleAuthResult(BaseContract):
    """Result for one auth protocol (SPF, DKIM, DMARC, ARC)."""
    protocol: AuthProtocol
    result: AuthResultValue = AuthResultValue.UNKNOWN
    domain: Optional[str] = None
    selector: Optional[str] = Field(
        default=None, description="DKIM selector, e.g. 's=default'"
    )
    identity: Optional[str] = Field(
        default=None, description="DKIM identity (i= tag) or SPF smtp.mailfrom"
    )
    policy: Optional[str] = Field(
        default=None, description="DMARC p= value: none/quarantine/reject"
    )
    alignment_spf: Optional[bool] = None
    alignment_dkim: Optional[bool] = None
    source_server: Optional[str] = Field(
        default=None, description="Server that reported this auth result"
    )
    raw_segment: Optional[str] = Field(
        default=None, description="The raw segment of Authentication-Results this was parsed from"
    )
    trust_level: TrustLevel = TrustLevel.REPORTED


class AuthenticationEvidence(BaseContract):
    """
    Structured authentication evidence from Authentication-Results header(s).

    Trust level on individual results is REPORTED: these are claims made
    by the receiving mail server. Verification happens downstream.
    """
    raw_authentication_results: Optional[str] = Field(
        default=None,
        description="Full raw Authentication-Results string preserved verbatim"
    )
    results: list[SingleAuthResult] = Field(default_factory=list)
    parse_status: ExtractionStatus = ExtractionStatus.OK
    parse_notes: Optional[str] = None


# ---------------------------------------------------------------------------
# Sender Evidence
# ---------------------------------------------------------------------------


class SenderEvidence(BaseContract):
    """
    Structured representation of the claimed sender identity.

    All values are EXTRACTED (from headers). They may be spoofed.
    Nothing here is VERIFIED — authentication evidence does that separately.
    """
    raw_from: Optional[str] = None
    display_name: Optional[str] = None
    email_address: Optional[str] = None
    domain: Optional[str] = None
    raw_reply_to: Optional[str] = None
    reply_to_email: Optional[str] = None
    reply_to_domain: Optional[str] = None
    raw_return_path: Optional[str] = None
    return_path_email: Optional[str] = None
    return_path_domain: Optional[str] = None
    trust_level: TrustLevel = TrustLevel.EXTRACTED


# ---------------------------------------------------------------------------
# Recipient Evidence
# ---------------------------------------------------------------------------


class RecipientEvidence(BaseContract):
    raw_to: Optional[str] = None
    email_addresses: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    delivered_to: Optional[str] = None
    trust_level: TrustLevel = TrustLevel.EXTRACTED


# ---------------------------------------------------------------------------
# Body Evidence
# ---------------------------------------------------------------------------


class BodyEvidence(BaseContract):
    has_plain_text: bool = False
    has_html: bool = False
    plain_text_length: Optional[int] = None
    html_length: Optional[int] = None
    # Raw text is not stored here — it stays in ParsedEmail (artifact).
    # Only metadata/indicators are stored in the evidence layer.
    url_count: int = 0
    extraction_status: ExtractionStatus = ExtractionStatus.OK


# ---------------------------------------------------------------------------
# Attachment Evidence
# ---------------------------------------------------------------------------


class AttachmentEvidence(BaseContract):
    """
    Metadata and hash indicators for an attachment.
    Raw bytes are NOT stored here — they stay in the artifact store.
    """
    indicator_id: str = Field(
        ...,
        description="Deterministic: sha256('attachment:' + sha256_hash)"
    )
    attachment_id: str
    filename: str
    raw_filename: str = Field(..., description="Exact filename as reported by MIME")
    normalized_filename: Optional[str] = Field(
        default=None, description="Lowercased filename"
    )
    mime_type: str
    size_bytes: int
    sha256_hash: str
    is_archive: bool = False
    is_executable_signature: bool = False
    trust_level: TrustLevel = TrustLevel.EXTRACTED
    extraction_confidence: float = 1.0


# ---------------------------------------------------------------------------
# Evidence Relationship
# ---------------------------------------------------------------------------


class EvidenceRelationship(BaseContract):
    """
    Explicit graph edge between two evidence entities.
    Used for correlation, campaign detection, graph analysis.
    """
    relationship_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    relationship_type: RelationshipType
    from_entity_id: str
    from_entity_type: str
    to_entity_id: str
    to_entity_type: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    notes: Optional[str] = None


# ---------------------------------------------------------------------------
# Header Evidence (top-level wrapper)
# ---------------------------------------------------------------------------


class HeaderEvidence(BaseContract):
    """
    Structural snapshot of the email headers.
    All values are EXTRACTED — not verified.
    """
    subject: Optional[str] = None
    date: Optional[datetime] = None
    message_id: Optional[str] = None
    raw_headers_count: int = 0
    has_reply_to_mismatch: bool = Field(
        default=False,
        description="True if Reply-To domain != From domain. Structural observation only — not a verdict."
    )
    has_return_path_mismatch: bool = Field(
        default=False,
        description="True if Return-Path domain != From domain. Structural observation only."
    )
    received_hop_count: int = 0


# ---------------------------------------------------------------------------
# Top-level EmailEvidencePackage
# ---------------------------------------------------------------------------


class EmailEvidencePackage(BaseContract):
    """
    The complete, normalized evidence package produced from one ParsedEmail.

    This is the contract consumed by all downstream layers:
      → URL Intelligence
      → IP Intelligence
      → Domain Intelligence
      → ML Models
      → Investigation Policy
      → Decision Engine
      → LLM Explanation

    schema_version allows evolution without breaking stored cases.
    """
    schema_version: str = Field(default="1.0")
    package_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: Optional[str] = Field(
        default=None,
        description="Set by the case manager when this package is assigned to a case"
    )
    email_sha256: str = Field(..., description="SHA256 of the raw .eml, links back to the artifact store")
    raw_artifact_reference: str = Field(..., description="File path to stored .eml artifact")
    parser_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Non-authoritative metadata from the parser, e.g. parse timing"
    )
    created_at: datetime = Field(default_factory=utcnow)

    # Structured evidence groups
    headers: HeaderEvidence
    sender: SenderEvidence
    recipients: RecipientEvidence
    received_hops: list[ReceivedHopEvidence] = Field(default_factory=list)
    authentication: AuthenticationEvidence
    body: BodyEvidence
    attachments: list[AttachmentEvidence] = Field(default_factory=list)

    # Indicator lists
    urls: list[URLIndicator] = Field(default_factory=list)
    ips: list[IPIndicator] = Field(default_factory=list)
    domains: list[DomainIndicator] = Field(default_factory=list)

    # Relationship graph
    evidence_relationships: list[EvidenceRelationship] = Field(default_factory=list)

    # Note: deduplication by indicator_id is performed by EvidenceNormalizer, not here.
