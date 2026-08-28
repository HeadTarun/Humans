"""
services/evidence/normalizer.py

Transforms a ParsedEmail → EmailEvidencePackage.

RESPONSIBILITIES:
  - Extract and normalize IPs from Received hop chain
  - Extract and normalize domains from From/Reply-To/Return-Path
  - Parse URL indicators from parser's raw URL list
  - Parse Authentication-Results into structured SingleAuthResult objects
  - Build the relationship graph between all indicators
  - Deduplicate indicators by deterministic indicator_id
  - Preserve ALL raw values alongside normalized values

NOT RESPONSIBILITIES:
  - External API calls (no VirusTotal, AbuseIPDB, GeoIP)
  - Verdict or risk score
  - ML inference
  - Modifying ParsedEmail

Every normalization failure produces partial evidence, never a crash.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid
from datetime import datetime, timezone
from email.utils import parseaddr
from typing import Optional
from urllib.parse import urlparse

from app.contracts.email import ParsedEmail
from app.contracts.headers import ReceivedHop

from .models import (
    AttachmentEvidence,
    AuthenticationEvidence,
    AuthProtocol,
    AuthResultValue,
    BodyEvidence,
    DomainIndicator,
    EmailEvidencePackage,
    EvidenceMetadata,
    EvidenceRelationship,
    ExtractionMethod,
    ExtractionStatus,
    HeaderEvidence,
    IPIndicator,
    IPVersion,
    ReceivedHopEvidence,
    RecipientEvidence,
    RelationshipType,
    SenderEvidence,
    SingleAuthResult,
    TrustLevel,
    URLIndicator,
)

_MODULE = "services.evidence.normalizer"


# ---------------------------------------------------------------------------
# Deterministic ID helpers
# ---------------------------------------------------------------------------

def _make_ip_id(normalized_ip: str) -> str:
    return hashlib.sha256(f"ip:{normalized_ip}".encode()).hexdigest()[:32]


def _make_domain_id(normalized_domain: str) -> str:
    return hashlib.sha256(f"domain:{normalized_domain}".encode()).hexdigest()[:32]


def _make_url_id(raw_url: str) -> str:
    return hashlib.sha256(f"url:{raw_url}".encode()).hexdigest()[:32]


def _make_attachment_id(sha256_hash: str) -> str:
    return hashlib.sha256(f"attachment:{sha256_hash}".encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# IP normalization
# ---------------------------------------------------------------------------

_IP_PATTERN = re.compile(
    r'\b(?:'
    r'(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'  # IPv4
    r'|\[?[0-9a-fA-F:]+\]?'  # IPv6 (loose)
    r')\b'
)


def _extract_ip_from_string(text: str) -> Optional[str]:
    """Extract first recognizable IP from a messy string like a Received header."""
    bracket_match = re.search(r'\[([^\]]+)\]', text)
    if bracket_match:
        candidate = bracket_match.group(1)
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    matches = _IP_PATTERN.findall(text)
    for m in matches:
        try:
            ipaddress.ip_address(m.strip('[]'))
            return m.strip('[]')
        except ValueError:
            continue
    return None


def _normalize_ip(raw: str) -> tuple[Optional[str], IPVersion, bool]:
    """Returns (normalized_ip, ip_version, is_valid)."""
    clean = raw.strip().strip('[]')
    try:
        obj = ipaddress.ip_address(clean)
        version = IPVersion.V4 if obj.version == 4 else IPVersion.V6
        return str(obj), version, True
    except ValueError:
        return None, IPVersion.UNKNOWN, False


# ---------------------------------------------------------------------------
# Domain normalization
# ---------------------------------------------------------------------------

def _normalize_domain(raw: str) -> tuple[Optional[str], bool]:
    """Returns (normalized_domain, is_valid)."""
    d = raw.strip().rstrip('.').lower()
    if not d or ' ' in d or len(d) > 253:
        return None, False
    # Minimal label check
    labels = d.split('.')
    if any(len(lab) == 0 or len(lab) > 63 for lab in labels):
        return None, False
    return d, True


def _domain_from_email(address: str) -> Optional[str]:
    _, addr = parseaddr(address)
    if '@' in addr:
        return addr.split('@', 1)[1].strip() or None
    return None


# ---------------------------------------------------------------------------
# URL parsing
# ---------------------------------------------------------------------------

def _parse_url(raw_url: str, extracted_from: str) -> URLIndicator:
    """Parse a raw URL string into a URLIndicator. Never raises."""
    meta = EvidenceMetadata(
        source_module=_MODULE,
        source_field=extracted_from,
        raw_value=raw_url,
        extraction_method=(
            ExtractionMethod.HTML_HREF if "html" in extracted_from
            else ExtractionMethod.REGEX
        ),
        confidence=0.85,
        trust_level=TrustLevel.EXTRACTED,
    )
    indicator_id = _make_url_id(raw_url)
    try:
        parsed = urlparse(raw_url)
        scheme = parsed.scheme or None
        hostname = parsed.hostname or None
        path = parsed.path or None
        query = parsed.query or None
        fragment = parsed.fragment or None

        domain = None
        if hostname:
            norm, valid = _normalize_domain(hostname)
            domain = norm if valid else None

        return URLIndicator(
            indicator_id=indicator_id,
            raw_url=raw_url,
            extracted_from=extracted_from,
            scheme=scheme,
            hostname=hostname,
            path=path,
            query=query,
            fragment=fragment,
            domain=domain,
            normalization_status=ExtractionStatus.OK,
            extraction_confidence=0.85,
            meta=meta.model_copy(update={"normalized_value": domain}),
        )
    except Exception as exc:
        return URLIndicator(
            indicator_id=indicator_id,
            raw_url=raw_url,
            extracted_from=extracted_from,
            normalization_status=ExtractionStatus.INVALID,
            extraction_confidence=0.3,
            meta=meta.model_copy(update={"normalization_status": ExtractionStatus.INVALID,
                                         "normalization_notes": str(exc)}),
        )


# ---------------------------------------------------------------------------
# Authentication-Results parser
# ---------------------------------------------------------------------------

_AUTH_PROTO_MAP = {
    "spf": AuthProtocol.SPF,
    "dkim": AuthProtocol.DKIM,
    "dmarc": AuthProtocol.DMARC,
    "arc": AuthProtocol.ARC,
}

_AUTH_RESULT_MAP = {r.value: r for r in AuthResultValue}


def _parse_auth_results(raw: str) -> tuple[list[SingleAuthResult], ExtractionStatus, Optional[str]]:
    """
    Parse the raw Authentication-Results header string into structured results.
    Returns (results, status, notes). Never raises.
    """
    if not raw:
        return [], ExtractionStatus.OK, None

    results: list[SingleAuthResult] = []
    notes: list[str] = []
    status = ExtractionStatus.OK

    # Split multiple server results on " | " (our concatenation separator from parser)
    for segment in raw.split(" | "):
        segment = segment.strip()
        if not segment:
            continue

        for proto_str, proto_enum in _AUTH_PROTO_MAP.items():
            pattern = re.compile(
                rf'\b{proto_str}=(\S+)', re.IGNORECASE
            )
            match = pattern.search(segment)
            if not match:
                continue

            raw_result = match.group(1).rstrip(';').lower()
            result_enum = _AUTH_RESULT_MAP.get(raw_result, AuthResultValue.UNKNOWN)
            if result_enum == AuthResultValue.UNKNOWN:
                notes.append(f"Unknown {proto_str} result: {raw_result!r}")
                status = ExtractionStatus.PARTIAL

            # Extract domain
            domain = None
            for tag in (f"header.{proto_str}", f"smtp.mailfrom", "header.from", "header.d"):
                dm = re.search(rf'{re.escape(tag)}=([^\s;]+)', segment, re.IGNORECASE)
                if dm:
                    domain = dm.group(1).strip()
                    break

            # Extract selector (DKIM)
            selector = None
            if proto_enum == AuthProtocol.DKIM:
                sel_m = re.search(r'header\.s=([^\s;]+)', segment, re.IGNORECASE)
                if sel_m:
                    selector = sel_m.group(1).strip()

            # Extract policy (DMARC)
            policy = None
            if proto_enum == AuthProtocol.DMARC:
                pol_m = re.search(r'p=([^\s;)]+)', segment, re.IGNORECASE)
                if pol_m:
                    policy = pol_m.group(1).strip()

            results.append(SingleAuthResult(
                protocol=proto_enum,
                result=result_enum,
                domain=domain,
                selector=selector,
                policy=policy,
                raw_segment=segment[:500],
                trust_level=TrustLevel.REPORTED,
            ))

    if not results and raw.strip():
        status = ExtractionStatus.PARTIAL
        notes.append("No recognizable auth protocols found in Authentication-Results header")

    return results, status, ("; ".join(notes) if notes else None)


# ---------------------------------------------------------------------------
# Received hop → IPIndicator
# ---------------------------------------------------------------------------

def _hop_to_evidence(hop: ReceivedHop, hop_ids: list[str]) -> tuple[ReceivedHopEvidence, list[IPIndicator]]:
    """Convert one parser ReceivedHop into a ReceivedHopEvidence + extracted IPIndicators."""
    hop_id = str(uuid.uuid4())
    ip_indicators: list[IPIndicator] = []
    ip_ids_for_hop: list[str] = []

    # Try to extract a sending IP from the raw_line
    raw_ip_candidate = _extract_ip_from_string(hop.raw_line)
    if raw_ip_candidate:
        normalized, version, is_valid = _normalize_ip(raw_ip_candidate)
        ind_id = _make_ip_id(normalized) if normalized else _make_ip_id(raw_ip_candidate)
        ip_indicators.append(IPIndicator(
            indicator_id=ind_id,
            raw_ip=raw_ip_candidate,
            normalized_ip=normalized,
            ip_version=version,
            is_valid=is_valid,
            source_header="Received",
            received_hop_id=hop_id,
            position_in_chain=hop.hop_index,
            trust_level=TrustLevel.REPORTED,
            extraction_confidence=0.8 if is_valid else 0.4,
            meta=EvidenceMetadata(
                source_module=_MODULE,
                source_field=f"Received[{hop.hop_index}]",
                raw_value=raw_ip_candidate,
                normalized_value=normalized,
                extraction_method=ExtractionMethod.RECEIVED_HEADER_PARSE,
                confidence=0.8 if is_valid else 0.4,
                trust_level=TrustLevel.REPORTED,
                normalization_status=ExtractionStatus.OK if is_valid else ExtractionStatus.INVALID,
            ),
        ))
        ip_ids_for_hop.append(ind_id)

    hop_evidence = ReceivedHopEvidence(
        hop_id=hop_id,
        position=hop.hop_index,
        raw_header=hop.raw_line,
        sending_hostname=hop.from_host,
        receiving_hostname=hop.by_host,
        sending_ip=raw_ip_candidate if raw_ip_candidate else None,
        timestamp=hop.timestamp,
        trust_level=TrustLevel.REPORTED,
        extraction_status=ExtractionStatus.OK,
        ip_indicators=ip_ids_for_hop,
    )
    return hop_evidence, ip_indicators


# ---------------------------------------------------------------------------
# Domain extraction helpers
# ---------------------------------------------------------------------------

def _make_domain_indicator(
    raw_domain: str,
    source: str,
    associated_email: Optional[str] = None,
    associated_url_id: Optional[str] = None,
    associated_hop_id: Optional[str] = None,
    confidence: float = 0.9,
) -> DomainIndicator:
    normalized, is_valid = _normalize_domain(raw_domain)
    ind_id = _make_domain_id(normalized) if normalized else _make_domain_id(raw_domain)
    status = ExtractionStatus.OK if is_valid else ExtractionStatus.INVALID
    return DomainIndicator(
        indicator_id=ind_id,
        raw_domain=raw_domain,
        normalized_domain=normalized,
        is_valid=is_valid,
        source=source,
        associated_email_address=associated_email,
        associated_url_id=associated_url_id,
        associated_hop_id=associated_hop_id,
        extraction_confidence=confidence if is_valid else 0.3,
        meta=EvidenceMetadata(
            source_module=_MODULE,
            source_field=source,
            raw_value=raw_domain,
            normalized_value=normalized,
            extraction_method=ExtractionMethod.HEADER_PARSE,
            confidence=confidence if is_valid else 0.3,
            trust_level=TrustLevel.EXTRACTED,
            normalization_status=status,
        ),
    )


# ---------------------------------------------------------------------------
# Main normalizer
# ---------------------------------------------------------------------------

class EvidenceNormalizer:
    """
    Transforms ParsedEmail → EmailEvidencePackage.

    Usage:
        normalizer = EvidenceNormalizer()
        package = normalizer.normalize(parsed_email)
    """

    def normalize(self, parsed: ParsedEmail) -> EmailEvidencePackage:
        seen_url_ids: set[str] = set()
        seen_ip_ids: set[str] = set()
        seen_domain_ids: set[str] = set()

        all_urls: list[URLIndicator] = []
        all_ips: list[IPIndicator] = []
        all_domains: list[DomainIndicator] = []
        all_hops: list[ReceivedHopEvidence] = []
        all_attachments: list[AttachmentEvidence] = []
        relationships: list[EvidenceRelationship] = []

        def add_domain(d: DomainIndicator) -> bool:
            if d.indicator_id not in seen_domain_ids:
                seen_domain_ids.add(d.indicator_id)
                all_domains.append(d)
                return True
            return False

        def add_ip(ip: IPIndicator) -> bool:
            if ip.indicator_id not in seen_ip_ids:
                seen_ip_ids.add(ip.indicator_id)
                all_ips.append(ip)
                return True
            return False

        def add_url(url: URLIndicator) -> bool:
            if url.indicator_id not in seen_url_ids:
                seen_url_ids.add(url.indicator_id)
                all_urls.append(url)
                return True
            return False

        # ------------------------------------------------------------------
        # 1. Sender evidence
        # ------------------------------------------------------------------
        h = parsed.headers
        _, from_addr = parseaddr(h.from_address or "")
        _, reply_addr = parseaddr(h.reply_to or "")
        _, return_addr = parseaddr(h.return_path or "")

        sender = SenderEvidence(
            raw_from=h.from_address,
            display_name=_display_name(h.from_address),
            email_address=from_addr or None,
            domain=h.from_domain,
            raw_reply_to=h.reply_to,
            reply_to_email=reply_addr or None,
            reply_to_domain=h.reply_to_domain,
            raw_return_path=h.return_path,
            return_path_email=return_addr or None,
            return_path_domain=h.return_path_domain,
            trust_level=TrustLevel.EXTRACTED,
        )

        # Sender domain indicators
        for raw_d, src, assoc_email in [
            (h.from_domain, "from_header", from_addr or None),
            (h.reply_to_domain, "reply_to_header", reply_addr or None),
            (h.return_path_domain, "return_path_header", return_addr or None),
        ]:
            if raw_d:
                dom = _make_domain_indicator(raw_d, src, associated_email=assoc_email)
                if add_domain(dom):
                    relationships.append(EvidenceRelationship(
                        relationship_type=RelationshipType.SENDER_HAS_DOMAIN,
                        from_entity_id="sender",
                        from_entity_type="SenderEvidence",
                        to_entity_id=dom.indicator_id,
                        to_entity_type="DomainIndicator",
                    ))

        # ------------------------------------------------------------------
        # 2. Recipient evidence
        # ------------------------------------------------------------------
        raw_to = h.raw_headers.get("To", "")
        delivered_to = h.raw_headers.get("Delivered-To")
        to_emails = _extract_emails_from_header(raw_to)
        to_domains = list({_domain_from_email(e) for e in to_emails if _domain_from_email(e)})
        recipients = RecipientEvidence(
            raw_to=raw_to or None,
            email_addresses=to_emails,
            domains=to_domains,
            delivered_to=delivered_to,
            trust_level=TrustLevel.EXTRACTED,
        )

        # ------------------------------------------------------------------
        # 3. Header evidence
        # ------------------------------------------------------------------
        from_domain = h.from_domain or ""
        reply_domain = h.reply_to_domain or ""
        return_domain = h.return_path_domain or ""

        has_reply_mismatch = bool(
            reply_domain and from_domain and
            _normalize_domain(reply_domain)[0] != _normalize_domain(from_domain)[0]
        )
        has_return_mismatch = bool(
            return_domain and from_domain and
            _normalize_domain(return_domain)[0] != _normalize_domain(from_domain)[0]
        )

        header_evidence = HeaderEvidence(
            subject=h.subject,
            date=h.date,
            message_id=h.message_id,
            raw_headers_count=len(h.raw_headers),
            has_reply_to_mismatch=has_reply_mismatch,
            has_return_path_mismatch=has_return_mismatch,
            received_hop_count=len(h.received_hops),
        )

        # ------------------------------------------------------------------
        # 4. Received hops + IP indicators
        # ------------------------------------------------------------------
        hop_ids: list[str] = []
        for hop in h.received_hops:
            hop_ev, ip_inds = _hop_to_evidence(hop, hop_ids)
            all_hops.append(hop_ev)
            hop_ids.append(hop_ev.hop_id)
            for ip in ip_inds:
                if add_ip(ip):
                    relationships.append(EvidenceRelationship(
                        relationship_type=RelationshipType.HOP_CONTAINS_IP,
                        from_entity_id=hop_ev.hop_id,
                        from_entity_type="ReceivedHopEvidence",
                        to_entity_id=ip.indicator_id,
                        to_entity_type="IPIndicator",
                    ))

        # ------------------------------------------------------------------
        # 5. Authentication evidence
        # ------------------------------------------------------------------
        auth_results, auth_status, auth_notes = _parse_auth_results(
            h.authentication_results_raw or ""
        )
        authentication = AuthenticationEvidence(
            raw_authentication_results=h.authentication_results_raw,
            results=auth_results,
            parse_status=auth_status,
            parse_notes=auth_notes,
        )

        # Domains from auth results
        for ar in auth_results:
            if ar.domain:
                dom = _make_domain_indicator(ar.domain, f"auth_results_{ar.protocol.value}", confidence=0.7)
                if add_domain(dom):
                    relationships.append(EvidenceRelationship(
                        relationship_type=RelationshipType.AUTH_VALIDATES_DOMAIN,
                        from_entity_id="authentication",
                        from_entity_type="AuthenticationEvidence",
                        to_entity_id=dom.indicator_id,
                        to_entity_type="DomainIndicator",
                    ))

        # ------------------------------------------------------------------
        # 6. URL indicators
        # ------------------------------------------------------------------
        for raw_url in parsed.urls:
            url_ind = _parse_url(raw_url, "body")
            if add_url(url_ind):
                relationships.append(EvidenceRelationship(
                    relationship_type=RelationshipType.EMAIL_CONTAINS_URL,
                    from_entity_id=parsed.sha256,
                    from_entity_type="EmailArtifact",
                    to_entity_id=url_ind.indicator_id,
                    to_entity_type="URLIndicator",
                ))
                # Domain from URL
                if url_ind.domain:
                    url_dom = _make_domain_indicator(
                        url_ind.domain,
                        f"url_{url_ind.indicator_id[:8]}",
                        associated_url_id=url_ind.indicator_id,
                        confidence=0.8,
                    )
                    url_dom_with_url = url_dom.model_copy(
                        update={"associated_url_id": url_ind.indicator_id}
                    )
                    if url_dom_with_url.indicator_id not in seen_domain_ids:
                        seen_domain_ids.add(url_dom_with_url.indicator_id)
                        all_domains.append(url_dom_with_url)
                        relationships.append(EvidenceRelationship(
                            relationship_type=RelationshipType.URL_CONTAINS_DOMAIN,
                            from_entity_id=url_ind.indicator_id,
                            from_entity_type="URLIndicator",
                            to_entity_id=url_dom_with_url.indicator_id,
                            to_entity_type="DomainIndicator",
                        ))

        # ------------------------------------------------------------------
        # 7. Body evidence
        # ------------------------------------------------------------------
        body = BodyEvidence(
            has_plain_text=parsed.plain_text is not None,
            has_html=parsed.html is not None,
            plain_text_length=len(parsed.plain_text) if parsed.plain_text else None,
            html_length=len(parsed.html) if parsed.html else None,
            url_count=len(all_urls),
            extraction_status=ExtractionStatus.OK,
        )

        # ------------------------------------------------------------------
        # 8. Attachment evidence
        # ------------------------------------------------------------------
        for att in parsed.attachments:
            att_ev = AttachmentEvidence(
                indicator_id=_make_attachment_id(att.sha256),
                attachment_id=att.attachment_id,
                filename=att.filename,
                raw_filename=att.filename,
                normalized_filename=att.filename.lower(),
                mime_type=att.mime_type,
                size_bytes=att.size_bytes,
                sha256_hash=att.sha256,
                is_archive=att.is_archive,
                is_executable_signature=att.is_executable_signature,
                trust_level=TrustLevel.EXTRACTED,
                extraction_confidence=1.0,
            )
            all_attachments.append(att_ev)
            relationships.append(EvidenceRelationship(
                relationship_type=RelationshipType.EMAIL_CONTAINS_ATTACHMENT,
                from_entity_id=parsed.sha256,
                from_entity_type="EmailArtifact",
                to_entity_id=att_ev.indicator_id,
                to_entity_type="AttachmentEvidence",
            ))

        # ------------------------------------------------------------------
        # 9. Assemble package
        # ------------------------------------------------------------------
        return EmailEvidencePackage(
            schema_version="1.0",
            email_sha256=parsed.sha256,
            raw_artifact_reference=parsed.raw_artifact_reference,
            parser_metadata={
                "message_id": parsed.message_id,
                "parsed_at": datetime.now(timezone.utc).isoformat(),
            },
            headers=header_evidence,
            sender=sender,
            recipients=recipients,
            received_hops=all_hops,
            authentication=authentication,
            body=body,
            attachments=all_attachments,
            urls=all_urls,
            ips=all_ips,
            domains=all_domains,
            evidence_relationships=relationships,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _display_name(raw_from: Optional[str]) -> Optional[str]:
    if not raw_from:
        return None
    name, _ = parseaddr(raw_from)
    return name.strip() or None


def _extract_emails_from_header(header_val: str) -> list[str]:
    """Extract all email addresses from a To/Cc header string."""
    if not header_val:
        return []
    emails = []
    for part in header_val.split(','):
        _, addr = parseaddr(part.strip())
        if addr and '@' in addr:
            emails.append(addr)
    return emails
