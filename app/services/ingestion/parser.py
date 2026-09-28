import email
import email.policy
from email.message import EmailMessage
import hashlib
import ipaddress
import logging
import os
import re
import uuid
from datetime import datetime
from email.utils import parsedate_to_datetime, parseaddr
from typing import Optional

logger = logging.getLogger(__name__)

from app.contracts.email import ParsedEmail
from app.contracts.headers import HeaderSet, ReceivedHop
from app.contracts.attachment import AttachmentRef
from app.services.evidence.htmlparser import HTMLEmailParser
from app.services.ingestion.file_signatures import (
    detect_file_type, is_executable_type, detect_extension_mismatch
)


def extract_domain(address: Optional[str]) -> Optional[str]:
    """Extract domain from an email address string safely."""
    if not address:
        return None
    _, email_addr = parseaddr(address)
    if not email_addr:
        return None
    parts = email_addr.rsplit('@', 1)
    if len(parts) == 2 and parts[1]:
        return parts[1].strip()
    return None

_IPV4_RE = r'(?:\d{1,3}\.){3}\d{1,3}'
_IPV6_RE = r'[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}'


def _extract_ip_from_segment(segment: str) -> Optional[str]:
    """Find the first valid IP literal in a 'from'/'by' clause.

    Bracketed forms (``host (host [1.2.3.4])`` or ``host ([1.2.3.4])``) are
    preferred because that is where mail servers place the verified
    connecting address; bare IPv4/IPv6 tokens are a fallback for relays
    that omit the hostname entirely.
    """
    if not segment:
        return None

    candidates: list[str] = []
    bracket_matches = re.findall(r'\[([0-9A-Fa-f:.]+)\]', segment)
    candidates.extend(bracket_matches)
    candidates.extend(re.findall(_IPV4_RE, segment))
    candidates.extend(re.findall(_IPV6_RE, segment))

    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return None


def classify_ip(ip_str: Optional[str]) -> Optional[str]:
    """Structural classification of an IP literal.

    This is deliberately limited to what the stdlib can determine about
    the address space itself (RFC 1918 / loopback / multicast / etc.).
    It is NOT a reputation or threat judgment — that belongs to the
    intelligence/enrichment layer, not the parser.
    """
    if not ip_str:
        return None
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown"
    if ip_obj.is_loopback:
        return "loopback"
    if ip_obj.is_link_local:
        return "link_local"
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.is_unspecified:
        return "unspecified"
    if ip_obj.is_private:
        return "private"
    if ip_obj.is_reserved:
        return "reserved"
    return "public"


def parse_received_hop(index: int, header_val: str) -> ReceivedHop:
    """Parse a single Received header loosely."""
    header_val = header_val.replace('\r', '').replace('\n', ' ').strip()

    # Isolate the 'from ...' and 'by ...' clauses first so IP extraction
    # only looks within the right clause, rather than grabbing whichever
    # IP literal happens to appear anywhere in the header (e.g. inside an
    # unrelated comment or id string).
    from_clause_match = re.search(
        r'\bfrom\s+(.*?)(?=\bby\b|\bvia\b|\bwith\b|;|$)', header_val, re.IGNORECASE
    )
    by_clause_match = re.search(
        r'\bby\s+(.*?)(?=\bvia\b|\bwith\b|\bid\b|;|$)', header_val, re.IGNORECASE
    )

    from_clause = from_clause_match.group(1).strip() if from_clause_match else ""
    by_clause = by_clause_match.group(1).strip() if by_clause_match else ""

    from_host_match = re.match(r'([^\s(]+)', from_clause) if from_clause else None
    by_host_match = re.match(r'([^\s(]+)', by_clause) if by_clause else None

    from_host = from_host_match.group(1) if from_host_match else None
    by_host = by_host_match.group(1) if by_host_match else None

    from_ip = _extract_ip_from_segment(from_clause)
    by_ip = _extract_ip_from_segment(by_clause)

    # A hostname that is itself a bare IP (no separate bracketed form)
    # should still count as that endpoint's IP.
    if from_ip is None and from_host:
        try:
            ipaddress.ip_address(from_host)
            from_ip = from_host
        except ValueError:
            logger.debug("from_host %r is not a valid IP literal", from_host)
    if by_ip is None and by_host:
        try:
            ipaddress.ip_address(by_host)
            by_ip = by_host
        except ValueError:
            logger.debug("by_host %r is not a valid IP literal", by_host)

    # The 'from' endpoint is the one that matters for origin/relay
    # reconstruction; only fall back to 'by' when 'from' has no IP at all
    # (e.g. some malformed or truncated Received headers).
    ip_classification = classify_ip(from_ip or by_ip)

    timestamp = None
    parts = header_val.split(';')
    if len(parts) >= 2:
        date_str = parts[-1].strip()
        try:
            timestamp = parsedate_to_datetime(date_str)
        except (ValueError, TypeError, IndexError):
            logger.debug("Could not parse Received timestamp from %r", date_str)

    return ReceivedHop(
        hop_index=index,
        from_host=from_host,
        from_ip=from_ip,
        by_host=by_host,
        by_ip=by_ip,
        ip_classification=ip_classification,
        raw_line=header_val,
        timestamp=timestamp
    )

class EmailParser:
    def __init__(self, storage_dir: str = "/tmp/emails"):
        self.storage_dir = storage_dir
        self.html_parser = HTMLEmailParser()
        os.makedirs(self.storage_dir, exist_ok=True)

    def parse(self, raw_bytes: bytes) -> ParsedEmail:
        sha256 = hashlib.sha256(raw_bytes).hexdigest()
        
        # Save raw artifact
        artifact_filename = f"{sha256}.eml"
        artifact_path = os.path.join(self.storage_dir, artifact_filename)
        if not os.path.exists(artifact_path):
            with open(artifact_path, "wb") as f:
                f.write(raw_bytes)

        try:
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        
            from_header = msg.get("From")
            reply_to_header = msg.get("Reply-To")
            return_path_header = msg.get("Return-Path")
        
            # Repeated header names (multiple Received, multiple DKIM-Signature,
            # multiple X-Google-* etc.) must not be silently merged into one
            # comma-joined string — that is real evidence loss, and a comma
            # join is also ambiguous with headers whose own value legitimately
            # contains a comma. `raw_headers` keeps the first-seen value for
            # convenient single-value lookups; `raw_headers_all` is the
            # lossless list-per-name record downstream/forensic consumers
            # should use when completeness matters.
            raw_headers: dict[str, str] = {}
            raw_headers_all: dict[str, list[str]] = {}
            for k, v in msg.items():
                raw_headers_all.setdefault(k, []).append(str(v))
                if k not in raw_headers:
                    raw_headers[k] = str(v)

            date_header = msg.get("Date")
            date_dt = None
            if date_header:
                try:
                    date_dt = parsedate_to_datetime(str(date_header))
                except Exception:
                    logger.debug("Could not parse Date header: %r", date_header)

            received_headers = msg.get_all("Received", [])
            hops = [parse_received_hop(i, str(h)) for i, h in enumerate(received_headers)]

            # Get Authentication-Results as a single concatenated string if multiple
            auth_results_list = msg.get_all("Authentication-Results", [])
            auth_results_raw = " | ".join(str(ar) for ar in auth_results_list) if auth_results_list else None

            header_set = HeaderSet(
                from_address=str(from_header) if from_header else None,
                from_domain=extract_domain(str(from_header)) if from_header else None,
                to=str(msg.get("To")) if msg.get("To") else None,
                cc=str(msg.get("Cc")) if msg.get("Cc") else None,
                reply_to=str(reply_to_header) if reply_to_header else None,
                reply_to_domain=extract_domain(str(reply_to_header)) if reply_to_header else None,
                return_path=str(return_path_header) if return_path_header else None,
                return_path_domain=extract_domain(str(return_path_header)) if return_path_header else None,
                message_id=str(msg.get("Message-ID")) if msg.get("Message-ID") else None,
                subject=str(msg.get("Subject")) if msg.get("Subject") else None,
                date=date_dt,
                received_hops=hops,
                authentication_results_raw=auth_results_raw,
                raw_headers=raw_headers,
                raw_headers_all=raw_headers_all
            )

            plain_text_parts = []
            html_parts = []
            attachments = []
            urls: set[str] = set()
            url_sources: dict[str, str] = {}

            def add_url(raw_url: str, source: str) -> None:
                """Keep one raw URL while retaining the strongest provenance."""
                if not raw_url:
                    return
                urls.add(raw_url)
                # A rendered link/image source is more useful than a generic
                # regex match when normalising evidence later.
                if raw_url not in url_sources or source != "plain_text":
                    url_sources[raw_url] = source

            for part in msg.walk():
                if part.is_multipart():
                    continue

                content_type = part.get_content_type()
                content_disposition = str(part.get_content_disposition() or "")
            
                payload = part.get_payload(decode=True)
                if not payload:
                    continue

                # Identify if it is an attachment
                filename = part.get_filename()
                if "attachment" in content_disposition or ("inline" in content_disposition and filename):
                    filename = filename or f"unnamed_{uuid.uuid4().hex[:8]}"
                    part_sha256 = hashlib.sha256(payload).hexdigest()
                    detected_type = detect_file_type(payload)
                    attachments.append(AttachmentRef(
                        attachment_id=uuid.uuid4().hex,
                        filename=filename,
                        mime_type=content_type,
                        size_bytes=len(payload),
                        sha256=part_sha256,
                        detected_type=detected_type,
                        is_executable_signature=is_executable_type(detected_type),
                        extension_mismatch=detect_extension_mismatch(filename, detected_type),
                        is_archive=detected_type in ("zip_or_office_openxml", "gzip", "7zip", "rar"),
                    ))
                else:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        text_content = payload.decode(charset, errors="replace")
                    except LookupError:
                        text_content = payload.decode("utf-8", errors="replace")

                    if content_type == "text/plain":
                        plain_text_parts.append(text_content)
                        found_urls = re.findall(r'(https?://[^\s<>"]+)', text_content)
                        for found_url in found_urls:
                            add_url(found_url, "plain_text")
                    elif content_type == "text/html":
                        html_parts.append(text_content)

            plain_text = "\n".join(plain_text_parts) if plain_text_parts else None
            html = "\n".join(html_parts) if html_parts else None

            # HTMLEmailParser is the single source for visible-text cleanup,
            # language detection and HTML URL/image provenance.  This prevents
            # scripts/styles/images from leaking into NLP input.
            body_analysis: dict[str, object] = {}
            if html:
                html_doc = self.html_parser.parse(html)
                for record in html_doc.url_records:
                    source = "html_href" if record.anchor_text is not None else "html_text"
                    add_url(record.url, source)
                for image in html_doc.images:
                    add_url(image.src, "html_src")
                profile = html_doc.language
                body_analysis = {
                    "language": profile.detected,
                    "language_confidence": profile.confidence,
                    "language_candidates": profile.top_candidates,
                    "source": "html",
                    "visible_text_length": profile.char_count,
                    "image_count": len(html_doc.images),
                    "tracking_pixel_count": sum(image.is_tracking_pixel for image in html_doc.images),
                }
            elif plain_text:
                # The same parser also handles plain text, giving text-only
                # messages the same language evidence as HTML messages.
                text_doc = self.html_parser.parse(plain_text)
                profile = text_doc.language
                body_analysis = {
                    "language": profile.detected,
                    "language_confidence": profile.confidence,
                    "language_candidates": profile.top_candidates,
                    "source": "plain_text",
                    "visible_text_length": profile.char_count,
                    "image_count": 0,
                    "tracking_pixel_count": 0,
                }

            visible_text = None
            if html:
                visible_text = html_doc.full_text if html_doc.full_text else html
                url_records = [record.to_dict() for record in html_doc.url_records]
            elif plain_text:
                text_doc = self.html_parser.parse(plain_text)
                visible_text = text_doc.full_text or plain_text
                url_records = []
            else:
                url_records = []

            return ParsedEmail(
                message_id=str(msg.get("Message-ID")) if msg.get("Message-ID") else None,
                headers=header_set,
                plain_text=plain_text,
                html=html,
                visible_text=visible_text,
                urls=list(urls),
                url_records=url_records,
                attachments=attachments,
                metadata={
                    "body_analysis": body_analysis,
                    "url_sources": url_sources,
                },
                raw_artifact_reference=artifact_path,
                sha256=sha256
            )
        except Exception as exc:
            logger.error(
                "EMAIL_PARSE_ERROR sha256=%s type=%s detail=%s",
                sha256, type(exc).__name__, exc,
            )
            return ParsedEmail(
                message_id=None,
                headers=HeaderSet(),
                raw_artifact_reference=artifact_path,
                sha256=sha256,
                parsing_status="error",
                parsing_error=str(exc)
            )
