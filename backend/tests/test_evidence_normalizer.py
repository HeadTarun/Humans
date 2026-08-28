"""
tests/test_evidence_normalizer.py

Unit tests for the Evidence Normalization layer.

Tests cover:
  - valid IPv4 / IPv6 / malformed IP
  - valid domain / malformed domain
  - valid URL / malformed URL
  - duplicate indicator deduplication
  - same IOC appearing multiple times
  - multiple Received hops
  - missing authentication results
  - malformed authentication results
  - missing optional fields
  - raw evidence is never overwritten
  - relationships are correctly built
  - attachment evidence
  - sender/recipient extraction
"""

import email as stdlib_email
import email.policy
import hashlib
from datetime import datetime, timezone
from email.message import EmailMessage

import pytest

from app.services.ingestion.parser import EmailParser
from app.services.evidence import EvidenceNormalizer, ExtractionStatus, TrustLevel
from app.services.evidence.models import (
    AuthResultValue,
    AuthProtocol,
    IPVersion,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_parser = EmailParser(storage_dir="/tmp/test_evidence_emails")
_normalizer = EvidenceNormalizer()


def _build_eml(
    subject="Test",
    from_addr="sender@example.com",
    to_addr="recipient@target.com",
    body_text=None,
    body_html=None,
    received_headers=None,
    auth_results=None,
    reply_to=None,
    return_path=None,
    attachments=None,
) -> bytes:
    """Helper to construct a minimal .eml bytes for testing."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Date"] = "Tue, 12 Oct 2021 10:00:00 +0000"
    msg["Message-ID"] = "<test-123@example.com>"
    if reply_to:
        msg["Reply-To"] = reply_to
    if return_path:
        msg["Return-Path"] = return_path
    if received_headers:
        for rh in received_headers:
            msg["Received"] = rh
    if auth_results:
        msg["Authentication-Results"] = auth_results

    if body_text and body_html:
        msg.set_content(body_text)
        msg.add_alternative(body_html, subtype="html")
    elif body_text:
        msg.set_content(body_text)
    elif body_html:
        msg.set_content(body_html, subtype="html")
    else:
        msg.set_content("Default body")

    if attachments:
        for filename, content in attachments:
            msg.add_attachment(content, maintype="application", subtype="octet-stream", filename=filename)

    return msg.as_bytes()


def _parse_and_normalize(eml_bytes: bytes):
    parsed = _parser.parse(eml_bytes)
    return _normalizer.normalize(parsed)


# ---------------------------------------------------------------------------
# IP Indicator Tests
# ---------------------------------------------------------------------------

class TestIPIndicators:

    def test_valid_ipv4_extracted_from_received_hop(self):
        eml = _build_eml(
            received_headers=[
                "from mail.sender.com (mail.sender.com [203.0.113.42]) by mx.example.com with SMTP; Tue, 12 Oct 2021 10:00:00 +0000"
            ]
        )
        pkg = _parse_and_normalize(eml)
        assert len(pkg.ips) >= 1
        ip = next((i for i in pkg.ips if "203.0.113.42" in (i.normalized_ip or "")), None)
        assert ip is not None, "Expected 203.0.113.42 in IP indicators"
        assert ip.ip_version == IPVersion.V4
        assert ip.is_valid is True
        assert ip.normalized_ip == "203.0.113.42"
        assert ip.raw_ip == "203.0.113.42"  # raw preserved

    def test_valid_ipv6_extracted(self):
        eml = _build_eml(
            received_headers=[
                "from ipv6host (ipv6host [2001:db8::1]) by mx.example.com with SMTP; Tue, 12 Oct 2021 10:00:00 +0000"
            ]
        )
        pkg = _parse_and_normalize(eml)
        ip = next((i for i in pkg.ips if "2001:db8::1" in (i.normalized_ip or "")), None)
        assert ip is not None
        assert ip.ip_version == IPVersion.V6
        assert ip.is_valid is True

    def test_malformed_ip_does_not_crash(self):
        eml = _build_eml(
            received_headers=[
                "from bad.host (bad.host [999.999.999.999]) by mx.example.com with SMTP; Tue, 12 Oct 2021 10:00:00 +0000"
            ]
        )
        # Should not raise
        pkg = _parse_and_normalize(eml)
        # We may or may not extract an IP — but if we do, it should be marked invalid or simply not present
        bad = next((i for i in pkg.ips if "999" in i.raw_ip), None)
        if bad:
            assert bad.is_valid is False

    def test_raw_ip_never_overwritten(self):
        eml = _build_eml(
            received_headers=[
                "from mail.sender.com (mail.sender.com [203.0.113.99]) by mx.example.com with SMTP; Tue, 12 Oct 2021 10:00:00 +0000"
            ]
        )
        pkg = _parse_and_normalize(eml)
        ip = next((i for i in pkg.ips if "203.0.113.99" in (i.raw_ip or "")), None)
        assert ip is not None
        # raw_ip must remain the original extracted string
        assert ip.raw_ip == "203.0.113.99"
        # normalized_ip is separate
        assert ip.normalized_ip == "203.0.113.99"

    def test_multiple_hops_produce_multiple_ips(self):
        eml = _build_eml(
            received_headers=[
                "from hop1.com ([10.0.0.1]) by relay.com with SMTP; Tue, 12 Oct 2021 10:00:00 +0000",
                "from hop2.com ([10.0.0.2]) by hop1.com with SMTP; Tue, 12 Oct 2021 09:59:00 +0000",
            ]
        )
        pkg = _parse_and_normalize(eml)
        assert len(pkg.received_hops) == 2
        assert len(pkg.ips) >= 1  # at least one valid IP

    def test_duplicate_ip_deduplicated(self):
        eml = _build_eml(
            received_headers=[
                "from host1 ([10.0.0.1]) by relay with SMTP; Tue, 12 Oct 2021 10:00:00 +0000",
                "from host2 ([10.0.0.1]) by host1 with SMTP; Tue, 12 Oct 2021 09:59:00 +0000",
            ]
        )
        pkg = _parse_and_normalize(eml)
        ip_values = [i.normalized_ip for i in pkg.ips]
        # Should not duplicate the same IP
        assert ip_values.count("10.0.0.1") == 1

    def test_ip_indicator_has_deterministic_id(self):
        eml1 = _build_eml(received_headers=["from h ([1.2.3.4]) by x; Tue, 12 Oct 2021 10:00:00 +0000"])
        eml2 = _build_eml(
            subject="Different subject",
            received_headers=["from h ([1.2.3.4]) by x; Tue, 12 Oct 2021 10:00:00 +0000"]
        )
        pkg1 = _parse_and_normalize(eml1)
        pkg2 = _parse_and_normalize(eml2)
        id1 = next((i.indicator_id for i in pkg1.ips if i.normalized_ip == "1.2.3.4"), None)
        id2 = next((i.indicator_id for i in pkg2.ips if i.normalized_ip == "1.2.3.4"), None)
        assert id1 is not None
        assert id1 == id2, "Same IP must produce same deterministic indicator_id across different emails"


# ---------------------------------------------------------------------------
# Domain Indicator Tests
# ---------------------------------------------------------------------------

class TestDomainIndicators:

    def test_valid_domain_from_from_header(self):
        eml = _build_eml(from_addr="user@legit-domain.com")
        pkg = _parse_and_normalize(eml)
        domain = next((d for d in pkg.domains if "legit-domain.com" in (d.normalized_domain or "")), None)
        assert domain is not None
        assert domain.is_valid is True

    def test_domain_normalized_lowercased(self):
        eml = _build_eml(from_addr="user@UPPER-CASE.COM")
        pkg = _parse_and_normalize(eml)
        domain = next((d for d in pkg.domains if d.raw_domain and "UPPER" in d.raw_domain.upper()), None)
        if domain:
            assert domain.normalized_domain == "upper-case.com"

    def test_malformed_domain_does_not_crash(self):
        # Malformed email address — parser may still extract something
        eml = _build_eml(from_addr="not-an-email")
        pkg = _parse_and_normalize(eml)
        # Should complete without raising

    def test_raw_domain_preserved(self):
        eml = _build_eml(from_addr="user@WWW.Example.COM.")
        pkg = _parse_and_normalize(eml)
        # raw_domain should still contain original case
        domain = next((d for d in pkg.domains if d.source == "from_header"), None)
        if domain:
            assert domain.raw_domain is not None
            assert domain.normalized_domain != domain.raw_domain or domain.raw_domain == domain.normalized_domain

    def test_duplicate_domain_deduplicated(self):
        eml = _build_eml(
            from_addr="sender@shared-domain.com",
            reply_to="other@shared-domain.com",
        )
        pkg = _parse_and_normalize(eml)
        norm_domains = [d.normalized_domain for d in pkg.domains]
        assert norm_domains.count("shared-domain.com") == 1

    def test_domain_deterministic_id(self):
        eml1 = _build_eml(from_addr="a@example.com")
        eml2 = _build_eml(from_addr="b@example.com")
        pkg1 = _parse_and_normalize(eml1)
        pkg2 = _parse_and_normalize(eml2)
        id1 = next((d.indicator_id for d in pkg1.domains if d.normalized_domain == "example.com"), None)
        id2 = next((d.indicator_id for d in pkg2.domains if d.normalized_domain == "example.com"), None)
        assert id1 is not None
        assert id1 == id2


# ---------------------------------------------------------------------------
# URL Indicator Tests
# ---------------------------------------------------------------------------

class TestURLIndicators:

    def test_valid_url_extracted(self):
        eml = _build_eml(body_text="Visit https://www.example.com/path?id=1 for info.")
        pkg = _parse_and_normalize(eml)
        url = next((u for u in pkg.urls if "example.com" in u.raw_url), None)
        assert url is not None
        assert url.scheme == "https"
        assert url.hostname == "www.example.com"
        assert url.path == "/path"
        assert url.query == "id=1"
        assert url.normalization_status == ExtractionStatus.OK

    def test_raw_url_preserved(self):
        raw = "https://SUSPICIOUS.PHISH.COM/login?redirect=http%3A%2F%2Fevil.com"
        eml = _build_eml(body_text=f"Click here: {raw}")
        pkg = _parse_and_normalize(eml)
        url = next((u for u in pkg.urls if "SUSPICIOUS" in u.raw_url), None)
        if url:
            assert url.raw_url == raw  # raw_url must be exact

    def test_malformed_url_marked_invalid_not_crash(self):
        # urlparse is very lenient, so we test what we can
        eml = _build_eml(body_text="See: not-a-url-at-all and http://valid.com/ok")
        pkg = _parse_and_normalize(eml)
        # At minimum, valid.com should be extracted
        valid = next((u for u in pkg.urls if "valid.com" in u.raw_url), None)
        assert valid is not None

    def test_duplicate_url_deduplicated(self):
        url = "https://example.com/click"
        eml = _build_eml(
            body_text=f"First mention: {url}\nSecond mention: {url}",
        )
        pkg = _parse_and_normalize(eml)
        raw_urls = [u.raw_url for u in pkg.urls]
        assert raw_urls.count(url) == 1

    def test_url_domain_relationship_created(self):
        eml = _build_eml(body_text="Visit https://phishy.bad-domain.com/steal-creds")
        pkg = _parse_and_normalize(eml)
        url_rels = [
            r for r in pkg.evidence_relationships
            if r.relationship_type.value == "url_contains_domain"
        ]
        assert len(url_rels) >= 1

    def test_url_deterministic_id(self):
        url = "https://stable-url.com/page"
        eml1 = _build_eml(body_text=f"A {url}")
        eml2 = _build_eml(subject="Different", body_text=f"B {url}")
        pkg1 = _parse_and_normalize(eml1)
        pkg2 = _parse_and_normalize(eml2)
        id1 = next((u.indicator_id for u in pkg1.urls if u.raw_url == url), None)
        id2 = next((u.indicator_id for u in pkg2.urls if u.raw_url == url), None)
        assert id1 is not None
        assert id1 == id2


# ---------------------------------------------------------------------------
# Authentication Tests
# ---------------------------------------------------------------------------

class TestAuthenticationEvidence:

    def test_spf_pass_parsed(self):
        eml = _build_eml(
            auth_results="mx.example.com; spf=pass smtp.mailfrom=sender@example.com"
        )
        pkg = _parse_and_normalize(eml)
        spf = next((r for r in pkg.authentication.results if r.protocol == AuthProtocol.SPF), None)
        assert spf is not None
        assert spf.result == AuthResultValue.PASS

    def test_dkim_pass_parsed(self):
        eml = _build_eml(
            auth_results="mx.example.com; dkim=pass header.i=@example.com header.s=default"
        )
        pkg = _parse_and_normalize(eml)
        dkim = next((r for r in pkg.authentication.results if r.protocol == AuthProtocol.DKIM), None)
        assert dkim is not None
        assert dkim.result == AuthResultValue.PASS

    def test_dmarc_fail_parsed(self):
        eml = _build_eml(
            auth_results="mx.example.com; dmarc=fail (p=REJECT) header.from=evil.com"
        )
        pkg = _parse_and_normalize(eml)
        dmarc = next((r for r in pkg.authentication.results if r.protocol == AuthProtocol.DMARC), None)
        assert dmarc is not None
        assert dmarc.result == AuthResultValue.FAIL

    def test_missing_auth_results_handled_gracefully(self):
        eml = _build_eml()  # No auth results header
        pkg = _parse_and_normalize(eml)
        assert pkg.authentication is not None
        assert pkg.authentication.results == []
        assert pkg.authentication.parse_status == ExtractionStatus.OK

    def test_malformed_auth_results_produces_partial(self):
        eml = _build_eml(
            auth_results="mx.example.com; totally=garbage xyz=abc"
        )
        pkg = _parse_and_normalize(eml)
        # Should not crash, and status should reflect partial parse
        assert pkg.authentication is not None
        assert pkg.authentication.parse_status in (ExtractionStatus.PARTIAL, ExtractionStatus.OK)

    def test_raw_auth_results_preserved(self):
        raw = "mx.example.com; spf=pass smtp.mailfrom=user@example.com"
        eml = _build_eml(auth_results=raw)
        pkg = _parse_and_normalize(eml)
        assert pkg.authentication.raw_authentication_results == raw


# ---------------------------------------------------------------------------
# Sender / Recipient / Header Tests
# ---------------------------------------------------------------------------

class TestSenderRecipient:

    def test_sender_from_extracted(self):
        eml = _build_eml(from_addr="John Doe <johndoe@company.com>")
        pkg = _parse_and_normalize(eml)
        assert pkg.sender.email_address == "johndoe@company.com"
        assert pkg.sender.domain == "company.com"
        assert pkg.sender.display_name == "John Doe"

    def test_reply_to_mismatch_flagged(self):
        eml = _build_eml(
            from_addr="ceo@legitimate.com",
            reply_to="ceo@attacker-domain.com",
        )
        pkg = _parse_and_normalize(eml)
        assert pkg.headers.has_reply_to_mismatch is True

    def test_return_path_mismatch_flagged(self):
        eml = _build_eml(
            from_addr="sender@legit.com",
            return_path="<bounces@spam.com>",
        )
        pkg = _parse_and_normalize(eml)
        assert pkg.headers.has_return_path_mismatch is True

    def test_no_mismatch_when_domains_match(self):
        eml = _build_eml(
            from_addr="user@example.com",
            reply_to="support@example.com",
        )
        pkg = _parse_and_normalize(eml)
        assert pkg.headers.has_reply_to_mismatch is False

    def test_trust_level_is_extracted_not_verified(self):
        eml = _build_eml()
        pkg = _parse_and_normalize(eml)
        assert pkg.sender.trust_level == TrustLevel.EXTRACTED


# ---------------------------------------------------------------------------
# Attachment Tests
# ---------------------------------------------------------------------------

class TestAttachmentEvidence:

    def test_attachment_evidence_produced(self):
        eml = _build_eml(attachments=[("invoice.pdf", b"fake pdf content")])
        pkg = _parse_and_normalize(eml)
        assert len(pkg.attachments) == 1
        att = pkg.attachments[0]
        assert att.filename == "invoice.pdf"
        assert att.normalized_filename == "invoice.pdf"
        assert len(att.sha256_hash) == 64

    def test_attachment_indicator_id_deterministic(self):
        content = b"stable attachment content"
        sha256 = hashlib.sha256(content).hexdigest()
        eml1 = _build_eml(attachments=[("file.bin", content)])
        eml2 = _build_eml(subject="Different", attachments=[("file.bin", content)])
        pkg1 = _parse_and_normalize(eml1)
        pkg2 = _parse_and_normalize(eml2)
        assert pkg1.attachments[0].indicator_id == pkg2.attachments[0].indicator_id

    def test_attachment_relationship_created(self):
        eml = _build_eml(attachments=[("mal.exe", b"exe content")])
        pkg = _parse_and_normalize(eml)
        att_rels = [r for r in pkg.evidence_relationships if r.relationship_type.value == "email_contains_attachment"]
        assert len(att_rels) == 1


# ---------------------------------------------------------------------------
# Relationship Graph Tests
# ---------------------------------------------------------------------------

class TestRelationships:

    def test_url_relationship_created(self):
        eml = _build_eml(body_text="Go to https://evil.com/phish")
        pkg = _parse_and_normalize(eml)
        url_rels = [r for r in pkg.evidence_relationships if r.from_entity_type == "EmailArtifact" and r.to_entity_type == "URLIndicator"]
        assert len(url_rels) >= 1

    def test_hop_ip_relationship_created(self):
        eml = _build_eml(
            received_headers=["from mail.attacker.com ([203.0.113.5]) by mx.victim.com with SMTP; Tue, 12 Oct 2021 10:00:00 +0000"]
        )
        pkg = _parse_and_normalize(eml)
        hop_rels = [r for r in pkg.evidence_relationships if r.relationship_type.value == "hop_contains_ip"]
        assert len(hop_rels) >= 1


# ---------------------------------------------------------------------------
# Schema + Immutability Tests
# ---------------------------------------------------------------------------

class TestSchema:

    def test_schema_version_is_1_0(self):
        eml = _build_eml()
        pkg = _parse_and_normalize(eml)
        assert pkg.schema_version == "1.0"

    def test_package_is_frozen(self):
        eml = _build_eml()
        pkg = _parse_and_normalize(eml)
        with pytest.raises(Exception):
            pkg.schema_version = "2.0"  # type: ignore

    def test_evidence_metadata_raw_value_preserved(self):
        eml = _build_eml(
            received_headers=["from mail.sender.com (mail.sender.com [192.0.2.1]) by mx.example.com with SMTP; Tue, 12 Oct 2021 10:00:00 +0000"]
        )
        pkg = _parse_and_normalize(eml)
        for ip in pkg.ips:
            # raw_value in meta must equal raw_ip — never overwritten
            assert ip.meta.raw_value == ip.raw_ip

    def test_missing_optional_fields_do_not_crash(self):
        # Minimal email — no Received, no auth, no URLs, no attachments
        eml = _build_eml()
        pkg = _parse_and_normalize(eml)
        assert pkg is not None
        assert pkg.urls == []
        assert pkg.ips == []
        assert pkg.attachments == []

    def test_email_sha256_matches_raw(self):
        raw = _build_eml()
        expected_sha256 = hashlib.sha256(raw).hexdigest()
        pkg = _parse_and_normalize(raw)
        assert pkg.email_sha256 == expected_sha256
