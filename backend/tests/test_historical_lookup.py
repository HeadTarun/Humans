from datetime import datetime, timezone
import pytest
from email.message import EmailMessage
import uuid

from app.contracts.common import utcnow
from app.contracts.historical import MatchType, MatchStrength
from app.contracts.evidence import EvidenceType, EvidenceCategory
from app.repositories.db import init_db, SessionLocal
from app.repositories.historical_repository import HistoricalRepository
from app.services.investigation.historical_lookup import FastHistoricalLookup
from app.services.evidence.models import EmailEvidencePackage, AttachmentEvidence, HeaderEvidence, URLIndicator, ReceivedHopEvidence
from app.services.ingestion.parser import EmailParser
from app.services.evidence import EvidenceNormalizer

def _build_eml(
    subject: str = "Test Email",
    from_addr: str = "sender@example.com",
    body_text: str | None = None,
    received_headers: list[str] | None = None,
) -> bytes:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = "target@example.com"
    msg["Message-ID"] = f"<{uuid.uuid4().hex}@test.com>"
    if received_headers:
        for rh in received_headers:
            msg["Received"] = rh
    msg.set_content(body_text or "http://evil-url.com", subtype="plain")
    return msg.as_bytes()

def test_fast_historical_lookup_exact_hash():
    init_db()
    db = SessionLocal()
    repo = HistoricalRepository(db)
    
    # 1. Setup past case
    past_case_id = "hist_case_123"
    repo.save_case(case_id=past_case_id, status="COMPLETED")
    repo.save_indicator(past_case_id, "ev_old_1", "EXACT_HASH", "evilhash123", utcnow())
    
    raw_eml = _build_eml()
    parser = EmailParser(storage_dir="/tmp/test_hist")
    parsed = parser.parse(raw_eml)
    package = EvidenceNormalizer().normalize(parsed)
    # Manually append attachment for testing since _build_eml doesn't make attachments easily
    package.attachments.append(AttachmentEvidence(
        indicator_id="ind_att_1",
        attachment_id="att_1",
        filename="evil.exe",
        raw_filename="evil.exe",
        mime_type="application/x-msdownload",
        size_bytes=1024,
        sha256_hash="evilhash123"
    ))
    
    # 3. Perform lookup
    lookup = FastHistoricalLookup(repo)
    evidence = lookup.perform_lookup(package)
    
    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.type == EvidenceType.HISTORICAL
    assert ev.category == EvidenceCategory.HISTORICAL
    
    val = ev.value
    assert val["match_type"] == MatchType.EXACT_HASH.value
    assert val["matched_indicator"] == "evilhash123"
    assert val["previous_case_id"] == past_case_id
    
    db.close()
    
def test_fast_historical_lookup_exact_ip():
    init_db()
    db = SessionLocal()
    repo = HistoricalRepository(db)
    
    past_case_id = "hist_case_ip"
    repo.save_case(case_id=past_case_id, status="COMPLETED")
    repo.save_indicator(past_case_id, "ev_old_2", "EXACT_IP", "1.2.3.4", utcnow())
    
    raw_eml = _build_eml(received_headers=["from phish.com ([1.2.3.4]) by mx.test.com"])
    parser = EmailParser(storage_dir="/tmp/test_hist")
    parsed = parser.parse(raw_eml)
    package = EvidenceNormalizer().normalize(parsed)
    
    lookup = FastHistoricalLookup(repo)
    evidence = lookup.perform_lookup(package)
    
    # Assert
    assert len(evidence) >= 1
    
    ip_match = [e for e in evidence if e.value["match_type"] == MatchType.EXACT_IP.value]
    assert len(ip_match) == 1
    ev = ip_match[0]
    
    assert ev.value["matched_indicator"] == "1.2.3.4"
    assert ev.value["previous_case_id"] == past_case_id
    
    db.close()

def test_fast_historical_lookup_no_match():
    init_db()
    db = SessionLocal()
    repo = HistoricalRepository(db)
    
    raw_eml = _build_eml()
    parser = EmailParser(storage_dir="/tmp/test_hist")
    parsed = parser.parse(raw_eml)
    package = EvidenceNormalizer().normalize(parsed)
    
    lookup = FastHistoricalLookup(repo)
    evidence = lookup.perform_lookup(package)
    
    assert len(evidence) == 0
    db.close()
