import pytest
from app.services.investigation.reinvestigation import start_reinvestigation
from app.services.ingestion.parser import EmailParser
from app.services.evidence import EvidenceNormalizer
import uuid
from email.message import EmailMessage

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

from app.repositories.db import init_db

def test_reinvestigation_creates_new_case_id():
    init_db()
    raw_eml = _build_eml()
    parser = EmailParser(storage_dir="/tmp/test_hist")
    parsed = parser.parse(raw_eml)
    pkg = EvidenceNormalizer().normalize(parsed)
    pkg = EvidenceNormalizer().normalize(parsed)
    pkg = pkg.model_copy(update={"package_id": "orig_case_1", "case_id": "orig_case_1"})
    
    result, final_state = start_reinvestigation(
        original_case_id="orig_case_1",
        reason="Analyst wants re-check",
        requested_by="analyst1",
        original_package=pkg
    )
    
    assert result.original_case_id == "orig_case_1"
    assert result.new_case_id != "orig_case_1"
    assert result.new_case_id.startswith("reinv_")
    assert final_state.original_case_id == "orig_case_1"
    assert len(final_state.observed_facts) > 0
