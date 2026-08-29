import pytest
from app.services.tools.handlers.historical_correlation import handle
from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.ingestion.parser import EmailParser
from app.services.evidence import EvidenceNormalizer
from app.repositories.historical_repository import HistoricalRepository
from app.repositories.db import SessionLocal, init_db
from app.contracts.common import utcnow
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

@pytest.mark.asyncio
async def test_deep_historical_correlation():
    init_db()
    db = SessionLocal()
    repo = HistoricalRepository(db)
    
    # 1. Setup past cases
    repo.save_case("past1", "COMPLETED")
    repo.save_indicator("past1", "ev1", "EXACT_URL", "http://evil.com", utcnow())
    repo.save_indicator("past1", "ev2", "EXACT_DOMAIN", "evil.com", utcnow())
    
    repo.save_case("past2", "COMPLETED")
    repo.save_indicator("past2", "ev3", "EXACT_URL", "http://evil.com", utcnow())
    
    repo.save_case("past3", "COMPLETED")
    repo.save_indicator("past3", "ev4", "EXACT_URL", "http://evil.com", utcnow())
    
    raw_eml = _build_eml(body_text="Click here", from_addr="test@evil.com")
    parser = EmailParser(storage_dir="/tmp/test_hist")
    parsed = parser.parse(raw_eml)
    pkg = EvidenceNormalizer().normalize(parsed)
    pkg = pkg.model_copy(update={"package_id": "curr_case", "case_id": "curr_case"})
    from app.services.evidence.models import URLIndicator, EvidenceMetadata
    from app.contracts.evidence import TrustLevel
    pkg.urls.append(URLIndicator(
        indicator_id="u1",
        raw_url="http://evil.com",
        scheme="http",
        extracted_from="body",
        extraction_confidence=1.0,
        meta=EvidenceMetadata(
            source_module="test",
            raw_value="http://evil.com",
            extraction_method="regex",
            trust_level=TrustLevel.VERIFIED,
            confidence=1.0
        )
    ))
    
    from app.services.investigation.budget import DEFAULT_BUDGET, make_full_budget_remaining
    state = InvestigationState(
        case_id="curr_case",
        budget=DEFAULT_BUDGET,
        budget_remaining=make_full_budget_remaining(DEFAULT_BUDGET)
    )
    
    req = ToolExecutionRequest(
        case_id="curr_case",
        tool_name="historical_correlation",
        input={},
        reason="test",
        policy_version="1.0"
    )
    
    result_items = await handle(req, state, package=pkg)
    
    # We should have deep correlation (past1 matches 2 indicators)
    # And campaign (http://evil.com matched in 3 cases)
    assert len(result_items) > 0
    
    has_deep = False
    has_campaign = False
    
    for item in result_items:
        if item["key"] == "deep_historical_correlation":
            has_deep = True
            assert item["related_entity"] == "past1"
        if item["key"] == "campaign_detected":
            has_campaign = True
            assert item["related_entity"] == "http://evil.com"
            
    assert has_deep
    assert has_campaign
    
    db.close()
