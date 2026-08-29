from datetime import datetime, timezone
import pytest
from app.repositories.db import init_db, SessionLocal
from app.repositories.historical_repository import HistoricalRepository
from app.contracts.common import utcnow

def test_historical_repository_save_and_lookup():
    init_db()
    db = SessionLocal()
    repo = HistoricalRepository(db)
    
    # 1. Save cases
    case1_id = "case_001"
    case2_id = "case_002"
    repo.save_case(case_id=case1_id, status="COMPLETED")
    repo.save_case(case_id=case2_id, status="COMPLETED")
    
    c1 = repo.get_case(case1_id)
    assert c1 is not None
    assert c1.status == "COMPLETED"
    
    # 2. Save indicators
    repo.save_indicator(
        case_id=case1_id,
        evidence_id="ev_1",
        indicator_type="EXACT_HASH",
        indicator_value="deadbeef",
        timestamp=utcnow()
    )
    
    # duplicate save should not crash
    repo.save_indicator(
        case_id=case1_id,
        evidence_id="ev_1",
        indicator_type="EXACT_HASH",
        indicator_value="deadbeef",
        timestamp=utcnow()
    )
    
    # 3. Lookup indicators
    # Looking up deadbeef from case2 should find case1's indicator
    matches = repo.find_historical_indicators("EXACT_HASH", "deadbeef", case2_id)
    assert len(matches) == 1
    assert matches[0].case_id == case1_id
    
    # Looking up deadbeef from case1 should return nothing (excludes itself)
    matches_self = repo.find_historical_indicators("EXACT_HASH", "deadbeef", case1_id)
    assert len(matches_self) == 0
    
    db.close()
