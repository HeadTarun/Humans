"""
services/tools/handlers/sender_history.py

Sender History Correlation Tool (Level 2).
Queries historical case database for previous encounters with this sender.
"""

from __future__ import annotations

import logging
from typing import Any

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.contracts.historical import HistoricalMatch, MatchType

logger = logging.getLogger(__name__)

async def handle(
    request: ToolExecutionRequest, 
    state: InvestigationState,
    package: Any = None
) -> dict[str, Any]:
    """
    Input: {"email_address": "attacker@example.com"}
    """
    email = request.input.get("email_address")
    if not email:
        raise ValueError("sender_history requires 'email_address' in input")
        
    # In a full implementation, this would query a PostgreSQL database.
    # For Stage 3 MVP, we simulate a lack of history unless specifically mocked.
    
    # Return nothing found (empty dict or UNKNOWN). 
    # For now we just return an empty features dict for the ProviderResult.
    return {
        "provider_name": "HistoricalDB",
        "indicator_value": email,
        "indicator_type": "EMAIL_ADDRESS",
        "features": {
            "historical_cases_found": 0
        }
    }
