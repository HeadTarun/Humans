"""Level-0 IP threat-intelligence enrichment using AbuseIPDB."""

from __future__ import annotations

from typing import Any

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.tools.handlers.abuseipdb_lookup import handle as abuseipdb_handle


async def handle(
    request: ToolExecutionRequest,
    state: InvestigationState,
    package: Any = None,
) -> dict[str, Any]:
    return await abuseipdb_handle(request, state, package=package)
