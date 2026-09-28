"""Level-0 URL reputation via the configured threat-intelligence adapter."""

from __future__ import annotations

from typing import Any

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.tools.handlers.virustotal_lookup import handle as virustotal_handle


async def handle(
    request: ToolExecutionRequest,
    state: InvestigationState,
    package: Any = None,
) -> dict[str, Any]:
    # Keep URL reputation as its own policy-visible capability while using the
    # provider-neutral VirusTotal adapter currently configured by the project.
    return await virustotal_handle(request, state, package=package)
