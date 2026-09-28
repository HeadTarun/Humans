"""Level-0 domain intelligence enrichment.

The lookup deliberately returns provider-neutral facts so the normaliser can
preserve the same evidence format through scoring, reporting, and verdicting.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.contracts.investigation import InvestigationState
from app.contracts.tool import ToolExecutionRequest
from app.services.intelligence.domain_intel import RDAPAdapter


async def handle(
    request: ToolExecutionRequest,
    state: InvestigationState,
    package: Any = None,
) -> dict[str, Any]:
    domain = str(request.input.get("domain") or "").strip().lower().rstrip(".")
    if not domain:
        raise ValueError("domain_intelligence requires 'domain' in input")

    result = await RDAPAdapter().lookup_domain(domain)
    if result.get("error"):
        return {"status": "failed", "error": f"domain intelligence failed: {result['error']}"}

    registration_date = result.get("registration_date")
    age_days: int | None = None
    if registration_date:
        if registration_date.tzinfo is None:
            registration_date = registration_date.replace(tzinfo=timezone.utc)
        age_days = max(0, (datetime.now(timezone.utc) - registration_date).days)

    labels = domain.split(".")
    return {
        "provider_name": "RDAP Domain Intelligence",
        "indicator_value": domain,
        "indicator_type": "DOMAIN",
        "features": {
            "domain_age_days": age_days,
            "domain_is_newly_registered": age_days is not None and age_days < 30,
            "domain_has_punycode": "xn--" in domain,
            "domain_label_count": len(labels),
        },
    }
