from app.services.evidence.models import EmailEvidencePackage
from app.services.analysis.header_heuristics import get_header_heuristics, create_heuristic_evidence

async def handle(request, state, package=None) -> list[dict]:
    evidence_items = get_header_heuristics(package, state.case_id)
    filtered = [e for e in evidence_items if e.key in ("spf_failure", "dkim_missing", "dkim_failure", "dmarc_failure")]
    
    updated_filtered = []
    for e in filtered:
        if e.key == "spf_failure":
            updated_filtered.append(e.model_copy(update={"key": "auth_spf_result", "value": str(e.value).lower()}))
        elif e.key == "dkim_failure":
            updated_filtered.append(e.model_copy(update={"key": "auth_dkim_result", "value": str(e.value).lower()}))
        elif e.key == "dmarc_failure":
            updated_filtered.append(e.model_copy(update={"key": "auth_dmarc_result", "value": str(e.value).lower()}))
        else:
            updated_filtered.append(e)
            
    if not updated_filtered:
        updated_filtered.append(
            create_heuristic_evidence(
                state.case_id,
                key="auth_check_complete",
                value=True,
                confidence=0.0
            )
        )
    return [e.model_dump(mode="json") for e in updated_filtered]
