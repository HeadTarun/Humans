from app.services.evidence.models import EmailEvidencePackage
from app.services.analysis.header_heuristics import get_header_heuristics, create_heuristic_evidence

async def handle(request, state, package=None) -> list[dict]:
    evidence_items = get_header_heuristics(package, state.case_id)
    filtered = [e for e in evidence_items if e.key in ("from_replyto_mismatch", "message_id_domain_mismatch")]
    
    updated_filtered = []
    for e in filtered:
        if e.key == "from_replyto_mismatch":
            updated_filtered.append(e.model_copy(update={"key": "reply_to_domain_mismatch"}))
        else:
            updated_filtered.append(e)
    
    if not updated_filtered:
        updated_filtered.append(
            create_heuristic_evidence(
                state.case_id,
                key="header_parse_complete",
                value=True,
                confidence=0.0
            )
        )
    return [e.model_dump(mode="json") for e in updated_filtered]
