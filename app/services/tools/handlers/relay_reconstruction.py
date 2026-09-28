from app.services.evidence.models import EmailEvidencePackage
from app.services.analysis.header_heuristics import get_header_heuristics, create_heuristic_evidence
from app.services.analysis.relay_reconstruction import reconstruct_relay_path
 
async def handle(request, state, package=None) -> list[dict]:
    evidence_items = get_header_heuristics(package, state.case_id)
    filtered = [e for e in evidence_items if e.key == "suspicious_relay_structure"]
 
    relay_path = reconstruct_relay_path(package.received_hops if package else [])
    if relay_path.origin_ip:
        filtered.append(
            create_heuristic_evidence(
                state.case_id,
                key="relay_origin_ip",
                value=relay_path.origin_ip,
                confidence=0.9,
                related_entity=relay_path.origin_ip,
            )
        )
    for anomaly in relay_path.anomalies:
        filtered.append(
            create_heuristic_evidence(
                state.case_id,
                key="relay_anomaly",
                value=anomaly,
                confidence=0.6,
            )
        )
 
    if not filtered:
        filtered.append(
            create_heuristic_evidence(
                state.case_id,
                key="relay_reconstruction_complete",
                value=True,
                confidence=0.0
            )
        )
    return [e.model_dump(mode="json") for e in filtered]
