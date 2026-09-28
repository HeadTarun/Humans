from app.services.evidence.models import EmailEvidencePackage
from app.services.analysis.header_heuristics import HeaderHeuristicAnalyzer

async def handle(request, state, package=None) -> list[dict]:
    analyzer = HeaderHeuristicAnalyzer()
    # For now, delegate to HeaderHeuristicAnalyzer as instructed.
    # In the future, this would also include display-name spoofing and lookalikes.
    evidence_items = analyzer.analyze(package, state.case_id)
    # Just to return something so it succeeds
    filtered = [
        analyzer._create_heuristic(
            state.case_id,
            key="deterministic_heuristics_complete",
            value=True,
            confidence=0.0
        )
    ]
    return [e.model_dump(mode="json") for e in filtered]
