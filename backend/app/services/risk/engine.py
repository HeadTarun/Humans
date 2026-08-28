"""
services/risk/engine.py

RiskEngine — the deterministic risk assessment component.

RESPONSIBILITY:
    "Given all evidence collected so far, what is the current risk and
    how confident are we?"

DOES NOT:
    - Call LLMs or Groq
    - Call external APIs
    - Modify evidence
    - Invoke tools
    - Make investigation-flow decisions (that is the policy's job)

DOES:
    - Consume EvidenceItem objects and InvestigationState
    - Apply the deterministic weight table (scoring.py)
    - Calculate confidence (confidence.py)
    - Assign a verdict (verdict.py)
    - Return RiskAssessment + ConfidenceAssessment

ARCHITECTURE POSITION:
    EmailEvidencePackage
        ↓
    InvestigationState (via case_manager)
        ↓
    RiskEngine.assess()    ← HERE
        ↓
    RiskAssessment + ConfidenceAssessment + Verdict
        ↓
    InvestigationResult (via result_factory)

Later (Stage 3+), after tool execution produces new evidence:
    New EvidenceItems
        ↓
    RiskEngine.assess()   ← RE-RUNS with expanded evidence
        ↓
    Updated RiskAssessment
        ↓
    Policy decides: continue / stop / escalate
"""

from __future__ import annotations

from dataclasses import dataclass

from app.contracts.evidence import EvidenceItem
from app.contracts.investigation import InvestigationState, StopReason
from app.contracts.risk import (
    ConfidenceAssessment,
    RiskAssessment,
    Verdict,
)
from app.contracts.common import Recommendation
from app.services.risk.confidence import calculate_confidence
from app.services.risk.scoring import score_evidence_items
from app.services.risk.verdict import assign_verdict_with_stop_guard

# Engine version — bump when scoring logic or thresholds change
_ENGINE_VERSION = "1.0.0-stage2"


@dataclass(frozen=True)
class RiskEngineResult:
    """
    Output of RiskEngine.assess().

    Contains both the risk assessment and confidence assessment as
    separate auditable objects, plus the final verdict for convenience.
    """
    risk_assessment: RiskAssessment
    confidence_assessment: ConfidenceAssessment
    verdict: Verdict


class RiskEngine:
    """
    Deterministic Risk Assessment Engine.

    Usage
    -----
    engine = RiskEngine()
    result = engine.assess(
        state=investigation_state,
        evidence_items=l0_facts,
        stop_reason=stop_decision.stop_reason if stop_decision else None,
    )
    # result.risk_assessment.risk_score  → float [0, 100]
    # result.confidence_assessment.confidence_score → float [0, 1]
    # result.verdict                     → Verdict enum
    """

    def assess(
        self,
        state: InvestigationState,
        evidence_items: list[EvidenceItem],
        stop_reason: StopReason | None = None,
        tools_failed_count: int = 0,
    ) -> RiskEngineResult:
        """
        Produce a deterministic risk assessment from the current evidence.

        Parameters
        ----------
        state : InvestigationState
            Current investigation state (used for budget, conflicts, etc.)
        evidence_items : list[EvidenceItem]
            All EvidenceItem objects collected so far.
            In Stage 2 (L0 only), these are the L0 facts from case_manager.
            In Stage 3+, this expands to include tool-produced evidence.
        stop_reason : Optional[StopReason]
            If provided, used to enforce the resource-stop security invariant
            (budget exhaustion cannot produce BENIGN).
        tools_failed_count : int
            Number of tool executions that failed/timed out (Stage 3+).

        Returns
        -------
        RiskEngineResult
            risk_assessment, confidence_assessment, verdict.
        """
        case_id = state.case_id

        # ----------------------------------------------------------------
        # 1. Score evidence items against the weight table
        # ----------------------------------------------------------------
        risk_score, contributions = score_evidence_items(
            evidence_items=evidence_items,
            case_id=case_id,
        )

        # ----------------------------------------------------------------
        # 2. Compute confidence
        # ----------------------------------------------------------------
        confidence_result = calculate_confidence(
            evidence_items=evidence_items,
            pending_conflicts=state.pending_conflicts,
            tools_failed_count=tools_failed_count,
            case_id=case_id,
        )
        confidence = confidence_result.confidence_score

        # ----------------------------------------------------------------
        # 3. Assign verdict (with resource-stop guard)
        # ----------------------------------------------------------------
        verdict = assign_verdict_with_stop_guard(
            risk_score=risk_score,
            confidence=confidence,
            stop_reason=stop_reason,
        )

        # ----------------------------------------------------------------
        # 4. Build unresolved questions list (deterministic)
        # ----------------------------------------------------------------
        unresolved_questions = self._build_unresolved_questions(
            state=state,
            confidence=confidence,
            stop_reason=stop_reason,
        )

        # ----------------------------------------------------------------
        # 5. Determine recommended action from verdict
        # ----------------------------------------------------------------
        recommended_action = self._verdict_to_recommendation(verdict)

        # ----------------------------------------------------------------
        # 6. Build and return RiskAssessment
        # ----------------------------------------------------------------
        risk_assessment = RiskAssessment(
            case_id=case_id,
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            verdict=verdict,
            contributing_evidence_ids=[item.evidence_id for item in evidence_items],
            contributions=contributions,
            reasons=[c.reason_code for c in contributions if c.weight > 0],
            unresolved_questions=unresolved_questions,
            recommended_action=recommended_action,
            engine_version=_ENGINE_VERSION,
        )

        return RiskEngineResult(
            risk_assessment=risk_assessment,
            confidence_assessment=confidence_result,
            verdict=verdict,
        )

    @staticmethod
    def _build_unresolved_questions(
        state: InvestigationState,
        confidence: float,
        stop_reason: StopReason | None,
    ) -> list[str]:
        """
        Build a deterministic list of open questions the investigation
        could not resolve before stopping.
        """
        questions: list[str] = []

        if stop_reason is not None:
            questions.append(
                f"Investigation stopped ({stop_reason.value}) before all "
                f"evidence could be collected."
            )

        if state.missing_evidence:
            questions.extend([
                f"Missing evidence: {ev}" for ev in state.missing_evidence
            ])

        if state.pending_conflicts:
            questions.append(
                f"{len(state.pending_conflicts)} unresolved evidence conflict(s) "
                f"remain: {', '.join(state.pending_conflicts)}"
            )

        if confidence < 0.35:
            questions.append(
                f"Confidence ({confidence:.2f}) is below the minimum threshold "
                f"for a definitive verdict (0.35). Further investigation required."
            )

        if not state.threat_intelligence:
            questions.append(
                "URL/domain/IP reputation was not checked "
                "(external API budget not yet available in Stage 2)."
            )

        if not state.historical_matches:
            questions.append(
                "Historical campaign correlation was not performed "
                "(Stage 3+ feature)."
            )

        return questions

    @staticmethod
    def _verdict_to_recommendation(verdict: Verdict) -> Recommendation:
        """Map Verdict to the closest Recommendation enum value."""
        mapping = {
            Verdict.MALICIOUS:    Recommendation.QUARANTINE,
            Verdict.SUSPICIOUS:   Recommendation.ESCALATE_TO_ANALYST,
            Verdict.BENIGN:       Recommendation.NO_ACTION,
            Verdict.INCONCLUSIVE: Recommendation.REQUEST_MORE_EVIDENCE,
        }
        return mapping[verdict]
