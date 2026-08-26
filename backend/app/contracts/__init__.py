"""
AShielder / PS 26106 — contracts package.

Every module boundary in the system crosses through one of these
contracts. No raw dicts across boundaries (see the top-level spec,
§2 and §39).

Import order below mirrors the dependency graph (common -> evidence ->
domain-specific -> investigation -> policy/tool -> risk -> groq ->
report -> audit), so this file also doubles as a quick map of the
contract inventory.
"""

from .common import (
    BaseContract,
    CaseId,
    ConflictId,
    ContractError,
    CorrelationId,
    EvidenceId,
    ExecutionId,
    HypothesisId,
    Provenance,
    Recommendation,
    SourceType,
    utcnow,
)
from .evidence import (
    EvidenceCategory,
    EvidenceItem,
    EvidenceStatus,
    EvidenceType,
    TrustLevel,
)
from .headers import HeaderFinding, HeaderSet, ReceivedHop
from .authentication import AuthenticationEvidence, AuthResult
from .relay import RelayHop, RelayPath
from .ioc import IOC, IOCType
from .url import URLRecord, URLStructuralFeatures
from .html import HTMLAnalysisResult, HTMLFinding, HTMLFindingType
from .attachment import AttachmentRef
from .email import ParsedEmail
from .ml import (
    HeaderFeatures,
    HeaderPrediction,
    ModelTask,
    NLPAnalysisResult,
    NLPLabel,
    Prediction,
    URLPrediction,
)
from .threat_intel import (
    CacheStatus,
    ThreatIntelProvider,
    ThreatIntelResult,
    ThreatIntelVerdict,
)
from .historical import HistoricalMatch, MatchType
from .correlation import CorrelationLink, CorrelationType
from .investigation import (
    AttackHypothesis,
    AttackHypothesisType,
    EscalationStatus,
    HypothesisStatus,
    InvestigationLevel,
    InvestigationState,
    StopReason,
)
from .policy import (
    InvestigationProfile,
    PolicyAction,
    PolicyDecision,
    RankedTool,
    ToolEligibility,
)
from .tool import (
    ToolDefinition,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolPriorityScore,
)
from .risk import (
    ConfidenceAssessment,
    ConflictSeverity,
    ConflictStatus,
    ConflictType,
    EvidenceConflict,
    RiskAssessment,
    RiskContribution,
    Verdict,
)
from .groq import (
    GroqInvestigationRequest,
    GroqReasoningResponse,
    RequestedAction,
    validate_referenced_evidence,
)
from .report import ForensicReport
from .audit import AuditEventType, AuditRecord, GENESIS_HASH, compute_record_hash

__all__ = [
    # common
    "BaseContract", "CaseId", "ConflictId", "ContractError", "CorrelationId",
    "EvidenceId", "ExecutionId", "HypothesisId", "Provenance", "Recommendation",
    "SourceType", "utcnow",
    # evidence
    "EvidenceCategory", "EvidenceItem", "EvidenceStatus", "EvidenceType", "TrustLevel",
    # headers / auth / relay / ioc
    "HeaderFinding", "HeaderSet", "ReceivedHop",
    "AuthenticationEvidence", "AuthResult",
    "RelayHop", "RelayPath",
    "IOC", "IOCType",
    # url / html / attachment / email
    "URLRecord", "URLStructuralFeatures",
    "HTMLAnalysisResult", "HTMLFinding", "HTMLFindingType",
    "AttachmentRef",
    "ParsedEmail",
    # ml
    "HeaderFeatures", "HeaderPrediction", "ModelTask", "NLPAnalysisResult",
    "NLPLabel", "Prediction", "URLPrediction",
    # threat intel / historical / correlation
    "CacheStatus", "ThreatIntelProvider", "ThreatIntelResult", "ThreatIntelVerdict",
    "HistoricalMatch", "MatchType",
    "CorrelationLink", "CorrelationType",
    # investigation
    "AttackHypothesis", "AttackHypothesisType", "EscalationStatus",
    "HypothesisStatus", "InvestigationLevel", "InvestigationState", "StopReason",
    # policy / tool
    "InvestigationProfile", "PolicyAction", "PolicyDecision", "RankedTool", "ToolEligibility",
    "ToolDefinition", "ToolExecutionRequest", "ToolExecutionResult",
    "ToolExecutionStatus", "ToolPriorityScore",
    # risk
    "ConfidenceAssessment", "ConflictSeverity", "ConflictStatus", "ConflictType",
    "EvidenceConflict", "RiskAssessment", "RiskContribution", "Verdict",
    # groq
    "GroqInvestigationRequest", "GroqReasoningResponse", "RequestedAction",
    "validate_referenced_evidence",
    # report / audit
    "ForensicReport",
    "AuditEventType", "AuditRecord", "GENESIS_HASH", "compute_record_hash",
]
