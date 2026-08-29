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
from .historical import HistoricalMatch, MatchType, MatchStrength, HistoricalCorrelationResult
from .correlation import CorrelationLink, CorrelationType
from .investigation import (
    AttackHypothesis,
    AttackHypothesisType,
    EscalationStatus,
    HypothesisStatus,
    InvestigationBudget,
    InvestigationLevel,
    InvestigationState,
    InvestigationStatus,
    StateMachineStatus,
    StopReason,
    ToolCostSpent,
)
from .result import InvestigationResult, RESOURCE_STOP_REASONS
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
    ReasoningInput,
    ReasoningOutput,
)
from .report import ForensicReport, InvestigationReport
from .audit import AuditEventType, AuditRecord, GENESIS_HASH, compute_record_hash
from .url_canonical import URLCanonical, URLCanonicalSet
from .provider_result import ProviderResult
from .domain_intel import DomainIntelResult
from .reinvestigation import ReinvestigationRequest, ReinvestigationResult

__all__ = [
    "BaseContract", "CaseId", "ConflictId", "ContractError", "CorrelationId",
    "EvidenceId", "ExecutionId", "HypothesisId", "Provenance", "Recommendation",
    "SourceType", "utcnow",
    "EvidenceCategory", "EvidenceItem", "EvidenceStatus", "EvidenceType", "TrustLevel",
    "HeaderFinding", "HeaderSet", "ReceivedHop",
    "AuthenticationEvidence", "AuthResult",
    "RelayHop", "RelayPath",
    "IOC", "IOCType",
    "URLRecord", "URLStructuralFeatures",
    "HTMLAnalysisResult", "HTMLFinding", "HTMLFindingType",
    "AttachmentRef",
    "ParsedEmail",
    "HeaderFeatures", "HeaderPrediction", "ModelTask", "NLPAnalysisResult",
    "NLPLabel", "Prediction", "URLPrediction",
    "CacheStatus", "ThreatIntelProvider", "ThreatIntelResult", "ThreatIntelVerdict",
    "HistoricalMatch", "MatchType", "MatchStrength", "HistoricalCorrelationResult",
    "CorrelationLink", "CorrelationType",
    "AttackHypothesis", "AttackHypothesisType", "EscalationStatus",
    "HypothesisStatus", "InvestigationBudget", "InvestigationLevel",
    "InvestigationState", "InvestigationStatus", "StateMachineStatus",
    "StopReason", "ToolCostSpent",
    "InvestigationResult", "RESOURCE_STOP_REASONS",
    "InvestigationProfile", "PolicyAction", "PolicyDecision", "RankedTool", "ToolEligibility",
    "ToolDefinition", "ToolExecutionRequest", "ToolExecutionResult",
    "ToolExecutionStatus", "ToolPriorityScore",
    "ConfidenceAssessment", "ConflictSeverity", "ConflictStatus", "ConflictType",
    "EvidenceConflict", "RiskAssessment", "RiskContribution", "Verdict",
    "GroqInvestigationRequest", "GroqReasoningResponse", "RequestedAction",
    "validate_referenced_evidence", "ReasoningInput", "ReasoningOutput",
    "ForensicReport", "InvestigationReport",
    "AuditEventType", "AuditRecord", "GENESIS_HASH", "compute_record_hash",
    "URLCanonical", "URLCanonicalSet", "ProviderResult", "DomainIntelResult",
    "ReinvestigationRequest", "ReinvestigationResult",
]
