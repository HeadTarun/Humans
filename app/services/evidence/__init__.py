"""
services/evidence/__init__.py
Exports the public interface for the evidence normalization layer.
"""
from .models import (
    AttachmentEvidence,
    AuthenticationEvidence,
    AuthProtocol,
    AuthResultValue,
    BodyEvidence,
    DomainIndicator,
    EmailEvidencePackage,
    EvidenceMetadata,
    EvidenceRelationship,
    ExtractionMethod,
    ExtractionStatus,
    HeaderEvidence,
    IPIndicator,
    IPVersion,
    ReceivedHopEvidence,
    RecipientEvidence,
    RelationshipType,
    SenderEvidence,
    SingleAuthResult,
    TrustLevel,
    URLIndicator,
)
from .normalizer import EvidenceNormalizer

__all__ = [
    "EvidenceNormalizer",
    "EmailEvidencePackage",
    "EvidenceMetadata",
    "TrustLevel",
    "ExtractionStatus",
    "ExtractionMethod",
    "IPIndicator",
    "IPVersion",
    "DomainIndicator",
    "URLIndicator",
    "ReceivedHopEvidence",
    "AuthenticationEvidence",
    "SingleAuthResult",
    "AuthProtocol",
    "AuthResultValue",
    "SenderEvidence",
    "RecipientEvidence",
    "HeaderEvidence",
    "BodyEvidence",
    "AttachmentEvidence",
    "EvidenceRelationship",
    "RelationshipType",
]
