"""EvidenceRepository — thin CRUD over EvidenceModel."""
from app.repositories.historical_repository import HistoricalRepository
# EvidenceRepository delegates to HistoricalRepository which already has full implementation
EvidenceRepository = HistoricalRepository
