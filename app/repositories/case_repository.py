"""CaseRepository — thin CRUD over CaseModel."""
from app.repositories.historical_repository import HistoricalRepository
# CaseRepository delegates to HistoricalRepository which already has full implementation
CaseRepository = HistoricalRepository
