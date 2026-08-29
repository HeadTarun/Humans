from typing import List, Optional
from datetime import datetime
from sqlalchemy import String, Float, DateTime, Text, Boolean, JSON, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .base import Base

class CaseModel(Base):
    __tablename__ = 'cases'
    
    case_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(50))
    verdict: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    
    # Optional pointer to a prior run if this is a reinvestigation
    original_case_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

class EvidenceModel(Base):
    __tablename__ = 'evidence'
    
    evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str] = mapped_column(String(64), index=True)
    evidence_type: Mapped[str] = mapped_column(String(50))
    category: Mapped[str] = mapped_column(String(50))
    key: Mapped[str] = mapped_column(String(255))
    
    # Store full EvidenceItem as JSON
    raw_json: Mapped[dict] = mapped_column(JSON)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class IndicatorModel(Base):
    __tablename__ = 'indicators'
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    indicator_type: Mapped[str] = mapped_column(String(50))
    indicator_value: Mapped[str] = mapped_column(String(1024))
    case_id: Mapped[str] = mapped_column(String(64))
    evidence_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    
    __table_args__ = (
        Index('ix_indicator_type_value', 'indicator_type', 'indicator_value'),
        Index('ix_indicator_case', 'case_id'),
    )

class AuditRecordModel(Base):
    __tablename__ = 'audit_records'
    
    hash_self: Mapped[str] = mapped_column(String(64), primary_key=True)
    hash_prev: Mapped[str] = mapped_column(String(64))
    case_id: Mapped[str] = mapped_column(String(64), index=True)
    step: Mapped[int] = mapped_column(primary_key=False) # Not unique globally
    
    raw_json: Mapped[dict] = mapped_column(JSON)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))

class ReportModel(Base):
    __tablename__ = 'reports'
    
    report_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    case_id: Mapped[str] = mapped_column(String(64), index=True, unique=True)
    raw_json: Mapped[dict] = mapped_column(JSON)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
