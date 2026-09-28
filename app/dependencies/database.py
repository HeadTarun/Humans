"""app/dependencies/database.py — FastAPI dependency injection for database sessions."""
from fastapi import Depends
from sqlalchemy.orm import Session
from app.repositories.db import SessionLocal

def get_db():
    """Yield a sync database session. Use as FastAPI dependency."""
    with SessionLocal() as db:
        yield db

__all__ = ["get_db"]
