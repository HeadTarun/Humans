"""app/services/llm/prompts.py
Prompt templates — re-exports from services/reasoning/prompts.py.
"""
from app.services.reasoning.prompts import build_investigation_prompt
__all__ = ["build_investigation_prompt"]
