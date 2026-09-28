"""app/services/llm/agent.py
LLM investigation agent — delegates to the ReasoningService.
The ReasoningService encapsulates all LLM safety, validation,
and fallback logic.
"""
from app.services.reasoning.service import ReasoningService as LLMAgent
__all__ = ["LLMAgent"]
