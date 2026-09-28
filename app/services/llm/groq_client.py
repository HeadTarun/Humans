"""app/services/llm/groq_client.py
Groq LLM client — delegates to the ReasoningService which handles
all Groq API calls with proper validation, timeout, and fallback.
"""
from app.services.reasoning.service import ReasoningService
__all__ = ["ReasoningService"]
