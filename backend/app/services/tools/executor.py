"""
services/tools/executor.py

ToolExecutor provides a central boundary for executing tools.
It handles resolution, caching, rate limiting, and failure semantics.
"""

from __future__ import annotations

import logging
import uuid
import importlib
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

from app.contracts.common import ExecutionId
from app.contracts.investigation import InvestigationState
from app.contracts.tool import (
    ToolDefinition,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from app.services.investigation.tool_registry import get_tool
from .cache import get_tool_cache

logger = logging.getLogger(__name__)

# Type for tool handlers: async def handler(request, state, package=None) -> dict[str, Any]
ToolHandler = Callable[..., Awaitable[dict[str, Any]]]

class ToolExecutor:
    """Central boundary for tool execution."""
    
    def __init__(self):
        self._handlers: dict[str, ToolHandler] = {}
        
    def _resolve_handler(self, handler_ref: str) -> ToolHandler:
        """Resolve a dotted path to a callable."""
        if handler_ref in self._handlers:
            return self._handlers[handler_ref]
            
        # e.g. "investigation.tools.virustotal_lookup" -> "app.services.tools.handlers.virustotal_lookup" -> "handle"
        # For Stage 3 MVP, we'll map the registry keys directly to handlers in app.services.tools.handlers
        module_name = handler_ref.split(".")[-1]
        full_module_path = f"app.services.tools.handlers.{module_name}"
        
        try:
            module = importlib.import_module(full_module_path)
            handler = getattr(module, "handle")
            self._handlers[handler_ref] = handler
            return handler
        except (ImportError, AttributeError) as e:
            logger.error(f"Failed to resolve handler {handler_ref}: {e}")
            raise ValueError(f"Could not resolve handler: {handler_ref}") from e

    async def execute(
        self, 
        request: ToolExecutionRequest, 
        state: InvestigationState,
        package: Any = None
    ) -> ToolExecutionResult:
        """Execute a tool with full semantics."""
        started_at = datetime.now(timezone.utc)
        execution_id = str(uuid.uuid4())
        
        try:
            tool_def = get_tool(request.tool_name)
        except KeyError as e:
            return ToolExecutionResult(
                execution_id=execution_id,
                tool_name=request.tool_name,
                status=ToolExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                error=str(e)
            )

        # 1. Resolve Handler
        try:
            handler = self._resolve_handler(tool_def.handler_ref)
        except ValueError as e:
            return ToolExecutionResult(
                execution_id=execution_id,
                tool_name=request.tool_name,
                status=ToolExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                error=str(e)
            )
            
        # 2. Check Cache
        # Cache checking logic goes here (simplified for executor shell)
        # Detailed caching happens in the adapters usually, or we can wrap the inputs.
            
        # 3. Execute
        try:
            # We pass package if needed (local tools like canonicalizer might need it)
            output = await handler(request, state, package=package)
            
            completed_at = datetime.now(timezone.utc)
            latency_ms = (completed_at - started_at).total_seconds() * 1000
            
            return ToolExecutionResult(
                execution_id=execution_id,
                tool_name=request.tool_name,
                status=ToolExecutionStatus.SUCCESS,
                started_at=started_at,
                completed_at=completed_at,
                latency_ms=latency_ms,
                output=output
            )
            
        except Exception as e:
            logger.exception(f"Tool {request.tool_name} failed")
            # In a full implementation, we'd catch specific exceptions for 
            # RATE_LIMITED, TIMEOUT, etc. For now, default to FAILED.
            return ToolExecutionResult(
                execution_id=execution_id,
                tool_name=request.tool_name,
                status=ToolExecutionStatus.FAILED,
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                error=str(e)
            )
