# ASHIELDER Reasoning Layer — Implementation Documentation

## Architecture Overview

The ASHIELDER Reasoning Layer is a **bounded, advisory intelligence component** that sits
**beside** the existing deterministic email investigation pipeline. It uses LangChain +
langchain-groq + ChatGroq with structured output to produce validated explanations and
hypothesis analysis.

### Authority Boundaries (Non-Negotiable)

| Authority | Owner | Reasoning Layer |
|-----------|-------|-----------------|
| Risk Score | Deterministic RiskEngine | ❌ Cannot set |
| Confidence | Deterministic RiskEngine | ❌ Cannot set |
| Verdict | Deterministic RiskEngine | ❌ Cannot set |
| Tool Execution | Adaptive Investigation Engine | ❌ Cannot execute |
| State Mutation | InvestigationState | ❌ Cannot modify |
| Evidence Creation | Evidence Normalizer | ❌ Cannot create |
| Database Writes | Repository Layer | ❌ Cannot write |
| Budget Modification | Budget Manager | ❌ Cannot modify |

### Data Flow

```
InvestigationState + Evidence Store
        │
        ▼
  Snapshot Builder (allowlist)
        │
        ▼
  ReasoningEvidenceSnapshot (sanitized)
        │
        ▼
  LangChain + ChatGroq (single call, no tools, no memory)
        │
        ▼
  ReasoningResult (structured output)
        │
        ▼
  Deterministic Validator (independent)
        │
        ▼
  ValidatedReasoningArtifact (with provenance)
```

## Snapshot Schema (ReasoningEvidenceSnapshot)

**Security Principle**: Built as an **allowlist** — only explicitly permitted typed fields
are included. NOT "all data except dangerous fields."

### Allowed Fields
- `case_id`, `investigation_id`, `investigation_level`
- `current_risk`, `current_confidence` (read-only context)
- `key_findings` — typed `ReasoningFinding` objects (max 100)
- `current_hypotheses` — typed `ReasoningHypothesis` objects (max 15)
- `missing_evidence`, `completed_tools`, `failed_tools`
- `budget_status` — coarse enum (AVAILABLE/LOW/EXHAUSTED), not exact numbers
- `supporting_evidence`, `contradictory_evidence` — evidence ID lists
- `historical_context` — bounded summary string (max 500 chars)
- `untrusted_content` — email-derived text in explicit `UntrustedContentItem` wrappers

### Structurally Excluded
- Raw .eml bytes
- Raw HTML blocks
- Raw email headers
- Attachment contents
- Credentials / API keys
- Internal infrastructure secrets

## Result Schema (ReasoningResult)

### Present Fields
- `schema_version` (Literal "1.0")
- `case_id`, `investigation_id`
- `summary` (max 2000 chars)
- `hypotheses` (max 10)
- `supporting_evidence_ids`, `contradicting_evidence_ids` (max 50 each)
- `uncertainty` (Literal "low" | "medium" | "high")
- `recommended_next_actions` (max 5, advisory only)
- `explanation` (max 5000 chars)
- `escalation_required` (bool)

### Deliberately Absent (Structural Defense)
- risk score
- confidence score
- verdict
- budget fields
- tool execution commands
- database mutation commands

## Validation

The `ReasoningValidator` runs independently after every LLM call:

1. Schema revalidation
2. case_id / investigation_id match verification
3. Evidence ID ground-truth check (reject hallucinated IDs)
4. Output size validation
5. Free-text forbidden content scanning:
   - Risk score patterns
   - Confidence score patterns
   - Verdict assertions
   - Secret/API key patterns
   - Tool execution instructions
   - System prompt extraction attempts

**On ANY failure**: entire result rejected → `ReasoningUnavailable` returned.
Never partially trusted.

## Groq Integration

- **Framework**: LangChain + langchain-groq
- **Class**: `ChatGroq` with `with_structured_output(ReasoningResult, method="function_calling")`
- **Stateless**: No LangChain memory, no LangGraph, no agent loops
- **Single call**: Exactly ONE LLM invocation per trigger
- **Zero tools**: No `Tool` objects, no `AgentExecutor`, no `create_agent`
- **Model**: Configurable via `GROQ_REASONING_MODEL` (default: `llama-3.3-70b-versatile`)

## Trigger Policy

Reasoning is invoked when ANY of:
- Analyst explicitly requests via "Ask Assistant" (`POST /api/v1/investigations/{id}/reason`)
- Verdict is INCONCLUSIVE with ML signals present
- Confidence below `REASONING_CONFIDENCE_THRESHOLD`
- Contradictory evidence exists
- Multiple competing hypotheses
- Historical correlation matches
- Investigation at L2/L3 with missing evidence

AND:
- `REASONING_ENABLED=true`
- `REASONING_AUTO_TRIGGER_ENABLED=true` (for automatic triggers)
- LLM token budget not exhausted

Maximum: ONE reasoning call per trigger event.

## Failure Handling

| Failure | Behavior |
|---------|----------|
| Timeout | `ReasoningUnavailable(PROVIDER_TIMEOUT)` |
| HTTP 429 | `ReasoningUnavailable(RATE_LIMITED)` |
| Network error | `ReasoningUnavailable(PROVIDER_UNAVAILABLE)` |
| Malformed output | `ReasoningUnavailable(SCHEMA_VALIDATION_FAILED)` |
| Hallucinated evidence | `ReasoningUnavailable(VALIDATION_FAILED)` |
| Forbidden content in output | `ReasoningUnavailable(VALIDATION_FAILED)` |

**Critical**: Reasoning failure NEVER breaks deterministic investigation.
Deterministic verdict is always returned regardless.

## API

### `POST /api/v1/investigations/{investigation_id}/reason`

- **Auth**: X-API-Key or Bearer JWT
- **RBAC**: Owner or admin only
- **Snapshot**: Constructed server-side from persisted evidence
- **Client cannot**: submit snapshot, set risk/verdict/confidence, submit system prompt

### Response (Success)
```json
{
    "investigation_id": "...",
    "reasoning_status": "available",
    "reasoning_result": { /* ReasoningResult */ },
    "artifact": {
        "source_type": "reasoning_model",
        "model": "llama-3.3-70b-versatile",
        "prompt_version": "1.0",
        "snapshot_hash": "...",
        "timestamp": "...",
        "validation_status": "validated"
    }
}
```

### Response (Unavailable)
```json
{
    "investigation_id": "...",
    "reasoning_status": "unavailable",
    "reason": "LLM call failed: TimeoutError",
    "category": "PROVIDER_TIMEOUT",
    "correlation_id": "..."
}
```

## Audit

Every reasoning attempt creates audit records using existing `GROQ_CALLED` / `GROQ_REJECTED` event types:
- `log_reasoning_attempt`: snapshot_hash, model, prompt_version
- `log_reasoning_success`: validation_status, latency_ms
- `log_reasoning_failure`: failure_category, reason

Never logged: raw snapshot, raw email, secrets, unvalidated model output.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GROQ_API_KEY` | `""` | Groq API key (from env, never committed) |
| `GROQ_REASONING_MODEL` | `llama-3.3-70b-versatile` | Model for reasoning calls |
| `GROQ_REASONING_TIMEOUT_SECONDS` | `30` | Request timeout |
| `GROQ_REASONING_MAX_TOKENS` | `2048` | Max output tokens |
| `REASONING_ENABLED` | `true` | Master switch for reasoning layer |
| `REASONING_AUTO_TRIGGER_ENABLED` | `true` | Enable automatic triggers |
| `REASONING_CONFIDENCE_THRESHOLD` | `0.6` | Trigger when confidence below this |
| `REASONING_PROMPT_VERSION` | `1.0` | System prompt version |

## Known Limitations (MVP)

- **No direct tool execution** — recommended actions are advisory text only
- **No LangGraph** — single stateless call, no multi-step reasoning
- **No LLM memory** — each call is independent
- **No autonomous agent loop** — one call per trigger event
- **No cross-case reasoning** — cache is scoped to case_id
- **No vector database** — not needed for MVP

## Future Design Proposals

- **Design B**: Structured tool suggestion — model proposes tool names from a fixed allowlist,
  deterministic engine evaluates and optionally executes
- **Design D**: Multi-turn reasoning with LangGraph — bounded conversation with
  explicit turn limits and deterministic checkpoints
