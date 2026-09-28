# ASHIELDER Reasoning Layer — API Report

## Endpoint Summary

### `POST /api/v1/investigations/{investigation_id}/reason`

**Purpose**: On-demand reasoning analysis for an existing investigation.

**Auth**: Dual-auth (X-API-Key header or Bearer JWT token).

**RBAC**: JWT users can only access their own cases unless they have admin role.

---

## Request

### Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `investigation_id` | `string` | Yes | The case ID to analyze |

### Headers

| Header | Type | Required | Description |
|--------|------|----------|-------------|
| `X-API-Key` | `string` | One of | Service API key |
| `Authorization` | `string` | One of | `Bearer <JWT token>` |

### Body

**None** — the server constructs the evidence snapshot from persisted data.
Clients cannot submit arbitrary snapshot data, system prompts, or influence
risk/confidence/verdict.

---

## Response: Reasoning Available (HTTP 200)

```json
{
    "investigation_id": "case_abc123",
    "reasoning_status": "available",
    "reasoning_result": {
        "schema_version": "1.0",
        "case_id": "case_abc123",
        "investigation_id": "case_abc123",
        "summary": "Analysis of the investigated email reveals...",
        "hypotheses": [
            "CREDENTIAL_PHISHING",
            "SPOOFING"
        ],
        "supporting_evidence_ids": ["EV-001", "EV-005"],
        "contradicting_evidence_ids": ["EV-003"],
        "uncertainty": "medium",
        "recommended_next_actions": [
            "Review DMARC configuration for sending domain",
            "Check URL reputation with additional providers"
        ],
        "explanation": "The email exhibits multiple indicators...",
        "escalation_required": false
    },
    "artifact": {
        "source_type": "reasoning_model",
        "model": "llama-3.3-70b-versatile",
        "prompt_version": "1.0",
        "snapshot_hash": "a1b2c3d4e5f6...",
        "timestamp": "2024-01-15T10:30:00Z",
        "validation_status": "validated"
    }
}
```

## Response: Reasoning Unavailable (HTTP 200)

```json
{
    "investigation_id": "case_abc123",
    "reasoning_status": "unavailable",
    "reason": "LLM call failed: TimeoutError",
    "category": "PROVIDER_TIMEOUT",
    "correlation_id": "uuid-correlation-id"
}
```

### Unavailable Categories

| Category | Description |
|----------|-------------|
| `REASONING_DISABLED` | `REASONING_ENABLED=false` in config |
| `PROVIDER_TIMEOUT` | Groq API timed out |
| `PROVIDER_UNAVAILABLE` | Groq API unreachable or API key missing |
| `RATE_LIMITED` | HTTP 429 from Groq |
| `SCHEMA_VALIDATION_FAILED` | LLM output didn't match expected schema |
| `VALIDATION_FAILED` | Validator rejected output (hallucinated IDs, forbidden content) |
| `INTERNAL_ERROR` | Unexpected internal error |

## Error Responses

| Status | Description |
|--------|-------------|
| 401 | Authentication required |
| 404 | Investigation not found (or RBAC denied) |
| 429 | Rate limit exceeded (API-level) |

---

## Security Guarantees

1. **Snapshot constructed server-side** — client cannot submit arbitrary evidence
2. **No prompt injection** — client cannot modify system prompt
3. **No authority override** — client cannot set risk, confidence, or verdict
4. **RBAC enforced** — JWT users limited to their own cases
5. **Validated output** — reasoning result passes deterministic validation
6. **Provenance tracked** — artifact includes model, prompt version, snapshot hash

---

## Integration Notes

- The endpoint does NOT modify the investigation state
- The endpoint does NOT change risk, confidence, or verdict
- The endpoint does NOT execute tools
- The endpoint does NOT write to the database
- Reasoning output is returned to the caller for display purposes only
- The deterministic investigation result remains the authority
