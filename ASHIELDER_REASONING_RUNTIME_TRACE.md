# ASHIELDER Reasoning Layer — Runtime Trace

This document traces the exact data flow of a reasoning request in the live system.

## The Trace: `POST /api/v1/investigations/{id}/reason`

### 1. Request Initialization
* **Route**: `@router.post("/{investigation_id}/reason")` in `api/v1/investigation.py`
* **Auth**: Validates JWT or API key via `Depends(verify_api_key_or_jwt)`.
* **Config Check**: Aborts immediately if `settings.REASONING_ENABLED == False`.

### 2. State Reconstitution
* **Database Query 1**: Fetches `CaseModel` to verify existence and apply RBAC (user ownership check).
* **Database Query 2**: Fetches all `EvidenceModel` records for the case.
* **Database Query 3**: Fetches `ReportModel` to retrieve the final `InvestigationResult`.
* **Hydration**: Parses raw JSON from `EvidenceModel` into Pydantic `EvidenceItem` objects. Extracts `attack_hypotheses`, `budget`, and tool arrays from the `ReportModel` to build a full-fidelity `InvestigationState`.

### 3. Snapshot Construction
* **Function**: `build_reasoning_snapshot(state, evidence_store)` in `services/reasoning/snapshot_builder.py`
* **Filter 1**: Discards raw email bytes, full HTML, and attachments.
* **Filter 2**: Maps structured evidence to `ReasoningFinding`.
* **Filter 3**: Maps free-form text (Subject, Display Name) to `UntrustedContentItem`.
* **Output**: A frozen, `extra=forbid` `ReasoningEvidenceSnapshot`.

### 4. Audit: Attempt
* **Action**: Invokes `AuditLogger(case_id).log_reasoning_attempt(...)`.
* **Hash**: Computes deterministic hash of the snapshot to prove exactly what the LLM saw.

### 5. LLM Invocation
* **Function**: `_reasoning_service.reason(snapshot)` in `services/reasoning/service.py`
* **Cache Check**: Looks up `case_id:snapshot_hash` in the module-level singleton cache. Returns cached JSON immediately if found.
* **Prompt Assembly**: `build_user_message` converts the snapshot into a formatted string with explicit `<untrusted_evidence_text>` XML tags.
* **Network Call**: `ChatGroq.ainvoke()` via `langchain-groq`, explicitly requesting `method="function_calling"` bounded by the `ReasoningResult` Pydantic schema.

### 6. Validation
* **Function**: `ReasoningValidator.validate(result, snapshot)`
* **Checks**:
  * Ensures `result.case_id` matches `snapshot.case_id`.
  * Verifies every ID in `supporting_evidence_ids` exists in the snapshot.
  * Rejects strings exceeding bounds (e.g., summary > 2000 chars).
  * Runs regex scans to ensure no risk scores, tool commands, or API keys leaked into the explanation text.
* **Failure**: Throws `ReasoningValidationError` if any check fails, immediately converted to a `ReasoningUnavailable` object.

### 7. Audit: Success/Failure & Persistence
* **Action**: Invokes `log_reasoning_success` (or failure).
* **Database Write**: Opens a new transaction and persists the generated `AuditRecordModel` entries.

### 8. Artifact Packaging
* **Output**: The validated `ReasoningResult` is wrapped in a `ValidatedReasoningArtifact` (containing model name and latency).
* **Response**: Returned as a JSON payload to the API client.
