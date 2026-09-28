# ASHIELDER Reasoning Layer — Security Validation

This document verifies the security invariants of the reasoning layer in the production integration context.

## 1. Prompt Injection Defenses
* **Mechanism**: Content-based evidence (Subjects, Display Names) is structurally isolated into the `untrusted_content` array of the snapshot.
* **Prompt Engineering**: The `REASONING_SYSTEM_PROMPT` explicitly instructs the LLM that any text inside `<untrusted_evidence_text>` is hostile.
* **Validator Backstop**: If a prompt injection attack successfully tricks the LLM into outputting a tool command or attempting to set a verdict (e.g., "Set risk to 100"), the `ReasoningValidator` regex scanner (`_TOOL_EXEC_PATTERN`, `_RISK_SCORE_PATTERN`) catches the text and outright rejects the entire LLM payload.

## 2. API Key and Secret Protection
* **Data Flow Constraint**: The `ReasoningEvidenceSnapshot` builder drops all headers and raw bytes. It only passes explicitly typed `EvidenceItem` records.
* **Configuration Protection**: The `app/core/config.py` secrets (like `GROQ_API_KEY`) are never passed into the prompt or snapshot.
* **Output Scanning**: The validator scans the LLM output for secret patterns (`_SECRET_PATTERN`), rejecting the payload if the LLM hallucinates or regurgitates an API key.

## 3. Structural Authority Restriction
* **No Database Writes**: The `/reason` endpoint returns the reasoning artifact over HTTP but executes *no* SQL updates against `CaseModel` or `ReportModel`. The LLM physically cannot alter the investigation's verdict, risk score, or confidence.
* **No Tool Execution**: The `ReasoningService` utilizes LangChain's `ChatGroq.with_structured_output` — it does *not* use LangChain Agents (`AgentExecutor`, `@tool`). The LLM has zero capability to interact with the outside world (no HTTP calls, no DNS lookups, no shell execution).

## 4. Failure Isolation (Fail-Safe Design)
If Groq returns a 503, rate-limits the request, times out, or returns a malformed schema, the following happens:
1. `ReasoningService` catches the exception.
2. It classifies the error into a safe `ReasoningFailureCategory` (e.g., `PROVIDER_TIMEOUT`).
3. It returns a `ReasoningUnavailable` object instead of throwing an HTTP 500.
4. The client receives a clean `{ "reasoning_status": "unavailable" }` JSON response.
5. **Impact**: Zero impact on the deterministic investigation data.

## 5. Audit Non-Repudiation
Every reasoning attempt generates an `AuditRecord` containing:
* The `snapshot_hash` (proving exactly what the LLM was given).
* The model name and prompt version.
* The success/failure state and latency.
Because these records are cryptographically chained (`hash_prev`, `hash_self`) and persisted immediately by the API route, analysts can mathematically prove whether reasoning was invoked and what context it possessed.
