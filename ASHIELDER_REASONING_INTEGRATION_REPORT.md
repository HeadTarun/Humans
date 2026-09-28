# ASHIELDER Reasoning Layer — Integration Report

## 1. Overview
This report details the Phase 5 integration of the Bounded Reasoning Layer (`services/reasoning`) into the main ASHIELDER backend (`api/v1/investigation.py` and `contracts/result.py`), resolving critical integration gaps identified during discovery.

## 2. Structural Integrations Made

### 2.1 InvestigationResult Expansion
The `InvestigationResult` contract (the core API payload returned for all investigations) was extended to support reasoning without violating deterministic authority.
* **Added Field**: `reasoning_artifact: Optional[dict] = None`
* **Boundary Rules Enforced**: The artifact is explicitly marked as "Advisory only" in the Pydantic schema description. It is typed as a simple dictionary to prevent it from mutating authoritative fields (like `risk_score` or `verdict`) during Pydantic validation passes.

### 2.2 Reconstitution of Rich Investigation State
The `/reason` endpoint was completely rewritten to correctly load the rich investigation state from the database.
* **Before**: The endpoint read raw evidence rows but constructed a dummy `InvestigationState` with an empty hypothesis list and default budgets. This caused the reasoning LLM to operate blind to the deterministic engine's conclusions.
* **After**: The endpoint queries the `ReportModel` to retrieve the persisted `InvestigationResult`. It uses this to hydrate the true `attack_hypotheses`, `budget`, `tools_used`, and `tools_failed` into the `InvestigationState` before snapshot construction. The LLM now sees exactly what the deterministic engine concluded.

### 2.3 Idempotency and Cache Fix
* **Before**: The `ReasoningService` was instantiated inside the HTTP request handler (`reasoning_service = ReasoningService()`). This meant its internal `_cache` was immediately garbage-collected after every request, rendering it useless.
* **After**: `ReasoningService` is instantiated as a module-level singleton (`_reasoning_service = ReasoningService()`). The cache now persists across requests. Repeated identical POSTs to `/{id}/reason` result in cache hits rather than duplicate Groq API charges.

### 2.4 Audit Logging Wired
* **Before**: The documentation claimed reasoning attempts, successes, and failures were audited, but the code in `audit_logger.py` was dead.
* **After**: The `/reason` endpoint explicitly instantiates `AuditLogger`, invokes `log_reasoning_attempt`, `log_reasoning_success` (or `log_reasoning_failure`), and manually writes the generated `AuditRecordModel` entries to the PostgreSQL database within a transaction block.

## 3. Discarded Approaches (Architectural Invariants Respected)
* **No `should_use_reasoning` hook in the main pipeline**: The reasoning trigger logic in `report_generator.py` relies on the legacy `GroqAdapter`. We purposefully did *not* auto-trigger reasoning during the standard `/analyze` pipeline. Reasoning remains strictly on-demand (`POST /{id}/reason`) to prevent uncontrolled LLM token spend on every ingested email.
* **No Database Mutation by LLM**: The reasoning endpoint returns the artifact to the client but deliberately does *not* mutate the `CaseModel` or `ReportModel`. The reasoning is a read-only lens over deterministic facts.

## 4. Trigger Policy
The integration follows a **Cost-Controlled Manual Strategy**:
* **Automatic**: Disabled. The main pipeline does not call ChatGroq.
* **Manual**: Enabled via authenticated `POST /api/v1/investigations/{investigation_id}/reason`.
* **Idempotency**: Repeated calls against an unchanged evidence store hit the in-memory cache.
