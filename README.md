# AShielder — `contracts/` package (PS 26106 greenfield rebuild, step 1)

This is the **first implementation step** from the master prompt's build
order (§34): contracts before anything else. No policy engine, risk
engine, tool registry, FastAPI layer, or frontend exists yet — those come
next, in the order the spec lays out.

## What's here

```
ashielder/
├── contracts/
│   ├── __init__.py        # public surface, import map / dependency order
│   ├── common.py          # BaseContract, Provenance, shared enums/ids
│   ├── evidence.py        # EvidenceItem — the canonical heart (§3)
│   ├── email.py            # ParsedEmail
│   ├── headers.py          # HeaderSet / HeaderFinding (raw vs interpretation, §6)
│   ├── authentication.py   # SPF/DKIM/DMARC
│   ├── relay.py            # Received: hop chain
│   ├── ioc.py               # provider-neutral indicators
│   ├── url.py / html.py / attachment.py
│   ├── ml.py                # Prediction envelope, Header/NLP/URL outputs (§7-10)
│   ├── threat_intel.py     # provider-neutral lookups (§11)
│   ├── historical.py / correlation.py   # cross-case matches (§12)
│   ├── investigation.py    # InvestigationState, AttackHypothesis (§13-14)
│   ├── policy.py            # InvestigationProfile, PolicyDecision (§16-17)
│   ├── tool.py               # ToolDefinition, ToolExecutionResult, ToolPriorityScore (§15,18)
│   ├── risk.py               # RiskAssessment, ConfidenceAssessment, EvidenceConflict (§19-22)
│   ├── groq.py               # GroqInvestigationRequest/Response + evidence validation (§24-25)
│   ├── report.py             # ForensicReport (§29)
│   └── audit.py              # AuditRecord with a real sha256 hash chain (§28)
├── tests/
│   └── test_contracts.py   # schema-validation tests + the §37 first vertical slice
├── pyproject.toml
└── requirements.txt
```

## Design rules encoded structurally (not just by convention)

- **`BaseContract`** (`common.py`): every contract is `extra="forbid"` and
  `frozen=True`. A producer can't smuggle an undeclared field through a
  boundary, and nothing can mutate a contract in place — you construct a
  new instance. This is what "contract-first" means mechanically.
- **`EvidenceItem`** rejects, at construction time, a `type=FACT` evidence
  item whose key looks like a model score (`*_probability`, `*_score`) —
  the exact mistake called out in §3. It also enforces that
  `ML_SIGNAL` / `THREAT_INTEL` / `HISTORICAL` evidence types always carry
  the matching `source_type`.
- **`RiskAssessment`** rejects a `risk_score` that doesn't equal the sum
  of its own `RiskContribution`s (clipped to 0–100) — enforcing "don't
  hide the calculation" from §20.
- **`GroqReasoningResponse`** + `validate_referenced_evidence()` reject
  any response that cites an `evidence_id` not present in the real
  evidence store (§25's "REJECT RESPONSE" rule).
- **`AuditRecord`** computes a real `sha256(hash_prev + canonical_json(fields))`
  chain. Hand-constructing a record with a stale `hash_self` fails
  validation immediately — this is the mechanism behind "audit chain
  detects tampering" (§35 critical test #12). Use `AuditRecord.create(...)`
  rather than the raw constructor so `hash_self` is always computed
  correctly for you.

## What's deliberately NOT here yet

Per §39 / §34's build order — no policy engine implementation, no risk
scoring implementation, no tool registry, no FastAPI routers, no Groq
client, no database models, no frontend. Those are separate steps; this
package is only the typed contracts they'll all be built against.

## Running the tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

The test suite includes the full **§37 first vertical-slice example**
(synthetic phishing email → header FACT evidence → HEURISTIC evidence →
URL ML_SIGNAL → credential_phishing hypothesis → URL reputation tool →
THREAT_INTEL evidence → weighted RiskAssessment → InvestigationState stop
condition → hash-chained AuditRecord), wired entirely through these
contracts with no raw dicts crossing any boundary.

## Suggested next step

Per the build order (§34, steps 2–4): core configuration, then the
evidence *module* (an in-memory or Postgres-backed store that persists
`EvidenceItem`s and enforces `evidence_ids`-only references from
`InvestigationState`), then investigation state management. Say the word
and I'll scaffold that next.
