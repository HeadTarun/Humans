# ASHIELDER STAGE 3 — TOOL RESEARCH & IMPLEMENTATION SPECIFICATION

**Problem Statement:** SIH 2026 — PS 26106 — AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform
**Document type:** Research + Architecture + Tool Contract Design (NO implementation)
**Stage:** 3 — Tool Execution + Adaptive Investigation (research & design phase)
**Backend:** Python 3.12 / FastAPI / Pydantic v2
**Author context:** ASHIELDER backend team
**Date:** 2026-08-27
**Registry baseline:** `TOOL_REGISTRY_VERSION = "1.0.0"` (16 tools)

---

## ⚠️ VERIFICATION STATUS BANNER — READ FIRST

This specification separates two classes of fact and treats them very differently, because the task's anti-fabrication rule is a hard constraint.

**Class 1 — High-confidence facts (drive tool-selection decisions).** Protocol behavior (RDAP RFCs, DNS), licensing *models*, data-distribution *models* (DB-lookup vs server-side fetch), and architectural properties (SSRF surface, local vs external). These are stable and are stated directly. They are what actually decide which tool we pick.

**Class 2 — Volatile facts (MUST be benchmarked/confirmed before coding).** Exact rate limits, exact prices, exact free-tier quotas, and verbatim Terms-of-Service clauses. **Live web egress was unavailable during the authoring of this document**, so every Class-2 fact below is explicitly tagged:

> `⚠️ UNVERIFIED — MUST CONFIRM (<canonical source URL>)`

**Rule for the implementer:** No Class-2 number in this document may be hard-coded into a rate limiter, budget, or billing assumption until it has been confirmed against the cited canonical source and captured in a benchmark. Treat every `⚠️ UNVERIFIED` tag as a required pre-implementation task. Where a decision depends on a Class-2 fact, the decision is written to be *robust to the fact being worse than expected* (e.g. we treat all external providers as low-quota and cache-first regardless of the published number).

**Nothing in this document authorizes writing tool code.** This is research + contract design only.

---

## HARD CONSTRAINTS HONORED BY THIS DOCUMENT

- **No tools are implemented.** Everything here is research and design.
- **The parser is not modified.** `app/services/ingestion/parser.py` stays as-is.
- **The Evidence Package architecture is not modified.** `app/services/evidence/{models,normalizer}.py` stays as-is.
- **Investigation Policy is not rewritten.** `app/services/investigation/policy.py` and the FSM keep their contracts; Stage 2+ ranking hooks are referenced, not redefined.
- **Groq is not integrated.** `groq_reasoning` stays `enabled=False` (Stage 5).
- **No popularity-driven choices.** Every tool is justified by investigative value per (latency + cost + complexity + security risk).
- **Existing contracts are reused.** `ToolDefinition`, `ToolExecutionResult`, `ThreatIntelResult`, `ThreatIntelProvider`, `EvidenceItem` are NOT duplicated. Extensions are additive and backward-compatible, and are proposed as design only.
- **GEO vs REPUTATION vs INFRASTRUCTURE evidence stays separate.** No single "IP score".
- **No live malware detonation in the MVP.**

---

## TABLE OF CONTENTS

1. Executive Summary
2. Tool Research Principles
3. Local vs External Decision
4. URL Tools
5. Domain Tools
6. IP Tools
7. Threat Intelligence
8. Attachment Tools
9. Historical Correlation Tools
10. Feed-Based Intelligence
11. Tool Security
12. Tool Privacy
13. Tool Latency
14. Tool Reliability
15. Tool Cost
16. Cache Strategy
17. Rate-Limit Strategy
18. Batch Strategy
19. Tool Contracts
20. Evidence Conversion
21. Attack Profile Mapping
22. Final MVP Tool Registry
23. Deferred Tools
24. Rejected Tools
25. Tool Execution Architecture
26. Testing Strategy
27. Provider Adapter Architecture
28. ToolPriority Compatibility
29. Implementation Roadmap
30. Final Recommendation

**Closing (mandatory):**
- THE TOOLS WE SHOULD ACTUALLY IMPLEMENT
- WHAT WE SHOULD NOT IMPLEMENT
- STAGE 3 IMPLEMENTATION ORDER

---

## 1. Executive Summary

ASHIELDER's Stage 1 already does more forensic work locally than most teams realize, and that fact dominates every Stage 3 tool decision. The parser computes SHA-256 over the raw message and every attachment, extracts and canonicalizes URLs, extracts and validates IPs, extracts domains, parses SPF/DKIM/DMARC from `Authentication-Results`, and reconstructs the `Received:` relay chain. The evidence normalizer turns all of that into a typed `EmailEvidencePackage` (`IPIndicator`, `DomainIndicator`, `URLIndicator`, `ReceivedHopEvidence`, `AuthenticationEvidence`, `AttachmentEvidence`). **The single most important conclusion of this research is therefore a negative one: the majority of "email forensic tools" a naive design would add are already implemented locally and must not be rebuilt as tools.** Stage 3 tooling exists to add three things the local package cannot produce on its own — (a) *ML judgments* over already-extracted features, (b) *external ground truth* about indicators (is this URL/IP/hash known-bad, where is this IP, who registered this domain), and (c) *historical correlation* against our own prior cases.

The recommended MVP toolset is deliberately small. It is built on a spine of **local, deterministic or ML tools that never leave the process**, plus a **tight set of two-to-four free external intelligence sources** chosen for licensing sanity and a lookup model that does not create a Server-Side Request Forgery (SSRF) surface. Concretely, the external MVP is: **URLhaus** (abuse.ch) as the free URL/host threat backbone, **AbuseIPDB** for IP abuse reputation, **RDAP** for domain registration age and registrar, and **MaxMind GeoLite2** (local database, zero transmission) for IP geolocation, with **Team Cymru** / GeoLite2-ASN for ASN/infrastructure classification and a cached **Tor exit list** for anonymizer detection. This is a "prefer 2–4 strong intelligence sources, not 12 APIs" posture by design.

A structural correction is required to the existing registry. Two of its Level-2 tools are *conflated capabilities* that violate the project's own invariant that IP GEOLOCATION, IP REPUTATION, and IP INFRASTRUCTURE must remain separate evidence. `ip_intelligence` currently implies one tool producing one "IP score"; this document recommends splitting it (at design level) into `ip_geolocation` (GEO, local), `ip_asn` (INFRA, local), `ip_reputation` (REP, external), and `tor_exit_check` (INFRA/anonymizer, local). Similarly `domain_intelligence` bundles registration data with passive DNS; passive DNS is a paid capability and is deferred, so the domain capability is split into `dns_resolve` (local, live DNS) and `rdap_domain` (registration), with `rdap_domain` as the canonical registration tool. These are *design recommendations*; no code changes are made here.

Every external fact that would normally be hard-coded — rate limits, quotas, prices, TOS clauses — is flagged UNVERIFIED because live verification was not possible in this session. The design is intentionally robust to those numbers being worse than hoped: all external tools are treated as low-quota, cache-first, single-lookup-per-unique-indicator, and non-blocking (a failed or throttled external tool degrades to `UNKNOWN`, never to `CLEAN`). The output of Stage 3 is a set of `ToolExecutionResult`s whose payloads normalize into `EvidenceItem`s and feed the deterministic Risk Engine — the LLM is never in the verdict path, and Groq stays disabled until Stage 5.

The remainder of this document works through research principles, a per-category tool survey (URL, domain, IP, threat intel, attachment, historical, feeds), the cross-cutting concerns (security, privacy, latency, reliability, cost, caching, rate-limiting, batching), the contract design (reusing existing Pydantic models, extensions additive-only), how each tool's output becomes evidence, the mapping from the 13 attack profiles to tools, and finally the concrete MVP registry, the deferred and rejected lists, the execution architecture, testing strategy, adapter architecture, `ToolPriority` compatibility, and a phased roadmap. It closes with the three mandated subsections naming exactly what to build, what not to build, and in what order to write the code.

---

## 2. Tool Research Principles

The selection method is an explicit objective function, not a popularity contest. For every candidate tool we ask: **what investigative value does it add per unit of latency, monetary cost, engineering complexity, and security/privacy risk?** A tool earns a place in the MVP only when that ratio is high *and* the value is not already produced locally. This mirrors the project's own `ToolPriority(t) = EIG(t) × Reliability(t) / Cost(t)` model, where `Cost` is a weighted blend of latency, API cost, and resource use — a tool that is slow, paid, and risky must deliver correspondingly large expected information gain to survive.

Seven principles govern the research.

**Principle 1 — Local beats external, always, when the signal is equivalent.** A capability that can run in-process over the already-parsed `EmailEvidencePackage` has zero network latency, zero API cost, no rate limit, no third-party data-sharing, and no external dependency to fail. External tools are admitted only when they provide *ground truth we cannot compute ourselves* (reputation, geolocation, registration facts, corpus membership).

**Principle 2 — Do not rebuild what Stage 1 already produces.** SHA-256 hashing, URL canonicalization, IP/domain extraction, SPF/DKIM/DMARC parsing, and relay reconstruction are done. A "tool" that merely re-derives these is pure cost with zero marginal information gain and is rejected on sight.

**Principle 3 — Separate the three IP questions and the two domain questions.** "Where is this IP" (GEO), "is this IP abusive" (REP), and "what network/operator is this IP" (INFRA) are independent facts with independent sources, reliabilities, and failure modes; collapsing them destroys forensic nuance and violates a project invariant. Likewise "what does this domain resolve to right now" (live DNS) and "who registered it and when" (RDAP) are separate.

**Principle 4 — A DB-lookup provider is strictly safer than a fetch-the-URL provider.** Any external service where *we* hand over an indicator string and it answers from its own database (URLhaus, AbuseIPDB, RDAP) introduces no SSRF risk. Any service that *fetches the attacker's URL on our behalf* (urlscan, sandboxes) is powerful but must be treated as a controlled, non-MVP capability with privacy and leakage implications.

**Principle 5 — Free-with-sane-licensing beats powerful-with-hostile-licensing.** For an SIH prototype that may become a product, a provider whose free tier forbids commercial use, or whose data cannot be redistributed, is a liability. Licensing model is a first-class selection criterion, not an afterthought.

**Principle 6 — Fail toward UNKNOWN, never toward CLEAN.** Every tool must have a defined failure behavior, and that behavior must never let a timeout, throttle, or error be interpreted as "this indicator is safe." This is enforced downstream by the Risk Engine invariant (resource-stop ≠ BENIGN), but tool design must respect it too.

**Principle 7 — Verify or flag; never fabricate.** Any quantitative external claim we cannot confirm from a canonical source in this session is tagged UNVERIFIED with that source URL. The design must remain correct even if the real number is worse.

These principles are applied uniformly in Sections 4–10 and are the reason the recommended set is small.

---

## 3. Local vs External Decision

The first architectural cut is deciding, per capability, whether it belongs *inside the process* or *across the network*. We classify every tool into six types (this is the classification the rest of the document uses):

| Type | Meaning | Network? | Cost | Rate limit | Example capabilities |
|------|---------|----------|------|-----------|----------------------|
| **A** | Local deterministic | No | ~0 | None | header/auth parse, relay reconstruction, deterministic heuristics, HTML structural analysis, static attachment inspection |
| **B** | Local ML inference | No | CPU/GPU | None | URL classifier, header ML, NLP/BEC model |
| **C** | Local DB / cache lookup | No (local DB) | Disk/RAM | None | GeoLite2 city, GeoLite2 ASN, Tor exit membership, our historical IOC store, cached provider answers |
| **D** | External single-indicator lookup | Yes (DB-lookup) | API quota | Yes | URLhaus, AbuseIPDB, RDAP, DNS resolution |
| **E** | External feed / bulk download | Yes (periodic) | Bandwidth | Soft | URLhaus bulk feeds, Tor bulk exit list, MaxMind DB updates |
| **F** | Expensive / deep / server-side-fetch | Yes | High + risk | Strict | urlscan.io, VirusTotal, live sandbox detonation |

The decision rule follows Principle 1: **push every capability to the lowest-cost type that still answers the question.** Concretely:

**Stays LOCAL (Type A/B/C) — the bulk of the toolset.** Everything derived from message structure and content is local: SPF/DKIM/DMARC evaluation, header anomaly detection, relay-chain trust analysis, deterministic phishing heuristics, HTML/link structural analysis, and static attachment inspection (type/extension/macro-presence over bytes we already have). All ML judgments are local Type-B inference over features from the evidence package — they need no network. Three intelligence capabilities are local *because the data ships as a file*: IP geolocation and ASN via MaxMind GeoLite2 databases, and Tor exit-node membership via a periodically downloaded list (Type C, refreshed by a Type-E job). Our own historical IOC correlation is a local database query.

**Goes EXTERNAL (Type D) — only for ground truth we cannot hold locally.** Three questions genuinely require calling out: "is this URL/host in a curated malware/phishing corpus" (URLhaus), "has this IP been reported for abuse and how confidently" (AbuseIPDB), and "who registered this domain and when" (RDAP). Live DNS resolution (`dns_resolve`) is also external in the sense that it queries the network, but via the local resolver library (dnspython), not a third-party API — it has no API quota, only DNS-server etiquette.

**Deferred to Type F — powerful but not MVP.** Server-side URL detonation (urlscan.io) and multi-engine file/URL verdicts (VirusTotal) are deferred: they add real value but carry SSRF/leakage, licensing, and quota constraints that a single-email MVP does not need to take on yet.

The practical consequence: **the MVP is local-first with a thin external edge.** Roughly two-thirds of the recommended tools never touch the network, which keeps median investigation latency and cost low and makes the system degrade gracefully when the external edge is throttled or offline. The external calls are individually cheap, individually cached, and individually optional to the verdict.

A note on the environment already reflecting this: `.env` carries `GROQ_API_KEY`, `VIRUSTOTAL_API_KEY`, and `ABUSEIPDB_API_KEY`, but **no MaxMind license key yet** — provisioning a MaxMind GeoLite2 account/license key is a prerequisite for the local geolocation capability and is called out in the roadmap.

---

## 4. URL Tools

**The investigative questions.** For each unique URL/host extracted from the email we want to know: (a) is it structurally suspicious (obfuscation, punycode, credential-in-URL, mismatched anchor text) — *local*; (b) does an ML model think it is phishing/malicious — *local*; (c) is it present in a curated malware/phishing corpus — *external ground truth*; (d) what does a live render/scan reveal — *external, server-side fetch, deferred*.

**(a) and (b) are already local.** URL parsing/canonicalization is done by the normalizer (`URLIndicator`: scheme/hostname/path/domain). Structural heuristics (`html_analysis`, `deterministic_heuristics`) and the ML classifier (`url_ml`) run in-process. No external tool is needed for these, and adding one would violate Principle 2.

**(c) External corpus membership — the decision.** The recommended free backbone is **URLhaus by abuse.ch**.

- **Why URLhaus wins.** Its dataset is distributed under **CC0** (public-domain dedication), which means we can query, cache, and even redistribute normalized results without a licensing landmine — decisive under Principle 5. Critically, it is a **pure database-lookup** service: we submit a URL/host string and it answers from its corpus. **It does not fetch the attacker URL on our behalf**, so it adds **no SSRF surface** (Principle 4). It offers both a per-indicator lookup API and **bulk feeds** (full dump, recent, and an "online" URLs feed), which lets us pre-load a local cache and answer many lookups with zero live calls (Type C over a Type-E feed).
- **Verify before coding.**
  - `⚠️ UNVERIFIED — MUST CONFIRM` — URLhaus now requires an **Auth-Key** for API/feed access, obtained via an abuse.ch account (auth.abuse.ch). Confirm current auth requirement and header name. (https://urlhaus.abuse.ch/api/)
  - `⚠️ UNVERIFIED — MUST CONFIRM` — exact per-endpoint rate limits and feed refresh cadence. (https://urlhaus.abuse.ch/api/)
  - `⚠️ UNVERIFIED — MUST CONFIRM` — CC0 status of the *data* vs any separate terms on the *API/feeds*. (https://urlhaus.abuse.ch/api/)
- **Verdict:** **MVP — the URL/host threat backbone.** Prefer the bulk feed loaded into a local cache; use the live lookup for cache misses only.

**PhishTank — rejected.** URL-only, redundant with URLhaus for our purposes, and — `⚠️ UNVERIFIED — MUST CONFIRM` — new API-key registration has been widely reported as **closed/unavailable** for an extended period (https://phishtank.org/). Depending on a provider we may not be able to register against is an unacceptable reliability risk (Principle 6). **Rejected** for MVP.

**Google Safe Browsing v4 / Web Risk — deferred.** Broad, high-quality URL threat data, but `⚠️ UNVERIFIED — MUST CONFIRM` the Safe Browsing v4 free tier's terms lean **non-commercial / anti-abuse-only**, and the commercial-friendly path (**Web Risk**) requires a **billed Google Cloud project** (https://developers.google.com/safe-browsing and https://cloud.google.com/web-risk/docs). Licensing/billing friction fails Principle 5 for the MVP. **Deferred.**

**(d) Live scan/render — deferred to Section 7/Type F.** urlscan.io is covered under Threat Intelligence because it is a server-side-fetch capability with SSRF/leakage/licensing implications; it is a **stretch** tool, not MVP.

**Recommended URL tooling.** Keep the local `url_ml`, `html_analysis`, and `deterministic_heuristics`. Redefine the external `url_reputation` tool to be backed by **URLhaus** (feed-first, lookup-on-miss, DB-lookup, no SSRF). Do not add PhishTank. Defer Safe Browsing/Web Risk and urlscan.

---

## 5. Domain Tools

**The investigative questions.** For each unique registrable domain: (a) how old is the registration and who is the registrar/registrant — *external, RDAP*; (b) what does it resolve to right now, and does it have plausible mail infrastructure (MX/SPF TXT) — *external via local resolver, DNS*; (c) historical resolution / passive DNS — *paid, deferred*.

**(a) Registration facts — RDAP is the canonical tool.** Domain age is one of the highest-value cheap signals in phishing detection: freshly registered domains are disproportionately malicious. The correct modern source is **RDAP (Registration Data Access Protocol)**, not legacy WHOIS.

- **Why RDAP.** It is an open IETF protocol (**RFC 7480/7481/9082/9083**, bootstrap **RFC 9224**) returning **structured JSON** over HTTPS, with the **IANA bootstrap registry** telling us which RDAP server is authoritative for a given TLD. It is **free**, standards-based, and needs no vendor account — a strong Principle-5 profile. The `events` array yields the **registration date** (→ domain age), and entities yield the **registrar**; this is exactly the ground truth we cannot compute locally.
- **Constraints to respect.**
  - RDAP is **mandatory for gTLDs** (ICANN) but only **voluntarily** offered by many **ccTLDs** — some ccTLDs have no RDAP server, so the tool must handle "no authoritative server" as `UNKNOWN`, not failure.
  - **Registrant PII is typically GDPR-redacted**; do not build logic that depends on registrant name/email being present.
  - RDAP is **per-domain (no batch)** — one lookup per unique domain, cached.
  - `⚠️ UNVERIFIED — MUST CONFIRM` — per-server RDAP rate limits vary by registry/registrar and are largely undocumented; treat as low and cache aggressively. (https://www.rfc-editor.org/rfc/rfc7480, https://data.iana.org/rdap/dns.json)
- **Verdict:** **MVP — canonical domain registration/age tool** (`rdap_domain`).

**(b) Live DNS — split out as a local-resolver tool.** The existing `domain_intelligence` tool conflated registration with resolution and passive DNS. Recommendation: introduce a distinct **`dns_resolve`** tool backed by **dnspython** (already a dependency; **ISC license**). It resolves A/AAAA/MX/TXT records to answer "does this domain have real mail infrastructure," "what IPs does it point to" (which then feed the IP tools), and "is there an SPF record." This is effectively local (uses the system/library resolver, no third-party API, no API quota) — Type D only in that it touches the network.

- **Constraints.** DNS answers are **volatile** (short TTLs) — cache briefly and timestamp. Respect resolver etiquette; set timeouts. Never resolve internal/reserved names in a way that could aid SSRF (see Section 11).
- **Verdict:** **MVP — new local tool `dns_resolve`.**

**(c) Passive DNS — deferred.** Historical resolution (SecurityTrails, Farsight/DNSDB, etc.) is valuable for infrastructure pivoting but is `⚠️ UNVERIFIED — MUST CONFIRM` predominantly **paid / quota-limited** (https://securitytrails.com/corp/api). It fails the cost test for a single-email MVP. **Deferred.**

**Recommended domain tooling.** Redefine `domain_intelligence` away from a passive-DNS bundle: use **`rdap_domain`** (RDAP, registration/age — MVP) and add **`dns_resolve`** (dnspython, live resolution — MVP). Defer passive DNS.

---

## 6. IP Tools

This is where the existing registry most needs correction. `ip_intelligence` implies a single tool emitting one blended "IP score." That both destroys forensic separation and violates the project invariant that **GEO, REPUTATION, and INFRASTRUCTURE are distinct evidence**. Recommendation (design-level split into four tools):

**6.1 `ip_geolocation` — GEO — LOCAL (MaxMind GeoLite2 City).**
- **Question:** where (country/region/city, coarse lat/long) is this IP?
- **Why MaxMind GeoLite2, local.** The GeoLite2 **City** database is a **downloadable file** queried entirely in-process (Type C) — **zero transmission** of our indicators to any third party, zero per-lookup latency, no rate limit. That privacy/latency profile is unbeatable for the origin-IP geolocation the platform is literally named for.
- **Constraints.**
  - `⚠️ UNVERIFIED — MUST CONFIRM` — GeoLite2 is free but requires a **MaxMind account + license key** (policy in effect since ~Dec 2019), and **attribution is required** by license. (https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
  - City-level accuracy is **limited and must not be overstated** in the forensic report — country is reliable, city much less so.
  - GeoLite2 does **not** provide VPN/proxy/Tor detection — do not conflate GEO with anonymizer status.
  - Redistribution of the DB is restricted; ship update tooling, not the DB, in the repo.
- **Blocker:** no MaxMind key in `.env` yet — provisioning is a roadmap prerequisite.
- **Verdict:** **MVP — GEO evidence.**

**6.2 `ip_asn` — INFRASTRUCTURE — LOCAL.**
- **Question:** what ASN / network operator / prefix owns this IP (hosting vs residential vs cloud)?
- **Sources.** MaxMind **GeoLite2-ASN** (local DB, same account) or **Team Cymru** IP-to-ASN (free; DNS/bulk/whois interface returning ASN | prefix | RIR). Team Cymru is the classic, free, high-reliability infra source; GeoLite2-ASN keeps it fully local.
  - `⚠️ UNVERIFIED — MUST CONFIRM` — Team Cymru acceptable-use / attribution for the IP-to-ASN service. (https://team-cymru.com/community-services/ip-asn-mapping/)
- **Verdict:** **MVP — INFRA evidence** (prefer GeoLite2-ASN local; Team Cymru as alternate/enrichment).

**6.3 `ip_reputation` — REPUTATION — EXTERNAL (AbuseIPDB).**
- **Question:** has this IP been reported for abuse, and how confidently?
- **Why AbuseIPDB.** Crowd-sourced abuse database with a clean **DB-lookup** API (submit IP → `abuseConfidenceScore` 0–100 + report metadata). DB-lookup = **no SSRF** (Principle 4). Free tier suits an MVP.
  - `⚠️ UNVERIFIED — MUST CONFIRM` — free-tier daily check quota (commonly cited ~1,000/day) and any commercial-use terms. (https://docs.abuseipdb.com/)
- **Handling.** `abuseConfidenceScore` is a **crowd-sourced confidence**, not proof — normalize to a REP EvidenceItem with its own reliability; never fold into GEO/INFRA.
- **Verdict:** **MVP — REP evidence.** (`ABUSEIPDB_API_KEY` already present in `.env`.)

**6.4 `tor_exit_check` — INFRASTRUCTURE/ANONYMIZER — LOCAL.**
- **Question:** is the origin IP a known Tor exit node?
- **Source.** The **Tor Project bulk exit list** (`check.torproject.org/torbulkexitlist`) downloaded periodically (Type E) and checked as **local set membership** (Type C) — no per-lookup network call.
  - `⚠️ UNVERIFIED — MUST CONFIRM` — exact bulk-list URL/format and refresh etiquette. (https://check.torproject.org/torbulkexitlist)
- **Verdict:** **MVP — INFRA/anonymizer evidence.** (Broader VPN/proxy detection is deferred — it is largely a paid capability.)

**Net IP recommendation.** Retire the single `ip_intelligence` tool (design-level) in favor of four separate tools — `ip_geolocation` (GEO, local), `ip_asn` (INFRA, local), `ip_reputation` (REP, external), `tor_exit_check` (INFRA, local) — each emitting its **own** EvidenceItem. Only one of the four (reputation) is an external API call.

---

## 7. Threat Intelligence

"Threat intelligence" here means external services that return a **verdict about an indicator**. ASHIELDER already has the right contract for this: `ThreatIntelResult` (provider, indicator, indicator_type, verdict ∈ MALICIOUS/SUSPICIOUS/CLEAN/UNKNOWN/ERROR, confidence, timestamp, raw_result_reference, error, cache_status) and the `ThreatIntelProvider` Protocol (`lookup_ip/domain/url/hash`). **We reuse these; we do not create new verdict contracts.** Each provider becomes an adapter implementing the Protocol.

**MVP threat-intel providers (all DB-lookup, no SSRF):**

- **URLhaus** — URL/host indicator → verdict. Free, CC0, feed-first. (See §4.) **MVP.**
- **AbuseIPDB** — IP indicator → abuse confidence → verdict. Free tier. (See §6.3.) **MVP.**

Those two, plus the local/registration tools, cover the indicator types that matter for a single phishing email (URL, host, IP, domain) without taking on a heavyweight provider.

**Stretch / deferred threat-intel providers:**

- **VirusTotal (API v3)** — aggregates many engines for file hashes, URLs, domains, IPs. Genuinely powerful, and `VIRUSTOTAL_API_KEY` is already in `.env`. But it is **stretch/analyst-only**, not MVP, because:
  - `⚠️ UNVERIFIED — MUST CONFIRM` — public/free API limits (commonly cited **4 lookups/min, 500/day, ~15.5k/month**) and **non-commercial-only** terms. (https://docs.virustotal.com/reference/public-vs-premium-api)
  - `⚠️ UNVERIFIED — MUST CONFIRM` — submissions/queries may be **shared with the VT community** — a data-sharing/privacy concern for potentially sensitive indicators. (https://docs.virustotal.com/docs/how-it-works)
  - Best use: **hash reputation lookups** (never uploading the file — hash only) and analyst-triggered enrichment, gated behind explicit action. **Deferred to stretch.**
- **urlscan.io** — submits a URL and **fetches/renders it server-side**, returning screenshots, DOM, resource graph, and contacted domains/IPs. Powerful and it **offloads the fetch away from our backend**, but:
  - It performs a **server-side fetch of the attacker URL** — an SSRF-shaped capability that must be deliberately controlled (Principle 4).
  - `⚠️ UNVERIFIED — MUST CONFIRM` — **public** scans are **permanently searchable**; must use **unlisted/private** visibility to avoid leaking victim-specific URLs; free tier is **non-commercial**; submit-then-poll (async) flow. (https://urlscan.io/docs/api/)
  - **Deferred to stretch**, private-visibility only, analyst-gated.
- **GreyNoise Community** — tells us whether an IP is "internet background noise" (mass scanners) vs targeted; free community endpoint helps *downgrade* noisy IPs.
  - `⚠️ UNVERIFIED — MUST CONFIRM` — community endpoint limits and terms. (https://docs.greynoise.io/) **Deferred to stretch.**

**Rejected as MVP threat-intel platforms.** **MISP** and **OpenCTI** are excellent *threat-intelligence platforms*, but they are **heavyweight systems to host and operate** — massive overkill for a single-email MVP. If we later want aggregated feeds, we **consume** from such a platform, we do not stand one up inside ASHIELDER now. **Rejected for MVP** (revisit as a feed source post-MVP).

**Design rule for all threat-intel tools.** Every provider is an adapter behind `ThreatIntelProvider`; every result normalizes to `ThreatIntelResult` then to an `EvidenceItem` with `type=THREAT_INTEL` and `source_type=THREAT_INTEL_API` (validator-enforced). A provider timeout/throttle/error yields `verdict=UNKNOWN`/`ERROR` — **never** `CLEAN` (Principle 6).

---

## 8. Attachment Tools

**What is already local.** The parser computes **SHA-256 per attachment**, and the normalizer produces `AttachmentEvidence`. So attachment *identity* (hash) and basic metadata already exist — do not rebuild (Principle 2).

**MVP attachment tool — `attachment_static_analysis` (LOCAL, Type A).** Static, in-process inspection over the attachment bytes we already hold: true file-type detection via magic bytes (extension-vs-content mismatch is a strong signal), dangerous-type flags (`.exe`, `.scr`, `.js`, `.hta`, double extensions), archive inspection (nested/again-archived, password-protected zip), and **macro presence** detection in Office documents (e.g. via `oletools`/`olevba`-style parsing — presence and auto-exec indicators, **not** execution). This is deterministic, fast, private, and needs no network. **MVP.**

- Optional dependency to confirm: `⚠️ UNVERIFIED — MUST CONFIRM` — packaging/license of the OLE/macro parsing library to be used (e.g. oletools). (https://github.com/decalage2/oletools)

**Stretch — attachment hash reputation (EXTERNAL, VirusTotal hash lookup).** Send only the **SHA-256** (never the file) to VirusTotal to see if the hash is a known-bad sample. Value is high when it hits, but it is gated by VT's non-commercial terms, quotas, and community-sharing concerns (see §7). **Stretch/analyst-gated**, hash-only.

**Deferred — YARA rules (LOCAL, Type A/B).** YARA signature matching over attachment bytes is a natural local enrichment and stays in-process, but authoring/curating a reliable rule set is real effort and not needed for the MVP's core email-triage value. **Deferred.**

**Rejected for MVP — live sandbox detonation (Type F).** Detonating attachments in a live sandbox (Cuckoo/CAPE/commercial) is explicitly **out of scope for the MVP** per the task and on its own merits: heavy infrastructure, latency in minutes, real operational risk. **Rejected for MVP.**

**Net attachment recommendation.** Keep `attachment_static_analysis` as a **local** tool. Optionally add **hash-only** VirusTotal reputation as a stretch. No YARA, no detonation in MVP.

---

## 9. Historical Correlation Tools

**The question.** Has ASHIELDER seen this indicator (sender, domain, IP, URL, attachment hash, subject pattern) — or a close variant — in a **prior case**? This is where a forensic platform compounds value over time, and it is entirely **local** (Type C, our own database) — no external dependency, no cost, no privacy leak.

**MVP — `historical_correlation` (exact-match, LOCAL).** A deterministic lookup of the current case's IOCs against our persisted store of prior-case IOCs: exact matches on sender address, registrable domain, IP, URL, and attachment SHA-256. Exact match is cheap, unambiguous, and high-signal (a hash or domain we've already convicted). The output is a **CORRELATION/HISTORICAL** EvidenceItem (`type=HISTORICAL` requires `source_type=HISTORICAL_CORRELATION`, validator-enforced). **MVP.**

- This tool is the reason the platform gets smarter with use: every convicted case enriches the store that future triage reads.

**Stretch — fuzzy / campaign correlation (LOCAL).** Near-duplicate detection (normalized subject/body similarity, sender look-alike/typosquat distance, shared infrastructure via ASN/registrar clustering) to link emails into **campaigns**. High analytical value for the `campaign` attack profile but more complex and false-positive-prone; needs the exact-match store in place first. **Stretch.**

**Deferred — graph correlation store.** A full entity-relationship graph (indicators ↔ cases ↔ campaigns) enabling multi-hop pivots is powerful but is a substantial subsystem. **Deferred** until there is enough case volume to justify it.

**Design note.** Historical tools depend on a **persistence layer** (SQLAlchemy/asyncpg are already dependencies). The MVP exact-match store is a modest schema; the fuzzy/graph tiers are where the real schema investment lands, which is exactly why they are staged later.

---

## 10. Feed-Based Intelligence

Feeds are the mechanism that lets us convert would-be **external per-lookup calls (Type D)** into **local database lookups (Type C)**. Instead of asking a provider about every indicator live, we periodically download the provider's corpus and answer locally. This slashes latency to ~zero, removes per-lookup rate-limit pressure, improves privacy (we stop announcing every indicator we're curious about), and keeps working during provider downtime. It is a core efficiency lever for the MVP.

**MVP feeds (Type E jobs feeding Type C lookups):**

- **URLhaus bulk feeds** — the full dump, "recent," and "online" URL/host feeds. Load into a local table; answer `url_reputation` from it, falling back to the live URLhaus lookup only on a cache miss. CC0 licensing makes local storage clean. `⚠️ UNVERIFIED — MUST CONFIRM` feed URLs, formats, and refresh cadence (https://urlhaus.abuse.ch/api/).
- **Tor bulk exit list** — periodic download → local set for `tor_exit_check`. `⚠️ UNVERIFIED — MUST CONFIRM` (https://check.torproject.org/torbulkexitlist).
- **MaxMind GeoLite2 City + ASN** — the geolocation/ASN "feeds" are literally databases updated on MaxMind's schedule; a refresh job keeps them current. `⚠️ UNVERIFIED — MUST CONFIRM` update cadence and license terms (https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).

**Deferred feeds:**

- **AbuseIPDB blacklist feed** — AbuseIPDB offers a bulk blacklist in addition to per-IP checks; adopting it would move IP reputation partly local too. `⚠️ UNVERIFIED — MUST CONFIRM` blacklist availability/limits on the free tier (https://docs.abuseipdb.com/). **Deferred** (start with live lookup + cache; adopt the feed if quota pressure appears).
- **STIX/TAXII feeds and MISP/OpenCTI exports** — standardized threat-intel feed formats. Useful later for ingesting curated community intelligence, but they presuppose a feed source we don't operate and add parsing/infra overhead. **Deferred.**

**Design rule.** A feed-backed tool must record **feed freshness** (when the corpus was last refreshed) so evidence can be timestamped and stale feeds can be flagged. A feed that fails to refresh degrades to "stale, lower confidence," and on a hard miss the tool falls back to the live lookup or returns `UNKNOWN` — never `CLEAN`.

---

## 11. Tool Security

The dominant security concern for this platform is **SSRF (Server-Side Request Forgery)** and, more broadly, *the backend being tricked into taking attacker-chosen network actions*. The email under analysis is **hostile input**; its URLs, domains, and IPs are attacker-controlled.

**11.1 Never fetch attacker URLs from the backend.** This is the cardinal rule. The MVP deliberately chooses **DB-lookup providers** (URLhaus, AbuseIPDB, RDAP) precisely because *we send a string and they answer* — the backend never dereferences the attacker's URL. The one capability that does fetch attacker URLs (urlscan.io) is **deferred** and, when adopted, is offloaded to a third party (never fetched from our own egress), private-visibility, and analyst-gated.

**11.2 IP/DNS SSRF guardrails.** Before any tool resolves or looks up a host/IP, validate it against a **deny-list of reserved ranges**: RFC1918 private space, loopback (127/8, ::1), link-local (169.254/16, fe80::/10), unique-local (fc00::/7), 0.0.0.0/8, multicast, and cloud metadata addresses (169.254.169.254). This prevents an attacker embedding `http://169.254.169.254/...` or an internal hostname to make our resolver/tooling probe internal infrastructure.

**11.3 DNS-rebinding defense.** When `dns_resolve` returns an IP that a later step would act on, **re-validate the resolved IP** against the reserved-range deny-list at use time (not just the hostname at parse time), because DNS answers can flip between check and use.

**11.4 Secret hygiene.** API keys (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, MaxMind license key, URLhaus Auth-Key) live in environment/secret storage, never in code, logs, or the evidence record. Redact keys from any `raw_result_reference` we persist.

**11.5 Untrusted-response handling.** Provider responses are themselves untrusted input: enforce **response size caps**, **strict timeouts**, and **schema validation** (parse into the provider's Pydantic model; reject extra/malformed fields — our contracts are `extra="forbid"`). Never `eval`/deserialize provider data into executable structures.

**11.6 Attachment safety.** Static analysis only in the MVP — bytes are parsed, never executed. Guard against zip-bombs/decompression bombs with nesting and output-size limits. No detonation.

**11.7 Per-tool security concern (summary).** Local tools (A/B/C): low network risk; main concern is resource exhaustion (bounded by budgets) and parser safety on hostile bytes. External DB-lookup (D): concern is secret handling, response validation, and *indicator leakage* (privacy, §12) — not SSRF. Server-side-fetch (F): SSRF/abuse — **deferred**. Every tool declares a `security_risk` level in its (extended) definition so the policy can factor it into selection.

---

## 12. Tool Privacy

Privacy has two subjects: the **email's subjects** (sender/recipient/victim), whose data we must not leak, and **third-party providers**, to whom every external lookup discloses something.

**12.1 Send indicators, never content.** External tools receive **only the specific indicator** needed — a URL, host, domain, IP, or SHA-256 hash. They must **never** receive raw email bodies, headers, recipient addresses, or attachment *contents*. (Attachment reputation, if enabled, sends the **hash only**.) This single rule eliminates the largest privacy exposure.

**12.2 Every external lookup is a disclosure.** Querying a provider about `evil-login.example` tells that provider we saw that indicator. For most abuse indicators this is fine, but for **victim-specific URLs** (containing tokens, email addresses, internal hostnames) it is not. Mitigations: prefer **feed-backed local lookups** (URLhaus feed) so we disclose nothing per-indicator; for any server-side-fetch tool use **private/unlisted** visibility; and consider suppressing external lookups for URLs that appear to carry personal tokens.

**12.3 Community-sharing providers need extra care.** VirusTotal and public urlscan can make submissions **visible to others**. This is why both are **deferred/analyst-gated** and, when used, are hash-only (VT) or private (urlscan).

**12.4 Data minimization in persistence.** Store normalized results and a `raw_result_reference` (pointer/hash), not necessarily the full raw provider payload, and **redact secrets/PII** from anything persisted. GDPR-redacted RDAP registrant fields are absent by design — do not attempt to re-identify.

**12.5 Per-tool privacy concern.** Local tools: **no external disclosure** (best privacy). RDAP/URLhaus/AbuseIPDB: disclose one indicator to one provider (acceptable; prefer feeds where possible). GeoLite2/Tor-list/historical: **local, no disclosure**. VirusTotal/urlscan: potential community exposure — **deferred**. Each tool declares a `privacy_risk` level in its (extended) definition.

---

## 13. Tool Latency

Latency budgets are already first-class in the architecture (`InvestigationBudget.max_latency_ms`, `ToolDefinition.estimated_latency_ms`). Stage 3 must populate realistic numbers **and measure them**, because latency is a term in the `ToolPriority` cost.

**Latency tiers (design targets — all real numbers `⚠️ UNVERIFIED — MUST BENCHMARK`):**

| Tier | Tools | Expected order of magnitude |
|------|-------|-----------------------------|
| Instant (local, in-memory) | header/auth parse, relay, deterministic heuristics, HTML analysis, static attachment, Tor set-membership, historical exact-match, GeoLite2/ASN DB lookup | sub-millisecond to low-ms |
| Fast (local ML) | url_ml, header_ml, nlp_bec_ml | low tens of ms (model-dependent) |
| Network (external DB-lookup) | dns_resolve, rdap_domain, url_reputation(live miss), ip_reputation | tens to hundreds of ms, tail-heavy |
| Slow (deferred) | urlscan (submit+poll), VT | seconds to minutes |

**Design consequences.**
- Record **p50 and p95**, not just a point estimate — external tails dominate user-perceived latency. (Recommend adding `p50_latency_ms`/`p95_latency_ms` to the tool definition; see §19.)
- **Feed-first** design collapses most external latency to local: a URLhaus feed hit is "instant," only a cache miss pays the network.
- Run independent external lookups **concurrently** (httpx async) so wall-clock ≈ the slowest call, not the sum (see §25).
- Enforce **per-tool timeouts** strictly; a timeout yields `TIMEOUT` status and `UNKNOWN` evidence, and counts against the budget.

---

## 14. Tool Reliability

The project models reliability as a single `reliability ∈ [0,1]` on both `ToolDefinition` and `ToolPriorityScore`. Research shows this **conflates two different things** that should be tracked separately:

- **Availability** — will the tool return an answer at all (uptime, quota headroom, timeout rate)? A property of the *provider/infrastructure*.
- **Evidence reliability** — when it does answer, how much should we trust the answer for verdict purposes? A property of the *data quality* (e.g. AbuseIPDB's crowd-sourced confidence is inherently softer than an RDAP registration date).

**Recommendation (design-level):** split into `availability_score` and `evidence_reliability` on the extended `ToolDefinition` (backward-compatible; keep `reliability` as a derived/legacy field). This lets the policy distinguish "flaky but authoritative" (RDAP behind a rate limit) from "always-up but soft" (crowd-sourced reputation).

**Reliability posture per class.**
- Local A/B/C: **highest availability** (no network); evidence reliability varies (deterministic facts high; ML signals medium, and never typed as FACT).
- External DB-lookup D: availability gated by provider uptime + our quota; must have **retry-with-backoff** (bounded) and a **failure policy** that degrades to `UNKNOWN`.
- Feed-backed: availability decoupled from live provider (great), but add **staleness** as a reliability modifier.

**Reliability rules.** (1) A tool failure **never** yields `CLEAN` (Principle 6, enforced by Risk Engine invariant). (2) Bounded retries only (`max_retries`), then degrade. (3) Circuit-breaking: repeated failures of one provider trip `REPEATED_FAILURES_EXCEEDED` and stop calling it for the case, rather than burning the whole latency budget.

---

## 15. Tool Cost

Cost is already modeled as a composite: `Cost = w_latency·norm_latency + w_api·norm_api_cost + w_resource·norm_resource_cost`, with `estimated_api_cost` per call on the tool definition. The Stage 3 research findings for cost:

- **Local tools (A/B/C): API cost = 0.** Their only cost is latency + CPU/RAM/disk. They should dominate the MVP precisely because they are nearly free on the cost axis.
- **MVP external tools are monetarily free but quota-bounded.** URLhaus, AbuseIPDB (free tier), RDAP, GeoLite2 (free DB), Tor list — **$0 per call** but subject to **rate/quota limits** (`⚠️ UNVERIFIED` per §4–§10). So their real "cost" is quota consumption, modeled as latency + a small resource weight, not dollars.
- **Deferred/stretch tools carry real cost or hostile licensing.** VT free tier is non-commercial and low-quota; Web Risk needs billing; passive DNS is paid. These are the tools whose `estimated_api_cost` and licensing push their `ToolPriority` down for the MVP.

**Cost design rules.** (1) Keep `estimated_api_cost = 0.0` for free tools but **do not treat them as unlimited** — quota is a cost, enforced via `InvestigationBudget.max_external_calls` and rate-limit strategy (§17). (2) Deduplicate before spending: **one lookup per unique indicator** (§18) is the single biggest cost saver. (3) Cache hits cost ~0 (§16). (4) Any tool with nonzero money cost or non-commercial licensing is **opt-in / stretch**, never on the default MVP path.

---

## 16. Cache Strategy

Caching is the highest-leverage efficiency mechanism in Stage 3: it cuts latency, saves quota/cost, improves privacy (fewer disclosures), and improves resilience (answers during provider downtime). Every external lookup MUST be cache-first.

**Cache key.** `(tool_name or provider, indicator_type, normalized_indicator)`. Normalization is essential and already partly done by the evidence normalizer (canonical URL, normalized IP, registrable domain) — cache on the **normalized** form so `HTTP://Evil.COM/` and `http://evil.com` share an entry.

**Per-tool TTLs (design targets — tune after benchmarking):**

| Tool / data | Suggested TTL | Rationale |
|-------------|---------------|-----------|
| `rdap_domain` (registration/age) | days–weeks | Registration facts change slowly |
| `ip_asn` | days | ASN assignments are stable |
| `ip_geolocation` (GeoLite2) | tied to DB version | Local DB; "cache" = DB refresh cadence |
| `url_reputation` (URLhaus) | hours | Malicious status can change; feed refresh drives it |
| `ip_reputation` (AbuseIPDB) | hours | Abuse confidence evolves |
| `dns_resolve` | minutes (respect record TTL) | DNS is volatile |
| `tor_exit_check` | tied to list refresh | Local set membership |
| Historical correlation | no external cache (it *is* the local store) | — |

**Rules.** (1) Cache stores the **normalized result + fetch timestamp + source freshness**, so evidence is timestamped and staleness is visible. (2) A cache hit is reported (`cache_hit=true`, `cache_status`) so audit can distinguish live vs cached evidence. (3) **Negative caching**: cache `UNKNOWN`/`not-found` too, with a shorter TTL, to avoid hammering a provider for an indicator it doesn't know. (4) Cache does not turn stale-unknown into clean — TTL expiry re-queries. The existing `ThreatIntelResult.cache_status` field already anticipates this; reuse it.

---

## 17. Rate-Limit Strategy

Because MVP external providers are free-tier and quota-limited (and the exact numbers are UNVERIFIED), the system must **behave well even if the real limits are low**. Rate-limit handling is defense against both hitting a wall and getting banned.

**Mechanisms.**
- **Per-provider token-bucket / limiter** sized to the *confirmed* published limit (once verified), applied across the whole app, not per-request.
- **Budget coupling.** `InvestigationBudget.max_external_calls` already caps external calls per investigation; the rate limiter caps calls per unit time across investigations. Both apply.
- **Backoff + Retry-After.** On HTTP 429 / quota responses, honor `Retry-After` and apply exponential backoff with jitter; after `max_retries`, degrade to `UNKNOWN`.
- **Feed-first to avoid limits entirely.** The best rate-limit strategy is not to make the call — URLhaus feed, Tor list, and GeoLite2 DB answer locally and consume no live quota.
- **Deduplication + caching** (see §16/§18) reduce call volume before the limiter ever engages.

**Contract gap.** The current `ToolExecutionStatus` enum has **no `RATE_LIMITED`** state — a throttled call can only be recorded as `FAILED`, which loses information the policy needs. **Recommendation (design-level):** add `RATE_LIMITED` to `ToolExecutionStatus` (additive, backward-compatible) so rate-limiting is first-class and distinguishable from genuine failure. A `RATE_LIMITED` outcome degrades evidence to `UNKNOWN` and can trip the external-budget stop reason, not the failure circuit-breaker.

---

## 18. Batch Strategy

Batching and deduplication are how we minimize the number of external calls per investigation.

**18.1 Deduplicate to unique IOCs first.** A single email often contains the same domain/IP/URL many times. The normalizer already canonicalizes; Stage 3 must reduce to the **unique set** per indicator type before any lookup: `raw_url → canonical → hostname → registrable_domain` (via tldextract), and unique IPs, unique hashes. **One lookup per unique indicator per tool** — this alone can cut external calls by an order of magnitude on link-heavy emails.

**18.2 Use native batch APIs where they exist; respect where they don't.**
- **RDAP: no batch** — strictly one domain per request; parallelize with concurrency limits + caching, do not attempt to batch.
- **AbuseIPDB:** offers bulk/blacklist mechanisms in addition to single check — `⚠️ UNVERIFIED — MUST CONFIRM` whether the free tier permits a batch/bulk endpoint (https://docs.abuseipdb.com/). If yes, batch unique IPs; if not, dedupe + cache + concurrency.
- **URLhaus:** feed-based bulk is the "batch" — load the corpus locally and answer all URLs from it; live endpoint is per-indicator.
- **Local tools:** naturally batch in-process (iterate the unique set); no network concern.

**18.3 Contract support for batch.** Add a `supports_batch: bool` flag to the extended `ToolDefinition` so the executor knows whether it may coalesce unique indicators into one call or must fan out. This is additive and design-only.

**18.4 Concurrency, not just batching.** Where a provider has no batch API, issue the per-indicator calls **concurrently** (bounded by the rate limiter and a concurrency cap) so latency stays near the single-call latency. See §25 for the execution model.

---

## 19. Tool Contracts

**Reuse, do not duplicate.** ASHIELDER already has the right contracts. This section proposes **additive, backward-compatible extensions only** — no field is removed or retyped, so existing tools, tests, and the registry keep working. Nothing here is applied yet; it is design.

**What already exists (reused as-is):**
- `ToolDefinition` — name, description, profiles, min_level, tier, input_contract, output_contract, reliability, cost, handler_ref, estimated_latency_ms, external_api, estimated_api_cost, enabled.
- `ToolExecutionRequest` — case_id, tool_name, input, reason, policy_version.
- `ToolExecutionResult` — execution_id, tool_name, status, started_at, completed_at, latency_ms, output, evidence_ids, error.
- `ToolExecutionStatus` — SUCCESS/FAILED/TIMEOUT/REJECTED/SKIPPED.
- `ToolPriorityScore` — tool_name, relevance, eligibility, eig, reliability, cost, cost_breakdown, priority, reason.
- `ThreatIntelResult` + `ThreatIntelProvider` Protocol — the provider-neutral verdict contract and adapter interface.

**Proposed extension 1 — `ToolDefinition` metadata (all optional with defaults ⇒ backward-compatible):**

```python
# DESIGN ONLY — additive fields for app/contracts/tool.py::ToolDefinition
class ToolCategory(str, Enum):
    URL = "URL"; DOMAIN = "DOMAIN"; IP = "IP"; THREAT_INTEL = "THREAT_INTEL"
    ATTACHMENT = "ATTACHMENT"; HISTORICAL = "HISTORICAL"; HEADER = "HEADER"
    AUTH = "AUTH"; CONTENT = "CONTENT"; REASONING = "REASONING"

class ToolType(str, Enum):
    A_LOCAL_DETERMINISTIC = "A"; B_LOCAL_ML = "B"; C_LOCAL_DB = "C"
    D_EXTERNAL_LOOKUP = "D"; E_FEED = "E"; F_EXPENSIVE = "F"

class RiskLevel(str, Enum):
    NONE = "NONE"; LOW = "LOW"; MEDIUM = "MEDIUM"; HIGH = "HIGH"

class FailurePolicy(str, Enum):
    DEGRADE_TO_UNKNOWN = "DEGRADE_TO_UNKNOWN"   # default; never CLEAN
    SKIP = "SKIP"
    FAIL_INVESTIGATION = "FAIL_INVESTIGATION"

# added to ToolDefinition (each Optional / defaulted):
    category: Optional[ToolCategory] = None
    tool_type: Optional[ToolType] = None
    provider: Optional[str] = None                 # "urlhaus","abuseipdb","rdap","maxmind_geolite2",...
    version: str = "1.0.0"
    # split reliability into two auditable axes (keep legacy `reliability`)
    availability_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    evidence_reliability: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    # latency distribution, not a point estimate
    p50_latency_ms: Optional[int] = Field(default=None, ge=0)
    p95_latency_ms: Optional[int] = Field(default=None, ge=0)
    # operational metadata
    rate_limit: Optional[str] = None               # e.g. "1000/day" (VERIFY before enforcing)
    cache_ttl_seconds: Optional[int] = Field(default=None, ge=0)
    supports_batch: bool = False
    security_risk: RiskLevel = RiskLevel.LOW
    privacy_risk: RiskLevel = RiskLevel.LOW
    failure_policy: FailurePolicy = FailurePolicy.DEGRADE_TO_UNKNOWN
    max_retries: int = Field(default=0, ge=0)
    timeout_ms: Optional[int] = Field(default=None, ge=0)
```

**Proposed extension 2 — `ToolExecutionStatus` gains `RATE_LIMITED`** (additive enum member; see §17):

```python
class ToolExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"; FAILED = "FAILED"; TIMEOUT = "TIMEOUT"
    REJECTED = "REJECTED"; SKIPPED = "SKIPPED"
    RATE_LIMITED = "RATE_LIMITED"   # NEW — throttled ≠ failed; degrades to UNKNOWN
```

**Proposed extension 3 — `ToolExecutionResult` observability (optional fields):**

```python
    provider: Optional[str] = None      # which adapter answered
    cache_hit: bool = False             # was this served from cache?
    retry_count: int = Field(default=0, ge=0)
```

**Proposed extension 4 — `ToolExecutionRequest` (optional):**

```python
    execution_id: Optional[ExecutionId] = None   # correlate request→result
    requested_at: Optional[datetime] = None
```

**Non-goals (explicitly not changing).** `handler_ref` stays a **string** registry key (keeps `ToolDefinition` serializable). The FSM, policy, evidence, and result contracts are untouched. `ToolPriorityScore` shape is unchanged (see §28). All new fields are optional/defaulted so `TOOL_REGISTRY_VERSION` can bump to `1.1.0` without breaking existing definitions.

---

## 20. Evidence Conversion

Every tool's job ends the same way: its normalized output becomes one or more `EvidenceItem`s that the deterministic Risk Engine consumes. The conversion is **contract-validated** and must respect the evidence type↔source_type invariants already enforced in `contracts/evidence.py`.

**The pipeline (per tool):**
```
raw provider payload
  → provider adapter (parse into provider Pydantic model, extra="forbid")
  → normalized result (e.g. ThreatIntelResult / GeoResult / RDAPResult)
  → EvidenceItem(type=..., source_type=..., provenance=..., value=...)
  → referenced by ToolExecutionResult.evidence_ids
  → merged into InvestigationState (immutable model_copy)
  → Risk Engine
```

**Type/source mapping (validator-enforced — must be exact):**

| Tool | EvidenceType | required SourceType | Evidence meaning |
|------|--------------|---------------------|------------------|
| spf_dkim_dmarc, header_parse, relay_reconstruction, deterministic_heuristics, html_analysis, attachment_static_analysis, dns_resolve, rdap_domain, ip_geolocation, ip_asn, tor_exit_check | FACT or HEURISTIC | deterministic | Observed/parsed facts; heuristics as HEURISTIC not FACT |
| url_ml, header_ml, nlp_bec_ml | **ML_SIGNAL** | **ml_model** | Model scores — **never** `FACT` (validator blocks it) |
| url_reputation, ip_reputation (+ deferred VT/urlscan) | **THREAT_INTEL** | **threat_intel_api** | External verdict about an indicator |
| historical_correlation | **HISTORICAL** (or CORRELATION) | **historical_correlation** | Match against prior cases |

**Keep GEO / REP / INFRA as separate EvidenceItems.** `ip_geolocation` → a GEO fact (country/city, coarse), `ip_asn` → an INFRA fact (ASN/operator), `ip_reputation` → a THREAT_INTEL signal (abuse confidence), `tor_exit_check` → an INFRA/anonymizer fact. **Four indicators, up to four distinct EvidenceItems for one IP** — never a single blended "IP score." This is the concrete mechanism that satisfies the project invariant.

**Rules.** (1) Provenance always records provider, tool, timestamp, and cache/freshness. (2) A soft/crowd-sourced source (AbuseIPDB) carries lower `evidence_reliability`; the Risk Engine weights accordingly. (3) `UNKNOWN`/`ERROR`/`RATE_LIMITED`/`TIMEOUT` produce **no positive evidence** and specifically **no CLEAN evidence** — absence of a hit is not proof of safety. (4) The Risk Engine — never a tool, never an LLM — produces verdict/risk/confidence.

---

## 21. Attack Profile Mapping

ASHIELDER already has all **13 attack-hypothesis types** wired to tools in `profile_registry.py` (validated at import). This section maps those profiles to the **recommended MVP toolset** (with the IP split and DNS/RDAP separation applied), classifying each tool as **mandatory (M)**, **optional (O)**, or **expensive/deferred (E)** per profile. Local tools carry most profiles; external tools sharpen a few.

| Attack profile | Mandatory (local core) | Optional (external/enrichment) | Deferred |
|----------------|------------------------|-------------------------------|----------|
| credential_phishing | deterministic_heuristics, html_analysis, url_ml, dns_resolve | url_reputation(URLhaus), rdap_domain (age), ip_reputation | urlscan, VT |
| malicious_url | url_ml, html_analysis, deterministic_heuristics | url_reputation(URLhaus), rdap_domain | urlscan |
| malware_delivery / malicious_attachment | attachment_static_analysis, deterministic_heuristics | url_reputation (payload URLs), (hash rep) | VT hash, YARA, sandbox |
| spoofing | spf_dkim_dmarc, header_parse, relay_reconstruction | rdap_domain, ip_geolocation, ip_asn | — |
| bec / executive_impersonation | header_parse, nlp_bec_ml, deterministic_heuristics | rdap_domain (lookalike age), historical_correlation | fuzzy correlation |
| invoice_fraud / payment_diversion / vendor_fraud | nlp_bec_ml, header_parse, deterministic_heuristics | rdap_domain, historical_correlation | fuzzy correlation |
| social_engineering | nlp_bec_ml, deterministic_heuristics, html_analysis | url_reputation | — |
| compromised_account | relay_reconstruction, header_parse, spf_dkim_dmarc | ip_geolocation, ip_asn, ip_reputation, tor_exit_check | — |
| campaign | historical_correlation, deterministic_heuristics | ip_asn, rdap_domain (clustering) | fuzzy/graph correlation |

**Reading the map.** (1) **Every profile is served primarily by local tools** — the external edge is optional enrichment, consistent with local-first design. (2) The IP quartet (`ip_geolocation`/`ip_asn`/`ip_reputation`/`tor_exit_check`) is most load-bearing for `spoofing`, `compromised_account`, and `campaign` — exactly the profiles where *where/what-network/anonymizer* matters. (3) `historical_correlation` is the backbone of `campaign` and a strong optional signal for the fraud/BEC family. (4) Deferred tools never sit on a profile's mandatory path, so the MVP is fully functional without them. This mapping is **compatible with** the existing `profile_registry.py`; applying the IP split would update those profile→tool lists (design-level, not done here).

---

## 22. Final MVP Tool Registry

The recommended MVP registry, relative to the existing 16-tool `TOOL_REGISTRY_VERSION = "1.0.0"`. **Legend:** Type A/B/C = local, D = external DB-lookup, E = feed. Tier M = must-have, S = should-have, and every external tool degrades to `UNKNOWN` on failure.

**MUST-HAVE — local core (Type A/B/C, no network, no cost):**

| Tool | Type | Category | Evidence | Registry status |
|------|------|----------|----------|-----------------|
| spf_dkim_dmarc | A | AUTH | FACT (auth results) | exists |
| header_parse | A | HEADER | FACT (header anomalies) | exists |
| relay_reconstruction | A | HEADER | FACT (relay chain) | exists |
| deterministic_heuristics | A | CONTENT | HEURISTIC | exists |
| html_analysis | A | CONTENT | HEURISTIC (reclassify to Type A) | exists |
| attachment_static_analysis | A | ATTACHMENT | FACT/HEURISTIC | exists |
| url_ml | B | URL | ML_SIGNAL | exists (needs model) |
| nlp_bec_ml | B | CONTENT | ML_SIGNAL | exists (needs model) |
| historical_correlation (exact-match) | C | HISTORICAL | HISTORICAL | exists (scope to exact-match) |
| dns_resolve | D→local resolver | DOMAIN | FACT (live DNS) | **NEW (split from domain_intelligence)** |
| ip_geolocation | C | IP | FACT (GEO) | **NEW (split from ip_intelligence)** |
| ip_asn | C | IP | FACT (INFRA) | **NEW (split from ip_intelligence)** |
| tor_exit_check | C (over E feed) | IP | FACT (INFRA/anonymizer) | **NEW (split from ip_intelligence)** |

**SHOULD-HAVE — external free edge (Type D/E, $0 but quota-bounded):**

| Tool | Type | Provider | Evidence | SSRF | Registry status |
|------|------|----------|----------|------|-----------------|
| rdap_domain | D | RDAP (IANA bootstrap) | FACT (registration/age) | none | exists (make canonical registration tool) |
| url_reputation | D+E | URLhaus (feed-first) | THREAT_INTEL | none | exists (bind to URLhaus) |
| ip_reputation | D | AbuseIPDB free tier | THREAT_INTEL | none | **NEW (split from ip_intelligence)** |

**Header/URL ML variants already in registry:** `header_ml` (B) is retained as optional ML; note it overlaps `header_parse` — keep deterministic parse mandatory, ML as optional enrichment.

**Disabled (as-is):** `groq_reasoning` stays `enabled=False` (Stage 5).

**Registry delta summary (design-level, additive; bump to `TOOL_REGISTRY_VERSION = "1.1.0"`):**
- **Split** `ip_intelligence` → `ip_geolocation` + `ip_asn` + `ip_reputation` + `tor_exit_check`.
- **Split** `domain_intelligence` → `dns_resolve` + keep `rdap_domain` as canonical registration (drop the passive-DNS bundle → deferred).
- **Bind** `url_reputation` to the URLhaus adapter (feed-first).
- **Scope** `historical_correlation` to exact-match for MVP.
- **Reclassify** `html_analysis` as Type A local.
- **Add** the extended metadata fields (§19) to every definition; keep all prior fields.

Net MVP: **~13 must-have (mostly local) + 3 should-have (external free)**, versus adding a sprawl of 12+ APIs. This is the "smallest reliable, highest-value" set the task asks for.

---

## 23. Deferred Tools

Deferred = real future value, but not justified for the MVP now. Each has a concrete re-entry condition.

| Tool / capability | Why deferred | Re-enter when |
|-------------------|--------------|---------------|
| **urlscan.io** (server-side URL render/scan) | SSRF-shaped fetch; public scans leak URLs; free tier non-commercial; async submit-poll | We need deep link forensics AND have private-visibility + analyst-gating + legal review |
| **VirusTotal v3** (multi-engine URL/hash) | Non-commercial free terms; low quota (⚠️ 4/min·500/day); community-sharing | Analyst enrichment path exists; hash-only lookups; quota/licensing confirmed |
| **VirusTotal attachment hash reputation** | Same VT constraints (hash-only mitigates privacy) | Alongside VT enablement |
| **GreyNoise Community** (scanner noise) | Nice-to-have downgrade signal, not core | We want to suppress mass-scanner IP false positives |
| **Passive DNS** (SecurityTrails/DNSDB) | Paid / quota-limited | Budget for paid intel; infra-pivot investigations needed |
| **AbuseIPDB blacklist feed** | Live lookup + cache suffices at MVP volume | Quota pressure appears; want IP rep local |
| **Historical fuzzy / campaign correlation** | Needs exact-match store first; FP-prone | Exact-match store is populated and stable |
| **Historical graph store** | Substantial subsystem | Case volume justifies multi-hop pivots |
| **YARA attachment rules** | Rule curation effort | Malware-family attribution becomes a goal |
| **Google Safe Browsing / Web Risk** | Non-commercial terms / billing | Commercial licensing path chosen |
| **STIX/TAXII feed ingestion** | Presupposes a feed source; parsing/infra overhead | We subscribe to a curated community feed |
| **Groq LLM reasoning** | Explicitly Stage 5; verdict must stay deterministic | Stage 5 (stays `enabled=False` until then) |

---

## 24. Rejected Tools

Rejected = actively advised against, not merely postponed.

| Tool / approach | Why rejected |
|-----------------|--------------|
| **Single blended `ip_intelligence` "IP score"** | Violates the GEO/REP/INFRA separation invariant; destroys forensic nuance. Replaced by the four-tool split. |
| **PhishTank** | URL-only and redundant with URLhaus; ⚠️ new API-key registration reported closed/unavailable — depending on a provider we may be unable to register against is an unacceptable reliability risk. |
| **Self-hosting MISP** | Heavyweight TIP; operating it is a project in itself — massive overkill for single-email MVP. Consume feeds later; do not host. |
| **Self-hosting OpenCTI** | Same as MISP — a full platform/graph DB to run and maintain; not warranted for MVP. |
| **Live malware sandbox detonation** (Cuckoo/CAPE/commercial) | Explicitly out of scope; minutes of latency, heavy infra, real operational risk. Static analysis only in MVP. |
| **Backend fetching attacker URLs directly** (DIY crawler) | Direct SSRF/exposure risk; the entire reason we chose DB-lookup providers. Never fetch hostile URLs from our own egress. |
| **Rebuilding local capabilities as "tools"** (hashing, URL/IP/domain extraction, SPF/DKIM/DMARC parse, relay reconstruction) | Already implemented in parser/normalizer; a re-derivation tool is pure cost, zero marginal information (Principle 2). |
| **Choosing providers by popularity** (e.g. "everyone uses VT so make it core") | Contradicts the value-per-cost/risk/licensing method; VT's licensing/quota/sharing make it stretch, not core. |

---

## 25. Tool Execution Architecture

The executor is the component that turns a policy-selected tool + `ToolExecutionRequest` into a validated `ToolExecutionResult`. Its lifecycle (design):

```
policy selects tool  →  ToolExecutionRequest(case_id, tool_name, input, reason, policy_version)
      │
      ▼
[1] Resolve      get_tool(tool_name)  # KeyError on unknown → LLM/policy cannot invent tools
[2] Validate in  parse `input` against tool.input_contract (pydantic, extra="forbid")
[3] Guard        SSRF/reserved-range checks on any host/IP; enabled? budget/quota available?
[4] Cache        cache-first: key=(provider,indicator_type,normalized_indicator); hit → return (cache_hit=true)
[5] Rate-limit   per-provider limiter + InvestigationBudget.max_external_calls
[6] Execute      handler_ref → callable; per-tool timeout_ms; bounded max_retries w/ backoff
[7] Normalize    raw → provider model → normalized result (§20)
[8] Evidence     build EvidenceItem(s) (type/source_type validated) → evidence_ids
[9] Result       ToolExecutionResult(status, latency_ms, output, evidence_ids, provider, cache_hit, retry_count)
[10] State        merge into InvestigationState via model_copy (immutable)
```

**Concurrency.** Independent tools/indicators run **concurrently** via `httpx.AsyncClient` and asyncio, bounded by a global concurrency cap and the per-provider rate limiter, so wall-clock ≈ slowest call, not the sum (§13/§18). Local tools run in-process and are trivially parallelizable across the unique-indicator set.

**Status semantics.** SUCCESS (evidence produced), FAILED (error → UNKNOWN evidence), TIMEOUT (deadline → UNKNOWN), REJECTED (guard/SSRF/disabled), SKIPPED (budget/dedup — already answered), and the proposed **RATE_LIMITED** (throttled → UNKNOWN, may trip external-budget stop). **No status ever yields CLEAN evidence.**

**Failure isolation.** One tool's failure never fails the investigation (unless `failure_policy=FAIL_INVESTIGATION`, reserved for none of the MVP tools). Repeated failures of one provider trip the circuit-breaker (`REPEATED_FAILURES_EXCEEDED`) and stop calling it for that case. Budget exhaustion trips `BUDGET_EXHAUSTED` / `EXTERNAL_CALL_BUDGET_EXHAUSTED` — and per the Risk Engine invariant, a resource-driven stop is **never** reported as BENIGN.

**Determinism & audit.** Every execution is recorded (existing `audit_logger`) with request, status, provider, cache_hit, latency, and evidence_ids, so any verdict is fully reconstructable. The executor itself is provider-agnostic — it knows contracts and the registry, not vendor APIs (those live in adapters, §27).

---

## 26. Testing Strategy

Testing is **mock-first** (matching the existing suite: `test_evidence_normalizer.py`, `test_risk_engine.py`, `test_e2e_investigation.py`). No live external calls in the default test run — determinism and offline CI are requirements.

**Layers.**
1. **Contract tests** — every tool's input/output validates against its declared `input_contract`/`output_contract`; frozen/`extra="forbid"` enforced; evidence type↔source_type invariants hold (ML never FACT; THREAT_INTEL⇒threat_intel_api; HISTORICAL⇒historical_correlation).
2. **Adapter unit tests with recorded fixtures** — for each provider (URLhaus, AbuseIPDB, RDAP, GeoLite2, Tor list), feed **saved real response fixtures** through the adapter and assert the normalized result. Fixtures are captured once (when live access is available) and committed — this is also how the ⚠️ UNVERIFIED facts get pinned down.
3. **Failure-mode tests** — timeout, HTTP 429/quota, malformed/oversized response, provider down: assert status ∈ {FAILED,TIMEOUT,RATE_LIMITED,REJECTED} and evidence degrades to **UNKNOWN, never CLEAN**. This is the single most important behavioral guarantee.
4. **Security tests** — SSRF guard rejects RFC1918/loopback/link-local/metadata IPs and internal hostnames; DNS-rebinding re-validation; secrets never appear in persisted results/logs.
5. **Cache/rate-limit/dedup tests** — cache hit returns without a call (`cache_hit=true`); negative caching works; limiter blocks past quota; unique-IOC dedup issues one call per indicator.
6. **Evidence-conversion tests** — GEO/REP/INFRA produce **separate** EvidenceItems for one IP (assert no blended score).
7. **E2E (mocked externals)** — full raw-email→verdict with all externals mocked; assert profiles select the right tools and the Risk Engine (not a tool/LLM) sets the verdict.
8. **Contract-drift canary (opt-in, network)** — a separately-tagged test hitting real providers to detect API changes; excluded from default CI, run manually/scheduled.

**Coverage priorities:** failure-to-UNKNOWN, SSRF guards, and evidence separation are must-pass; provider happy-paths are fixture-driven.

---

## 27. Provider Adapter Architecture

The adapter layer is what keeps ASHIELDER **provider-neutral**: the executor and evidence pipeline speak normalized contracts; only adapters know vendor specifics. The pattern already exists — `ThreatIntelProvider` Protocol with `lookup_ip/domain/url/hash` returning `ThreatIntelResult`. We **extend the pattern, reuse the shape.**

```
                 ┌─────────────────────────────────────────┐
   executor ───► │  Protocol interfaces (provider-neutral)  │
                 │  ThreatIntelProvider  (exists)           │
                 │  GeoProvider          (new, design)      │
                 │  ASNProvider          (new, design)      │
                 │  DomainRegistrationProvider (new)        │
                 │  DNSResolver          (new, design)      │
                 │  HistoricalStore      (new, design)      │
                 └───────────────┬─────────────────────────┘
                                 │ implemented by
   ┌───────────────┬─────────────┼───────────────┬───────────────┐
   ▼               ▼             ▼               ▼               ▼
URLhausAdapter  AbuseIPDBAdapter  RDAPAdapter  GeoLite2Adapter  TorListAdapter
(ThreatIntel)   (ThreatIntel)     (DomainReg)  (Geo+ASN)        (INFRA)
```

**New Protocols (design-only; mirror the existing one):**
```python
class GeoProvider(Protocol):
    def lookup_ip_geo(self, ip: str) -> GeoResult: ...        # country/region/city, coarse lat/long, accuracy
class ASNProvider(Protocol):
    def lookup_ip_asn(self, ip: str) -> ASNResult: ...        # asn, org, prefix, rir, hosting/cloud class
class DomainRegistrationProvider(Protocol):
    def lookup_domain(self, domain: str) -> RegistrationResult: ...  # created/updated/expires, registrar, age_days
class DNSResolver(Protocol):
    def resolve(self, name: str, rrtypes: list[str]) -> DNSResult: ...  # A/AAAA/MX/TXT + resolved-at
class HistoricalStore(Protocol):
    def match_exact(self, iocs: IOCSet) -> HistoricalMatchResult: ...
```
Each normalized result type is a small frozen Pydantic contract living in `app/contracts/` (GEO/ASN/RDAP/DNS/historical shapes — the historical/ioc/url contracts already exist; add geo/asn/registration result shapes as needed). Adapters are swappable: URLhaus↔another URL-TI, GeoLite2↔a paid geo provider, without touching the executor, policy, or evidence pipeline. This is what makes provider choices reversible and the ⚠️ UNVERIFIED providers safe to adopt — if one fails verification, we swap the adapter, not the architecture.

**Adapter rules.** Adapters (1) accept a normalized indicator, (2) call the vendor, (3) parse into a vendor model, (4) return the normalized result, (5) never raise past the executor (translate errors into ERROR/UNKNOWN), (6) hold no verdict logic (verdict is the Risk Engine's job), (7) carry the provider's `evidence_reliability` so soft sources are weighted correctly.

---

## 28. ToolPriority Compatibility

Stage 3 must not break the Stage 2+ ranking model. The existing `ToolPriorityScore` contract encodes `ToolPriority(t) = EIG(t) × Reliability(t) / Cost(t)` with `Cost = w_latency·norm_latency + w_api·norm_api_cost + w_resource·norm_resource_cost`, `relevance ≥ RELEVANCE_FLOOR (0.15)` gating, and `priority = 0` below the floor. **We keep this shape unchanged.** Compatibility notes:

- **Reliability term.** The extended definition splits reliability into `availability_score` and `evidence_reliability` (§14/§19). For ranking, feed `Reliability(t)` from `availability_score` (will it answer?) and let `evidence_reliability` weight the *evidence* downstream. If the split fields are absent, fall back to the legacy `reliability` field — **fully backward-compatible**, so existing `ToolPriorityScore` computations keep working.
- **Cost term.** MVP externals have `estimated_api_cost = 0.0` but non-trivial latency/quota; the cost blend already captures this via the latency and resource weights. Populate `p50/p95_latency_ms` to feed `norm_latency` more accurately.
- **EIG term.** Unchanged; still the approved uncertainty proxy (not true Shannon entropy), computed in Stage 2+. Stage 3 adds no EIG logic — it only provides better-populated definitions for the existing formula to consume.
- **Relevance floor.** Unchanged at 0.15 inclusive; the profile→tool mapping (§21) supplies relevance; tools below the floor score `priority = 0` and are not run.
- **Determinism.** Priority is computed by deterministic policy code, never by an LLM; the ranking is auditable via the unchanged `ToolPriorityScore.cost_breakdown`/`reason` fields.

Net: the extensions **enrich the inputs** to the existing priority function without changing its formula, contract shape, or the policy skeleton — exactly the "recommend extensions only where necessary" posture.

---

## 29. Implementation Roadmap

Phased so that each phase is independently testable and the MVP is usable after Phase 3. **This is a build order, not a schedule; no code is written in this document.**

**Phase 0 — Contracts & prerequisites (design → code).** Apply the additive contract extensions (§19): `ToolDefinition` metadata, `RATE_LIMITED` status, result observability fields, new Protocols (§27). Bump `TOOL_REGISTRY_VERSION → 1.1.0`. Provision credentials: **MaxMind license key** (missing), confirm/obtain **URLhaus Auth-Key**, verify **AbuseIPDB** key/quota. Resolve every ⚠️ UNVERIFIED fact and capture as fixtures. *Gate: contracts compile, existing tests still pass.*

**Phase 1 — Local deterministic tools (Type A).** Fill `analysis/{header,auth,url,nlp,attachment}_analyzer.py` stubs and HTML/heuristics over the existing evidence package. All local, no network. Highest value-per-cost; makes the investigation useful with zero external dependency. *Gate: profiles resolve; evidence types validated.*

**Phase 2 — Local DB/feed tools (Type C/E).** `ip_geolocation` + `ip_asn` (GeoLite2), `tor_exit_check` (bulk list), `historical_correlation` (exact-match store + schema), and the feed-refresh jobs. Still no per-lookup external calls. *Gate: GEO/ASN/INFRA emit separate evidence; feeds refresh + timestamp.*

**Phase 3 — External DB-lookup edge (Type D) → MVP COMPLETE.** Adapters for **URLhaus** (feed-first + live miss), **AbuseIPDB** (`ip_reputation`), **RDAP** (`rdap_domain`), and **`dns_resolve`** (dnspython). Wire cache-first, rate-limiter, SSRF guards, failure→UNKNOWN. *Gate: full raw-email→verdict E2E with mocked+fixtured externals; failure-mode and SSRF tests pass.*

**Phase 4 — Local ML tools (Type B).** Integrate `url_ml`, `nlp_bec_ml` (and optional `header_ml`) once models are ready; ML_SIGNAL evidence only. *Gate: ML never typed FACT; scores flow to Risk Engine.*

**Phase 5 — Stretch (Type F, gated).** urlscan (private, analyst-gated), VirusTotal (hash-only, analyst-gated), GreyNoise, fuzzy/campaign correlation — each behind explicit enablement + licensing review. *Gate: privacy/SSRF review per tool.*

**Phase 6 — Stage 5 (out of scope here).** Groq reasoning over the assembled evidence; verdict stays deterministic. `groq_reasoning` remains `enabled=False` until then.

---

## 30. Final Recommendation

Build ASHIELDER's Stage 3 as a **local-first investigation engine with a thin, carefully-chosen external edge**, and resist the urge to bolt on a dozen APIs. The parser and evidence normalizer already produce the forensic backbone (hashes, canonical URLs, IPs, domains, SPF/DKIM/DMARC, relay chain), so the tool layer should spend its complexity budget only where it buys ground truth we cannot compute ourselves: ML judgments, indicator reputation/geolocation/registration, and correlation against our own history.

Concretely: implement the **local core** first (deterministic analyzers + GeoLite2 geo/ASN + Tor check + exact-match historical), then add exactly **three or four free, DB-lookup external sources** — **URLhaus, AbuseIPDB, RDAP, and live DNS** — each cache-first, deduplicated to unique indicators, rate-limited, SSRF-guarded, and degrading to `UNKNOWN` (never `CLEAN`) on any failure. Split the conflated `ip_intelligence` and `domain_intelligence` tools so GEO, REPUTATION, and INFRASTRUCTURE remain separate evidence and registration is cleanly separated from resolution. Reuse every existing contract; add only optional, backward-compatible fields; keep verdicts in the deterministic Risk Engine and Groq disabled until Stage 5.

Treat every unverified external number as a required pre-implementation confirmation, captured as a committed fixture. The result is the smallest toolset that maximizes investigative value per unit of latency, cost, complexity, and security risk — powerful, auditable, privacy-respecting, and cheap to run — with a clear, gated path to add the heavier stretch tools (urlscan, VirusTotal, fuzzy correlation) only when their value clearly justifies their cost.

---

# THE TOOLS WE SHOULD ACTUALLY IMPLEMENT

Each tool below is specified with the full attribute set. **All latency/rate-limit/quota figures are `⚠️ UNVERIFIED — MUST BENCHMARK/CONFIRM`** (live web access was unavailable); official docs are cited for confirmation. `InvestigationLevel` values reference the existing FSM (L0_TRIAGE, L1_TARGETED, L2_DEEP). Every external tool's failure behavior is **degrade to UNKNOWN, never CLEAN**.

---

## A. LOCAL CORE — MUST-HAVE (no network, no API cost)

### A1. `spf_dkim_dmarc`
- **Purpose:** Interpret parsed SPF/DKIM/DMARC results for spoofing/authenticity signals.
- **Local/External:** LOCAL (Type A).
- **Exact input:** `AuthenticationEvidence` (from `EmailEvidencePackage`).
- **Exact normalized output:** auth verdicts per mechanism (pass/fail/none/softfail), alignment findings.
- **Evidence produced:** `FACT` (source_type=deterministic) — auth outcomes; alignment as HEURISTIC.
- **Attack profiles:** spoofing (M), compromised_account (O), credential_phishing (O).
- **Investigation level:** L0_TRIAGE. **Tier:** MANDATORY.
- **Latency:** instant (sub-ms). **Cost:** 0. **Reliability:** availability ~1.0, evidence high.
- **Cache TTL:** n/a (pure function of input). **Rate limit:** none.
- **Failure behavior:** cannot fail on valid input; missing headers → UNKNOWN auth, not "pass".
- **Security concern:** none (in-process). **Privacy concern:** none.
- **Official docs:** RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC).
- **Implementation priority:** Phase 1.

### A2. `header_parse`
- **Purpose:** Detect header anomalies (From/Return-Path/Reply-To mismatch, display-name spoofing, malformed/injected headers).
- **Local/External:** LOCAL (Type A).
- **Exact input:** parsed headers from `EmailEvidencePackage`.
- **Exact normalized output:** structured list of header anomalies + severities.
- **Evidence produced:** `FACT`/`HEURISTIC` (deterministic).
- **Attack profiles:** spoofing (M), bec (M), executive_impersonation (M), compromised_account (O).
- **Investigation level:** L0_TRIAGE. **Tier:** MANDATORY.
- **Latency:** instant. **Cost:** 0. **Reliability:** high.
- **Cache TTL:** n/a. **Rate limit:** none.
- **Failure behavior:** robust to malformed headers; degrade to partial findings.
- **Security concern:** parser safety on hostile header bytes. **Privacy concern:** none (local).
- **Official docs:** RFC 5322, RFC 7489.
- **Implementation priority:** Phase 1.

### A3. `relay_reconstruction`
- **Purpose:** Reconstruct/trust-analyze the `Received:` hop chain; identify origin hop and injection point.
- **Local/External:** LOCAL (Type A).
- **Exact input:** `ReceivedHopEvidence[]` from `EmailEvidencePackage`.
- **Exact normalized output:** ordered hop chain, candidate origin IP/host, trust boundary.
- **Evidence produced:** `FACT` (deterministic).
- **Attack profiles:** spoofing (M), compromised_account (M), campaign (O).
- **Investigation level:** L0_TRIAGE. **Tier:** MANDATORY.
- **Latency:** instant. **Cost:** 0. **Reliability:** high (feeds IP tools with origin IP).
- **Cache TTL:** n/a. **Rate limit:** none.
- **Failure behavior:** partial chain → mark origin UNKNOWN, never assume.
- **Security concern:** none. **Privacy concern:** none.
- **Official docs:** RFC 5321/5322 (trace fields).
- **Implementation priority:** Phase 1.

### A4. `deterministic_heuristics`
- **Purpose:** Rule-based phishing/social-engineering indicators (urgency language patterns, credential-in-URL, punycode, extension mismatch, etc.).
- **Local/External:** LOCAL (Type A).
- **Exact input:** `EmailEvidencePackage` (headers, URLs, content features).
- **Exact normalized output:** fired-rule list + weights.
- **Evidence produced:** `HEURISTIC` (deterministic) — never FACT.
- **Attack profiles:** all content-driven profiles (M for credential_phishing, malicious_url, social_engineering).
- **Investigation level:** L0_TRIAGE. **Tier:** MANDATORY.
- **Latency:** instant. **Cost:** 0. **Reliability:** medium (heuristic).
- **Cache TTL:** n/a. **Rate limit:** none.
- **Failure behavior:** degrade to fewer rules; never blocks.
- **Security concern:** ReDoS-safe regex only. **Privacy concern:** none.
- **Official docs:** internal ruleset (ASHIELDER).
- **Implementation priority:** Phase 1.

### A5. `html_analysis`
- **Purpose:** Structural analysis of HTML body (anchor-text vs href mismatch, hidden links, form actions, remote-resource beacons, obfuscation).
- **Local/External:** LOCAL (Type A — reclassified from any ML assumption).
- **Exact input:** HTML body + `URLIndicator[]` from `EmailEvidencePackage`.
- **Exact normalized output:** structured HTML findings (mismatch links, forms, hidden content).
- **Evidence produced:** `HEURISTIC` (deterministic).
- **Attack profiles:** credential_phishing (M), malicious_url (M), social_engineering (O).
- **Investigation level:** L1_TARGETED. **Tier:** MANDATORY.
- **Latency:** fast (parse). **Cost:** 0. **Reliability:** medium-high.
- **Cache TTL:** n/a. **Rate limit:** none.
- **Failure behavior:** malformed HTML → partial findings (BeautifulSoup tolerant).
- **Security concern:** no rendering, no fetching remote resources (parse only — avoids SSRF). **Privacy concern:** none (local).
- **Official docs:** beautifulsoup4 (already a dependency).
- **Implementation priority:** Phase 1.

### A6. `attachment_static_analysis`
- **Purpose:** Static inspection of attachment bytes — true type (magic), extension mismatch, dangerous types, archive/macro presence (no execution).
- **Local/External:** LOCAL (Type A).
- **Exact input:** `AttachmentEvidence[]` (bytes + SHA-256 already computed by parser).
- **Exact normalized output:** per-attachment findings (true_type, mismatch, macro_present, archive_flags).
- **Evidence produced:** `FACT` (type/hash) + `HEURISTIC` (risk flags), deterministic.
- **Attack profiles:** malicious_attachment (M), malware_delivery (M).
- **Investigation level:** L1_TARGETED. **Tier:** MANDATORY.
- **Latency:** fast. **Cost:** 0. **Reliability:** high for type; medium for risk flags.
- **Cache TTL:** n/a (or by SHA-256). **Rate limit:** none.
- **Failure behavior:** unparseable → flag "opaque", never "safe".
- **Security concern:** zip-bomb/decompression limits; parse-not-execute. **Privacy concern:** none (local; file never leaves).
- **Official docs:** ⚠️ confirm lib/license — oletools (https://github.com/decalage2/oletools).
- **Implementation priority:** Phase 1.

### A7. `historical_correlation` (exact-match)
- **Purpose:** Match current IOCs against prior-case IOC store (sender, domain, IP, URL, attachment hash).
- **Local/External:** LOCAL (Type C — our DB).
- **Exact input:** unique IOC set from `EmailEvidencePackage`.
- **Exact normalized output:** matches with prior case IDs + prior verdicts.
- **Evidence produced:** `HISTORICAL` (source_type=historical_correlation, validator-enforced).
- **Attack profiles:** campaign (M), bec/invoice_fraud/vendor_fraud (O).
- **Investigation level:** L2_DEEP. **Tier:** OPTIONAL (MANDATORY for campaign).
- **Latency:** fast (indexed DB query). **Cost:** 0. **Reliability:** high (exact match).
- **Cache TTL:** n/a (is the store). **Rate limit:** none.
- **Failure behavior:** DB unavailable → UNKNOWN (no correlation), never CLEAN.
- **Security concern:** parameterized queries only. **Privacy concern:** internal store; no external disclosure.
- **Official docs:** internal (SQLAlchemy/asyncpg schema).
- **Implementation priority:** Phase 2.

### A8. `dns_resolve` (NEW — split from `domain_intelligence`)
- **Purpose:** Live DNS resolution — A/AAAA/MX/TXT — to establish current infrastructure and mail plausibility; feeds IP tools.
- **Local/External:** LOCAL RESOLVER (Type D by network, no third-party API/quota).
- **Exact input:** unique registrable domains/hostnames.
- **Exact normalized output:** `DNSResult` (A/AAAA/MX/TXT records, resolved_at timestamp).
- **Evidence produced:** `FACT` (deterministic) — timestamped, volatile.
- **Attack profiles:** credential_phishing (M), malicious_url (O), spoofing (O).
- **Investigation level:** L2_DEEP. **Tier:** MANDATORY (local edge).
- **Latency:** network (tens–hundreds ms). **Cost:** 0 (no API). **Reliability:** high availability; volatile data.
- **Cache TTL:** minutes (respect record TTL). **Rate limit:** resolver etiquette (no vendor quota).
- **Failure behavior:** NXDOMAIN = fact; timeout/servfail → UNKNOWN.
- **Security concern:** SSRF/rebinding — re-validate resolved IPs against reserved ranges before any downstream use; never resolve to probe internal hosts. **Privacy concern:** low (DNS query reveals interest in a domain to resolver).
- **Official docs:** dnspython (ISC license) https://dnspython.readthedocs.io/.
- **Implementation priority:** Phase 3.

### A9. `ip_geolocation` (NEW — split from `ip_intelligence`)
- **Purpose:** Geolocate the origin/candidate IP(s) — country/region/city, coarse lat/long. (The platform's namesake capability.)
- **Local/External:** LOCAL (Type C — MaxMind GeoLite2 City DB in-process).
- **Exact input:** unique candidate-origin IPs (from relay reconstruction).
- **Exact normalized output:** `GeoResult` (country, region, city, lat/long, accuracy_radius, db_version).
- **Evidence produced:** `FACT` — **GEO** (deterministic). Kept SEPARATE from REP/INFRA.
- **Attack profiles:** spoofing (O), compromised_account (M — impossible-travel/geo-anomaly), campaign (O).
- **Investigation level:** L2_DEEP. **Tier:** MANDATORY (local).
- **Latency:** instant (local DB). **Cost:** 0 per lookup. **Reliability:** country high; city LIMITED (do not overstate).
- **Cache TTL:** tied to DB version (refresh job). **Rate limit:** none.
- **Failure behavior:** IP not in DB → UNKNOWN location; never fabricate.
- **Security concern:** none (local). **Privacy concern:** none — **zero transmission** of the IP to any third party.
- **Official docs:** ⚠️ CONFIRM account/license-key + attribution requirement — https://dev.maxmind.com/geoip/geolite2-free-geolocation-data.
- **Implementation priority:** Phase 2. **Prerequisite:** MaxMind license key (missing from `.env`).

### A10. `ip_asn` (NEW — split from `ip_intelligence`)
- **Purpose:** Infrastructure classification — ASN, network operator/org, prefix, RIR, hosting-vs-residential-vs-cloud.
- **Local/External:** LOCAL (Type C — GeoLite2-ASN DB) with Team Cymru as alternate/enrichment.
- **Exact input:** unique candidate-origin IPs.
- **Exact normalized output:** `ASNResult` (asn, org, prefix, rir, infra_class).
- **Evidence produced:** `FACT` — **INFRA** (deterministic). SEPARATE from GEO/REP.
- **Attack profiles:** spoofing (O), compromised_account (O), campaign (M — infra clustering).
- **Investigation level:** L2_DEEP. **Tier:** MANDATORY (local).
- **Latency:** instant (local DB) / low (Team Cymru DNS). **Cost:** 0. **Reliability:** high.
- **Cache TTL:** days (ASN stable). **Rate limit:** none (local) / DNS etiquette (Team Cymru).
- **Failure behavior:** unmapped IP → UNKNOWN ASN.
- **Security concern:** none (local). **Privacy concern:** none (local DB) / low (Team Cymru).
- **Official docs:** MaxMind GeoLite2-ASN (as A9); ⚠️ CONFIRM Team Cymru AUP — https://team-cymru.com/community-services/ip-asn-mapping/.
- **Implementation priority:** Phase 2.

### A11. `tor_exit_check` (NEW — split from `ip_intelligence`)
- **Purpose:** Determine whether the origin IP is a known Tor exit node (anonymizer signal).
- **Local/External:** LOCAL (Type C set-membership over a Type-E downloaded list).
- **Exact input:** unique candidate-origin IPs.
- **Exact normalized output:** `{is_tor_exit: bool, list_fetched_at}`.
- **Evidence produced:** `FACT` — **INFRA/anonymizer** (deterministic). SEPARATE.
- **Attack profiles:** compromised_account (O), spoofing (O), campaign (O).
- **Investigation level:** L2_DEEP. **Tier:** OPTIONAL.
- **Latency:** instant (set membership). **Cost:** 0. **Reliability:** high (authoritative list).
- **Cache TTL:** tied to list refresh (e.g. hourly). **Rate limit:** none (local check).
- **Failure behavior:** stale/missing list → UNKNOWN, never "not tor".
- **Security concern:** none. **Privacy concern:** none (local).
- **Official docs:** ⚠️ CONFIRM URL/format/etiquette — https://check.torproject.org/torbulkexitlist.
- **Implementation priority:** Phase 2.

---

## B. LOCAL ML — MUST-HAVE WHEN MODELS READY (no network, CPU/GPU cost)

### B1. `url_ml`
- **Purpose:** ML classification of URLs as phishing/malicious from lexical/structural features.
- **Local/External:** LOCAL (Type B inference).
- **Exact input:** `URLIndicator[]` features.
- **Exact normalized output:** per-URL score + label + model_version.
- **Evidence produced:** **ML_SIGNAL** (source_type=ml_model) — **never FACT** (validator-enforced).
- **Attack profiles:** malicious_url (M), credential_phishing (M).
- **Investigation level:** L1_TARGETED. **Tier:** OPTIONAL (MANDATORY for URL profiles when model present).
- **Latency:** low tens of ms. **Cost:** 0 API (local compute). **Reliability:** medium (model-dependent).
- **Cache TTL:** by (model_version, normalized_url). **Rate limit:** none.
- **Failure behavior:** model load/inference error → UNKNOWN (no score), never CLEAN.
- **Security concern:** none (local). **Privacy concern:** none.
- **Official docs:** internal model card.
- **Implementation priority:** Phase 4 (model-gated).

### B2. `nlp_bec_ml`
- **Purpose:** NLP model for BEC/social-engineering intent (payment redirection, urgency, impersonation cues).
- **Local/External:** LOCAL (Type B inference).
- **Exact input:** normalized email text features.
- **Exact normalized output:** intent score + label + model_version.
- **Evidence produced:** **ML_SIGNAL** (source_type=ml_model) — never FACT.
- **Attack profiles:** bec (M), executive_impersonation (M), invoice_fraud/payment_diversion/vendor_fraud (M), social_engineering (M).
- **Investigation level:** L1_TARGETED. **Tier:** OPTIONAL (MANDATORY for BEC family when model present).
- **Latency:** tens of ms. **Cost:** 0 API. **Reliability:** medium.
- **Cache TTL:** by (model_version, content_hash). **Rate limit:** none.
- **Failure behavior:** error → UNKNOWN, never CLEAN.
- **Security concern:** none (local; content never leaves). **Privacy concern:** none.
- **Official docs:** internal model card.
- **Implementation priority:** Phase 4 (model-gated).

*(Optional `header_ml` (B): retained in registry as optional ML enrichment; deterministic `header_parse` stays mandatory. Same profile as A2, ML_SIGNAL evidence, Phase 4.)*

---

## C. EXTERNAL FREE EDGE — SHOULD-HAVE (DB-lookup, $0, quota-bounded, no SSRF)

### C1. `rdap_domain`
- **Purpose:** Domain registration facts — creation date (→ age), registrar, status; freshly-registered = strong phishing signal.
- **Local/External:** EXTERNAL (Type D — DB-lookup over HTTPS; no fetch of attacker content).
- **Exact input:** unique registrable domains.
- **Exact normalized output:** `RegistrationResult` (created_at, updated_at, expires_at, age_days, registrar, statuses).
- **Evidence produced:** `FACT` (deterministic) — registration facts. (Domain "age" as a strong HEURISTIC.)
- **Attack profiles:** credential_phishing (O), bec/executive_impersonation (O — lookalike age), spoofing (O), campaign (O).
- **Investigation level:** L2_DEEP. **Tier:** OPTIONAL (should-have).
- **Latency:** network (tens–hundreds ms). **Cost:** $0. **Reliability:** high for gTLDs.
- **Cache TTL:** days–weeks (registration changes slowly). **Rate limit:** ⚠️ per-registry, undocumented → treat low, cache hard.
- **Failure behavior:** no RDAP server for ccTLD / rate-limited → UNKNOWN age, never assume old/safe.
- **Security concern:** none (DB-lookup, no attacker fetch); validate/parse JSON strictly. **Privacy concern:** low (we disclose one domain); registrant PII is GDPR-redacted — do not re-identify.
- **Official docs:** RFC 7480/7481/9082/9083/9224; IANA bootstrap https://data.iana.org/rdap/dns.json.
- **Implementation priority:** Phase 3. **Note:** no batch — one domain/request, parallelize + cache.

### C2. `url_reputation` (bound to URLhaus)
- **Purpose:** Determine if a URL/host is in a curated malware/phishing corpus.
- **Local/External:** EXTERNAL (Type D live) + Type E feed (feed-first, live on miss). **DB-lookup — does NOT fetch the URL → no SSRF.**
- **Exact input:** unique canonical URLs / hostnames.
- **Exact normalized output:** `ThreatIntelResult` (provider=urlhaus, verdict, confidence, threat/tags, raw_result_reference, cache_status). **Reuses existing contract.**
- **Evidence produced:** **THREAT_INTEL** (source_type=threat_intel_api).
- **Attack profiles:** malicious_url (M), credential_phishing (M), malware_delivery (O — payload URLs), social_engineering (O).
- **Investigation level:** L2_DEEP. **Tier:** OPTIONAL (should-have; the free URL-TI backbone).
- **Latency:** instant on feed hit; network on live miss. **Cost:** $0. **Reliability:** high when hit; absence ≠ clean.
- **Cache TTL:** hours (+ feed refresh). **Rate limit:** ⚠️ CONFIRM (Auth-Key required); feed-first minimizes calls.
- **Failure behavior:** miss = "not in corpus" (NOT clean); error/throttle → UNKNOWN.
- **Security concern:** none (DB-lookup); strict response parsing. **Privacy concern:** low; feed-first discloses nothing per-indicator.
- **Official docs:** ⚠️ CONFIRM auth/limits/CC0-of-data — https://urlhaus.abuse.ch/api/ (auth.abuse.ch for key).
- **Implementation priority:** Phase 3 (feed loader in Phase 2/3).

### C3. `ip_reputation` (NEW — split from `ip_intelligence`; AbuseIPDB)
- **Purpose:** Abuse reputation of the origin IP — crowd-sourced confidence + report metadata.
- **Local/External:** EXTERNAL (Type D — DB-lookup; no SSRF).
- **Exact input:** unique candidate-origin IPs.
- **Exact normalized output:** `ThreatIntelResult` (provider=abuseipdb, verdict from abuseConfidenceScore 0–100, confidence, categories, cache_status). **Reuses existing contract.**
- **Evidence produced:** **THREAT_INTEL** — **REP** (source_type=threat_intel_api). SEPARATE from GEO/INFRA.
- **Attack profiles:** compromised_account (O), spoofing (O), campaign (O).
- **Investigation level:** L2_DEEP. **Tier:** OPTIONAL (should-have).
- **Latency:** network. **Cost:** $0 (free tier). **Reliability:** availability high; evidence SOFT (crowd-sourced — lower evidence_reliability).
- **Cache TTL:** hours. **Rate limit:** ⚠️ CONFIRM free daily quota (commonly cited ~1000/day) — https://docs.abuseipdb.com/.
- **Failure behavior:** low/zero score ≠ clean; error/throttle → UNKNOWN.
- **Security concern:** secret handling; strict parsing. **Privacy concern:** low (one IP disclosed).
- **Official docs:** https://docs.abuseipdb.com/. **Key:** `ABUSEIPDB_API_KEY` present in `.env`.
- **Implementation priority:** Phase 3.

---

## D. STRETCH — GATED, NOT MVP (implement only after Phase 3, with review)

- **`url_scan` (urlscan.io)** — server-side render/scan. Type F. Input: URL. Output→`ThreatIntelResult` + artifacts ref. **SSRF-offloaded to third party (never our egress); PRIVATE/unlisted visibility only; analyst-gated.** ⚠️ non-commercial free tier, public-scan leakage, async submit-poll — https://urlscan.io/docs/api/. Priority: Phase 5.
- **`vt_lookup` (VirusTotal v3)** — multi-engine verdict for **hash/URL/domain/IP**. Type F. **Hash-only for attachments (never upload files); analyst-gated.** ⚠️ non-commercial, ~4/min·500/day, community-sharing — https://docs.virustotal.com/reference/public-vs-premium-api. Key present in `.env`. Priority: Phase 5.
- **`greynoise_community`** — scanner-noise downgrade for IPs. ⚠️ community limits/terms — https://docs.greynoise.io/. Priority: Phase 5.
- **`historical_correlation` (fuzzy/campaign)** — near-duplicate/lookalike/infra clustering. Local. Needs exact-match store first. Priority: Phase 5.

---

# WHAT WE SHOULD NOT IMPLEMENT

**Do not rebuild local capabilities as tools.** SHA-256 hashing (raw + per-attachment), URL parsing/canonicalization, IP extraction/validation, domain extraction, SPF/DKIM/DMARC *parsing*, and `Received:` chain extraction are **already done** by the parser and evidence normalizer. A tool that re-derives them is pure cost with zero marginal information gain. (Stage-3 tools *interpret* this evidence; they do not re-extract it.)

**Do not implement a single blended `ip_intelligence` "IP score".** It conflates three independent facts and violates the GEO/REP/INFRA separation invariant. Implement the four separate tools instead (`ip_geolocation`, `ip_asn`, `ip_reputation`, `tor_exit_check`).

**Do not implement PhishTank.** URL-only, redundant with URLhaus, and ⚠️ its API-key registration has been reported closed/unavailable — a provider we may be unable to register against is an unacceptable dependency.

**Do not self-host MISP or OpenCTI.** These are full threat-intelligence platforms; standing one up and operating it is a separate project, wildly disproportionate to a single-email MVP. If aggregated intel is wanted later, **consume** a feed — do not host a platform.

**Do not implement live malware sandbox detonation.** Out of scope for the MVP and on the merits: minutes of latency, heavy infrastructure, real operational risk. Static attachment analysis only.

**Do not let the backend fetch attacker URLs directly.** No DIY crawler/renderer on our own egress — that is the SSRF risk the whole design avoids by using DB-lookup providers. If server-side scanning is needed, offload it to urlscan.io (stretch, private, gated), never our backend.

**Do not adopt Google Safe Browsing v4 for commercial use, or Web Risk, in the MVP.** ⚠️ non-commercial-leaning terms / required billing make them a licensing/cost liability now. Revisit only with a chosen commercial path.

**Do not put VirusTotal or urlscan on the default MVP path.** Licensing (non-commercial), quotas, and community data-sharing make them stretch/analyst-gated enrichment — not core, and never chosen merely because they are popular.

**Do not integrate Groq / any LLM into the verdict path.** `groq_reasoning` stays `enabled=False` until Stage 5; verdict/risk/confidence come only from the deterministic Risk Engine.

**Do not let any tool failure become "CLEAN".** Timeout, throttle (RATE_LIMITED), error, or "not found in corpus" degrade to **UNKNOWN** — absence of a hit is not proof of safety. A resource-driven stop is never BENIGN.

**Do not duplicate existing contracts.** Reuse `ToolDefinition`, `ToolExecutionRequest/Result`, `ToolExecutionStatus`, `ToolPriorityScore`, `ThreatIntelResult`, `ThreatIntelProvider`, `EvidenceItem`. Extend additively only; do not fork parallel contract shapes.

**Do not hard-code any ⚠️ UNVERIFIED number.** No rate limit, quota, price, or TOS assumption goes into code until confirmed from the cited canonical source and captured as a committed fixture.

---

# STAGE 3 IMPLEMENTATION ORDER

Exact coding sequence. Each step is independently testable; the MVP is functional after Step 7. **No step begins until the ⚠️ UNVERIFIED facts it depends on are confirmed and fixtured.**

**Step 0 — Verify & provision (no code).** Confirm every ⚠️ UNVERIFIED fact (URLhaus auth/limits/CC0, AbuseIPDB quota, RDAP behavior, GeoLite2 license/attribution, Tor list URL, VT/urlscan terms) from the cited docs; capture responses as committed test fixtures. Provision the **MaxMind license key** (missing) and confirm URLhaus Auth-Key + AbuseIPDB key.

**Step 1 — Contract extensions (additive).** Apply §19 design to `app/contracts/tool.py`: `ToolCategory`, `ToolType`, `RiskLevel`, `FailurePolicy`, the optional `ToolDefinition` fields, `RATE_LIMITED` status, `ToolExecutionResult` observability fields, `ToolExecutionRequest` correlation fields. Add new result contracts (`GeoResult`, `ASNResult`, `RegistrationResult`, `DNSResult`) and Protocols (`GeoProvider`, `ASNProvider`, `DomainRegistrationProvider`, `DNSResolver`, `HistoricalStore`). Run existing tests — all must still pass. Bump `TOOL_REGISTRY_VERSION → 1.1.0`.

**Step 2 — Registry refactor (design→config).** In `tool_registry.py`/`profile_registry.py`: split `ip_intelligence` → `ip_geolocation` + `ip_asn` + `ip_reputation` + `tor_exit_check`; split `domain_intelligence` → `dns_resolve` + `rdap_domain` (canonical registration); bind `url_reputation` to URLhaus; scope `historical_correlation` to exact-match; reclassify `html_analysis` as Type A; populate extended metadata. Update profile→tool maps. Validate at import.

**Step 3 — Executor + guards.** Build the execution lifecycle (§25): resolve→validate-in→SSRF/reserved-range guard→cache-first→rate-limit→execute(timeout,retries)→normalize→evidence→result→state-merge. Wire the audit logger. Unit-test guards and status semantics against mocks (esp. failure→UNKNOWN, SSRF rejection).

**Step 4 — Local deterministic analyzers (Type A).** Implement the `analysis/{header,auth,url,nlp→heuristic parts,attachment}_analyzer.py` stubs + `html_analysis` + `deterministic_heuristics` over the existing evidence package. These give a useful investigation with zero external dependency.

**Step 5 — Local DB/feed tools (Type C/E).** `ip_geolocation` + `ip_asn` (GeoLite2 adapters), `tor_exit_check` (+ list-refresh job), `historical_correlation` exact-match (+ store schema), and the URLhaus **feed loader** (so the external URL tool is feed-first). Assert GEO/ASN/INFRA emit **separate** evidence.

**Step 6 — External DB-lookup adapters (Type D).** In dependency order: `dns_resolve` (dnspython) → `rdap_domain` (RDAP + IANA bootstrap) → `url_reputation` (URLhaus live-on-miss) → `ip_reputation` (AbuseIPDB). Each behind its Protocol adapter, cache-first, rate-limited, degrade-to-UNKNOWN. Fixture-driven tests + failure-mode tests.

**Step 7 — E2E wiring → MVP COMPLETE.** Raw-email→verdict end-to-end with externals mocked/fixtured; assert profiles select the right tools, evidence types validate, and the **Risk Engine** (not any tool/LLM) sets the verdict. Failure-mode, SSRF, cache, dedup, and evidence-separation suites green.

**Step 8 — Local ML (Type B).** Integrate `url_ml`, `nlp_bec_ml` (and optional `header_ml`) when models are ready; ML_SIGNAL evidence only, never FACT.

**Step 9 — Stretch (Type F, gated).** urlscan (private/gated), VirusTotal (hash-only/gated), GreyNoise, fuzzy/campaign correlation — each behind explicit enablement + privacy/licensing review.

**Step 10 — Stage 5 (out of scope).** Enable Groq reasoning over assembled evidence; verdict stays deterministic. Until then `groq_reasoning.enabled = False`.

---

*End of specification. This document is research + design only; no tool code is implemented, the parser and Evidence Package are unmodified, Investigation Policy is not rewritten, and Groq remains disabled.*
