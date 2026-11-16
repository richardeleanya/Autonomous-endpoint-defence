# Reference Architecture v1 — Autonomous Agentic Endpoint Defence Mesh

**Document ID:** ARC-v1 (P0.2)
**Date:** 2026-11-16
**Status:** Draft for review
**Owner:** Principal Systems Architect
**Depends on:** Threat Model v1 (P0.1), Master Rules
**Inputs status:** Core Design and Detection-to-recovery flow were not supplied; treated as OQ-01/OQ-02 and handled via labelled assumptions (MR9).

---

## 0. Architectural invariants (ARC IDs)

| ID | Invariant |
|---|---|
| ARC-001 | Node decomposed into the listed components (§2) |
| ARC-002 | Control plane decomposed into the listed services (§3) |
| ARC-003 | Privilege separation with minimal TCB (§4) |
| ARC-004 | Policy engine and enforcement path: small, memory-safe, AI-free |
| ARC-005 | No AI component has a write path to the system |
| ARC-006 | Enforcement fails closed for T2 and above |
| ARC-007 | T0 evidence collection always continues |
| ARC-008 | No custom cryptography; proven libraries only |
| ARC-009 | Degraded-mode behaviour per matrix (§6) |
| ARC-010 | Performance/resource budgets are TARGETs with measurement methods |
| ARC-011 | FMEA coverage (§8) |
| ARC-012 | SBOM-ready dependency list (§11) |
| ARC-013 | Every component has a complete card |
| ARC-014 | No single point of authority |
| ARC-015 | Every R4 (manual) action has a human path |
| ARC-016 | Every SEC maps to at least one component (§10) |

---

## 1. Consequence tiers

| Tier | Name | Examples | Enforcement failure mode |
|---|---|---|---|
| T0 | Evidence collection | Telemetry, observation, logging | Always continues (ARC-007) |
| T1 | Advisory analysis | Scoring, ranking, recommendation | Degrade to no-op |
| T2 | Containment | Process terminate, network isolate, host isolate | Fail-closed (deny) (ARC-006) |
| T3 | Destructive/recovery | Rollback, wipe, restore, re-image | Fail-closed (deny); human path required (ARC-015) |

No component may escalate its own tier. Tier is assigned by the policy engine from a signed policy bundle (SEC-004).

---

## 2. Node decomposition (component cards)

Component: sensors
Trust: Untrusted (sandboxed) | Language: managed/sandboxed (ADR-004) | Privilege: user, read-only OS telemetry, no network
Inputs: OS events, file/process/network telemetry
Outputs: Raw observations to case-graph
Failure: sensor failure degrades detection only; T0 evidence from other sensors continues (ARC-007)
Traces: SEC-001, SEC-007, ARC-001, ARC-007

Component: case-graph
Trust: Untrusted (sandboxed) | Language: managed/sandboxed (ADR-004) | Privilege: user, no network, no privileged
Inputs: Observations from sensors
Outputs: Correlated cases to reasoning tiers
Failure: case-graph failure drops T1 analysis; T0 evidence continues; no T2 action proposed
Traces: SEC-005, SEC-006, ARC-001, ARC-007

Component: reasoning-tiers
Trust: Untrusted (AI-capable) | Language: managed/sandboxed (ADR-004) | Privilege: user, no write path, no network
Inputs: Cases from case-graph; signed policy context
Outputs: Recommendations/advisory scores to action-proposer only
Failure: reasoning failure degrades to T1 none; T0 continues; no action authority (ARC-005)
Traces: SEC-036, SEC-037, SEC-038, SEC-039, ARC-005, ARC-007

Component: action-proposer
Trust: Untrusted (sandboxed) | Language: managed/sandboxed (ADR-004) | Privilege: user, no network, no write path
Inputs: Recommendations from reasoning-tiers
Outputs: Signed proposals to policy-engine
Failure: proposer failure yields no proposals; T0 continues; fail-closed for T2+ (ARC-006)
Traces: SEC-005, SEC-006, SEC-018, ARC-004, ARC-005

Component: policy-engine
Trust: TCB | Language: memory-safe (ADR-003) | Privilege: user, no network
Inputs: Proposal signed by local proposer; signed policy bundle; mesh attestations
Outputs: Decision (ALLOW, DOWNGRADE, ESCALATE, DENY)
Failure: fail-closed for T2+, T0 unaffected (ARC-006, ARC-007)
Traces: SEC-004, SEC-005, SEC-021, SEC-030, SEC-034, ARC-004, ARC-006

Component: containment-controller
Trust: TCB (enforcement core) | Language: memory-safe core + OS adapters (ADR-003) | Privilege: privileged (admin/root) for enforcement only; no network
Inputs: Decision from policy-engine
Outputs: OS-level containment actions via os-adapters
Failure: enforcement failure fails closed for T2+; T0 evidence continues (ARC-006, ARC-007)
Traces: SEC-002, SEC-007, SEC-015, SEC-024, ARC-004, ARC-006

Component: recovery-verifier
Trust: TCB (verification) | Language: memory-safe (ADR-003) | Privilege: user, no network
Inputs: Recovery action requests; system state
Outputs: Verification result; compensation trigger
Failure: verification failure blocks T3 action; requires human path (ARC-015)
Traces: SEC-035, SEC-018, ARC-006, ARC-015

Component: evidence-ledger (node)
Trust: TCB | Language: memory-safe (ADR-003) | Privilege: user, append-only local store, no network
Inputs: Observations, decisions, actions
Outputs: Append-only local ledger; anchor to control plane when online
Failure: ledger write failure fails the action (no unlogged T2+ action); T0 collection continues to buffer
Traces: SEC-009, SEC-025, SEC-026, ARC-007

Component: mesh-coordinator
Trust: Untrusted (sandboxed) | Language: managed/sandboxed (ADR-004) | Privilege: user, network (peer only), sandboxed
Inputs: Local observations to share; peer messages
Outputs: Attested peer observations to case-graph
Failure: mesh failure degrades to local-only mode; T0 continues; peer-dependent T2 denied (ARC-009)
Traces: SEC-012, SEC-013, SEC-014, SEC-015, SEC-016, SEC-017, ARC-009

Component: enrolment-client
Trust: Untrusted (sandboxed) | Language: managed/sandboxed (ADR-004) | Privilege: user, network (control plane) during enrolment only
Inputs: Device identity material; control-plane enrolment challenge
Outputs: Enrolment credential; tenant binding
Failure: enrolment failure prevents mesh participation; T0 local evidence continues (ARC-007)
Traces: SEC-010, SEC-019, SEC-040, ARC-009

Component: updater
Trust: TCB (verification) | Language: memory-safe (ADR-003) | Privilege: user for verification; privileged install via os-adapters
Inputs: Signed update artefacts; version policy
Outputs: Verified update applied or rejected
Failure: update verification failure rejects update; system remains on last known good (ARC-008)
Traces: SEC-030, SEC-031, SEC-032, SEC-033, SEC-034, SEC-035, ARC-008

Component: watchdog
Trust: TCB | Language: memory-safe (ADR-003) | Privilege: privileged (monitor/restart only)
Inputs: Health signals from components
Outputs: Restart/escalation; quarantine of compromised component
Failure: watchdog failure removes self-healing; reported to control plane; T0 continues where possible
Traces: SEC-001, SEC-009, ARC-006, ARC-007

Component: os-adapters
Trust: TCB (privileged shims) | Language: memory-safe where feasible; minimal (ADR-003) | Privilege: privileged, minimal surface
Inputs: Enforcement requests from containment-controller
Outputs: OS-specific containment primitives
Failure: adapter failure fails the specific action closed; T0 continues (ARC-006, ARC-007)
Traces: SEC-002, SEC-004, ARC-004, ARC-006

---

## 3. Control-plane decomposition (component cards)

Component: identity
Trust: TCB (service) | Language: memory-safe service (ADR-003) | Privilege: service account, network (internal)
Inputs: Authentication requests; identity proofs
Outputs: Authenticated principal; MFA status
Failure: identity failure denies new sessions; existing short-lived tokens continue until expiry; T0 on nodes unaffected
Traces: SEC-019, SEC-020, SEC-027, ARC-002

Component: tenancy
Trust: TCB (service) | Language: memory-safe service (ADR-003) | Privilege: service account, network (internal)
Inputs: Tenant context; resource requests
Outputs: Tenant scoping; isolation enforcement
Failure: tenancy failure fails closed (deny cross-tenant); no data bleed (SEC-010, SEC-045)
Traces: SEC-010, SEC-023, SEC-043, SEC-045, ARC-002

Component: policy-signing
Trust: TCB (service) | Language: memory-safe service (ADR-003) | Privilege: service account, HSM-backed keys (proven crypto, ADR-005)
Inputs: Policy content; approval records
Outputs: Signed policy bundle
Failure: signing failure blocks policy distribution; nodes retain last known good (SEC-022)
Traces: SEC-004, SEC-021, SEC-022, ARC-008

Component: token-issuance
Trust: TCB (service) | Language: memory-safe service (ADR-003) | Privilege: service account, network (internal)
Inputs: Authenticated principal; scope request
Outputs: Short-lived scoped tokens
Failure: issuance failure denies new access; existing tokens expire naturally
Traces: SEC-019, SEC-020, SEC-027, ARC-002

Component: fleet-budget
Trust: Service (sandboxed) | Language: managed service (ADR-004) | Privilege: service account, network (internal)
Inputs: Usage metrics; quota policy
Outputs: Budget decisions; throttling signals
Failure: budget failure defaults to deny expansion (fail-closed for new high-impact actions)
Traces: SEC-024, SEC-044, ARC-002

Component: telemetry-ingestion
Trust: Service (sandboxed) | Language: managed service (ADR-004) | Privilege: service account, network (ingress)
Inputs: Node telemetry; evidence anchors
Outputs: Stored telemetry; schema-validated records
Failure: ingestion failure buffers at node; T0 collection continues (ARC-007)
Traces: SEC-029, SEC-030, ARC-007

Component: console-api
Trust: Service (sandboxed) | Language: managed service (ADR-004) | Privilege: service account, network (ingress)
Inputs: Operator requests
Outputs: Tenant-scoped responses; audit events
Failure: console failure denies operator actions; node autonomy continues (ARC-009)
Traces: SEC-040, SEC-041, SEC-042, ARC-002

Component: audit
Trust: TCB (service) | Language: memory-safe service (ADR-003) | Privilege: service account, append-only store
Inputs: Action/decision events from all services
Outputs: Immutable audit trail; evidence anchoring
Failure: audit failure blocks privileged actions (no unlogged action); T0 continues
Traces: SEC-025, SEC-026, SEC-047 (n/a), ARC-002

Component: evidence-anchor
Trust: TCB (service) | Language: memory-safe service (ADR-003) | Privilege: service account, append-only store
Inputs: Node ledger anchors
Outputs: Anchored evidence; integrity proofs
Failure: anchoring failure queues anchors; node ledger remains authoritative locally
Traces: SEC-009, SEC-026, ARC-002

---

## 4. Privilege separation and TCB

**TCB (trusted computing base):** policy-engine, containment-controller enforcement core, recovery-verifier, evidence-ledger (node + anchor), updater verification, os-adapters privileged shims, watchdog, and control-plane identity/tenancy/policy-signing/token-issuance/audit/evidence-anchor services. Plus the proven crypto library (ADR-005).

**Sandboxed / untrusted:** sensors, case-graph, reasoning-tiers, action-proposer, mesh-coordinator, enrolment-client, fleet-budget, telemetry-ingestion, console-api. These hold no action authority and have no write path to the system (ARC-005).

**Privilege summary:**
- User-level (no privileged OS capability): policy-engine, case-graph, reasoning-tiers, action-proposer, recovery-verifier, evidence-ledger, mesh-coordinator, enrolment-client, updater (verify), identity, tenancy, policy-signing, token-issuance, fleet-budget, telemetry-ingestion, console-api, audit, evidence-anchor.
- Privileged (minimal, only where unavoidable): containment-controller enforcement, os-adapters, watchdog, updater (install via os-adapters).
- Network: mesh-coordinator (peer), enrolment-client (control plane, enrolment only), updater (update service), control-plane services (internal/ingress as noted). Policy engine has **no network** (ARC-004).

**TCB minimisation rationale:** AI-bearing components (reasoning-tiers) are excluded from the TCB and have no write path; enforcement decisions are made by a small memory-safe policy engine operating on signed proposals and signed policy (ARC-004, ARC-005).

---

## 5. AI write-path prohibition (ARC-005)

No AI component (reasoning-tiers, and any future model) may:
- write to the evidence ledger, policy store, or configuration;
- call containment or recovery actions directly;
- modify its own prompts/policy without human-reviewed signed update (SEC-038, SEC-034).

AI outputs are recommendations consumed only by action-proposer, which must produce a signed proposal; the policy engine retains final authority.

---

## 6. Degraded-mode matrix

| State | T0 Evidence | T1 Advisory | T2 Containment | T3 Destructive/Recovery | Notes |
|---|---|---|---|---|---|
| Online | Allowed (full) | Allowed | Allowed (policy + corroboration + approval) | Allowed (human approval) | Normal operation |
| Partitioned | Allowed (local + queued sync) | Allowed (local only) | Allowed only for pre-authorised local rules with no external dependency; otherwise denied | Denied (R4 human path) | Peer-dependent T2 denied; fail-closed (ARC-009) |
| Fully offline | Allowed (local buffer) | Allowed (local only) | Denied | Denied | Evidence queued for later sync; no network actions |
| Control plane suspected compromised | Allowed (local + anchor paused) | Allowed (local) | Allowed under cached signed policy + local corroboration; no new fleet actions | Denied unless human-approved locally | Ignore control-plane updates; use last known good signed policy (SEC-022, SEC-030) |
| Node suspected compromised | Allowed (tamper-evident collection) | Denied | Denied (node cannot self-authorise) | Denied | Peers treat node as untrusted; recovery via re-enrolment (human path) |

**R4 (manual) actions always require a human path** (console/API with MFA + approval) regardless of state (ARC-015).

---

## 7. Performance and resource budgets (TARGETs)

All values are **TARGET (HYPOTHESIS)** until measured; measurement method stated. No claim of achieved performance is made (MR3).

| ID | Budget (TARGET) | Measurement method |
|---|---|---|
| PB-01 | Node agent average CPU <= 2% (TARGET) | OS perf counters sampled over 24 h under mixed load |
| PB-02 | Node agent RSS <= 256 MiB (TARGET) | RSS sampling at 1 Hz over 24 h |
| PB-03 | T0 evidence capture latency <= 1 s (TARGET) | Timestamp delta between event and ledger append (local) |
| PB-04 | Policy decision latency <= 5 ms (HYPOTHESIS) | Local benchmark harness, signed proposal to decision |
| PB-05 | Mesh message propagation <= 5 s (HYPOTHESIS) | End-to-end timestamp delta across peers |
| PB-06 | Control-plane API p99 <= 500 ms (HYPOTHESIS) | Load-test with representative tenant mix |
| PB-07 | Update verification time <= 30 s (HYPOTHESIS) | Timed verification of max-size artefact |
| PB-08 | Evidence anchor lag <= 60 s when online (HYPOTHESIS) | Timestamp delta node-to-control-plane |
| PB-09 | Watchdog detection of component failure <= 5 s (HYPOTHESIS) | Fault-injection test |

---

## 8. FMEA (>=25 rows)

| # | Component | Failure mode | Effect | Sev | Detection | Mitigation / Recovery class |
|---|---|---|---|---|---|---|
| 1 | sensors | Sensor crash | Reduced detection | M | watchdog | Restart; T0 continues via others (R1) |
| 2 | sensors | Sensor spoofed data | False observations | H | case-graph anomaly; SEC-029 | Discard invalid; quarantine sensor (R2) |
| 3 | case-graph | Crash | No cases built | M | watchdog | Restart; T0 continues (R1) |
| 4 | case-graph | Memory exhaustion | Node DoS | H | resource caps SEC-003 | Restart with caps; fail-closed T2+ (R2) |
| 5 | reasoning-tiers | Model hang | No recommendations | M | watchdog/timeout | Restart; T0 continues (R1) |
| 6 | reasoning-tiers | Prompt injection | Harmful recommendation | H | SEC-036 output validation | Reject; action-proposer blocks (R2) |
| 7 | action-proposer | Crash | No proposals | M | watchdog | Restart (R1) |
| 8 | action-proposer | Excessive proposals | Flood policy engine | M | rate limits | Throttle; fail-closed (R2) |
| 9 | policy-engine | Crash | No decisions | H | watchdog | Restart; fail-closed T2+ (R1/R2) |
| 10 | policy-engine | Corrupt policy bundle | Bad decisions | C | signature verify SEC-004 | Reject bundle; last known good (R3) |
| 11 | containment-controller | Partial enforcement | Incomplete containment | H | verifier | Retry; escalate (R2) |
| 12 | containment-controller | Over-enforcement (DW) | Business outage | C | protected lists SEC-007; human approval | Rollback; R4 human (R4) |
| 13 | recovery-verifier | False verification | Bad recovery | H | dual check | Block T3; human path (R4) |
| 14 | evidence-ledger | Write failure | Unlogged action risk | H | sync check | Block action; buffer (R2) |
| 15 | evidence-ledger | Tampering | Lost audit | C | anchoring SEC-026 | Detect via anchor; investigate (R3) |
| 16 | mesh-coordinator | Partition | Split-brain risk | H | heartbeat | Fail-closed; local mode (R1) |
| 17 | mesh-coordinator | Peer spoofing | False corroboration | C | attestation SEC-012 | Reject peer (R2) |
| 18 | enrolment-client | Enrolment failure | No mesh participation | M | retry/backoff | Manual re-enrol (R4) |
| 19 | updater | Bad update accepted | Fleet compromise | C | SEC-030/033 | Rollback; re-image (R3/R4) |
| 20 | updater | Update unavailable | Stale version | M | version check | Retry; manual (R4) |
| 21 | watchdog | Watchdog crash | No self-healing | H | external monitor | Control-plane alert; manual (R4) |
| 22 | os-adapters | Adapter mismatch | Action fails | M | error returns | Fail-closed; update adapter (R2) |
| 23 | identity (CP) | Outage | No new auth | H | health check | Existing tokens; retry (R1) |
| 24 | tenancy (CP) | Isolation bug | Cross-tenant bleed | C | isolation tests SEC-045 | Fail closed; incident (R4) |
| 25 | policy-signing (CP) | Key compromise | Malicious policy | C | key ceremony; SEC-033 | Revoke/rotate; investigate (R4) |
| 26 | token-issuance (CP) | Token leak | Account takeover | H | audit SEC-025 | Revoke tokens (R2) |
| 27 | fleet-budget (CP) | Mis-throttle | Service degradation | M | metrics | Adjust quota (R1) |
| 28 | telemetry-ingestion (CP) | Ingestion loss | Blind spots | M | lag metrics | Buffer at node; replay (R2) |
| 29 | console-api (CP) | XSS/CSRF | Account takeover | H | DAST SEC-041 | Patch; revoke sessions (R2) |
| 30 | audit (CP) | Audit gap | Unlogged actions | H | integrity check | Block privileged actions (R2) |
| 31 | evidence-anchor (CP) | Anchor lag | Delayed integrity proof | M | lag metric | Retry; local ledger authoritative (R2) |

**FMEA rows: 31 (>=25).**

---

## 9. Architecture Decision Records (>=10)

### ADR-001: Local policy engine holds final authority
- **Status:** Accepted
- **Context:** Need no single point of authority and resilience to control-plane compromise.
- **Decision:** Each node runs a local policy engine that is the sole authoriser of T2+ actions; control plane distributes signed policy but never commands actions directly.
- **Alternatives rejected:** Centralised decision service (single point of authority, control-plane compromise = fleet compromise); agent self-authorisation (violates ARC-004).
- **Traces:** ARC-014, SEC-004, SEC-022

### ADR-002: AI is advisory only with no write path
- **Status:** Accepted
- **Context:** Prompt injection and hallucination risks (TM-037, TM-038).
- **Decision:** AI components produce recommendations only; action-proposer creates signed proposals; policy engine decides. No AI write path (ARC-005).
- **Alternatives rejected:** AI direct action execution (violates MR2); AI in TCB (violates ARC-004).
- **Traces:** ARC-005, SEC-036, SEC-037

### ADR-003: Memory-safe language for TCB components
- **Status:** Accepted
- **Context:** Need small, memory-safe enforcement path (SEC-002, ARC-004).
- **Decision:** TCB components implemented in a memory-safe language; unsafe code only in minimal os-adapters with review.
- **Alternatives rejected:** C/C++ for entire node (memory-safety risk); rewriting OS kernel (out of scope).
- **Traces:** ARC-003, ARC-004, SEC-002

### ADR-004: Sandbox untrusted components
- **Status:** Accepted
- **Context:** Sensors, case-graph, reasoning, mesh coordinator are high-risk and compromise-prone.
- **Decision:** Run untrusted components in OS-level sandboxes with least privilege and no action authority.
- **Alternatives rejected:** Single process with in-process isolation (insufficient against compromise, MR6); separate VMs per component (resource cost, TARGET unmeasured).
- **Traces:** ARC-003, ARC-005

### ADR-005: Proven cryptography only
- **Status:** Accepted
- **Context:** MR8/MR? no custom crypto.
- **Decision:** Use established crypto libraries and standard algorithms; no custom cryptography (ARC-008).
- **Alternatives rejected:** Custom lightweight crypto (unverified, high risk); novel post-quantum schemes as default (premature; revisit on evidence).
- **Traces:** ARC-008, SEC-004, SEC-030

### ADR-006: Fail-closed enforcement for T2+
- **Status:** Accepted
- **Context:** Uncertainty must not cause harmful action.
- **Decision:** Enforcement actions T2 and above are denied on any uncertainty; T0 evidence collection always continues (ARC-006, ARC-007).
- **Alternatives rejected:** Fail-open (availability over safety, unacceptable); best-effort enforcement (non-deterministic).
- **Traces:** ARC-006, ARC-007, SEC-006

### ADR-007: Fail-closed on partition for peer-dependent actions
- **Status:** Accepted
- **Context:** Network adversary can partition (TM-017).
- **Decision:** Peer-dependent containment denied when quorum unavailable; node enters local mode.
- **Alternatives rejected:** Cached quorum acceptance (collusion risk, TM-021); single-peer trust (violates SEC-005).
- **Traces:** ARC-009, SEC-005, SEC-015

### ADR-008: Last known good policy on control-plane doubt
- **Status:** Accepted
- **Context:** Control plane may be compromised (ADV-04).
- **Decision:** Nodes verify signatures and use last known good signed policy within validity; ignore unverifiable updates.
- **Alternatives rejected:** Always accept latest (supply-chain risk); hard-coded policy (no adaptability).
- **Traces:** ARC-009, SEC-004, SEC-022, SEC-030

### ADR-009: Human approval for high-impact and R4 actions
- **Status:** Accepted
- **Context:** Defender-as-weapon risk (TM-009..TM-042).
- **Decision:** T3 and bulk T2 actions require human approval; R4 recovery is manual with documented path.
- **Alternatives rejected:** Fully autonomous high-impact (unacceptable risk); permanent manual-only (no value).
- **Traces:** ARC-015, SEC-018, SEC-007

### ADR-010: Append-only evidence with remote anchoring
- **Status:** Accepted
- **Context:** Repudiation and tampering risks (TM-005, TM-027).
- **Decision:** Node ledger append-only; control plane anchors hashes; WORM where available.
- **Alternatives rejected:** Mutable log (repudiation risk); fully centralised ledger (offline gap).
- **Traces:** ARC-007, SEC-009, SEC-026

### ADR-011: Degraded-mode local autonomy
- **Status:** Accepted
- **Context:** Availability under partition/outage.
- **Decision:** T0 always continues; T1 local; T2/T3 gated per degraded matrix.
- **Alternatives rejected:** Full shutdown on partition (availability loss); full autonomy (safety loss).
- **Traces:** ARC-009, ARC-007, SEC-006

### ADR-012: Component-level watchdog and restart
- **Status:** Accepted
- **Context:** Need resilience and detection of compromise.
- **Decision:** A privileged watchdog monitors components; restarts or quarantines; reports.
- **Alternatives rejected:** No watchdog (silent failure); watchdog with action authority (violates ARC-004 scope); watchdog remains TCB but action-limited.
- **Traces:** ARC-006, ARC-007, SEC-001

---

## 10. SEC-to-component mapping (ARC-016)

| SEC group | Components |
|---|---|
| SEC-001, SEC-002 | sensors, containment-controller, os-adapters, watchdog |
| SEC-003 | sensors, case-graph, policy-engine |
| SEC-004, SEC-022, SEC-030, SEC-034 | policy-engine, policy-signing, updater |
| SEC-005, SEC-006, SEC-017, SEC-018 | case-graph, action-proposer, policy-engine, console-api |
| SEC-007, SEC-008 | policy-engine, containment-controller |
| SEC-009, SEC-025, SEC-026 | evidence-ledger (node), audit, evidence-anchor |
| SEC-010, SEC-023, SEC-043, SEC-045 | tenancy, enrolment-client, console-api |
| SEC-011 | sensors, mesh-coordinator, reasoning-tiers |
| SEC-012, SEC-013, SEC-014, SEC-015, SEC-016 | mesh-coordinator |
| SEC-019, SEC-020, SEC-027, SEC-040, SEC-041, SEC-042 | identity, token-issuance, console-api |
| SEC-021 | policy-signing, console-api |
| SEC-024, SEC-044 | fleet-budget, telemetry-ingestion |
| SEC-028 | updater, mesh-coordinator, policy-engine |
| SEC-029 | telemetry-ingestion, sensors |
| SEC-031, SEC-032, SEC-033 | updater, policy-signing |
| SEC-035 | recovery-verifier, updater |
| SEC-036, SEC-037, SEC-038, SEC-039 | reasoning-tiers, action-proposer, policy-engine |
| SEC-044 | fleet-budget, telemetry-ingestion |

Every SEC-001..SEC-045 maps to at least one component above.

---

## 11. Dependency list (SBOM-ready, categories)

Versions and exact packages are TBD (P0.3/P0.5); categories only here.

| Category | Used by | Purpose |
|---|---|---|
| Memory-safe language runtime | TCB components | Safe execution (ADR-003) |
| OS sandbox/primitive APIs | os-adapters, sandboxed components | Containment, isolation (ADR-004) |
| Proven crypto library | policy-engine, policy-signing, updater, identity | Signing/verification (ADR-005) |
| Serialisation/schema library | telemetry, mesh, control plane | Structured data (P0.5) |
| Logging/observability SDK | all components | T0 evidence (ARC-007) |
| Network transport library | mesh-coordinator, enrolment-client, control plane | Peer/control-plane comms (P0.3) |
| Database/storage engine | control plane, evidence-anchor | Append-only storage (ADR-010) |
| Scheduler/watchdog primitives | watchdog | Health monitoring (ADR-012) |

---

## 12. R4 (manual) action human paths (ARC-015)

| R4 action | Human path |
|---|---|
| Re-enrolment of suspected-compromised node | Console operator (MFA) + approval; documented runbook |
| Manual rollback of bad update | Release authority (multi-party) + signed rollback instruction |
| Manual recovery from quarantine | Operator approval via console; policy-engine still gates |
| Re-imaging host | Local admin + evidence preserved; T0 ledger exported first |
| Key rotation after compromise | Key ceremony; multi-party signing (SEC-033) |

---

## Contract Closure

1. **Deliverables produced:**
   - Node decomposition with component cards (§2, 13 cards)
   - Control-plane decomposition with component cards (§3, 9 cards)
   - Privilege separation + TCB statement (§4)
   - AI write-path prohibition (§5)
   - Degraded-mode matrix (§6, 5 states)
   - Performance/resource budgets as TARGETs (§7, 9 budgets)
   - FMEA (§8, 31 rows)
   - ADR set (§9, 12 ADRs)
   - SEC-to-component mapping (§10)
   - SBOM-ready dependency list (§11)
   - R4 human paths (§12)

2. **Acceptance checks:**
   - Every SEC maps to at least one component: **PASS** (§10)
   - No single point of authority: **PASS** (ADR-001; local policy engine)
   - Every R4 action has a human path: **PASS** (§12)
   - Every component card complete: **PASS** (§2, §3)
   - FMEA >= 25 rows: **PASS** (31)
   - ADRs >= 10: **PASS** (12)
   - No AI write path: **PASS** (§5)
   - Fail-closed T2+: **PASS** (§1, §6)
   - T0 always continues: **PASS** (§1, §6)
   - No custom crypto: **PASS** (ADR-005)

3. **Assumptions made:** Core Design and detection-to-recovery flow absent (OQ-01/OQ-02); gate definitions from P0.1 assumed; budget values TARGET/HYPOTHESIS; dependency versions TBD.

4. **Open questions:**
   - OQ-01: Core Design (node components and authorisation tiers) not supplied; tier model assumed (T0–T3).
   - OQ-02: Detection-to-recovery flow not supplied; FMEA/degraded matrix derived from stated rules.
   - OQ-03: Numeric budgets are TARGET/HYPOTHESIS pending measurement.
   - OQ-04: Exact dependency versions/packages deferred to P0.3/P0.5.

5. **Out-of-scope items noticed (not acted on):** byte-level protocols (P0.3), policy language (P0.4), schemas (P0.5), code, technology version selection.

6. **Handoff:** Consumed by P0.3 (protocols), P0.4 (policy language), P0.5 (schemas), P0.10 (tests). Downstream must trace to ARC-xxx and SEC-xxx IDs. IDs to preserve: ARC-001..ARC-016, T0–T3, PB-01..PB-09, ADR-001..ADR-012.
