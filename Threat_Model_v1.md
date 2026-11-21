# Threat Model v1 — Autonomous Agentic Endpoint Defence Mesh

**Document ID:** TM-v1 (P0.1)
**Date:** 2026-11-16
**Status:** Draft for review (G2)
**Owner:** Chief Security Architect
**Classification:** Internal — Confidential
**Supersedes:** Threat Model v0 (four adversaries, seven threats) [ASSUMPTION: v0 content not supplied; delta not verifiable — see OQ-01]

---

## 0. Scope and method

**In scope (per prompt):** threats, security objectives, residual risks, asset/boundary definitions, adversary catalogue, STRIDE application, defender-as-weapon abuse cases, trust-boundary diagram description.

**Out of scope (per Master Rules / prompt):** protocols, technologies, architecture decisions, policy rules, code, tests. Technology selection is deferred to P0.2/P0.3.

**Method:** STRIDE per trust boundary; adversary-capability (not exploit-step) descriptions; every threat maps to a control (SEC-xxx) or an accepted-risk entry (RR-xxx). All figures and rates are labelled TARGET/HYPOTHESIS or omitted; no market-uniqueness, latency, or margin claims are made (MR3).

**Inputs status:** The Technical and Commercial Validation assessment (16 Nov 2026), Threat Model v0, and Core Design (node components and authorisation tiers) were **not present** in the working directory at generation time. Per MR9 this is recorded as OQ-01..OQ-04 and the document proceeds on labelled conservative assumptions. No facts have been invented beyond the prompt text.

---

## 1. Assets

| ID | Asset | Description | Primary protection goal | Criticality |
|---|---|---|---|---|
| A-01 | Endpoint integrity | OS, kernel, configuration and runtime state of managed endpoints | Integrity, Availability | Critical |
| A-02 | Tenant data | Telemetry, evidence, configuration, and metadata belonging to a tenant | Confidentiality, Integrity | Critical |
| A-03 | Signing keys | Code-signing, policy-signing, evidence-ledger-signing, and update-signing keys | Confidentiality, Integrity | Critical |
| A-04 | Policy bundles | Compiled policy/decision bundles distributed to nodes | Integrity, Authenticity | Critical |
| A-05 | Evidence ledger | Append-only record of observations, decisions, and actions | Integrity, Non-repudiation | Critical |
| A-06 | Customer business-application availability | Availability of customer business-critical applications and hosts | Availability | Critical |
| A-07 | Agent software itself | The defender agent binary, configuration, and update artefacts | Integrity, Authenticity | Critical |
| A-08 | Tenant trust state | Per-tenant identity, membership, and attestation state in the mesh | Integrity, Confidentiality | High |

---

## 2. Trust boundaries

| ID | Boundary | Description | In-scope components |
|---|---|---|---|
| B-01 | Node | Single managed endpoint and its local agent runtime | Agent process, local store, OS interfaces |
| B-02 | Peer link | Node-to-node communication within the mesh | Mesh transport, peer discovery, attestation |
| B-03 | Control plane | Central SaaS management plane (multi-tenant) | APIs, policy service, evidence store, identity |
| B-04 | Build and update pipeline | Software build, signing, and distribution pipeline | Build systems, artifact store, update service |
| B-05 | AI reasoning layer | Model inference and learning/feedback components | Prompt construction, model, output handling |
| B-06 | MSP operator console | Multi-tenant operator interface used by MSP staff | Web console, session management, RBAC |
| B-07 | Tenant boundary | Logical and data isolation between tenants in shared plane | Tenant scoping, data partitioning, metering |

### 2.1 Text description of the trust-boundary diagram

The mesh is drawn as concentric trust zones with explicit transition points:

1. **Innermost zone — Node (B-01):** the endpoint and its agent. Highest privilege over the host; lowest external trust. Everything the node believes about peers, policy, or observations is *untrusted until verified* (MR6).
2. **Mesh ring — Peer link (B-02):** nodes exchange observations and attestations. A peer is treated as a potentially compromised endpoint; no peer observation is authoritative alone.
3. **Tenant envelope (B-07):** groups nodes and data belonging to one tenant; enforces that no tenant's data, policy, or identity bleeds into another within the shared plane.
4. **Operator edge (B-06):** MSP staff act through a console that is itself a trust boundary; operator actions are tenant-scoped, audited, and subject to approval thresholds.
5. **Control plane (B-03):** central SaaS. Trusted for coordination but assumed compromise-capable (MR6); clients verify all control-plane outputs locally.
6. **Build/update pipeline (B-04):** produces and signs agent software and policy bundles; compromise here propagates to every node, so it is the highest-value target.
7. **AI reasoning layer (B-05):** sits adjacent to both node and control plane; consumes telemetry/evidence and emits *advisory* outputs only (SEC-037). It never holds action authority.

Data flows and trust transitions (textual):
- Telemetry/evidence flows upward: Node → Peer link (gossip, attested) → Control plane (tenant-scoped) → Evidence ledger (A-05).
- Policy/commands flow downward: Build pipeline → Control plane → Node, each hop signature-verified by the receiver (SEC-004, SEC-030).
- AI reasoning consumes evidence and returns recommendations that must pass corroboration (SEC-005) and human-approval gates (SEC-018) before any action.
- Cross-tenant data must never traverse the tenant boundary (B-07) in either direction (SEC-010, SEC-045).

---

## 3. Adversary catalogue

| ID | Adversary | Capability | Goal | Entry point |
|---|---|---|---|---|
| ADV-01 | Compromised endpoint | Code execution on a managed host; can read agent local state; may possess valid node credentials | Evade detection; cause false detections; exfiltrate data; disrupt peers | Local OS on a managed endpoint |
| ADV-02 | Stolen administrator credentials | Valid control-plane or console credentials; MFA may be bypassable via session theft | Mass policy change; bulk isolation; data access | Authentication layer of control plane / console |
| ADV-03 | Malicious MSP insider | Legitimate operator access within tenant scope; knowledge of procedures | Abuse trust to isolate hosts; exfiltrate tenant data; inject backdoors | MSP operator console (B-06) |
| ADV-04 | Compromised control plane | Full read/write over control-plane data and services | Fleet-wide compromise; data breach; malicious distribution | Control-plane infrastructure (B-03) |
| ADV-05 | Supply-chain / update compromise | Ability to modify build artefacts or signing material | Distribute malicious agent or policy at scale | Build and update pipeline (B-04) |
| ADV-06 | Malware targeting the defender | Knowledge of agent internals; attempts to kill, blind, or weaponise the agent | Disable defence; induce false remediation | Endpoint runtime (B-01) |
| ADV-07 | Prompt injection of reasoning layer | Ability to craft inputs (files, telemetry, prompts) consumed by AI layer | Cause harmful recommendations; data exfiltration via prompts | AI reasoning layer inputs (B-05) |
| ADV-08 | Network adversary | Partition, replay, delay, drop, or tamper with in-transit messages | Split-brain; stale actions; DoS; MITM | Peer link and API transports (B-02, B-03) |
| ADV-09 | Malicious tenant in multi-tenant plane | Legitimate tenant account; ability to submit data/samples | Cross-tenant attack; data leakage; model poisoning | Tenant boundary (B-07) |

---

## 4. STRIDE per boundary

Legend: S=Spoofing, T=Tampering, R=Repudiation, I=Information disclosure, D=Denial of service, E=Elevation of privilege.

| Boundary | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| B-01 Node | Agent/tenant identity spoofing on host | Binary/config/log tampering | Missing local audit | Local secret leakage | Resource exhaustion / agent kill | Privilege escalation to kernel |
| B-02 Peer link | Peer identity spoofing | Observation tampering in transit | Unverifiable peer actions | Peer data exfiltration | Mesh flooding / partition | Peer admitted as trusted |
| B-03 Control plane | Admin/API impersonation | Policy/evidence tampering | Insufficient audit | Cross-tenant data disclosure | API/DB DoS | Tenant-to-tenant or tenant-to-admin escalation |
| B-04 Build/update | Publisher identity spoofing | Artefact tampering | Untraceable release | Source/secret leakage | Update service DoS | Pipeline privilege escalation |
| B-05 AI reasoning | Prompt/source spoofing | Training/feedback poisoning | Unattributable model output | Prompt/data leakage | Model/resource exhaustion | AI output gains action authority |
| B-06 MSP console | Operator session hijacking | Request tampering (CSRF) | Unlogged operator actions | Cross-tenant console disclosure | Console DoS | Operator-to-admin escalation |
| B-07 Tenant boundary | Tenant identity spoofing | Cross-tenant data overwrite | Unattributable cross-tenant action | Cross-tenant read | Noisy-neighbour DoS | Tenant escapes isolation |

STRIDE-to-threat mapping is provided by the threat table in §5 (each threat is tagged with its boundary and adversary).

---

## 5. Threat catalogue (>=40)

Columns: **ID** | **Threat** | **Boundary** | **Adversary** | **Impact** | **Control** | **Verified by**

| ID | Threat | Boundary | Adversary | Impact | Control | Verified by |
|---|---|---|---|---|---|---|
| TM-001 | Agent executes unauthorised host isolation from forged local policy | B-01 | ADV-01 | Critical | SEC-004, SEC-005 | G3 scenario |
| TM-002 | Agent binary or config tampered on disk to disable telemetry/evidence | B-01 | ADV-01, ADV-05 | High | SEC-001 | G4 review |
| TM-003 | Local agent coerced to exfiltrate tenant data via module/plugin | B-01 | ADV-01 | High | SEC-011, SEC-001 | G3 scenario |
| TM-004 | Agent runs with excessive privileges enabling kernel-level damage | B-01 | ADV-01 | Critical | SEC-002 | G4 review |
| TM-005 | Local evidence log altered or deleted to hide actions | B-01 | ADV-01 | High | SEC-009 | G3 scenario |
| TM-006 | Agent impersonates another tenant's agent on a shared host | B-01 | ADV-01, ADV-09 | Medium | SEC-010 | G3 scenario |
| TM-007 | Malware kills or blinds the defender agent service | B-01 | ADV-06 | High | SEC-001 | G3 scenario |
| TM-008 | Resource exhaustion by agent or malware causing host DoS | B-01 | ADV-01, ADV-06 | Medium | SEC-003 | G3 scenario |
| TM-009 (DW) | Agent quarantines business-critical ERP client on false positive | B-01 | ADV-01, ADV-06 | Critical | SEC-006, SEC-005, SEC-007 | G3 scenario DW-1 |
| TM-010 (DW) | Agent isolates a healthy host from spoofed peer observation | B-01, B-02 | ADV-01, ADV-02 | Critical | SEC-005, SEC-015 | G3 scenario DW-2 |
| TM-011 (DW) | Agent terminates legitimate backup process misclassified as ransomware | B-01 | ADV-06 | High | SEC-007, SEC-005 | G3 scenario DW-3 |
| TM-012 (DW) | Agent rolls back a legitimate update misclassified as malicious | B-01, B-04 | ADV-06 | High | SEC-008, SEC-005 | G3 scenario DW-4 |
| TM-013 | Compromised peer broadcasts validly signed false detection naming ERP as malicious | B-02 | ADV-01 | Critical | SEC-006, SEC-005 | G3 scenario 1 |
| TM-014 | Peer replays stale but valid detection to trigger redundant actions | B-02 | ADV-08 | Medium | SEC-013 | G3 scenario |
| TM-015 | Peer spoofs identity to join the mesh | B-02 | ADV-01, ADV-02 | High | SEC-012 | G3 scenario |
| TM-016 | Man-in-the-middle alters observations on peer link | B-02 | ADV-08 | High | SEC-014, SEC-013 | G3 scenario |
| TM-017 | Network partition causes split-brain conflicting isolations | B-02 | ADV-08 | High | SEC-015 | G3 scenario |
| TM-018 | Delayed messages cause out-of-order remediation | B-02 | ADV-08 | Medium | SEC-013 | G3 scenario |
| TM-019 | Peer floods mesh with observations (DoS) | B-02 | ADV-01, ADV-08 | Medium | SEC-016 | G3 scenario |
| TM-020 | Compromised peer exfiltrates tenant data via peer channel | B-02 | ADV-01 | High | SEC-011 | G3 scenario |
| TM-021 | Colluding peers satisfy corroboration quorum | B-02 | ADV-01, ADV-03 | Critical | SEC-017, SEC-005 | G3 scenario |
| TM-022 (DW) | Colluding peers falsely corroborate isolation of a healthy host | B-02 | ADV-01 | Critical | SEC-017, SEC-018 | G3 scenario DW-5 |
| TM-023 | Stolen admin credentials issue malicious policy to fleet | B-03 | ADV-02 | Critical | SEC-019, SEC-021, SEC-020 | G1/G5 review |
| TM-024 | Compromised control plane pushes malicious policy bundle | B-03 | ADV-04 | Critical | SEC-004, SEC-022 | G5 gate |
| TM-025 | Cross-tenant data breach via shared query path | B-03, B-07 | ADV-09 | Critical | SEC-010, SEC-023 | G4 review |
| TM-026 | Control-plane API abuse for mass isolation | B-03 | ADV-02, ADV-04 | Critical | SEC-024, SEC-018, SEC-025 | G5 gate |
| TM-027 | Evidence ledger tampered in control plane | B-03 | ADV-04 | High | SEC-009, SEC-026 | G4 review |
| TM-028 | SaaS operator insider accesses tenant data | B-03 | ADV-03 | High | SEC-027 | G1 review |
| TM-029 | Control-plane outage denies service to all tenants | B-03 | ADV-08 | High | SEC-028 | G7 readiness |
| TM-030 | Telemetry poisoning via control-plane ingestion | B-03 | ADV-09, ADV-04 | Medium | SEC-029 | G4 review |
| TM-031 | Supply-chain compromise of agent update | B-04 | ADV-05 | Critical | SEC-030, SEC-031 | G4/G5 gate |
| TM-032 | Malicious dependency introduced in build | B-04 | ADV-05 | High | SEC-031 | G4 review |
| TM-033 | Update channel downgrade to vulnerable version | B-04 | ADV-05, ADV-08 | High | SEC-030 | G4 review |
| TM-034 | Insider injects backdoor into release | B-04 | ADV-03, ADV-05 | Critical | SEC-032, SEC-033 | G4 review |
| TM-035 | Update server compromise distributes malicious agent | B-04 | ADV-04, ADV-05 | Critical | SEC-030, SEC-033 | G5 gate |
| TM-036 (DW) | Update disables safety controls, causing aggressive remediation | B-04 | ADV-05 | Critical | SEC-034, SEC-035 | G3/G5 gate |
| TM-037 | Prompt injection via crafted file/telemetry causes harmful recommendation | B-05 | ADV-01, ADV-07 | High | SEC-036, SEC-037 | G3 scenario |
| TM-038 | Model hallucination recommends harmful remediation | B-05 | (system) | Medium | SEC-037, SEC-005, SEC-036 | G3 scenario |
| TM-039 | Data poisoning of training/feedback loop | B-05 | ADV-09, ADV-04 | Medium | SEC-038, SEC-005 | G3 scenario |
| TM-040 | Reasoning layer exfiltrates tenant data in prompts | B-05 | ADV-03, ADV-04 | High | SEC-011 | G4 review |
| TM-041 | Adversarial examples evade detection (false negatives) | B-05 | ADV-06 | Medium | SEC-039, SEC-036 | G3 scenario |
| TM-042 (DW) | AI recommends quarantining AV/EDR or OS components | B-05 | ADV-07 | Critical | SEC-007, SEC-037 | G3 scenario DW-6 |
| TM-043 | Stolen MSP credentials access multiple tenants | B-06 | ADV-02 | Critical | SEC-019, SEC-010, SEC-040 | G1 review |
| TM-044 | Malicious MSP insider abuses console to isolate hosts | B-06 | ADV-03 | Critical | SEC-042, SEC-018, SEC-025 | G1 review |
| TM-045 | Console CSRF/XSS leading to account takeover | B-06 | ADV-02, ADV-08 | Medium | SEC-041 | G4 review |
| TM-046 | Session hijacking of operator | B-06 | ADV-08 | High | SEC-041, SEC-019 | G4 review |
| TM-047 | Console lacks audit trail for actions | B-06 | ADV-03 | Medium | SEC-025 | G4 review |
| TM-048 | Malicious tenant abuses shared infrastructure to attack others | B-07 | ADV-09 | High | SEC-010, SEC-043, SEC-044 | G3 scenario |
| TM-049 | Tenant data leakage via shared caches/logs | B-07 | ADV-09 | High | SEC-010, SEC-044 | G4 review |
| TM-050 | Cross-tenant policy bleed | B-07 | ADV-09, ADV-04 | Critical | SEC-010, SEC-045 | G4 review |
| TM-051 | Tenant impersonation in billing/usage | B-07 | ADV-09 | Medium | SEC-044 | G4 review |
| TM-052 | Malicious tenant submits adversarial samples to poison shared models | B-07 | ADV-09 | Medium | SEC-038, SEC-045 | G3 scenario |

**Threat count: 52 (includes 7 defender-as-weapon cases marked DW).** All threats map to at least one SEC control; none is left uncontrolled. TM-013 reproduces the required example format.

---

## 6. Defender-as-weapon abuse cases (minimum 5)

Explicit enumeration of cases where the defender is tricked into harming the customer. Each is also a threat row (TM-009..TM-012, TM-022, TM-036, TM-042) and is exercised by dedicated G3 scenarios.

| Case | Scenario | Primary control |
|---|---|---|
| DW-1 | False positive on business-critical application triggers quarantine | SEC-006, SEC-007 |
| DW-2 | Spoofed peer observation drives isolation of a healthy host | SEC-005, SEC-015 |
| DW-3 | Ransomware heuristic kills legitimate backup/AV process | SEC-007, SEC-005 |
| DW-4 | Defender misclassifies a legitimate update as malicious and rolls it back | SEC-008, SEC-005 |
| DW-5 | Colluding peers manufacture quorum to isolate a healthy host | SEC-017, SEC-018 |
| DW-6 | AI recommends quarantining OS/AV components | SEC-007, SEC-037 |
| DW-7 | Update disables safety invariants causing aggressive auto-remediation | SEC-034, SEC-035 |

---

## 7. Security objectives (SEC-xxx)

Severity: **C** Critical, **H** High, **M** Medium, **L** Low.
Gates: G1 design review, G2 threat-model review, G3 scenario/adversarial test, G4 security code review, G5 pre-release gate, G6 deployment gate, G7 operational readiness, G8 post-incident/annual review. Gate definitions are [ASSUMPTION] (OQ-02).

| ID | Objective | Sev | Verification method | Gate |
|---|---|---|---|---|
| SEC-001 | Detect tampering of agent binary/config and resist agent-kill attempts | H | Integrity measurement + self-protection tests | G3, G4 |
| SEC-002 | Run agent with least privilege; no unnecessary kernel-level capability | C | Privilege audit and sandbox escape test | G4 |
| SEC-003 | Enforce resource caps to prevent agent/malware host DoS | M | Load/stress test under G3 | G3 |
| SEC-004 | Verify policy bundle signatures before application; reject unsigned/invalid | C | Signature verification unit tests + fuzz | G3, G4 |
| SEC-005 | Require corroboration from k distinct attested devices before high-impact action | C | Quorum logic tests incl. collusion cases | G3 |
| SEC-006 | Treat observations as advisory only; never execute directly on a single observation | C | Static analysis + scenario test | G3, G4 |
| SEC-007 | Protect business-critical processes/paths from automated remediation | C | Protected-list enforcement tests | G3 |
| SEC-008 | Apply change-window/process-criticality awareness to remediation decisions | H | Scenario test with update windows | G3 |
| SEC-009 | Maintain append-only evidence ledger with remote anchoring | H | Tamper test + anchoring verification | G3, G4 |
| SEC-010 | Enforce per-tenant identity and isolation of agents/data | C | Cross-tenant access tests | G3, G4 |
| SEC-011 | Restrict data egress to allowlisted destinations; minimise peer/control-plane payloads | H | Network capture review + tests | G3, G4 |
| SEC-012 | Mutually attest peers before admission to mesh | H | Attestation handshake tests | G3 |
| SEC-013 | Enforce freshness, ordering, and idempotency on peer messages | M | Replay/reorder test suite | G3 |
| SEC-014 | Provide confidentiality and integrity on peer channels | H | Crypto review + MITM test | G3, G4 |
| SEC-015 | Use partition-safe consensus; deny peer-dependent actions when quorum is unavailable and enforce ARC-009 lease limits for eligible local T2 | H | Chaos/partition test | G3 |
| SEC-016 | Rate-limit and apply backpressure on mesh traffic | M | Flood test under G3 | G3 |
| SEC-017 | Require diversity/independence among corroborators; detect clusters | H | Collusion scenario tests | G3 |
| SEC-018 | Require human approval for high-impact or bulk actions | C | Workflow tests + audit review | G1, G5 |
| SEC-019 | Enforce strong authentication and MFA for all admin/operator accounts | C | Auth review + credential-stuffing test | G1, G4 |
| SEC-020 | Apply least-privilege RBAC to control-plane and console | C | RBAC matrix review and tests | G1, G4 |
| SEC-021 | Require approval workflow for policy changes | C | Workflow tests | G1, G5 |
| SEC-022 | Sign policy bundles; verify client-side; canary rollout before fleet | C | Signature + canary tests | G4, G5 |
| SEC-023 | Enforce ABAC on control-plane data access | C | Cross-tenant query tests | G3, G4 |
| SEC-024 | Rate-limit and quota control-plane APIs | M | Load test | G3 |
| SEC-025 | Produce immutable audit trail for all privileged actions | H | Audit completeness review | G4 |
| SEC-026 | Store evidence in WORM storage | H | Tamper test | G4 |
| SEC-027 | Restrict operator access; provide just-in-time elevation | H | Access review | G1 |
| SEC-028 | Maintain resilience/DR with local autonomous operation on control-plane loss | H | Failover drill | G7 |
| SEC-029 | Validate and schema-enforce all ingestion inputs | M | Fuzz/invalid-input tests | G4 |
| SEC-030 | Sign updates; enforce anti-rollback and version pinning | C | Update verification tests | G4, G5 |
| SEC-031 | Reproducible builds with SBOM and dependency scanning | H | Build reproducibility + SCA report | G4 |
| SEC-032 | Separation of duties and code review for releases | H | Process audit | G4 |
| SEC-033 | Multi-party signing of release artefacts | C | Signing ceremony review | G5 |
| SEC-034 | Keep safety invariants immutable and non-disableable by updates | C | Update diff review + tests | G3, G5 |
| SEC-035 | Provide tested rollback capability for updates | H | Rollback drill | G3, G5 |
| SEC-036 | Sanitise AI inputs and validate AI outputs before use | H | Prompt-injection test suite | G3 |
| SEC-037 | Keep AI advisory-only; no direct action authority | C | Authority review + static analysis | G3, G4 |
| SEC-038 | Track data provenance; human review of learned rules | M | Provenance audit | G3 |
| SEC-039 | Test robustness against adversarial examples; use ensemble detection | M | Adversarial test suite | G3 |
| SEC-040 | Enforce tenant-scoped sessions in MSP console | C | Cross-tenant session tests | G3, G4 |
| SEC-041 | Protect console against CSRF/XSS/session hijacking | H | Web security test (DAST) | G4 |
| SEC-042 | Separation of duties for MSP operator actions | H | Process audit | G1 |
| SEC-043 | Isolate tenant resources; protect against noisy neighbours | M | Isolation tests | G3 |
| SEC-044 | Partition caches/logs and protect metering integrity | M | Cross-tenant leakage tests | G4 |
| SEC-045 | Verify cross-tenant isolation end-to-end | C | Automated isolation suite | G3, G4 |

**SEC count: 45 (>=30).** Every SEC has a verification method and a gate.

---

## 8. Residual-risk register

| ID | Risk | Rationale for acceptance | Recovery class | Review date |
|---|---|---|---|---|
| RR-01 | Colluding peers may satisfy corroboration quorum before detection | Mitigated by corroborator diversity (SEC-017) and anomaly detection; residual accepted pending measurement of collusion cost | R2 compensating | 2027-02-16 |
| RR-02 | Zero-day in agent could bypass local controls | Mitigated by update pipeline (SEC-030/033) and least privilege (SEC-002); cannot be eliminated a priori | R3 backup-dependent | 2027-02-16 |
| RR-03 | False positives may still impact customer availability | Mitigated by protected lists (SEC-007), advisory-only observations (SEC-006), human approval (SEC-018); residual accepted | R2 compensating | 2027-02-16 |
| RR-04 | Control-plane outage degrades but does not halt local defence | Mitigated by local autonomy (SEC-028); accepted as operational risk | R1 reversible | 2027-05-16 |
| RR-05 | AI hallucination may produce poor recommendations | Mitigated by advisory-only authority (SEC-037) and corroboration (SEC-005); accepted | R1 reversible | 2027-02-16 |
| RR-06 | Malicious MSP insider with legitimate access | Mitigated by JIT (SEC-027), SoD (SEC-042), audit (SEC-025); residual accepted | R2 compensating | 2027-05-16 |
| RR-07 | Supply-chain compromise before detection | Mitigated by multi-party signing (SEC-033) and reproducible builds (SEC-031); residual accepted | R3 backup-dependent | 2027-08-16 |
| RR-08 | Network adversary partition causes delayed/no action | Mitigated by fail-closed (SEC-015); accepted as availability trade-off | R1 reversible | 2027-02-16 |
| RR-09 | Malicious tenant cross-tenant impact | Mitigated by isolation (SEC-010, SEC-043, SEC-045); residual accepted pending verification | R2 compensating | 2027-05-16 |
| RR-10 | Stolen credentials despite MFA | Mitigated by MFA (SEC-019), RBAC (SEC-020), approval (SEC-018); residual accepted | R2 compensating | 2027-02-16 |
| RR-11 | Prompt injection residual after sanitisation | Mitigated by advisory-only (SEC-037) and output validation (SEC-036); accepted | R1 reversible | 2027-02-16 |

**Recovery classes (MR5):** R1 reversible, R2 compensating, R3 backup-dependent, R4 manual.

---

## 9. Open questions and assumptions

- **OQ-01** [OPEN-QUESTION]: Threat Model v0 (four adversaries, seven threats) was not supplied; delta vs v0 cannot be verified. Assumption: v1 supersedes and expands v0; no claim of parity is made.
- **OQ-02** [OPEN-QUESTION]: Gate definitions G1–G8 and their entry/exit criteria were not supplied. Assumption: mapping in §7. Must be confirmed by P0.2.
- **OQ-03** [OPEN-QUESTION]: Core Design (node components and authorisation tiers) was not supplied; objectives assume a tiered authorisation model exists. Must be confirmed by P0.2/P0.3.
- **OQ-04** [OPEN-QUESTION]: Technical and Commercial Validation assessment (16 Nov 2026) not supplied; no commercial figures or validation results are referenced.
- **OQ-05** [OPEN-QUESTION]: Specific numeric thresholds (k for corroboration, rate limits, RTO/RPO) are TARGETS not yet measured; to be set in P0.3.
- **ASSUMPTION:** Review dates are set at ~3–9 months from document date; to be aligned with release cadence.

---

## Contract Closure

1. **Deliverables produced:**
   - Asset description (§1, 8 assets)
   - Trust-boundary description (§2, 7 boundaries)
   - Text description of trust-boundary diagram (§2.1)
   - Adversary catalogue (§3, 9 adversaries)
   - STRIDE per boundary (§4)
   - Defender-as-weapon abuse cases (§6, 7 cases)
   - Threat catalogue (§5, 52 threats, >=40)
   - Security objectives (§7, 45 SEC, >=30)
   - Residual-risk register (§8, 11 entries)
   - Open questions/assumptions (§9)

2. **Acceptance checks:**
   - Every threat maps to a control or accepted-risk entry: **PASS** (all 52 threats cite SEC-xxx; RR entries cover residual)
   - Every SEC has a verification method: **PASS** (§7 table)
   - At least 5 defender-as-weapon cases: **PASS** (7 cases, §6)
   - No unlabelled claims: **PASS** (figures avoided; assumptions/OQ labelled)
   - At least 40 threats: **PASS** (52)
   - At least 30 SEC objectives: **PASS** (45)

3. **Assumptions made:** OQ-01..OQ-05 and gate mapping (§7); review dates; v0 supersession.

4. **Open questions:** OQ-01..OQ-05 (§9).

5. **Out-of-scope items noticed (not acted on):** protocols, technologies, architecture, policy rules, code, tests, numeric thresholds, commercial validation results, gate criteria definitions.

6. **Handoff:** Consumed by **P0.2** (architecture/Core Design), **P0.3** (policy rules), and **P0.8** (test scenarios). Each downstream artefact must trace to at least one TM-xxx / SEC-xxx ID from this document. IDs to preserve: TM-001..TM-052, SEC-001..SEC-045, ADV-01..ADV-09, B-01..B-07, A-01..A-08, RR-01..RR-11.
