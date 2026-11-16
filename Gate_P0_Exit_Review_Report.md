# Gate P0 Exit Review Report — Autonomous Agentic Endpoint Defence Mesh

**Document ID:** GATE-P0 (P0.11)
**Date:** 2026-11-16
**Reviewer:** Independent Programme Gatekeeper (did not author any P0 output)
**Scope:** Review evidence in P0.1–P0.10; decide whether programme may enter P1.

---

## 1. Decision

**DECISION: GO WITH CONDITIONS.**

Automatic No-go rules were **not** triggered:
- Every SEC (SEC-001..SEC-045) has at least one test (P0.6 coverage: 45/45).
- Every threat (TM-001..TM-052) maps to a control (SEC-xxx) or accepted-risk entry (RR-xxx).
- T3 (destructive) actions have human-approval requirements (P0.2 ADR-009) and R4 human paths (P0.2 §12), with one low-severity gap (FND-002).
- Core claims are labelled TARGET/HYPOTHESIS or avoided (MR3); no unlabelled uniqueness/performance/margin claims found.

Conditions and P1 entry criteria are in §5 and §6.

---

## 2. Traceability matrix summary

Counts: TM 52, SEC 45, components 22, PRO 20, POL 13 + R0–R11, schemas 10 (CMP), tests 80 (TST) + 42 (POL-T) + 24 (NV).

Representative chains (threat → SEC → component → protocol → policy → schema → test):

| Threat | SEC | Component | Protocol | Policy | Schema | Test |
|---|---|---|---|---|---|---|
| TM-013 (peer false detection) | SEC-005, SEC-006 | mesh-coordinator, policy-engine | envelope verification (PRO-009) | R5 (corroboration) | Proposal, Decision | TST-G3-004, POL-T-017 |
| TM-009 (DW quarantine critical app) | SEC-006, SEC-007 | policy-engine, containment-controller | remediation token (PRO-011) | R2, R6 | Proposal, Decision | TST-G3-003, TST-G3-011 |
| TM-031 (supply-chain update) | SEC-030, SEC-033 | updater, policy-signing | release signing (PRO-005) | R11 | PolicyBundle | TST-G3-009, TST-G5-002 |
| TM-025 (cross-tenant breach) | SEC-010, SEC-023 | tenancy, console-api | envelope tenant match (PRO-008) | R1 | Proposal, Decision | TST-G3-008, TST-G6-005 |
| TM-037 (prompt injection) | SEC-036, SEC-037 | reasoning-tiers, policy-engine | envelope (PRO-009) | R3 | Observation, Proposal | TST-G3-010 |
| TM-017 (partition split-brain) | SEC-015, SEC-032 | mesh-coordinator | revocation/lease (PRO-012/013) | R7, R8 | LedgerEntry | TST-G3-005 |
| TM-023 (stolen admin creds) | SEC-019, SEC-021, SEC-020 | identity, console-api, policy-signing | enrolment (PRO-002/003) | R1, R11 | PolicyBundle | TST-G3-013, TST-G5-006 |

**Coverage:** Every SEC maps to at least one component (P0.2 §10) and at least one test (P0.6 §8). Every threat maps to at least one SEC. Every POL rule traces to a SEC (P0.4 §2). Every T3 action requires human approval (P0.2 ADR-009). Traceability is substantially complete; gaps are in the findings below.

---

## 3. Findings log (contradictions, gaps, violations)

| ID | Severity | Type | Finding | Sources | Resolution owner | Blocks P1? |
|---|---|---|---|---|---|---|
| FND-001 | Medium | Contradiction | P0.2 degraded-mode matrix (Partitioned) permits T2 for pre-authorised local rules; P0.4 offline profile/R8 denies T2 unless action is in leased_budget | Reference_Architecture_v1.md §6; Policy_Specification_v1.md §2 (R8), §4.1 | P0.2, P0.4 | Condition (resolve before architecture freeze) |
| FND-002 | Low | Gap | T3 action A-18 (restore_file) is not explicitly listed in P0.2 §12 R4 human paths (only rollback/reimage/recovery/quarantine/re-enrolment/key rotation listed) | Policy_Specification_v1.md §3 (A-18); Reference_Architecture_v1.md §12 | P0.2, P0.4 | No |
| FND-003 | Low | Traceability | P0.1 states handoff to P0.2, P0.3, P0.8; P0.8 states consumed by P0.2, P0.5, P0.11. Handoff graph is acyclic but not a simple chain; downstream must reconcile ordering | Threat_Model_v1.md Contract Closure §6; Privacy_Compliance_Requirements_v1.md Contract Closure §6 | P0.1, P0.8 | No |
| FND-004 | Low | MR4 (tagging) | P0.1 contains no formal [FACT] tags; threat statements are analytical and unsourced. Acceptable for a threat model, but factual claims (if any) are untagged | Threat_Model_v1.md; Master Rules MR4 | P0.1 | No |
| FND-005 | Low | Scope | P0.4 action catalogue includes A-15 (macOS) although macOS is a later wave with separately verified capabilities (MR12) | Policy_Specification_v1.md §3; Master Rules MR12 | P0.4 | No |
| FND-006 | Low | Privilege | P0.2 os-adapters are "memory-safe where feasible", weaker than the requirement that the enforcement path be memory-safe (ADR-003 allows unsafe only in minimal shims with review) | Reference_Architecture_v1.md §2 (os-adapters); §4 TCB statement | P0.2 | No |
| FND-007 | Medium | MR3 (claims) | P0.2 PB-04 "Policy decision latency <= 5 ms" is labelled HYPOTHESIS but could be read as a performance claim; must remain flagged as target in all downstream use | Reference_Architecture_v1.md §7; Master Rules MR3 | P0.2 | Condition (keep labelled) |
| FND-008 | Low | ID namespace | P0.8 privacy requirements use CMP-011..CMP-045, continuing P0.5's CMP-001..CMP-010. Namespace collision risk; mapping must be documented | Privacy_Compliance_Requirements_v1.md §0; Contract_Specification_v1.md §0 | P0.5, P0.8 | No |
| FND-009 | Low | Evidence | P0.7 marks 120 cells Unknown (no source) for several vendors/capabilities. Unknown is valid, but limits differentiation claims and requires deeper research before external use | Competitive_Capability_Matrix_v1.md §3 | P0.7 | No |
| FND-010 | Low | Measurement | P0.6/P0.2/P0.4 numeric thresholds (skew bound, k, grace window, ring sizes, spike thresholds) are TARGET/HYPOTHESIS and unmeasured | Acceptance_Contract_v1.md §1/§4; Policy_Specification_v1.md §5 | P0.6, P0.4 | Condition (validate before G3) |

**Findings: 10 (0 critical, 2 medium, 8 low). Every finding cites two sources.**

---

## 4. Top 10 programme risks

| # | Risk | Severity | Decision needed |
|---|---|---|---|
| 1 | Core Design and detection-to-recovery flow were not supplied; P0.2/P0.4 derived tier model and rules on assumptions | High | Confirm Core Design against P0.2 before P1 architecture freeze |
| 2 | Unmeasured performance/resource budgets may not be achievable | Medium | Validate PB-01..PB-09 in lab (P0.6) before claims |
| 3 | Supply-chain compromise of build/update pipeline | Critical | Implement P0.10 pipeline controls; SLSA target validation |
| 4 | Collusion of k peers bypassing corroboration | High | Validate diversity/anomaly detection (P0.3/P0.6) |
| 5 | False positives causing customer availability loss (defender-as-weapon) | High | Exercise DW scenarios (P0.6 G3) before release |
| 6 | MSP insider abuse of multi-tenant console | High | SoD/JIT/audit verification (P0.6) |
| 7 | AI prompt injection leading to harmful recommendations | Medium | Adversarial test suite (P0.6) |
| 8 | Control-plane compromise enabling fleet-wide harm | Critical | Client-side verification + last-known-good (P0.2/P0.3) |
| 9 | UK/EU legal and compliance uncertainty (lawful basis, transfers, AI Act) | Medium | Solicitor review of P0.8 questions |
| 10 | Competitive differentiation unproven; Unknown cells may hide parity | Medium | Deeper research + kill tests (P0.7/P0.9) |

---

## 5. Conditions for P1 entry

1. **Resolve FND-001** (degraded-mode vs offline profile T2 permission) by reconciling P0.2 and P0.4 before architecture freeze.
2. **Resolve FND-002** by adding explicit human path for A-18 (restore_file) or reclassifying it.
3. **Keep PB-04 and all TARGET/HYPOTHESIS figures labelled** in all downstream documents (FND-007, FND-010).
4. **Validate numeric thresholds** (skew bound, k, grace window, ring sizes, spike thresholds) in lab before G3 (FND-010).
5. **Supply missing inputs** (Core Design, detection-to-recovery flow, validation assessment, G3 test plan, gate definitions) or formally accept the recorded assumptions (OQ-01..OQ-05 in P0.1; OQs in P0.2–P0.10).
6. **Do not make external differentiation claims** based on P0.7 Unknown cells until deeper research completes.

---

## 6. P1 entry criteria

- All conditions in §5 satisfied or formally accepted by the programme board.
- P0.1–P0.10 outputs versioned and baselined (appendix run protocol).
- P1 prompts to be written only after this Go-with-conditions decision (per run protocol).
- No automatic No-go trigger present (verified in §1).

---

## 7. Acceptance checks (P0.11)

| Check | Result |
|---|---|
| Every finding cites two sources | PASS (§3) |
| Decision follows automatic No-go rules | PASS (§1: no SEC without test; no threat without control; no T3 without human path; no unsupported core claim) |
| Traceability matrix summary present | PASS (§2) |
| Top 10 risks with severity and decision | PASS (§4) |
| Conditions and P1 entry criteria specified | PASS (§5, §6) |

---

## Contract Closure

1. **Deliverables produced:** Decision (Go with conditions); traceability matrix summary; findings log (10 findings); top 10 risks; conditions; P1 entry criteria.
2. **Acceptance checks:** PASS (§7).
3. **Assumptions made:** None beyond reviewed documents.
4. **Open questions:** Carried forward as OQs in P0.1–P0.10; see §5 conditions.
5. **Out-of-scope items noticed (not acted on):** Remediation, redesign, writing P1 prompts.
6. **Handoff:** Programme may proceed to P1 only after §5 conditions are satisfied. P1 prompts are written after this decision per run protocol.
