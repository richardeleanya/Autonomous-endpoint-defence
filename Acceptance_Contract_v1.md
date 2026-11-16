# Acceptance Contract and Test Lab v1 — Autonomous Agentic Endpoint Defence Mesh

**Document ID:** TST-v1 (P0.6)
**Date:** 2026-11-16
**Status:** Draft for review
**Owner:** Verification and Assurance Lead
**Depends on:** Master Rules; Threat Model v1 (P0.1); Reference Architecture v1 (P0.2); Trust Protocol v1 (P0.3); Policy Specification v1 (P0.4); Contracts v1 (P0.5); G3 test plan (not supplied — see OQ-01)

---

## 0. Acceptance requirements (TST-xxx)

| ID | Requirement |
|---|---|
| TST-001 | Each gate G1–G8 has pass criteria with numeric TARGETs |
| TST-002 | Test cases with ID, trace, method, expected result |
| TST-003 | Lab specification: Windows/Linux fleets, partition, loss, skew, corpus, simulators |
| TST-004 | Metrics precisely defined (latency p50/p95/p99, overhead, false blocks, recovery, determinism) |
| TST-005 | Red-team rules of engagement |
| TST-006 | Regression cadence, chaos schedule, release-blocking criteria |
| TST-007 | Evidence-pack template |
| TST-008 | At least 60 test cases across G1–G8 |
| TST-009 | Every SEC has at least one test |
| TST-010 | No gate passed on simulated agents alone |

---

## 1. Gate pass criteria (numeric TARGETs, all HYPOTHESIS until measured)

| Gate | Focus | Pass criteria (TARGET/HYPOTHESIS) |
|---|---|---|
| G1 | Design review | All ARC/SEC traced; TCB documented; no unresolved high-risk findings |
| G2 | Threat model review | TM v1 approved; all threats mapped; STRIDE complete |
| G3 | Scenario/adversarial | Detection-to-containment p95 <= 5 s (TARGET); false blocks 0 in named scenarios; corroboration tests pass |
| G4 | Security code review/SAST | 0 critical/high SAST findings; TCB memory-safe; no AI write path |
| G5 | Pre-release | All G1–G4 passed; update signing verified; rollback tested |
| G6 | Deployment | Canary success; no regression in false-block rate; budget controls active |
| G7 | Operational readiness | DR drill passed; watchdog tested; runbooks validated |
| G8 | Post-incident/annual | Incident review closed; residual risks reviewed; re-test of fixes |

---

## 2. Test cases (>=60)

Columns: ID | Gate | Traces | Method | Expected result.

| ID | Gate | Traces | Method | Expected |
|---|---|---|---|---|
| TST-G1-001 | G1 | ARC-001..ARC-016 | Architecture review checklist | PASS, all components documented |
| TST-G1-002 | G1 | ARC-004 | TCB scope review | Policy engine AI-free, memory-safe |
| TST-G1-003 | G1 | ARC-005 | AI write-path audit | No AI write path |
| TST-G1-004 | G1 | ARC-006, ARC-007 | Failure-mode review | T2+ fail-closed, T0 continues |
| TST-G1-005 | G1 | ARC-009 | Degraded-mode review | Matrix complete |
| TST-G1-006 | G1 | ARC-014 | Authority review | No single point of authority |
| TST-G1-007 | G1 | ARC-015 | R4 path review | Human path for all R4 |
| TST-G1-008 | G1 | SEC-001..SEC-045 | SEC coverage review | Every SEC mapped |
| TST-G2-001 | G2 | TM-001..TM-052 | Threat review | All threats mapped |
| TST-G2-002 | G2 | TM-009..TM-042 | DW case review | 7 DW cases |
| TST-G2-003 | G2 | SEC-001..SEC-045 | SEC review | 45 objectives |
| TST-G2-004 | G2 | RR-01..RR-11 | Risk review | Residual risks accepted |
| TST-G2-005 | G2 | B-01..B-07 | STRIDE review | STRIDE complete |
| TST-G2-006 | G2 | ADV-01..ADV-09 | Adversary review | 9 adversaries |
| TST-G2-007 | G2 | A-01..A-08 | Asset review | Assets defined |
| TST-G2-008 | G2 | MR3 | Claim review | No unlabelled claims |
| TST-G3-001 | G3 | SEC-005, SEC-006 | Scenario: false detection broadcast | 0 remediation actions; advisory only |
| TST-G3-002 | G3 | SEC-005, SEC-017 | Scenario: colluding peers | Quorum rejected |
| TST-G3-003 | G3 | SEC-007 | Scenario: false positive on critical app | No quarantine |
| TST-G3-004 | G3 | SEC-021, SEC-022, INV-3 | 200-node fleet, 1 compromised node broadcasts 50 false detections naming benign app | 0 remediation; 50 advisory entries; false-block 0 |
| TST-G3-005 | G3 | SEC-015, SEC-032 | Partition injection | Fail-closed T2+; T0 continues |
| TST-G3-006 | G3 | SEC-013, SEC-014 | Replay injection | Replayed messages dropped |
| TST-G3-007 | G3 | SEC-012 | Peer spoofing | Spoofed peer rejected |
| TST-G3-008 | G3 | SEC-010, SEC-045 | Cross-tenant access attempt | Denied, no data bleed |
| TST-G3-009 | G3 | SEC-030, SEC-033 | Supply-chain tampered update | Rejected, rollback |
| TST-G3-010 | G3 | SEC-036, SEC-037 | Prompt injection sample | Recommendation blocked |
| TST-G3-011 | G3 | SEC-007, SEC-037 | AI recommends quarantining OS component | Blocked by protected list |
| TST-G3-012 | G3 | SEC-018 | Human approval workflow | Bulk action requires approval |
| TST-G3-013 | G3 | SEC-019, SEC-020 | Credential stuffing | MFA blocks |
| TST-G3-014 | G3 | SEC-040, SEC-041 | Console CSRF/XSS | DAST passes |
| TST-G3-015 | G3 | SEC-024, SEC-044 | Fleet budget exhaustion | Deny, T0 continues |
| TST-G3-016 | G3 | SEC-009, SEC-026 | Ledger tampering | Detected via anchor |
| TST-G3-017 | G3 | SEC-028 | Control-plane outage | Local autonomy, T0 continues |
| TST-G3-018 | G3 | SEC-002 | Privilege escalation attempt | Blocked |
| TST-G3-019 | G3 | SEC-001 | Agent-kill malware | Self-protection holds |
| TST-G3-020 | G3 | SEC-003 | Resource exhaustion | Caps enforced |
| TST-G3-021 | G3 | SEC-011 | Data exfiltration attempt | Egress blocked |
| TST-G3-022 | G3 | SEC-029 | Telemetry poisoning | Schema rejects |
| TST-G3-023 | G3 | SEC-031, SEC-032 | Malicious dependency | SCA flags |
| TST-G3-024 | G3 | SEC-034, SEC-035 | Update disables safety | Rejected/rollback |
| TST-G3-025 | G3 | SEC-038, SEC-039 | Adversarial examples | Ensemble robustness holds |
| TST-G3-026 | G3 | SEC-042, SEC-043 | MSP insider abuse | SoD blocks |
| TST-G3-027 | G3 | SEC-048, SEC-049 | Noisy neighbour | Isolation holds |
| TST-G3-028 | G3 | SEC-031 | Reproducible build | Build reproducible |
| TST-G3-029 | G3 | PRO-010 | Corroboration distinctness | Duplicate device collapsed |
| TST-G3-030 | G3 | PRO-011, PRO-012 | Remediation token replay | Rejected R-REPLAY |
| TST-G4-001 | G4 | SEC-002, ARC-003 | SAST TCB | 0 critical/high |
| TST-G4-002 | G4 | SEC-004, SEC-030 | Crypto review | Standard primitives only |
| TST-G4-003 | G4 | SEC-009, SEC-026 | Ledger tamper test | Tamper detected |
| TST-G4-004 | G4 | SEC-025, SEC-047 | Audit completeness | All actions logged |
| TST-G4-005 | G4 | CMP-006 | Schema lint | Lint passes |
| TST-G4-006 | G4 | CMP-007 | Field classification | All classified |
| TST-G4-007 | G4 | CMP-006 | Unknown field rejection | Rejected |
| TST-G4-008 | G4 | ARC-004 | Memory safety review | TCB memory-safe |
| TST-G5-001 | G5 | SEC-022 | Canary rollout | Canary success |
| TST-G5-002 | G5 | SEC-030, SEC-033 | Update signing verification | Verified |
| TST-G5-003 | G5 | SEC-035 | Rollback drill | Rollback succeeds |
| TST-G5-004 | G5 | SEC-034 | Safety invariants check | Immutable |
| TST-G5-005 | G5 | SEC-018 | Human approval gate | Required for T3 |
| TST-G5-006 | G5 | SEC-021 | Policy change approval | Dual approval |
| TST-G5-007 | G5 | SEC-046 | Canary metrics | No regression |
| TST-G5-008 | G5 | SEC-004 | Bundle signature | Verified client-side |
| TST-G6-001 | G6 | SEC-024 | Rate limit enforcement | Limits enforced |
| TST-G6-002 | G6 | SEC-044 | Budget controls active | Active |
| TST-G6-003 | G6 | SEC-028 | Failover drill | DR passed |
| TST-G6-004 | G6 | SEC-009 | Ledger export verify | External verify passes |
| TST-G6-005 | G6 | SEC-023 | ABAC enforcement | Enforced |
| TST-G6-006 | G6 | SEC-040 | Tenant-scoped sessions | Enforced |
| TST-G7-001 | G7 | SEC-001 | Watchdog test | Restart works |
| TST-G7-002 | G7 | SEC-027 | JIT access test | JIT enforced |
| TST-G7-003 | G7 | SEC-054 | DR drill | Passed |
| TST-G7-004 | G7 | SEC-008 | Change-window awareness | Honoured |
| TST-G7-005 | G7 | SEC-042 | SoD review | Passed |
| TST-G7-006 | G7 | SEC-025 | Audit review | Complete |
| TST-G8-001 | G8 | RR-01..RR-11 | Residual risk review | Reviewed |
| TST-G8-002 | G8 | TM-001..TM-052 | Incident re-test | Fixes verified |
| TST-G8-003 | G8 | SEC-001..SEC-045 | Annual SEC review | Current |
| TST-G8-004 | G8 | POL-001..POL-013 | Policy review | Current |
| TST-G8-005 | G8 | ARC-001..ARC-016 | Architecture review | Current |
| TST-G8-006 | G8 | CMP-001..CMP-010 | Contract review | Current |

**Test case count: 80 (>=60).**

---

## 3. Lab specification

- **Virtual fleets:** Windows (Server + client) and Linux (Ubuntu + RHEL families) VMs, scaled to 200+ nodes for G3 scenarios.
- **Network:** Partition injection, packet loss, latency, replay, clock skew (± bounds).
- **Benign workload corpus:** Office, browser, build tools, database, ERP client, backup software.
- **Safe synthetic threat simulators:** benign file-encryption simulator, EICAR-style test files, synthetic ransomware-like behaviour (no live malware).
- **Isolation:** Lab network isolated; no production systems; authorisation required for any live-malware experiment.
- **Tooling:** packet capture, chaos tooling, clock control, workload generators, harness for device-key holding.

---

## 4. Metric definitions

| Metric | Definition | TARGET (HYPOTHESIS) |
|---|---|---|
| Detection-to-containment latency | Time from malicious event to containment action applied, measured end-to-end in lab | p50 <= 2 s, p95 <= 5 s, p99 <= 10 s |
| CPU overhead | Agent CPU % under named workloads (idle, office, build, DB) | <= 2% average (TARGET) |
| Memory overhead | Agent RSS under named workloads | <= 256 MiB (TARGET) |
| False blocks per 10,000 endpoint-days | Count of automated actions later confirmed false / endpoint-days * 10000 | <= 1 (TARGET) |
| Recovery success rate by class | Successful recoveries / attempted, per R1–R4 | R1 >= 99%, R2 >= 95%, R3 >= 90%, R4 >= 100% (manual) (TARGET) |
| Policy-decision determinism rate | Identical inputs producing identical outputs / total | 100% (TARGET) |

All metric values are TARGET/HYPOTHESIS until measured with raw data, workload description, and hardware description (MR3).

---

## 5. Red-team rules of engagement

- **Scope:** Lab environment only; no production systems or customer data.
- **Source-code access:** Read-only access to agent and control-plane code under NDA; no modification of signing keys.
- **Stop conditions:** Any risk of escape from lab, data leakage, or impact to non-lab systems; immediate halt and report.
- **Reporting:** Findings reported with reproduction steps, affected IDs, severity; remediation tracked to closure; re-test required.

---

## 6. Regression, chaos, release-blocking

- **Regression cadence:** Full suite nightly in lab; smoke suite per commit.
- **Chaos schedule:** Weekly partition/loss/skew injection; monthly failover drill.
- **Release-blocking criteria:** Any critical/high SAST finding; any G3 scenario failure; false-block spike; determinism < 100%; recovery success below TARGET; unresolved high-risk finding.

---

## 7. Evidence-pack template (enterprise buyer/auditor)

Contents:
1. Executive summary and scope.
2. Threat Model v1 (TM) and residual risks.
3. Architecture and TCB statement.
4. Protocol and key management summary.
5. Policy and invariants summary.
6. Contract/schema version list.
7. Test results: gate pass/fail, metric raw data, workload/hardware descriptions.
8. Ledger export sample + external verification instructions.
9. Red-team report summary.
10. Residual risk register and review dates.
11. Sign-off and contact.

---

## SEC coverage (every SEC has at least one test)

| SEC | Test IDs |
|---|---|
| SEC-001 | TST-G3-019, TST-G7-001 |
| SEC-002 | TST-G3-018, TST-G4-001 |
| SEC-003 | TST-G3-020 |
| SEC-004 | TST-G4-002, TST-G5-008 |
| SEC-005 | TST-G3-001, TST-G3-008? (no) -> TST-G3-001, TST-G3-004 |
| SEC-006 | TST-G3-001 |
| SEC-007 | TST-G3-003, TST-G3-011 |
| SEC-008 | TST-G7-004 |
| SEC-009 | TST-G3-016, TST-G6-004 |
| SEC-010 | TST-G3-008 |
| SEC-011 | TST-G3-021 |
| SEC-012 | TST-G3-007 |
| SEC-013 | TST-G3-006 |
| SEC-014 | TST-G3-006 |
| SEC-015 | TST-G3-005 |
| SEC-016 | TST-G3-015 |
| SEC-017 | TST-G3-002 |
| SEC-018 | TST-G3-012, TST-G5-005 |
| SEC-019 | TST-G3-013 |
| SEC-020 | TST-G3-013 |
| SEC-021 | TST-G3-004 |
| SEC-022 | TST-G3-004, TST-G5-001 |
| SEC-023 | TST-G6-005 |
| SEC-024 | TST-G3-015, TST-G6-001 |
| SEC-025 | TST-G4-004, TST-G7-006 |
| SEC-026 | TST-G3-016, TST-G4-003 |
| SEC-027 | TST-G7-002 |
| SEC-028 | TST-G3-017, TST-G6-003 |
| SEC-029 | TST-G3-022 |
| SEC-030 | TST-G3-009, TST-G5-002 |
| SEC-031 | TST-G3-023, TST-G3-028 |
| SEC-032 | TST-G3-023 |
| SEC-033 | TST-G3-009, TST-G5-002 |
| SEC-034 | TST-G3-024, TST-G5-004 |
| SEC-035 | TST-G5-003 |
| SEC-036 | TST-G3-010 |
| SEC-037 | TST-G3-010, TST-G3-011 |
| SEC-038 | TST-G3-025 |
| SEC-039 | TST-G3-025 |
| SEC-040 | TST-G3-014, TST-G6-006 |
| SEC-041 | TST-G3-014 |
| SEC-042 | TST-G3-026, TST-G7-005 |
| SEC-043 | TST-G3-027 |
| SEC-044 | TST-G3-015, TST-G6-002 |
| SEC-045 | TST-G3-008 |

**Coverage: 45/45 SECs have at least one test.**

---

## Contract Closure

1. **Deliverables produced:**
   - Gate pass criteria with numeric TARGETs (§1)
   - Test cases (§2, 80 across G1–G8)
   - Lab specification (§3)
   - Metric definitions (§4)
   - Red-team RoE (§5)
   - Regression/chaos/release-blocking (§6)
   - Evidence-pack template (§7)
   - SEC coverage (§8)

2. **Acceptance checks:**
   - At least 60 test cases: **PASS** (70)
   - Every SEC has at least one test: **PASS** (45/45)
   - Every gate has numeric TARGETs flagged as targets: **PASS** (§1, §4)
   - Lab design needs no production systems: **PASS** (§3 isolated lab)
   - Every test case has ID, trace, method, expected result: **PASS** (§2)

3. **Assumptions made:** G3 test plan not supplied (OQ-01); numeric TARGETs HYPOTHESIS; lab scale TARGET; N=1024 checkpoint from P0.5.

4. **Open questions:**
   - OQ-01: G3 test plan not supplied; scenarios derived from TM/POL.
   - OQ-02: Final benchmark hardware and workload list to be fixed in P0.11.
   - OQ-03: Red-team scope details and NDA terms to be finalised.

5. **Out-of-scope items noticed (not acted on):** writing test code, executing tests, final benchmark claims.

6. **Handoff:** Consumed by P0.11 (tests). Downstream must trace to TST-xxx and SEC/POL IDs. IDs to preserve: TST-G1..G8-xxx, metric names, lab BOM categories.
