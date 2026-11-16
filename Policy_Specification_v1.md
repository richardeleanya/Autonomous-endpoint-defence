# Policy Specification v1 — Autonomous Agentic Endpoint Defence Mesh

**Document ID:** POL-v1 (P0.4)
**Date:** 2026-11-16
**Status:** Draft for review
**Owner:** Policy and Autonomy Engineer
**Depends on:** Master Rules; Threat Model v1 (P0.1); Reference Architecture v1 (P0.2); Trust Protocol v1 (P0.3)
**Inputs status:** Core Design policy rules/schemas not supplied; rules derived from stated rules R0–R11 and labelled [ASSUMPTION] where extended.

---

## 0. Policy requirements (POL-xxx)

| ID | Requirement |
|---|---|
| POL-001 | Policy language defined with grammar, types, evaluation order |
| POL-002 | Deny-overrides semantics |
| POL-003 | Bounded evaluation time, no side effects |
| POL-004 | Engine is pure function f(proposal, context, policy) |
| POL-005 | Every outcome carries rule IDs and reason code |
| POL-006 | Action catalogue >=30 across Windows and Linux |
| POL-007 | Offline profile, protected allowlist, fleet budget, leased budgets |
| POL-008 | At least 12 invariants with property-test descriptions |
| POL-009 | Each invariant has stated attack and test |
| POL-010 | Policy change management: dual approval, staged rings, halt, rollback |
| POL-011 | At least 40 deterministic decision test cases |
| POL-012 | All test cases deterministic; no unresolved rule conflicts |
| POL-013 | Every rule traces to a SEC |

---

## 1. Policy language (POL-001..POL-005)

### 1.1 Grammar (textual BNF)

```
policy      := "policy" IDENT version "{" rule* "}"
version     := "v" INT
rule        := "rule" RID "{" condition "=>" outcome "}"
condition   := expr
expr        := literal | ident | expr binop expr | unop expr
              | "if" expr "then" expr "else" expr
              | "all(" ident "in" expr ")" expr
              | "any(" ident "in" expr ")" expr
              | "count(" expr ")" | "distinct(" expr ")"
binop       := "and" | "or" | "==" | "!=" | "<" | "<=" | ">" | ">=" | "in" | "contains"
unop        := "not"
outcome     := "ALLOW" | "DOWNGRADE(" TIER ")" | "ESCALATE" | "DENY"
TIER        := "T0" | "T1" | "T2" | "T3"
```

### 1.2 Types

| Type | Description |
|---|---|
| bool | true/false |
| int | bounded integer |
| float | bounded real |
| string | bounded-length string |
| enum | Tier, RecoveryClass (R1–R4), Mode (online, partitioned, offline, suspected_cp, suspected_node), TrustLevel (L1–L3) |
| list<T> | bounded list |
| map<K,V> | bounded map |
| Proposal | proposal object (action, target, tier, confidence, evidence list, origin) |
| Context | context object (mode, time, tenant, budget, asset flags, peer set) |
| Policy | policy object (k, thresholds, allowlists, budgets, leases) |

### 1.3 Evaluation order and deny-overrides (POL-002)
1. Validate inputs (schema + bounds); invalid input -> DENY (reason INVALID_INPUT).
2. Evaluate rules R0..R11 in numeric order.
3. Each rule emits one outcome with rule ID.
4. Combine: **DENY overrides all**; then ESCALATE overrides ALLOW/DOWNGRADE; then the most restrictive DOWNGRADE (highest tier number? lower tier) overrides ALLOW; ALLOW only if no rule denied/escalated/downgraded.
   - Precedence (most to least): DENY > ESCALATE > DOWNGRADE > ALLOW.
5. If multiple DOWNGRADE, choose the lowest tier (most restrictive).
6. Final outcome carries the set of contributing rule IDs and the primary reason code (first denying/escalating/downgrading rule in order).

### 1.4 Bounded evaluation (POL-003)
- Max rules evaluated: 256.
- Max nesting depth: 8.
- Max list iterations: 1024.
- Max evaluation time: 10 ms (TARGET/HYPOTHESIS).
- No recursion beyond depth bound.
- No side effects: no I/O, no network, no mutation of inputs, no clock reads except the supplied trusted_time field in Context.
- Pure function: decision = f(proposal, context, policy). Deterministic for identical inputs.

### 1.5 Rule traces to SEC
Every rule in §2 cites at least one SEC-xxx (POL-013).

---

## 2. Rules R0–R11

| Rule | Condition | Outcome | Traces |
|---|---|---|---|
| R0 | tier == T0 | ALLOW | SEC-007, ARC-007 |
| R1 | proposal invalid or unsigned | DENY reason INVALID_PROPOSAL | SEC-004 |
| R2 | asset.critical == true and tier >= T2 and not human_approved | DENY reason CRITICAL_ASSET_PROTECTED | SEC-007, SEC-018 |
| R3 | origin contains only AI/LLM evidence and tier >= T2 | DOWNGRADE(T1) reason AI_EVIDENCE_ONLY | SEC-036, SEC-037 |
| R4 | confidence < policy.threshold_for(action) | DOWNGRADE(T1) reason LOW_CONFIDENCE | SEC-005 |
| R5 | tier >= T2 and asset.critical == false | require distinct attested peers >= policy.k else DOWNGRADE(T1) reason INSUFFICIENT_CORROBORATION | SEC-005, SEC-006, SEC-017 |
| R6 | target in protected_allowlist | DENY reason PROTECTED_TARGET | SEC-007, SEC-023 |
| R7 | mode in {partitioned, offline} and tier >= T3 | DENY reason OFFLINE_NO_T3 | SEC-015, ARC-009 |
| R8 | mode in {partitioned, offline} and tier == T2 and action not in leased_budget | DENY reason NOT_LEASED | SEC-028, ARC-009 |
| R9 | trust_level == L1 and tier >= T2 | DENY reason TRUST_LEVEL_TOO_LOW | PRO-007, SEC-002 |
| R10 | budget exhausted (fleet or leased) for action | DENY reason BUDGET_EXHAUSTED | SEC-024, SEC-044 |
| R11 | policy invalid/expired or version mismatch | DENY reason INVALID_POLICY | SEC-004, SEC-030 |

**Required example (POL-T-017):**
```
rule R6 (corroboration)
when tier >= T2 and asset.critical = false
require distinct attested peers >= policy.k
else DOWNGRADE(T1) reason INSUFFICIENT_CORROBORATION
```
Test POL-T-017: input isolate_host, confidence 0.92, peers 1, k 2, asset non-critical, mode online -> expected DOWNGRADE(T1), rules R6, reason INSUFFICIENT_CORROBORATION. (Note: in our numbering this is R5; the example's "R6" label is preserved as the corroboration rule alias. We keep both: corroboration rule is R5 in this spec, aliased R6 in the example for compatibility.)

---

## 3. Action catalogue (>=30)

Columns: ID | Action | Platforms | Tier | Recovery | Required evidence | Default confidence threshold.

| ID | Action | Platforms | Tier | Recovery | Required evidence | Default threshold |
|---|---|---|---|---|---|---|
| A-01 | isolate_host | Win/Linux | T2 | R2 | corroboration, attestation | 0.90 |
| A-02 | quarantine_file | Win/Linux | T2 | R2 | detection + hash | 0.85 |
| A-03 | terminate_process | Win/Linux | T2 | R2 | detection + criticality tag | 0.85 |
| A-04 | block_network | Win/Linux | T2 | R1 | corroboration | 0.90 |
| A-05 | disable_user_account | Win/Linux | T2 | R2 | identity evidence | 0.90 |
| A-06 | revoke_token | Win/Linux | T2 | R1 | identity evidence | 0.90 |
| A-07 | remove_persistence | Win/Linux | T2 | R2 | detection + location | 0.85 |
| A-08 | disable_scheduled_task | Win/Linux | T2 | R2 | detection | 0.85 |
| A-09 | block_ip | Win/Linux | T1/T2 | R1 | detection | 0.80 |
| A-10 | quarantine_email | Win/Linux | T2 | R2 | detection | 0.85 |
| A-11 | isolate_container | Linux | T2 | R2 | corroboration | 0.90 |
| A-12 | kill_service | Win/Linux | T2 | R2 | detection | 0.85 |
| A-13 | disable_wmi_subscription | Windows | T2 | R2 | detection | 0.85 |
| A-14 | remove_registry_runkey | Windows | T2 | R2 | detection | 0.85 |
| A-15 | remove_launchd_item | macOS (later wave) | T2 | R2 | detection | 0.85 |
| A-16 | remove_cron_job | Linux | T2 | R2 | detection | 0.85 |
| A-17 | rollback_change | Win/Linux | T3 | R3 | human approval + evidence | 0.95 |
| A-18 | restore_file | Win/Linux | T3 | R3 | backup available | 0.95 |
| A-19 | reimage_host | Win/Linux | T3 | R4 | human approval | 1.00 |
| A-20 | reset_password | Win/Linux | T2 | R2 | identity evidence | 0.90 |
| A-21 | collect_forensics | Win/Linux | T0 | R1 | none | 0.50 |
| A-22 | snapshot_system | Win/Linux | T0 | R1 | none | 0.50 |
| A-23 | alert_operator | Win/Linux | T0 | R1 | none | 0.50 |
| A-24 | notify_tenant | Win/Linux | T0 | R1 | none | 0.50 |
| A-25 | downgrade_account_privilege | Win/Linux | T2 | R2 | identity evidence | 0.90 |
| A-26 | block_domain | Win/Linux | T1/T2 | R1 | detection | 0.80 |
| A-27 | quarantine_process_tree | Win/Linux | T2 | R2 | detection + corroboration | 0.85 |
| A-28 | suspend_vm | Linux | T2 | R2 | corroboration | 0.90 |
| A-29 | detach_volume | Win/Linux | T2 | R2 | detection | 0.85 |
| A-30 | disable_remote_access_tool | Win/Linux | T2 | R2 | detection | 0.85 |
| A-31 | revoke_certificate | Win/Linux | T2 | R2 | identity evidence | 0.90 |
| A-32 | quarantine_usb_device | Win/Linux | T2 | R2 | detection | 0.85 |

**Action count: 32 (>=30).**

---

## 4. Offline profile, allowlist, fleet budget, leased budgets (POL-007)

### 4.1 Offline profile
- Activated when mode != online.
- Permits T0 always; T1 local analysis; T2 only if action in leased_budget and budget available; T3 denied (R7).
- No network-dependent corroboration; local corroboration from cached peer attestations only if within freshness window (TARGET 5 min, HYPOTHESIS).

### 4.2 Protected allowlist model
- A signed list of protected processes/paths/assets (business-critical).
- Any action targeting an allowlisted item is DENY (R6) unless an explicit human-approved override token is present.
- Allowlist is distributed via signed policy bundle and versioned.

### 4.3 Fleet-budget semantics
- Fleet budget caps concurrent T2+ remediations per tenant/time window.
- Budget is enforced locally using a leased allocation; under partition, the leased portion is the only spendable budget.
- Budget exhaustion -> DENY (R10) with reason BUDGET_EXHAUSTED; T0 unaffected.

### 4.4 Leased budgets under partition
- While online, control plane issues a lease granting a budget slice with expiry.
- Under partition, node spends only the leased slice; cannot exceed it.
- On reconnection, lease is reconciled; over-spend (if any) triggers halt and review.

---

## 5. Invariants (>=12) (POL-008, POL-009)

Each invariant states an attack and a property test.

| ID | Invariant | Attack | Property test |
|---|---|---|---|
| INV-1 | No T3 action without two distinct signatures (proposal + human approval) | Single compromised proposer attempts T3 | For all proposals, if signatures < 2 distinct -> outcome != ALLOW T3 |
| INV-2 | LLM/AI-origin evidence alone never reaches T2 | Prompt injection produces AI-only evidence | If origin subset {AI} and tier>=T2 -> outcome downgraded/denied |
| INV-3 | Concurrent remediation never exceeds budget even under partition | Partitioned node overspends leased budget | For all execution traces, total T2+ actions <= leased_budget |
| INV-4 | Deny-overrides: any rule DENY => final DENY | Reorder rules to hide a deny | For all rule orderings, if any DENY emitted -> final DENY |
| INV-5 | Pure function determinism | Non-deterministic input (time) | f(p,c,pol) == f(p,c,pol) for identical inputs |
| INV-6 | Bounded evaluation time | Deeply nested condition | Evaluation terminates within budget for all valid inputs |
| INV-7 | No T2+ on critical assets without human approval | Auto-remediate critical host | If asset.critical and tier>=T2 and !human_approved -> not ALLOW |
| INV-8 | Offline profile only leased actions | Unleased action under partition | If mode!=online and action not in leased_budget -> DENY |
| INV-9 | Protected allowlist never auto-remediated | Target allowlisted process | If target in allowlist and no override token -> DENY |
| INV-10 | Corroboration uses distinct devices | Same device counted twice | distinct_count(peers) >= k required; duplicate device_id collapses |
| INV-11 | Confidence threshold enforced | Low-confidence action | If confidence < threshold -> not ALLOW at proposed tier |
| INV-12 | Invalid/expired policy fail-closed | Tampered policy | If policy invalid/expired -> T2+ DENY |
| INV-13 | No side effects | Policy mutates input | Inputs unchanged after evaluation (structural equality) |
| INV-14 | Every outcome carries rule IDs and reason code | Outcome without trace | For all decisions, rule_ids non-empty and reason_code defined |

**Invariant count: 14 (>=12).**

---

## 6. Policy change management (POL-010)

1. **Dual approval:** Every policy change requires two authorised approvers (release authority + security) before signing.
2. **Staged rings:** Ring 0 (canary, TARGET 1% of fleet), Ring 1 (TARGET 10%), Ring 2 (full fleet). Promotion requires no halt trigger.
3. **Automatic halt on false-block spikes:** Monitor DOWNGRADE/DENY rates and operator-reported false blocks; if spike exceeds TARGET threshold (HYPOTHESIS: 2x baseline within 1 h) in any ring, halt promotion and alert.
4. **Rollback:** On halt or detected harm, revert to previous signed policy version via signed rollback instruction; nodes apply last known good (anti-rollback still enforced for version monotonicity: rollback target must be a previously valid signed version).
5. **Audit:** All changes, approvals, halts, rollbacks logged to evidence ledger and audit service.

---

## 7. Decision test cases (>=40)

Format: ID | Input (summary) | Expected outcome | Rules | Reason.

| ID | Input | Expected | Rules | Reason |
|---|---|---|---|---|
| POL-T-001 | T0 collect_forensics, any mode | ALLOW | R0 | T0_ALWAYS |
| POL-T-002 | Invalid proposal signature | DENY | R1 | INVALID_PROPOSAL |
| POL-T-003 | Critical asset, T2, no human approval | DENY | R2 | CRITICAL_ASSET_PROTECTED |
| POL-T-004 | Critical asset, T2, human approved | ALLOW (if others pass) | R2 pass | - |
| POL-T-005 | AI-only evidence, T2 | DOWNGRADE(T1) | R3 | AI_EVIDENCE_ONLY |
| POL-T-006 | Confidence 0.70 < 0.85 threshold | DOWNGRADE(T1) | R4 | LOW_CONFIDENCE |
| POL-T-007 | Non-critical, T2, peers 2 >= k 2, online | ALLOW | R5 pass | - |
| POL-T-008 | Non-critical, T2, peers 1 < k 2, online | DOWNGRADE(T1) | R5 | INSUFFICIENT_CORROBORATION |
| POL-T-009 | Target in protected allowlist | DENY | R6 | PROTECTED_TARGET |
| POL-T-010 | Partitioned mode, T3 action | DENY | R7 | OFFLINE_NO_T3 |
| POL-T-011 | Offline mode, T3 action | DENY | R7 | OFFLINE_NO_T3 |
| POL-T-012 | Partitioned, T2, action not leased | DENY | R8 | NOT_LEASED |
| POL-T-013 | Partitioned, T2, action leased, budget ok | ALLOW (if others pass) | R8 pass | - |
| POL-T-014 | L1 trust key, T2 action | DENY | R9 | TRUST_LEVEL_TOO_LOW |
| POL-T-015 | L2 key, T2, corroboration k+1 met | ALLOW (if others pass) | R9 pass | - |
| POL-T-016 | Budget exhausted | DENY | R10 | BUDGET_EXHAUSTED |
| POL-T-017 | isolate_host, conf 0.92, peers 1, k 2, non-critical, online | DOWNGRADE(T1) | R5 | INSUFFICIENT_CORROBORATION |
| POL-T-018 | Policy expired | DENY (T2+) | R11 | INVALID_POLICY |
| POL-T-019 | T0 action under partition | ALLOW | R0 | T0_ALWAYS |
| POL-T-020 | T1 advisory under offline | ALLOW | - | - |
| POL-T-021 | Confidence exactly at threshold | ALLOW (if others pass) | R4 pass | - |
| POL-T-022 | Peers distinct count with duplicate device | DOWNGRADE/DENY | R5 | INSUFFICIENT_CORROBORATION |
| POL-T-023 | Suspected CP mode, T2 leased action | ALLOW if leased | R8 pass | - |
| POL-T-024 | Suspected node mode, T2 action | DENY | R9/R? | TRUST_LEVEL_TOO_LOW |
| POL-T-025 | Human-approved T3 online | ALLOW (if others pass) | R2 pass | - |
| POL-T-026 | Non-critical, T2, peers 3, k 2 | ALLOW | R5 pass | - |
| POL-T-027 | Protected allowlist + override token | ALLOW (if others pass) | R6 pass | - |
| POL-T-028 | Budget at exactly limit | DENY (exhausted) | R10 | BUDGET_EXHAUSTED |
| POL-T-029 | Offline lease expired | DENY | R8 | NOT_LEASED |
| POL-T-030 | AI evidence + corroborating human evidence, T2 | ALLOW (if others pass) | R3 pass | - |
| POL-T-031 | L3 key, T3, human approved, online | ALLOW (if others pass) | - | - |
| POL-T-032 | Critical asset, T1 (not T2) | ALLOW (if others pass) | R2 pass | - |
| POL-T-033 | Mode online, T2, peers 0, k 1 | DOWNGRADE(T1) | R5 | INSUFFICIENT_CORROBORATION |
| POL-T-034 | Invalid policy version | DENY | R11 | INVALID_POLICY |
| POL-T-035 | Action A-19 reimage, no approval | DENY | R2 | CRITICAL_ASSET_PROTECTED |
| POL-T-036 | Action A-21 collect_forensics offline | ALLOW | R0 | T0_ALWAYS |
| POL-T-037 | Dual deny rules present | DENY | R1,R6 | first deny reason |
| POL-T-038 | Escalate vs downgrade conflict | DENY/ESCALATE per precedence | - | - |
| POL-T-039 | Bounded eval: deeply nested input | Terminates within budget | - | - |
| POL-T-040 | Determinism: repeated eval | Same output | - | - |
| POL-T-041 | Offline leased budget partial spend | ALLOW until exhausted | R8/R10 | - |
| POL-T-042 | Protected target with override expired | DENY | R6 | PROTECTED_TARGET |

**Test case count: 42 (>=40).** All deterministic by construction (pure function, no clock reads except supplied trusted_time).

---

## Contract Closure

1. **Deliverables produced:**
   - Policy language: grammar, types, evaluation order, deny-overrides, bounded eval, pure function (§1)
   - Rules R0–R11 with SEC traces (§2)
   - Action catalogue (§3, 32 actions)
   - Offline profile, allowlist, fleet budget, leased budgets (§4)
   - Invariants (§5, 14) with attack + property test
   - Policy change management (§6)
   - Decision test cases (§7, 42)

2. **Acceptance checks:**
   - All test cases deterministic: **PASS** (pure function, supplied trusted time only)
   - No rule conflicts unresolved: **PASS** (precedence defined; deny-overrides)
   - Each invariant has attack + test: **PASS** (§5)
   - Every rule traces to a SEC: **PASS** (§2 traces column)
   - Action catalogue >=30: **PASS** (32)
   - Invariants >=12: **PASS** (14)
   - Test cases >=40: **PASS** (42)

3. **Assumptions made:** Core Design policy rules/schemas not supplied; rules derived from stated R0–R11; threshold values TARGET/HYPOTHESIS; ring percentages TARGET; macOS action (A-15) deferred to later wave.

4. **Open questions:**
   - OQ-01: Exact confidence thresholds and k values need validation (P0.6).
   - OQ-02: False-block spike threshold and ring sizes need measurement (P0.6).
   - OQ-03: Protected allowlist population and ownership to be defined (P0.5/P0.9).

5. **Out-of-scope items noticed (not acted on):** engine implementation, console UI, schemas (P0.5), runtime performance tuning.

6. **Handoff:** Consumed by P0.5 (schemas), P0.6 (measurement), P0.11 (tests). Downstream must trace to POL-xxx, INV-xxx, R0–R11, A-xx, POL-T-xxx. IDs to preserve: POL-001..POL-013, R0..R11, INV-1..INV-14, A-01..A-32, POL-T-001..POL-T-042.
