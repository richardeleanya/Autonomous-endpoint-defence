# Customer Discovery and Commercial Evidence Plan v1 — Autonomous Agentic Endpoint Defence Mesh

**Document ID:** DIS-v1 (P0.9)
**Date:** 2026-11-16
**Status:** Draft for review
**Owner:** Customer Discovery and Commercial Strategist
**Depends on:** Master Rules; Competitive Capability Matrix v1 (P0.7); two lead segments (MSPs managing Windows/Linux fleets; organisations deploying autonomous AI agents)
**Assumption:** Capital-constrained team; prefers low-cost, cloud-based tooling.

---

## 0. Discovery requirements (DIS-xxx)

| ID | Requirement |
|---|---|
| DIS-001 | ICPs and buyer/user/blocker roles for 2 lead + 2 candidate segments |
| DIS-002 | Interview guide with >=20 open questions probing behaviour/spending |
| DIS-003 | Plan for >=40 interviews with sourcing, sequencing, scoring |
| DIS-004 | Evidence thresholds numeric and pre-stated |
| DIS-005 | Pricing research design without stated prices |
| DIS-006 | Unit-economics template with empty inputs |
| DIS-007 | Pilot offer + agreement structure, success metrics, kill criteria |
| DIS-008 | No product pitching during interviews |
| DIS-009 | Every hypothesis has a disproof method |

---

## 1. Ideal customer profiles and roles

### Segment 1 (lead): MSPs managing Windows and Linux fleets
- **ICP:** MSP with 500–5,000 managed endpoints across SMB/mid-market customers, mixed Windows/Linux, multi-tenant operations, existing EDR tooling, margin pressure.
- **Buyer:** MSP owner / service director (P&L responsibility).
- **User:** SOC/operations lead, tier-1/2 analysts.
- **Blocker:** Security vendor account manager, compliance officer, existing contract lock-in.

### Segment 2 (lead): Organisations deploying autonomous AI agents
- **ICP:** Mid-market/enterprise with internal AI agents (coding assistants, workflow agents) touching production systems; security team concerned with prompt injection and tool misuse.
- **Buyer:** CISO / head of security.
- **User:** Security engineer, AI platform owner.
- **Blocker:** Legal/privacy, AI governance committee, platform vendor.

### Segment 3 (candidate): Regulated mid-market (finance/health)
- **ICP:** 1,000–10,000 endpoints, compliance-driven, audit-heavy.
- **Buyer:** CISO/compliance director; **User:** SOC; **Blocker:** procurement, regulator.

### Segment 4 (candidate): MSSPs with 24/7 SOC
- **ICP:** MSSP with dedicated SOC, multi-tenant, seeking differentiation.
- **Buyer:** VP services; **User:** SOC analysts; **Blocker:** existing platform contracts.

---

## 2. Interview guide (>=20 open questions)

Rules: Do not pitch the product. Probe past behaviour and spending. Record numbers, not opinions.

1. Q1: Walk me through the last endpoint compromise you handled. What happened in the first hour?
2. Q2: Who was woken up, and what tools were used? (Probe: manual steps)
3. Q3: How many hours of manual work did that incident take? (record number)
4. Q4: What did it cost (staff time, downtime, recovery)? (record number)
5. Q5: How often does this happen per quarter? (record number)
6. Q6: What is your current endpoint security stack and annual spend? (record £/$)
7. Q7: What do you pay per endpoint per month today? (record)
8. Q8: What manual tasks consume the most analyst time weekly? (record hours)
9. Q9: How do you handle a compromised host today (isolate, reimage, restore)? (probe steps)
10. Q10: How often do you reimage vs restore? (record)
11. Q11: What is your false-positive rate per 10,000 endpoints per month? (record)
12. Q12: How do you verify a host is clean after remediation? (probe)
13. Q13: What evidence do auditors/regulators ask for after an incident? (probe)
14. Q14: How do you manage endpoints across tenants (MSP)? (probe)
15. Q15: What is your biggest pain in multi-tenant operations? (probe specifics)
16. Q16: How do you handle management-plane outages? (probe)
17. Q17: What AI agents do you deploy, and what access do they have? (probe)
18. Q18: Have you had a prompt-injection or tool-misuse incident? (record)
19. Q19: What would a successful pilot look like in numbers? (record)
20. Q20: What would make you refuse to deploy autonomous response? (probe)
21. Q21: Who must approve a new security tool, and how long does approval take? (record)
22. Q22: What is your budget cycle and who owns it? (probe)
23. Q23: What would you stop paying for if this worked? (record £/$)
24. Q24: What is the one metric you would use to judge success? (record)

**Interview guide count: 24 (>=20).**

---

## 3. Interview plan (>=40)

- **Total:** 45 interviews (20 MSP segment, 15 AI-agent segment, 5 each candidate segment).
- **Sourcing channels:** UK MSP communities/forums, LinkedIn, partner ecosystems, industry events, existing network, referrals.
- **Sequencing:** Weeks 1–2: MSPs; Weeks 3–4: AI-agent orgs; Weeks 5–6: candidates; ongoing refinement.
- **Scoring sheet (per interview):**
  - Pain frequency (1–5)
  - Pain severity/cost (1–5)
  - Current spend (recorded £/$)
  - Manual hours (recorded)
  - Decision-maker access (1–5)
  - Urgency (1–5)
  - Total score; threshold for qualified lead: >=18/30.

---

## 4. Evidence thresholds (numeric, pre-stated before interviews)

- **Validated pain:** >=70% of interviewed segment report >=10 manual hours per incident OR >=1 incident per quarter with measurable cost.
- **Validated willingness to pay:** >=40% state a concrete budget range or existing spend they would reallocate; no price pitching.
- **Qualified pilot:** >=5 organisations meet scoring threshold and express interest in a time-boxed pilot with defined success metrics.
- **Paid pilot commitment (G7):** >=3 signed paid pilots (any non-zero fee) with success metrics and kill criteria.

All thresholds are HYPOTHESIS until measured (MR3).

---

## 5. Pricing research design (no prices stated)

- **Methods:** Van Westendorp price sensitivity meter; Gabor-Granger; conjoint (if budget allows); pilot willingness-to-pay (paid pilots).
- **Execution:** Present as neutral research; no product pitch; ask about current spend and acceptable ranges.
- **Unit-economics template (empty inputs):**
  - Security operations cost per endpoint per month: [ ]
  - Support cost per endpoint per month: [ ]
  - Cloud/infrastructure cost per endpoint per month: [ ]
  - Insurance/liability cost per endpoint per month: [ ]
  - Sales/acquisition cost per customer: [ ]
  - Gross margin target (HYPOTHESIS): [ ]
  - Break-even endpoint count: [ ]

---

## 6. Pilot offer and agreement structure

- **Offer:** 90-day time-boxed pilot on a defined fleet (e.g., 100–500 endpoints), with success metrics and kill criteria.
- **Agreement:** Pilot agreement with data processing terms, authorisation for autonomous action within agreed scope, liability limits, termination rights.
- **Success metrics:** reduction in manual hours per incident; containment latency; false-block count; recovery success rate; NPS/CSAT from operators.
- **Kill criteria (whole product line):**
  - <2 paid pilots after 2 quarters.
  - No validated willingness to pay in >=40% of interviews.
  - False-block rate exceeds acceptable threshold in pilot.
  - Recovery verification fails in >10% of cases.
  - Unit economics cannot reach target margin at plausible price.

---

## 7. Hypotheses (labelled HYPOTHESIS) with disproof

| ID | Hypothesis (HYPOTHESIS) | Disproof method |
|---|---|---|
| H-01 | MSPs will pay for verified recovery over rollback | Pilot conversion + WTP interviews |
| H-02 | AI-agent orgs need runtime protection for tool calls | Interview evidence of incidents + pilot uptake |
| H-03 | Management-plane resilience is a buying criterion | Interview ranking + pilot success |
| H-04 | Evidence-ledger external verifiability matters to auditors | Auditor interviews + pilot requirement |
| H-05 | Low-cost cloud tooling sufficient for research | Budget tracking |

---

## Contract Closure

1. **Deliverables produced:**
   - ICPs and roles (§1)
   - Interview guide (§2, 24 questions)
   - Interview plan (§3, 45 interviews)
   - Evidence thresholds (§4)
   - Pricing research design + unit-economics template (§5)
   - Pilot offer + kill criteria (§6)
   - Hypotheses with disproof (§7)

2. **Acceptance checks:**
   - No fabricated figures: **PASS** (no market sizes/prices; thresholds labelled HYPOTHESIS)
   - Every hypothesis has disproof method: **PASS** (§7)
   - Thresholds numeric and pre-stated: **PASS** (§4)
   - Interview guide >=20 open questions: **PASS** (24)
   - Interview plan >=40: **PASS** (45)
   - No product pitching during interviews: **PASS** (rules stated)

3. **Assumptions made:** Low-cost cloud tooling preference; segment sizes not estimated; thresholds HYPOTHESIS.

4. **Open questions:**
   - OQ-01: Validation assessment candidate differentiators not supplied.
   - OQ-02: Actual sourcing channel effectiveness unknown.
   - OQ-03: Pilot pricing to be determined via WTP research.

5. **Out-of-scope items noticed (not acted on):** running interviews, final pricing, marketing copy.

6. **Handoff:** Consumed by P0.11. IDs to preserve: DIS-001..DIS-009, H-01..H-05, evidence thresholds.
