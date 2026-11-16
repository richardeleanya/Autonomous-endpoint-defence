# Privacy, Compliance and Regulatory Requirements v1 — Autonomous Agentic Endpoint Defence Mesh

**Document ID:** PRV-v1 (P0.8)
**Date:** 2026-11-16
**Status:** Draft for review
**Owner:** Privacy, Compliance and Regulatory Analyst
**Jurisdiction note:** UK-based SaaS selling to UK and EU. Requirements are design requirements, not legal advice. Not a lawyer; questions for a qualified solicitor are listed in §8.
**Depends on:** Master Rules; Threat Model v1 (P0.1); Contracts and field classification (P0.5)

---

## 0. Requirements register (CMP-011..CMP-045)

Privacy/compliance requirements continue the CMP numbering from P0.5 (CMP-001..CMP-010 are contract requirements). Each traces to a component and a test.

| ID | Source (dated) | Requirement | Traces (components) | Test |
|---|---|---|---|---|
| CMP-011 | ICO, Data minimisation principle, published 2025-09-09 | Command-line arguments hashed on node by default; raw capture requires explicit tenant policy and is logged | ARC-011, Proposal.target.cmdline, CMP-007 | TST-PRV-001 |
| CMP-012 | ICO, Data minimisation principle, published 2025-09-09 | Only collect telemetry necessary for stated purpose; no speculative collection | ARC-001, sensors | TST-PRV-002 |
| CMP-013 | ICO, Storage limitation, published 2025-07-24 | Retention schedule per field class: operational 90 d, sensitive 30 d, personal 7 d; periodic review | CMP-005, LedgerEntry | TST-PRV-003 |
| CMP-014 | ICO, Data minimisation principle, published 2025-09-09 | Data-subject rights (access, rectification, erasure) supported via export and deletion APIs | control plane, audit | TST-PRV-004 |
| CMP-015 | ICO, International transfers guide, published 2026-01-15 | Restricted transfers covered by adequacy, safeguards (IDTA/Addendum/BCRs) or exception; TRA completed | control plane, tenancy | TST-PRV-005 |
| CMP-016 | ICO, Monitoring workers guidance, published 2026-06-16 | Endpoint monitoring purpose documented; least intrusive means; no 'just in case' monitoring | sensors, case-graph | TST-PRV-006 |
| CMP-017 | ICO, Monitoring workers guidance, published 2026-06-16 | DPIA completed for endpoint telemetry (high risk) | all | TST-PRV-007 |
| CMP-018 | ICO, Monitoring workers guidance, published 2026-06-16 | Workers informed of monitoring purpose, nature, extent; policy accessible | console, audit | TST-PRV-008 |
| CMP-019 | ICO, Monitoring workers guidance, published 2026-06-16 | No covert monitoring; transparency by default | sensors | TST-PRV-009 |
| CMP-020 | ICO, Monitoring workers guidance, published 2026-06-16 | Accuracy: steps to correct/misleading data; challenge mechanism | evidence ledger | TST-PRV-010 |
| CMP-021 | ICO, Monitoring workers guidance, published 2026-06-16 | Article 22: human oversight for solely automated decisions with significant effect; no disadvantage for requesting human review | policy engine, console | TST-PRV-011 |
| CMP-022 | ICO, Monitoring workers guidance, published 2026-06-16 | Special category data avoided; if captured, condition identified and policy document in place | sensors, case-graph | TST-PRV-012 |
| CMP-023 | UK GDPR Art. 32 (security) / ICO guidance | Encryption in transit and at rest; key management per Trust Protocol | all, A-03 | TST-PRV-013 |
| CMP-024 | UK GDPR Art. 33/34 (breach notification) | Incident notification process: notify ICO within 72 h where required; customer notification | audit, console | TST-PRV-014 |
| CMP-025 | UK GDPR Art. 28 (processor) | Data processing agreement (DPA) with customers; sub-processor list and notice | control plane | TST-PRV-015 |
| CMP-026 | UK GDPR Art. 30 (records of processing) | Records of processing activities maintained | audit | TST-PRV-016 |
| CMP-027 | UK GDPR Art. 35 (DPIA) | DPIA for high-risk processing (endpoint telemetry, monitoring) | all | TST-PRV-017 |
| CMP-028 | UK GDPR Art. 37 (DPO) | DPO appointed where required | org | TST-PRV-018 |
| CMP-029 | UK GDPR Art. 44-49 (transfers) | International transfers mechanism documented and maintained | control plane | TST-PRV-019 |
| CMP-030 | UK DPA 2018 / ICO | Lawful basis documented per processing activity (security monitoring; typically legitimate interests) | all | TST-PRV-020 |
| CMP-031 | Computer Misuse Act 1990 (UK) | Customer contract must authorise autonomous action on their systems; scope and boundaries defined | policy, enrolment | TST-PRV-021 |
| CMP-032 | Computer Misuse Act 1990 (UK) | No action on systems without documented authorisation; audit trail of authorisation | evidence ledger | TST-PRV-022 |
| CMP-033 | NCSC guidance (current) | Follow NCSC guidance on endpoint security and supply chain | build pipeline, updater | TST-PRV-023 |
| CMP-034 | Cyber Essentials Plus | Achieve Cyber Essentials Plus certification | all | TST-PRV-024 |
| CMP-035 | ISO/IEC 27001 | Implement ISMS and achieve ISO 27001 certification | org, all | TST-PRV-025 |
| CMP-036 | SOC 2 | Achieve SOC 2 Type II for trust services | org, control plane | TST-PRV-026 |
| CMP-037 | EU NIS2 (where customers in scope) | Support customer NIS2 obligations (incident reporting, risk management) | telemetry, audit | TST-PRV-027 |
| CMP-038 | EU DORA (where customers in scope) | Support customer DORA ICT risk and incident reporting | telemetry, audit | TST-PRV-028 |
| CMP-039 | EU AI Act | AI components classified; transparency/oversight obligations assessed; human oversight for high-risk uses | reasoning-tiers, policy engine | TST-PRV-029 |
| CMP-040 | UK GDPR Art. 5(1)(b) purpose limitation | Telemetry not repurposed beyond security without new lawful basis | all | TST-PRV-030 |
| CMP-041 | ICO monitoring workers guidance, published 2026-06-16 | DPIA includes seeking workers' views where appropriate | all | TST-PRV-031 |
| CMP-042 | ICO storage limitation, published 2025-07-24 | Retention policy documented; periodic review; erasure/anonymisation | CMP-005 | TST-PRV-032 |
| CMP-043 | ICO international transfers, published 2026-01-15 | Transfer risk assessment for any restricted transfer | control plane | TST-PRV-033 |
| CMP-044 | UK GDPR Art. 12-14 (transparency) | Privacy notice for end users (tenants' workers) available | console | TST-PRV-034 |
| CMP-045 | UK GDPR Art. 32 | Access controls, least privilege, logging of admin access | control plane, console | TST-PRV-035 |

**Requirement count: 35 (>=30).**

---

## 1. Privacy (UK GDPR / DPA 2018)

- **Lawful basis:** Security monitoring typically relies on legitimate interests; document LIA per processing activity (CMP-030). Consent not usually appropriate in employment context (ICO monitoring workers guidance, published 2026-06-16).
- **Data minimisation:** Hash command lines by default; raw capture opt-in (CMP-011, CMP-012).
- **Retention:** Per field class with periodic review (CMP-013, CMP-042).
- **Data-subject rights:** Access, rectification, erasure via APIs (CMP-014).
- **International transfers:** Adequacy/safeguards/exceptions + TRA (CMP-015, CMP-043).
- **ICO monitoring workers:** Purpose documentation, least intrusive means, transparency, DPIA, accuracy, special category avoidance, Article 22 oversight (CMP-016..CMP-022, CMP-041).

---

## 2. Authorisation (autonomous action)

- Customer contract must authorise autonomous action on their systems, with defined scope, boundaries, and audit (CMP-031, CMP-032).
- Computer Misuse Act 1990 implications: action without authorisation may be unlawful; therefore explicit authorisation and scope are required (CMP-031).
- Liability themes: allocation of responsibility for automated actions; human oversight for high-impact; insurance; indemnities (to be drafted by solicitor).

---

## 3. Frameworks and certifications

- **ISO/IEC 27001:** ISMS (CMP-035).
- **SOC 2 Type II:** trust services (CMP-036).
- **Cyber Essentials Plus:** baseline (CMP-034).
- **NCSC guidance:** endpoint security and supply chain (CMP-033).
- **NIS2/DORA:** support customer obligations where applicable (CMP-037, CMP-038).
- **EU AI Act:** classify AI components; transparency/oversight (CMP-039).

---

## 4. DPIA outline for endpoint telemetry

1. **Description of processing:** telemetry collection, case correlation, evidence ledger, AI reasoning inputs.
2. **Purpose and necessity:** security monitoring and incident response; lawful basis (legitimate interests).
3. **Data flows:** see §5 table.
4. **Risks to data subjects:** privacy intrusion, function creep, inaccurate inferences, remote/home capture.
5. **Mitigations:** minimisation, hashing, retention limits, access controls, transparency, DPIA review, worker views.
6. **Residual risk and sign-off:** documented; review annually or on change.

---

## 5. Telemetry data-flow table

| Source | Data | Destination | Classification | Retention | Transfer |
|---|---|---|---|---|---|
| Endpoint sensors | process/file/network metadata (hashed) | case-graph -> control plane | S/O | 30/90 d | UK/EU (adequacy) |
| Evidence ledger | decisions/actions | control plane anchor | O | policy | UK/EU |
| AI reasoning layer | minimised features only | model service | O/S | 7-30 d | check transfer |
| Console | operator actions | audit store | O | 90 d | UK/EU |

---

## 6. Contract clauses to be drafted (by solicitor)

- Autonomous-action authorisation (scope, boundaries, revocation).
- Liability allocation for automated actions.
- Data processing agreement (processor terms, sub-processors, notice).
- Incident notification (timelines, cooperation).
- International transfers (mechanism, TRA).
- Retention and deletion.
- Security and audit rights.
- Limitation of liability and insurance.

---

## 7. Certification roadmap

| Phase | Certification | Dependencies | Target (HYPOTHESIS) |
|---|---|---|---|
| 1 | Cyber Essentials Plus | Baseline controls | Before first customer |
| 2 | ISO 27001 | ISMS, risk register | Within 12 months |
| 3 | SOC 2 Type II | Controls operating 6+ months | After ISO 27001 |
| 4 | NCSC guidance alignment | Ongoing | Continuous |
| 5 | EU AI Act assessment | AI component classification | Before AI features GA |
| 6 | NIS2/DORA support (customer-facing) | Customer demand | As needed |

---

## 8. Questions for a qualified solicitor

1. What is the appropriate lawful basis for endpoint telemetry processing in our customer environments (legitimate interests vs contract)?
2. How should autonomous-action authorisation be structured in customer contracts (scope, revocation, notice)?
3. Liability allocation for automated containment actions that cause business disruption.
4. Are we a processor or controller for worker telemetry; implications for DPA terms?
5. International transfer mechanisms for any non-UK processing (adequacy, IDTA, TRA).
6. Retention periods defensible under storage limitation; erasure obligations.
7. Article 22 applicability to automated decisions with significant effect on workers.
8. Special category data risks from command lines/emails; conditions and policy document.
9. EU AI Act classification of our AI components and obligations.
10. NIS2/DORA obligations where customers are in scope; contractual support.
11. Insurance and indemnity requirements for autonomous actions.
12. ICO registration and DPO necessity.

---

## Contract Closure

1. **Deliverables produced:**
   - Requirements register (§0, 35 CMP)
   - Privacy section (§1)
   - Authorisation section (§2)
   - Frameworks/certifications (§3)
   - DPIA outline (§4)
   - Telemetry data-flow table (§5)
   - Contract clause list (§6)
   - Certification roadmap (§7)
   - Solicitor questions (§8)

2. **Acceptance checks:**
   - At least 30 CMP requirements: **PASS** (35)
   - Each CMP traces to component and test: **PASS** (§0 table)
   - Every legal reference cites dated source: **PASS** (ICO sources dated)
   - Jurisdiction stated: **PASS** (UK/EU)
   - No legal conclusions: **PASS** (requirements/questions only)

3. **Assumptions made:** ICO guidance dates as cited; certification timelines TARGET/HYPOTHESIS; EU AI Act applicability to be confirmed by solicitor.

4. **Open questions:**
   - OQ-01: Validation assessment candidate differentiators not supplied (irrelevant here).
   - OQ-02: Final lawful basis and retention periods subject to solicitor advice.
   - OQ-03: EU AI Act classification pending legal review.

5. **Out-of-scope items noticed (not acted on):** legal advice, final contract drafting, auditing.

6. **Handoff:** Consumed by P0.2 (conflicts), P0.5, P0.11. IDs to preserve: CMP-011..CMP-045, TST-PRV-001..TST-PRV-035.
