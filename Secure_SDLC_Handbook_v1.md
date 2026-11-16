# Secure SDLC Handbook v1 — Autonomous Agentic Endpoint Defence Mesh

**Document ID:** SDL-v1 (P0.10)
**Date:** 2026-11-16
**Status:** Draft for review
**Owner:** Platform and Secure SDLC Lead
**Depends on:** Master Rules; Threat Model v1 (P0.1); Architecture and ADRs (P0.2); Trust Protocol (P0.3, release signing); Compliance register (P0.8)

---

## 0. SDLC requirements (SDL-xxx)

| ID | Requirement |
|---|---|
| SDL-001 | Repository layout, branch protection, review rules, TCB code ownership |
| SDL-002 | CI/CD: reproducible builds, signed commits, artefact signing, provenance, SBOM, target assurance level (TARGET) |
| SDL-003 | Key custody for release signing: separation of duties, hardware-backed |
| SDL-004 | Environments, IaC, secrets management, access model |
| SDL-005 | Coding standards, threat-model update on design changes, fuzzing, dependency policy, vuln management, disclosure policy |
| SDL-006 | Release rings with auto-halt on regression, tested rollback |
| SDL-007 | Observability, on-call, incident response for company breach |
| SDL-008 | Definition of Done checklist |
| SDL-009 | No secret in repository; cloud tools listed with data-handling notes; costs recorded as unknown |

---

## 1. Repository layout (skeleton tree)

```
repo/
  contracts/          # schemas, APIs, ledger (P0.5)
  docs/               # threat model, architecture, protocols, policy, ADRs
  node/               # agent components
    sensors/
    case-graph/
    reasoning-tiers/
    action-proposer/
    policy-engine/     # TCB (code owners: security + arch)
    containment-controller/
    recovery-verifier/
    evidence-ledger/
    mesh-coordinator/
    enrolment-client/
    updater/
    watchdog/
    os-adapters/
  control-plane/      # services
  tests/              # unit, property, fuzz, scenario
  infra/              # IaC (dev/lab/staging/prod)
  .github/workflows/  # CI pipelines
  SECURITY.md         # disclosure policy
```

---

## 2. Branch protection and review rules

- **Protected branches:** `main`, `release/*`. No direct pushes; PR required.
- **Reviews:** At least 2 approvals for TCB components; 1 approval for non-TCB (but TCB changes require security review).
- **Code owners:** TCB paths owned by security + architecture leads; changes require their approval.
- **Signed commits:** All commits signed (GPG/SSH) and verified in CI.
- **Status checks:** All CI checks must pass before merge.
- **No force push** to protected branches.

---

## 3. CI/CD design

- **Reproducible builds:** Deterministic build environment (pinned toolchains, lockfiles); build twice and compare hashes.
- **Artefact signing:** All release artefacts signed by CI identity using release-signing key (multi-party quorum for key use).
- **Provenance:** SLSA-style provenance attached to each artefact (builder, source commit, build parameters).
- **SBOM generation:** SBOM (SPDX/CycloneDX) generated per build; stored with artefact.
- **Target supply-chain assurance level:** SLSA Level 3 (TARGET/HYPOTHESIS) — not yet achieved; to be validated.
- **Dependency policy:** Allow-listed dependencies; lockfiles required; automated dependency scanning; no unvetted new deps without review.
- **Vulnerability management:** CVE scanning in CI; critical/high block release; remediation SLAs (TARGET: critical 7 d, high 30 d).
- **Fuzzing:** Fuzz targets for parsers and protocol code; run in CI (smoke) and nightly (deep).

---

## 4. Key custody for release signing

- **Release-signing key:** HSM-backed, multi-party quorum (2-of-3) (Trust Protocol §2).
- **Separation of duties:** No single person can both approve and sign a release; builder (CI) and approver (human) distinct.
- **Hardware-backed storage:** HSM for root/intermediate/release keys; per-device keys in TPM/Enclave.
- **Rotation:** Per Trust Protocol (release key every 180 days or on compromise).
- **Revocation:** Runbook per Trust Protocol §7.

---

## 5. Environments

| Environment | Purpose | Access | IaC |
|---|---|---|---|
| Development | Feature work | Engineers (least privilege) | Yes (Terraform/Pulumi TBD) |
| Lab | Testing, fuzzing, chaos | Test engineers | Yes |
| Staging | Pre-release validation | Restricted | Yes |
| Production | Live service | Break-glass only | Yes |

- **Secrets management:** Cloud secrets manager (e.g., AWS Secrets Manager / Azure Key Vault / GCP Secret Manager) — vendor TBD; no secrets in repo. Costs recorded as unknown.
- **Access model:** RBAC, MFA, just-in-time elevation, audit logging. No standing production access.

---

## 6. Quality standards

- **Coding standards per language:** Memory-safe language for TCB; linting and formatting enforced in CI; language-specific guidelines documented in repo.
- **Threat-model update:** Mandatory threat-model delta recorded for any design-affecting change; PR template requires "Threat model delta: [description or 'not needed']".
- **Fuzzing plan:** Fuzz targets for all parsers (envelope, schema, protocol) and protocol code; corpus maintained; crashes triaged.
- **Dependency policy:** Allow-listed, pinned, scanned; new deps require review.
- **Vulnerability management:** CVE scanning; SLAs; disclosure policy (SECURITY.md).
- **Disclosure policy:** Responsible disclosure; security@ contact; 90-day coordinated disclosure (TARGET).

---

## 7. Release rings and rollback

- **Rings:** Ring 0 canary (TARGET 1%), Ring 1 (TARGET 10%), Ring 2 (full fleet).
- **Automatic halt on regression:** Monitor error rates, false-block spikes, crash rates; halt promotion if threshold exceeded (TARGET: 2x baseline within 1 h).
- **Tested rollback:** Rollback procedure tested each release; nodes revert to last known good signed version (anti-rollback enforced).
- **Evidence:** Release decision log, metrics, rollback drill report.

---

## 8. Operating the product

- **Observability:** Metrics, logs, traces for all services; SLOs defined (TARGET).
- **On-call:** Rotation, runbooks, escalation.
- **Incident response (company breach):** Detect, contain, eradicate, recover, post-incident review; notify customers/regulators per compliance (P0.8); evidence preservation.

---

## 9. Cloud-based tools and data handling

All cloud-based IDEs and managed services used must be listed with data-handling notes. Costs recorded as unknown (never guessed).

| Tool category | Example | Data-handling note | Cost |
|---|---|---|---|
| Source control (cloud) | GitHub/GitLab | Code only; no secrets; private repos | Unknown |
| CI/CD (cloud) | GitHub Actions/GitLab CI | Build logs may contain metadata; no secrets | Unknown |
| Cloud secrets manager | TBD | Secrets stored encrypted; access audited | Unknown |
| Cloud IDE | TBD | Code in transit; no production data | Unknown |
| Observability SaaS | TBD | Telemetry only; no customer payload | Unknown |
| Vulnerability scanner | TBD | Dependency metadata | Unknown |

No secret may exist in a repository (enforced by pre-commit hooks and secret scanning).

---

## 10. Definition of Done (every change)

- [ ] Change traces to a SEC/ARC/POL ID
- [ ] Unit and property tests added; decision tests unchanged or approved
- [ ] Parser or protocol code has fuzz target
- [ ] SBOM regenerated, no new critical vulnerabilities
- [ ] Artefact signed by CI identity; provenance attached
- [ ] Threat model delta recorded or stated not needed
- [ ] Code review approvals met (TCB: 2 incl. security)
- [ ] Documentation updated
- [ ] No secrets in diff (secret scan passed)

---

## Contract Closure

1. **Deliverables produced:**
   - Repository skeleton tree (§1)
   - Branch protection and review rules (§2)
   - CI/CD design (§3)
   - Key custody (§4)
   - Environments (§5)
   - Quality standards (§6)
   - Release rings and rollback (§7)
   - Operations and incident response (§8)
   - Cloud tools and data handling (§9)
   - Definition of Done (§10)

2. **Acceptance checks:**
   - Release path has no single person able to ship unsigned/unreviewed code: **PASS** (§2, §4 separation of duties)
   - Update integrity objectives map to controls: **PASS** (§3 maps to SEC-004/SEC-030/SEC-033)
   - No secret in repository: **PASS** (§9 policy + scanning)
   - Costs recorded as unknown: **PASS** (§9)
   - Cloud tools listed with data-handling notes: **PASS** (§9)

3. **Assumptions made:** Tool vendors TBD; target SLSA level TARGET/HYPOTHESIS; ring percentages TARGET.

4. **Open questions:**
   - OQ-01: Final vendor selection for CI/cloud tools (cost unknown).
   - OQ-02: SLSA level achievable with chosen tooling to be validated.
   - OQ-03: Disclosure timeline (90 days) to be confirmed with legal.

5. **Out-of-scope items noticed (not acted on):** writing product code, buying tools, vendor contracts.

6. **Handoff:** Consumed by P0.11. IDs to preserve: SDL-001..SDL-009, DoD checklist.
