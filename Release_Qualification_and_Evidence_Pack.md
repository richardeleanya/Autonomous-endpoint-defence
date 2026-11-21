# Release qualification and evidence pack

**Decision: NO-GO for customer rollout.** There is no production release candidate or hosted deployment configuration to approve. The repository has an internal observe-only fixture. P2.G remains NO-GO pending controller, ledger, investigator and recovery evidence. [P2 gate](P2.G_Gate_P2_Report.md)

## Candidate record

Create one immutable pack per candidate. Fill these fields before requesting approval. Record fixture evidence separately from candidate evidence.

| Field | Current candidate |
|---|---|
| Clean Git commit, build run ID, build toolchain and provenance digest | Pending production build |
| Windows MSI/driver and Linux deb/rpm digests and signature verification | Pending endpoint packages |
| Registry image digests and SBOM digests | Pending production images |
| Deployment config digest, IaC revision, migration versions, policy and schema versions | Pending deployment configuration |
| Non-production account, regions, topology and target rollout ring | Pending hosted environment |
| Evidence manifest digest, reviewers, approval timestamp and decision | Pending candidate evidence and approvals |

Every result records the candidate ID, requirement or test ID, environment, run time, command or procedure revision, expected and actual outcome, status, and evidence checksum. Use PASS, FAIL, BLOCKED, or NOT RUN. Skipped and blocked checks do not satisfy release gates. Archive raw evidence with access controls. Use redacted summaries for external review.

## Qualification matrix

| Track | Required environment and coverage | Evidence and acceptance | Status |
|---|---|---|---|
| Docker integration | Candidate API, datastore, queue, identity emulator and synthetic tenants | Service contract results, migration tests from empty and supported prior schemas, upgrade and restore results, tenant isolation across API and async processing, and offboarding with audit retained | Fixture lifecycle only. Product contracts and migrations NOT RUN |
| Windows endpoint | Supported Windows 10 21H2+ and Windows 11 editions/builds, plus Server 2016, 2019, 2022 and 2025. Record exact edition, servicing status, patch baseline and Secure Boot state. | Verify signed MSI and driver installation under Secure Boot, delivery of approved test events, watchdog, protected configuration, supported upgrades, rollback, reboot and uninstall. Verify coexistence with OS protections and supported security products. Record baseline and loaded CPU/RSS and regressions for each supported row. [Windows spec](P1.1_Windows_Sensors_v1.md#6-compatibility-plan) | BLOCKED on signed packages and Windows lab |
| Linux endpoint | Ubuntu 20.04, 22.04, 24.04 and RHEL 8/9, plus each advertised derivative. Record exact kernels, Secure Boot where supported, and SELinux/AppArmor state. | Verify signed deb/rpm lifecycle, eBPF CO-RE on eligible kernels and observable fanotify/audit fallback where required. Check event delivery, protected configuration, coexistence, watchdog, upgrades, rollback and uninstall. Record per-row baseline and loaded CPU/RSS. [Linux spec](P1.2_Linux_Sensors_v1.md#2-support-matrix) | BLOCKED on native packages and VM lab |
| Hosted identity, keys and deployment | Non-production account with scoped workload identities, deployment role, key service, registry and segregated signing authority | Verify allowed operations and denial for out-of-scope identities, signed candidate verification, key lifecycle, and traceability from deployment to approved digest and configuration. Use disposable tenants and auditable identities. | BLOCKED on deployment artifacts and scoped account access |
| Hosted restore and failover | Candidate topology in the target regions, representative state and controlled service interruptions | Restore data, audit and policy into a fresh environment. Measure data loss and time to verified service recovery. Test failover, then verify tenant isolation and fleet-budget consistency on reconciliation. Compare measured RPO/RTO to CP-005 targets of 15 minutes and one hour. [Control-plane spec](P3.3_Control_Plane_v1.md#5-storage-queueing-deployment-availability) | BLOCKED on deployed candidate |
| Hosted performance and fleet safety | Representative tenant mix, approved workload generator and endpoint fleet. Exercise the contracted lab scale and CP-006 load profile. | Record p50/p95/p99 latency, error rate, throughput, saturation, isolation and fleet cap. Collect raw endpoint timing samples, false-block counts and endpoint-days, and attempted/successful recovery counts by class. Compare to the [acceptance metrics](Acceptance_Contract_v1.md#4-metric-definitions). | BLOCKED on deployed candidate and native agents |

Endpoint Runtime owns the native matrix. SRE and Control Plane Engineering own hosted runs. QA records the exact versions, sample sizes and workload conditions. Product and Security must approve any change to the advertised support matrix. Measure the acceptance contract's latency, false-block, recovery and overhead figures with raw data before reporting them as achieved. An observe-only run does not measure automated false blocks or containment latency.

## Local evidence recorded

The Docker lifecycle ran successfully on 21 November 2026. One scenario passed, with no skipped tests and successful cleanup. The Windows-labelled agent was simulated and the Linux agent ran in a container. The run covers enrollment, heartbeat ingestion, synthetic tenant isolation, audit, revocation and offboarding.

- Base Git commit: `ec12720e5ef5eb70afe1cf64733f1c2851c42af7` with a dirty checkout.
- Compose input SHA-256: `75e2792ae7664cbc04addefc0a2295f44eedaa81df9760a4c71de63e6c1635b6`.
- API image ID: `sha256:99627b3f5be69b960f445bc6bc44516556a5ab1db8e059508007bbc6e50e2904`.
- Test image ID: `sha256:58b21566963730ec41cdc7ccb5a6d9ea5a9556a452414b76a04b5671213312e4`.
- Verified evidence manifest SHA-256: `9da10b9eb5619c34ca18e7b6df4af8b517264135031cf7548f40ee1133786e85`. The local run directory is `/tmp/ada-docker-check.RIP3D04E`.

## Customer rollout gate

| Evidence group | Accountable reviewer | Required approval evidence | Current status |
|---|---|---|---|
| Signed artifacts and configuration | Release Engineering and Security | Verify package and image signatures, SBOM and provenance. Match tested and promoted digests and the deployment config digest. | BLOCKED |
| Tenant isolation and audit | Security and QA | Candidate evidence across API, jobs, exports, support access and restore. Include audit completeness and ledger verification. | BLOCKED. Synthetic fixture evidence only |
| Fleet safety, recovery and rollback | Endpoint Runtime and Security | P2.G sign-off, native matrix, phased rollout/stop criteria, signed rollback and safe recovery drill. Autonomous enforcement requires specific approval backed by these results. | BLOCKED |
| Privacy and customer authority | Privacy and Legal | Approved data inventory, DPIA, customer terms and authority, retention/export/deletion evidence and worker transparency. | Approval and implementation evidence pending |
| Hosted restore and failover | SRE | Restore integrity checks, measured RPO/RTO, failover and service recovery evidence for the deployment topology. | BLOCKED |
| Support and incident ownership | Support and SRE | Named on-call owners, escalation and customer communications, exercised incident and rollback runbooks. | Sign-off and drill evidence pending |
| Commercial lifecycle | Product and Customer Operations | Demonstrate onboarding, entitlements and usage reconciliation, support handoff, suspension, export and offboarding for the sales model. | Product evidence pending |

Include gate summaries, workload and hardware details, a ledger verification sample, residual risks and review dates, and reviewer contacts as required by the [acceptance contract](Acceptance_Contract_v1.md#7-evidence-pack-template-enterprise-buyerauditor). Record dated approvals or rejection reasons against the candidate and evidence manifest. The CTO records the final GO or NO-GO for the specified deployment and rollout ring after all required approvals. A change to a candidate artifact or deployment configuration requires impact review and requalification of affected evidence before promotion.

The available Docker environment can exercise the synthetic observe-only workflow. Completing release qualification requires signed native endpoint packages, access to the licensed Windows and Linux VM matrix, and a deployed non-production candidate with scoped credentials. Privacy, support and commercial owners must supply their approvals and evidence before customer rollout.
