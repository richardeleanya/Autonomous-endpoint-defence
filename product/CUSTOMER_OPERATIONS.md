# Customer operations for observe-only service

The control plane accepts customer data after the tenant enters `active`. Before that, the deployment administrator configures its UUID, operator identity and unique backup key as described in the [product guide](README.md). Schema v3 preserves existing records. Tenants previously active without verified approval move to `pending`. Suspended and offboarded states retain their restrictions. Both migrations clear enrollment and support grants and cancel queued work. Reconcile the existing inventory and obtain activation approval before upgrading a customer installation.

## Privacy and customer authorisation record

**Status: pending authorised review.** File the approved records in the restricted customer case system. A deployment administrator prepares tenant-specific activation metadata from verified signatures. Customer Operations records the exact signed references during provisioning. Expiry or removal of the approved configuration blocks service and queued work.

| Required decision | Signer and evidence to record |
|---|---|
| Privacy assessment | Privacy Lead and Legal record the signed DPIA, role allocation, applicable lawful basis, worker notice, retention and deletion schedule, legal holds, processor terms, subprocessors, and transfer assessment. Record residual risks, decision date and review date. |
| Customer scope and authorisation | The customer's authorised representative signs the tenant UUID, enrolled asset scope, permitted heartbeat fields and purpose, support access rules, term and revocation contact. Share an authoritative asset list through the restricted case system. The product scope here is observe-only. |
| Commercial terms | Customer Operations and the customer commercial owner confirm contract ID, endpoint cap, billable-unit definition, billing interval, usage dispute process, export and exit terms. |
| Activation record | Record the signed document versions, signer authority, date and applicable tenant UUID. An operations reviewer checks that scope and terms are current and enters their references. Use a distinct person for tenant operator or support duties. |

### Data inventory for review

| Data | Use and destination | Pending production decision |
|---|---|---|
| Device UUID, platform, architecture, heartbeat ID, build and server receipt time | Tenant-local inventory, heartbeat history and usage totals. Heartbeat data can be exported or materialised in tenant-scoped backup and recovery artifacts. | Approved retention and deletion across database, artifacts, customer exports and backup copies. |
| Tenant operator and support principal IDs, support grants and operation timestamps | Tenant-local support and access audit. Case references link to separately restricted approval records. | Retention, access log review, and approved handling of rights requests and legal holds. |
| Hashed bearer credentials, enrollment grants and per-tenant artifact key | Deployment configuration, credential checks and artifact verification. Enrollment grants expire after ten minutes. | Managed identity, controlled key rotation and revocation, and encryption at rest in the target hosted environment. |

Use the [privacy requirements register](../Privacy_Compliance_Requirements_v1.md) when filing approvals.

To prepare activation, obtain distinct Privacy, Legal and customer signatures over the exact bytes of `approval.json`. The document contains `version` = 1, `tenant` UUID, `mode` = `observe-only`, the three approval references, integer `retention_days`, and future Unix seconds `expires_at`. Each signer must review the referenced version of the underlying approved records before signing. Place the detached OpenSSH signatures in `signatures/privacy.sig`, `signatures/legal.sig` and `signatures/customer.sig`. Use the `ada-customer-approval-v1` signature namespace. Pin the corresponding Ed25519 public keys in an administrator-managed JSON role map outside the submitted bundle.

```bash
python3 -B release/verify_customer_approval.py \
  --bundle "$APPROVAL_BUNDLE" --trust-policy "$TENANT_APPROVAL_KEYS" --tenant "$TENANT_UUID"
```

Only the successful verifier output goes into the matching tenant's `approved_activation` object in the protected deployment configuration. The output retains the exact signed payload alongside its digest. The API and worker reject mismatches between signed bytes and the configured approval fields. Regenerate earlier verifier output before upgrading. Customer and operations clients have no write access to that configuration. Protect the key policy and verifier installation as privileged administration inputs. Retain the signed approval bundle and document versions in the restricted case record. The deployment administrator restarts the API and worker after configuration changes. Suspend and use `resume` with current approvals for a renewed active account, providing all three references if changed.

### Retention and deletion evidence

Configure a distinct `privacy_operations` staff principal map using the same UUID and token digest format as Customer Operations. The corresponding bearer can submit the following tenant-scoped POST operations. Verify case authority with the approved privacy owner before executing them against customer data.

| Operation | Behaviour and evidence |
|---|---|
| `privacy-hold` | Supply `case_ref` and boolean `held`. An active hold blocks the other privacy operations and is recorded in the audit. |
| `retain-telemetry` | Supply the authorised `case_ref`. Removes live heartbeat rows older than the signed retention cutoff and invalidates local artifacts containing expired telemetry. Fresh telemetry is preserved. Use this operation for a case-driven sweep. The worker also applies the last activated, matching verified retention policy at startup and hourly, preserving records under a hold. It audits scheduled removals with the cutoff and row and file counts. |
| `erase-telemetry` | Supply the disposition `case_ref` after terminal offboarding and approved usage closeout. Removes local telemetry, inventory, job data and associated local artifacts. A retry reports what it removed during that invocation. |

Export reads and restores enforce the effective cutoff even before the physical removal step. Persist the response, case reference, cutoff, affected store counts and audit action in the restricted evidence record. An unclassified artifact or storage failure requires investigation and re-verification before recording completion. The tenant-level retention floor protects against bringing expired telemetry back from an old artifact.

Activation records and audit records remain available for approved legal and operational purposes. Customer downloads, independent snapshots, hosted replicas and backups require evidence from their respective custodians. The local controls demonstrate logical deletion from the application database and files in its tenant artifact volume. Production disposal of audit data, externally retained copies and storage media requires the approved schedule, legal-hold decisions and separate evidence.

## Operations API

Configure optional `customer_operations` in `tenants.json` as a map from staff principal UUID to SHA-256 bearer-token digest. Customer Operations is a distinct platform role scoped to the actions below. Operator or support credentials cannot perform them. Use `POST /v1/tenants/{tenant}/{operation}` with the Customer Operations credential.

| Operation | Request and effect |
|---|---|
| `provision` | From pending, supply `max_endpoints`, `contract_ref`, `privacy_ref` and `customer_authorisation_ref`. Activates the configured tenant only when all three references match the current independently verified approval. The active device cap is checked transactionally when each enrollment grant is redeemed. |
| `entitlement` | Supply `max_endpoints` and `case_ref` for the approved amendment. A reduction below enrolled active devices is rejected. |
| `reconcile` | Supply Unix second `start` and `end` for an already closed UTC interval `[start,end)`, `expected_endpoints` from the billing register, and `case_ref`. The service compares distinct reporting endpoint IDs with the expected count and returns the variance and status, plus accepted event count. Duplicate heartbeat IDs are counted once. Investigate mismatches before approving a manual invoice. Endpoint replacements can affect distinct count independently of the simultaneous enrollment cap. |
| `suspend` | Supply `case_ref`. Stops ingestion and tenant access, cancels queued jobs, and clears enrollment and support grants. A scoped tenant operator can still revoke a specific device while suspended. |
| `resume` | Supply the approved incident closure or resumption `case_ref`. Unrevoked devices can reconnect. Revoked devices, cleared grants and cancelled jobs require fresh approved actions. |
| `retire` | From suspended, supply the documented exit `case_ref`. Terminal offboarding invalidates all device credentials and tenant access. The operations role retains aggregate reconciliation access for approved closing periods. |

For a planned exit, verify the customer's request and complete any authorised export while the tenant is active. Confirm delivery through the approved secure channel and record it. Suspend, retire and confirm old credentials and export access are denied. Reconcile final usage and record disposition owners and deadlines. Record endpoint uninstall and hosted backup disposition when their environments are available.

## Support runbook

1. Confirm customer identity, tenant UUID, requested scope and urgency in the case. The tenant operator grants short-lived inventory access for the named support principal.
2. Confirm access is restricted to the granting tenant's device inventory. Inspect only the required fields and record the support action. Route any data or evidence request through the tenant operator's approved export workflow.
3. Revoke the grant on resolution and verify access is denied. Confirm grant, successful access and revoke events in the tenant audit. Check the incident path if there is evidence of mis-scoped access.

The Docker drill exercised default denial, scoped grant, allowed inventory read, cross-tenant denial, denied audit and export access, expiry, revocation and audit attribution using disposable identities.

## Incident runbook

1. Open an incident record with tenant, timestamp, reported impact, severity, identity of the incident lead and next review time. Escalate to Support, SRE, Security and Privacy according to the affected data and customer agreement. Record who owns notification and the required deadline.
2. Suspend the affected tenant when continued access or ingestion is unsafe. Check rejected ingestion and revoked support access, and verify queued work is cancelled. Preserve evidence under the documented handling and legal-hold process. Revoke any suspected device credential using the tenant operator path while suspended.
3. Verify the scope of the issue and affected data. Record remediation, required legal or customer notifications, and the reviewer who authorised resumption. Resume only after validation. Confirm a healthy unrevoked device reconnects, the revoked credential fails, and stale grants stay unusable.
4. Record the timeline and audit IDs, customer impact and corrective actions. For a hosted outage, use the approved backup/restore and failover procedures and capture measured RPO and RTO.

The Docker drill exercised suspension, queued work cancellation, credential revocation during suspension, resumption, stale credential denial, audit checks and a separate telemetry restore. Live paging, regulator or customer notification, and full hosted disaster recovery require authorised operational exercises.

Run the local drills with [the Docker qualification command](README.md#build-sign-and-qualify). The tests use synthetic authorisation references and distinct disposable lab signing keys. The tests verify rejection of tampered signatures and altered activation metadata, expired artifact restore, holds on scheduled and manual deletion, audit evidence, local deletion and a zero-removal retry. Customer rollout requires the actual signed approvals and remaining release evidence in the [qualification pack](../Release_Qualification_and_Evidence_Pack.md).
