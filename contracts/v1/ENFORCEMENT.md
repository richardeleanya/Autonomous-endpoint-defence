# v1 execution binding contract

This contract defines the signed EXECUTION_DECISION and HUMAN_APPROVAL payloads for P2.2. The node decision signer records the effective P2.1 outcome. The control-plane approval service attests the independent human approval after checking the approver's tenant role, MFA and scope. The control-plane authorisation service issues any separate PRO-011 remediation token.

## Shared scope

Both payloads carry an identical `scope` object. The controller reconstructs the expected scope from the verified proposal, trusted local identity, resolved target and exact active policy. It also supplies the current target protection, criticality, bulk classification and time from trusted state.

| Fields | Meaning |
|---|---|
| `tenant_id`, `device_id` | Canonical lowercase hyphenated UUIDs for the controlling tenant and the endpoint. |
| `incident_id`, `proposal_id`, `proposal_sha256` | Incident and proposal IDs, with a digest of the verified canonical proposal payload. |
| `requester_id` | Stable tenant-scoped identity for the verified requester. The approval service uses the same identity namespace for the approver. |
| `action_id`, `tier` | Catalogue action ID in the form `A-NN`, with two decimal digits. The trusted catalogue supplies `T2` or `T3`. |
| `target_id`, `parameters_sha256` | Resolved target ID and digest of the validated canonical action parameters. For A-18 these parameters include the exact destination, backup identity and verified backup digest and record. |
| `policy_version`, `policy_sha256` | Active policy version and digest of its verified canonical payload. |

IDs and versions other than UUIDs, the tier and the action ID are ASCII strings of 1–128 characters. The first character is alphanumeric. Subsequent characters can also include `_`, `.`, `:` or `-`. Digests are 64 lowercase hexadecimal characters. Producers use SHA-256 over the canonical bytes defined for each referenced object.

## Payload fields and validation

Each payload is an ASCII JSON object of at most 4,096 bytes. Keys are sorted lexicographically at every level. Use no whitespace between JSON tokens and no trailing newline. The v1 schema is closed. Unknown, missing or duplicate keys and noncanonical bytes are rejected. [Executable codec and validator](enforcement.py)

| Fields | Requirements |
|---|---|
| Common | Integer `version` is `1`. `kind` is the authenticated message type. `scope` exactly matches trusted context. Integer Unix UTC seconds `issued_at` and `expires_at` match the authenticated envelope. Timestamps range from `0` through `253402300799`. The trusted time satisfies `issued_at <= now < expires_at`. |
| EXECUTION_DECISION | `decision_id` is an issuer-assigned ID unique within the tenant. `outcome` follows the policy outcomes. Only `ALLOW` passes binding validation. `approval_sha256` is the digest of the exact canonical approval payload or JSON null when there is no approval. |
| HUMAN_APPROVAL | `approval_id` is an issuer-assigned ID unique within the tenant. `approver_id` identifies the verified approver and differs from `requester_id`. `mfa` is JSON true and `max_uses` is integer `1`. The approval is issued before or at decision issuance, and the decision validity interval ends by approval expiry. |

R6 always rejects a protected target. T3, bulk T2 and critical-asset T2 require approval. Any approval supplied with an executable decision must match the scope, envelope and digest. The control-plane service can issue approval for the proposed scope before the evaluator runs. The final decision then binds the particular approval it used.

## Controller integration and evidence

The PRO-009 verifier authenticates signature, payload hash, issuer role, tenant, envelope type, expiry, applicable lifetime, clock and revocation checks before constructing a `VerifiedPayload`. The controller passes the authenticated payload bytes and envelope metadata to `validate_binding` at the same trusted time. Raw request bodies never create this trusted input. The parser and matcher are executable in Python using only the standard library.

Successful binding validation permits the controller to proceed with its other mandatory checks. Observe-only, trusted state, policy, token, lease and budget checks, durable consumption across retries and restarts, ledger writes and safe recovery are P2.2 integration requirements. A separate remediation token must bind the canonical decision digest and pass PRO-011. [Controller sign-off](../../P2.2_Enforcement_Controller_v1.md#4-sign-off-evidence)

Run the contract checks locally or through the existing Docker evidence runner from the checkout root.

```bash
python3 -B -m unittest discover -s test/enforcement-contract -v
./scripts/docker-release-check.sh integration test/enforcement-contract/compose.yaml
```

The suite supplies synthetic authenticated-envelope inputs to cover scope, approval identity and digest, expiration, malformed payloads and POL-T-009/027/042. Full signature verification, controller rejection evidence, ledger integrity and recovery evidence are separate P2.G requirements. [P2 gate](../../P2.G_Gate_P2_Report.md)
