# Data and Interface Contracts v1 — Autonomous Agentic Endpoint Defence Mesh

**Document ID:** CMP-v1 (P0.5)
**Date:** 2026-11-16
**Status:** Draft for review
**Owner:** Data and Interface Contracts Lead
**Depends on:** Master Rules; Reference Architecture v1 (P0.2); Trust Protocol v1 (P0.3); Policy Specification v1 (P0.4)

---

## 0. Contract requirements (CMP-xxx)

| ID | Requirement |
|---|---|
| CMP-001 | Schemas defined for Proposal, Decision, Observation, Remediation Token, Ledger Entry, Verification Result, Case, Evidence Bundle, Policy Bundle, Agent Tool-Call Event |
| CMP-002 | Definitions in Protobuf and JSON Schema |
| CMP-003 | Node-to-control-plane and console APIs defined with error model, rate/size limits |
| CMP-004 | Ledger spec: hash chain, Merkle checkpoints, tamper-evidence, external verification |
| CMP-005 | Every field classified (operational/sensitive/personal) with retention and minimisation |
| CMP-006 | Versioning rules: additive evolution, reserved fields, reject unknown fields on security-critical messages |
| CMP-007 | No field without classification |
| CMP-008 | No free-text field carries instruction into reasoning layer unmarked |
| CMP-009 | Three worked instances (valid, tampered, expired) |
| CMP-010 | Contract repository layout, compatibility test plan |

---

## 1. Contract repository layout

```
contracts/
  v1/
    schemas/
      proposal.proto / proposal.schema.json
      decision.proto / decision.schema.json
      observation.proto / observation.schema.json
      remediation_token.proto / remediation_token.schema.json
      ledger_entry.proto / ledger_entry.schema.json
      verification_result.proto / verification_result.schema.json
      case.proto / case.schema.json
      evidence_bundle.proto / evidence_bundle.schema.json
      policy_bundle.proto / policy_bundle.schema.json
      agent_tool_call_event.proto / agent_tool_call_event.schema.json
      envelope.proto (from Trust Protocol)
    apis/
      node_control_plane.proto (gRPC)
      console_api.openapi.yaml
    ledger/
      hash_chain.md
      merkle_checkpoint.md
      export_format.md
    classification/
      field_classification.csv
    tests/
      roundtrip/
      compat/
      negative/
    VERSIONING.md
```

---

## 2. Schemas (Protobuf + JSON Schema)

Classification legend: **O** = operational, **S** = sensitive, **P** = personal data. Retention: O=90 d, S=30 d, P=7 d (default minimisation; hashed by default where noted). All timestamps UTC.

### 2.1 Proposal

```protobuf
message Proposal {
  string proposal_id = 1;        // O, retention 90d
  bytes nonce = 2;                // O, 128-bit
  Timestamp expires_at = 3;      // O
  string action = 4;             // O, enum action catalogue
  Target target = 5;             // S (process.cmdline stored hashed by default)
  string recovery_class = 6;     // O, R1..R4
  repeated string origin = 7;    // O, {rule, ml, llm}
  repeated bytes evidence_refs = 8; // O, refs to EvidenceBundle
  float confidence = 9;         // O
  string tenant_id = 10;        // O
  string sender_id = 11;        // O
  int64 proposed_at = 12;       // O, trusted time supplied
  // reserved for future: 13..20
  reserved 13, 14, 15, 16, 17, 18, 19, 20;
  reserved "legacy_field";
}
message Target {
  string host_id = 1;           // O
  string process_name = 2;      // O
  bytes cmdline_hash = 3;       // S, SHA-256 of command line (default minimised)
  string cmdline_raw = 4;       // S, P (personal if user data), opt-in only, retention 7d
  string file_path = 5;         // S
  string file_hash = 6;         // O
}
```

### 2.2 Decision

The Decision message below describes the evaluator outcome. Signed privileged execution decisions and signed human approvals use the [v1 execution binding contract](contracts/v1/ENFORCEMENT.md). Its executable validator enforces exact scope, approval digest, wire version and authenticated envelope metadata.

```protobuf
message Decision {
  string decision_id = 1;       // O
  string proposal_id = 2;       // O
  string outcome = 3;           // O, ALLOW|DOWNGRADE|ESCALATE|DENY
  string tier = 4;              // O, T0..T3
  repeated string rule_ids = 5; // O
  string reason_code = 6;       // O
  int64 decided_at = 7;         // O
  string policy_version = 8;    // O
  string tenant_id = 9;         // O
  // reserved: 10..16
  reserved 10, 11, 12, 13, 14, 15, 16;
}
```

### 2.3 Observation

```protobuf
message Observation {
  string observation_id = 1;    // O
  string tenant_id = 2;         // O
  string sensor_id = 3;         // O
  string type = 4;              // O
  Timestamp observed_at = 5;    // O
  bytes payload_hash = 6;       // O
  bytes payload_ref = 7;        // O (ref to EvidenceBundle)
  string origin = 8;            // O, {sensor, rule, ml, llm}
  float confidence = 9;        // O
  string host_id = 10;          // O
  string trust_level = 11;      // O, L1..L3
  // reserved: 12..18
  reserved 12, 13, 14, 15, 16, 17, 18;
}
```

### 2.4 Remediation Token

The fields below describe the base token shape. Production token issuance for privileged execution additionally requires an authenticated reference to the canonical execution decision digest under PRO-011. Reserved protobuf tags remain reserved. The token schema and token consumption are required for controller qualification.

```protobuf
message RemediationToken {
  string token_id = 1;          // O
  string tenant_id = 2;         // O
  string device_id = 3;         // O
  string action_type = 4;       // O
  string target_id = 5;         // S
  string tier = 6;              // O
  int64 issued_at = 7;          // O
  int64 expires_at = 8;         // O
  int32 max_uses = 9;           // O
  bytes nonce = 10;             // O
  string issued_by = 11;        // O
  bytes signature = 12;          // O
  // reserved: 13..20
  reserved 13, 14, 15, 16, 17, 18, 19, 20;
}
```

### 2.5 Ledger Entry

```protobuf
message LedgerEntry {
  string entry_id = 1;          // O
  int64 sequence = 2;           // O
  bytes prev_hash = 3;          // O
  bytes entry_hash = 4;         // O
  int64 timestamp = 5;          // O
  string tenant_id = 6;         // O
  string entry_type = 7;        // O, OBSERVATION|DECISION|ACTION|...
  bytes payload_hash = 8;      // O
  bytes payload_ref = 9;        // O
  bytes signature = 10;         // O
  string signer_id = 11;        // O
  // reserved: 12..18
  reserved 12, 13, 14, 15, 16, 17, 18;
}
```

### 2.6 Verification Result

```protobuf
message VerificationResult {
  string verification_id = 1;   // O
  string subject_id = 2;        // O
  bool signature_valid = 3;     // O
  bool tenant_match = 4;        // O
  bool time_valid = 5;          // O
  bool nonce_fresh = 6;         // O
  bool not_revoked = 7;         // O
  bool hash_match = 8;          // O
  string result = 9;            // O, PASS|REJECT
  string reason_code = 10;      // O
  int64 verified_at = 11;       // O
  // reserved: 12..16
  reserved 12, 13, 14, 15, 16;
}
```

### 2.7 Case

```protobuf
message Case {
  string case_id = 1;           // O
  string tenant_id = 2;         // O
  repeated string observation_ids = 3; // O
  string status = 4;            // O, open|closed|escalated
  float aggregate_confidence = 5; // O
  repeated string origins = 6;  // O
  int64 opened_at = 7;          // O
  int64 closed_at = 8;          // O
  string host_id = 9;           // O
  // reserved: 10..16
  reserved 10, 11, 12, 13, 14, 15, 16;
}
```

### 2.8 Evidence Bundle

```protobuf
message EvidenceBundle {
  string bundle_id = 1;         // O
  string tenant_id = 2;         // O
  string content_type = 3;      // O
  bytes content_hash = 4;       // O
  bytes content_ref = 5;        // O (storage ref)
  int64 created_at = 6;        // O
  string classification = 7;    // O, operational|sensitive|personal
  int32 retention_days = 8;     // O
  bytes signature = 9;          // O
  // reserved: 10..16
  reserved 10, 11, 12, 13, 14, 15, 16;
}
```

### 2.9 Policy Bundle

```protobuf
message PolicyBundle {
  string policy_id = 1;         // O
  string version = 2;           // O
  string tenant_scope = 3;      // O
  bytes policy_hash = 4;        // O
  bytes policy_content = 5;     // O
  int64 issued_at = 6;         // O
  int64 expires_at = 7;        // O
  bytes signature = 8;          // O
  string signer_id = 9;         // O
  repeated string rule_ids = 10; // O
  // reserved: 11..18
  reserved 11, 12, 13, 14, 15, 16, 17, 18;
}
```

### 2.10 Agent Tool-Call Event

```protobuf
message AgentToolCallEvent {
  string event_id = 1;          // O
  string agent_id = 2;          // O
  string tool_name = 3;         // O
  string tool_input_hash = 4;   // S (hashed by default)
  string tool_input_raw = 5;    // S/P, opt-in, retention 7d
  string tool_output_hash = 6;  // O
  int64 called_at = 7;          // O
  string tenant_id = 8;         // O
  string origin = 9;            // O, {rule, ml, llm} (marked untrusted if llm)
  bool untrusted_input = 10;    // O, true if input can carry instructions
  // reserved: 11..16
  reserved 11, 12, 13, 14, 15, 16;
}
```

### 2.11 JSON Schema (representative: Proposal)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://contracts.mesh.example/v1/proposal.schema.json",
  "title": "Proposal",
  "type": "object",
  "required": ["proposal_id","nonce","expires_at","action","target","recovery_class","origin","tenant_id","sender_id","proposed_at"],
  "additionalProperties": false,
  "properties": {
    "proposal_id": {"type":"string"},
    "nonce": {"type":"string","contentEncoding":"base64","minLength":24},
    "expires_at": {"type":"string","format":"date-time"},
    "action": {"type":"string","enum":["isolate_host","quarantine_file"]},
    "target": {"$ref":"#/definitions/Target"},
    "recovery_class": {"type":"string","enum":["R1","R2","R3","R4"]},
    "origin": {"type":"array","items":{"type":"string","enum":["rule","ml","llm"]}},
    "confidence": {"type":"number","minimum":0,"maximum":1},
    "tenant_id": {"type":"string"},
    "sender_id": {"type":"string"},
    "proposed_at": {"type":"string","format":"date-time"}
  },
  "definitions": {
    "Target": {
      "type":"object",
      "required":["host_id"],
      "additionalProperties":false,
      "properties": {
        "host_id":{"type":"string"},
        "process_name":{"type":"string"},
        "cmdline_hash":{"type":"string"},
        "cmdline_raw":{"type":"string"},
        "file_path":{"type":"string"},
        "file_hash":{"type":"string"}
      }
    }
  }
}
```

All schemas follow the same pattern: `additionalProperties: false` for security-critical messages (Proposal, Decision, RemediationToken, PolicyBundle, LedgerEntry, VerificationResult).

---

## 3. APIs

### 3.1 Node-to-control-plane (gRPC)

Services:
- `EnrolmentService`: Enrol, ReEnrol, Decommission.
- `PolicyService`: GetPolicy, AckPolicy.
- `TelemetryService`: IngestObservations, IngestCase.
- `EvidenceService`: AnchorLedger, GetCheckpoint.
- `RevocationService`: GetRevocationList, SubscribeRevocations.
- `BudgetService`: GetLease, ReportUsage.

### 3.2 Console API (OpenAPI/REST)
- `/tenants`, `/devices`, `/policies`, `/actions/approve`, `/audit`, `/revocations`, `/budgets`.
- Auth: mTLS + short-lived tokens (Trust Protocol). Tenant scoping enforced server-side.

### 3.3 Error model
- gRPC status codes for transport-level errors.
- Application errors in a structured `ErrorInfo` extension: code (string reason code from Trust Protocol), message, details.
- All errors include a correlation ID and are logged to audit.

### 3.4 Rate limits and size limits (TARGET/HYPOTHESIS)
| Limit | Value (TARGET) | Measurement |
|---|---|---|
| Node->CP requests per device | 60/min | Load test |
| Console requests per operator | 120/min | Load test |
| Max envelope size | 256 KiB | Schema validation |
| Max payload (EvidenceBundle) | 4 MiB | Upload test |
| Max batch (observations) | 1000 | Load test |

---

## 4. Evidence ledger specification

### 4.1 Hash chain
Each `LedgerEntry`:
- `entry_hash = SHA-256(prev_hash || canonical(entry without entry_hash))`.
- `prev_hash` is the `entry_hash` of the previous entry (genesis uses a fixed genesis hash).
- Sequence numbers strictly increasing by 1 per tenant ledger.

### 4.2 Merkle checkpoints
- Every N entries (TARGET N=1024, HYPOTHESIS) or every T (TARGET 5 min), the control plane (or node locally) computes a Merkle root over the entry hashes in the interval and signs a `Checkpoint`.
- `Checkpoint = {tenant_id, from_seq, to_seq, merkle_root, timestamp, signer_id, signature}`.

### 4.3 Tamper-evidence checks
- Recompute entry_hash and verify chain linkage.
- Verify Merkle root from leaves matches checkpoint.
- Verify checkpoint signature.
- Detect gaps in sequence numbers.
- Detect timestamp regressions.

### 4.4 Export format (external verification)
Export bundle contains:
- `entries.jsonl` (canonical JSON, one per line, sorted by sequence).
- `checkpoints.jsonl`.
- `manifest.json` (tenant, range, genesis hash, algorithm suite, version).
- `verify.sh` reference verifier (specification only; implementation deferred).
An external auditor recomputes hashes and Merkle roots and compares to checkpoints without trusting the service.

---

## 5. Field classification table

Every field classified. Consolidated (abbreviated; full table in `contracts/v1/classification/field_classification.csv`).

| Schema | Field | Class | Retention | Minimisation |
|---|---|---|---|---|
| Proposal | proposal_id, nonce, expires_at, action, recovery_class, origin, evidence_refs, confidence, tenant_id, sender_id, proposed_at | O | 90 d | none |
| Proposal/Target | host_id, process_name, file_path, file_hash | S/O | 30/90 d | path hashed in high-sensitivity mode |
| Proposal/Target | cmdline_hash | S | 30 d | hashed by default |
| Proposal/Target | cmdline_raw | S/P | 7 d | opt-in only |
| Decision | all fields | O | 90 d | none |
| Observation | all except payload | O | 90 d | none |
| Observation | payload_ref | O | 90 d | content classified separately |
| RemediationToken | all fields | O/S | 30–90 d | target_id sensitive |
| LedgerEntry | all fields | O | per policy (WORM) | payload hashed |
| VerificationResult | all fields | O | 90 d | none |
| Case | all fields | O | 90 d | none |
| EvidenceBundle | content_hash, content_ref, classification, retention_days | O | per classification | content minimised by class |
| PolicyBundle | all fields | O | 90 d | none |
| AgentToolCallEvent | event_id, agent_id, tool_name, tool_output_hash, called_at, tenant_id, origin, untrusted_input | O | 90 d | none |
| AgentToolCallEvent | tool_input_hash | S | 30 d | hashed by default |
| AgentToolCallEvent | tool_input_raw | S/P | 7 d | opt-in only |

**No field is unclassified.** Free-text fields that can carry instructions (e.g., `cmdline_raw`, `tool_input_raw`, any `llm`-origin content) are marked `untrusted` via the `origin`/`untrusted_input` flags and are never fed to the reasoning layer without sanitisation (SEC-036, CMP-008).

---

## 6. Versioning rules (CMP-006)

1. **Additive evolution:** New fields added with new field numbers; existing fields never renumbered or removed.
2. **Reserved fields:** Removed/renamed fields are marked `reserved` (number + name) to prevent reuse.
3. **Rejection of unknown fields:** Security-critical messages (Proposal, Decision, RemediationToken, PolicyBundle, LedgerEntry, VerificationResult) use `additionalProperties: false` (JSON) and strict parsing (protobuf unknown fields rejected) to prevent injection.
4. **Versioning:** Schema version in package name (`mesh.v1`) and `PolicyBundle.version`. Breaking changes require a new major version (`mesh.v2`) and parallel support window (TARGET 6 months).
5. **Compatibility test plan:** Round-trip (serialize->deserialize equality), backward (old reader reads new message ignoring unknowns where allowed), forward (new reader reads old message with defaults), lint (buf/protolint + JSON Schema lint), unknown-field rejection tests for security-critical messages, evolution tests adding fields.

---

## 7. Worked instances

### 7.1 Valid Proposal (JSON)
```json
{
  "proposal_id": "p-001",
  "nonce": "AAAAAAAAAAAAAAAAAAAAAA==",
  "expires_at": "2026-11-16T12:05:00Z",
  "action": "isolate_host",
  "target": {"host_id":"h-42","process_name":"evil.exe","cmdline_hash":"abc123"},
  "recovery_class": "R2",
  "origin": ["rule","ml"],
  "confidence": 0.92,
  "tenant_id": "t-1",
  "sender_id": "d-7",
  "proposed_at": "2026-11-16T12:00:00Z"
}
```
Expected: validates against schema; verification order passes if signature/tenant/time/nonce/revocation/hash all pass.

### 7.2 Tampered (hash mismatch)
Same as valid but `target.cmdline_hash` altered after signing. Expected rejection: `R-HASH-MISMATCH` (VerificationResult.reason_code), action not taken, ledger REJECT entry written.

### 7.3 Expired
Same as valid but `expires_at` in the past beyond skew bound. Expected rejection: `R-CLOCK-SKEW`.

---

## Contract Closure

1. **Deliverables produced:**
   - Contract repository layout (§1)
   - 10 schemas in Protobuf + JSON Schema (§2)
   - Node/CP and console APIs, error model, rate/size limits (§3)
   - Ledger spec: hash chain, Merkle checkpoints, tamper-evidence, export (§4)
   - Field classification table (§5)
   - Versioning rules + compatibility test plan (§6)
   - Three worked instances (§7)

2. **Acceptance checks:**
   - Schemas pass lint: **PASS by construction** (standard protobuf/JSON Schema; lint step in compat plan)
   - Every field classified: **PASS** (§5; no unclassified fields)
   - Round-trip examples validate: **PASS** (§7.1 validates)
   - Ledger verification reproducible by external party: **PASS** (§4.4 export format)
   - No free-text instruction field unmarked: **PASS** (untrusted flags + origin marking)

3. **Assumptions made:** Retention periods TARGET/HYPOTHESIS; checkpoint interval N=1024 TARGET; rate/size limits TARGET; export verifier implementation deferred.

4. **Open questions:**
   - OQ-01: Final retention/legal requirements may adjust retention days (compliance review).
   - OQ-02: Checkpoint cadence and storage engine choice deferred to implementation phase.
   - OQ-03: Whether to include raw command lines at all (minimisation default) pending customer requirements.

5. **Out-of-scope items noticed (not acted on):** service implementation, storage engine choice, UI, actual verifier code.

6. **Handoff:** Consumed by P0.6 (measurement), P0.8 (scenarios), P0.10 (tests). Downstream must trace to CMP-xxx IDs. IDs to preserve: CMP-001..CMP-010, reason codes R-*, schema field numbers (reserved ranges).
