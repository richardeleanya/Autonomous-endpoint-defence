# Trust Protocol Specification v1 — Autonomous Agentic Endpoint Defence Mesh

**Document ID:** PRO-v1 (P0.3)
**Date:** 2026-11-16
**Status:** Draft for review
**Owner:** Principal Cryptography and Identity Engineer
**Depends on:** Master Rules; Threat Model v1 (P0.1); Reference Architecture v1 (P0.2)
**Inputs status:** Core Design not supplied; enrolment/revocation state machines derived from stated rules and P0.2 components (labelled [ASSUMPTION] where applicable).

---

## 0. Protocol requirements (PRO-xxx)

| ID | Requirement |
|---|---|
| PRO-001 | Device identity is tenant-scoped and unique per device |
| PRO-002 | Enrolment tokens are single-use, tenant-scoped, and time-limited |
| PRO-003 | Administrator approval required before certificate issuance |
| PRO-004 | Re-enrolment revokes prior identity; decommissioning revokes and removes |
| PRO-005 | Key hierarchy: offline root, intermediates, policy-signing, release-signing, per-device |
| PRO-006 | Each key has defined custody, rotation, and revocation |
| PRO-007 | Hardware-backed keys preferred; software-only keys receive lower trust level |
| PRO-008 | Message envelope contains tenant, sender, type, nonce, issued-at, expiry, payload hash, signature, version |
| PRO-009 | Envelope verification follows the canonical order in §4.3 |
| PRO-010 | Peer corroboration proves distinct devices with collusion limits |
| PRO-011 | Remediation tokens are scoped, short-lived, and clock-skew aware |
| PRO-012 | Offline leases bound autonomous action under partition |
| PRO-013 | Revocation functions under partition with grace windows |
| PRO-014 | Key-compromise runbook documented |
| PRO-015 | What signatures prove / do not prove stated in writing |
| PRO-016 | Standard vetted primitives only; no custom cryptography |
| PRO-017 | Algorithm agility supported |
| PRO-018 | Post-quantum migration note included |
| PRO-019 | Each message type has replay and forgery analysis |
| PRO-020 | At least 20 negative test vectors with reason codes |

---

## 1. Primitives and algorithm agility (PRO-016, PRO-017, PRO-018)

**Standard primitives only (no custom cryptography):**
- Signatures: Ed25519 (preferred) or ECDSA P-256 (compatibility).
- Hash: SHA-256 (SHA-384 when paired with P-256 policy).
- AEAD: AES-256-GCM or ChaCha20-Poly1305 for confidential payloads.
- Key derivation: HKDF-SHA256.
- Transport: mutual TLS 1.3 with standard cipher suites.
- Attestation: TPM 2.0 quotes (Windows/Linux); Secure Enclave attestation (Apple silicon).
- Identity: X.509 v3 certificates, standard extensions.

**Algorithm agility:** Every signed object carries a `suite_id` selecting the algorithm set. Verifiers accept a configured allow-list of suites; deprecated suites are removed by signed policy update. No single algorithm is hard-coded as the only option.

**Post-quantum migration note:** Current primitives are classical. A future migration to a NIST-standardised post-quantum signature scheme (e.g., ML-DSA) is anticipated via algorithm agility: new `suite_id` values will be introduced, dual-signing (classical + PQ) will be supported during transition, and root/intermediate rotation will re-issue certificates. No PQ primitive is mandated today; selection deferred until standards mature and interoperability evidence exists. [ASSUMPTION: migration window TARGET 2028–2030; not a commitment.]

---

## 2. Key hierarchy (PRO-005, PRO-006)

| Key | Owner | Custody | Rotation rule | Revocation path |
|---|---|---|---|---|
| Root CA key | Security team (key ceremony) | Offline HSM, air-gapped, multi-party quorum (3-of-5) | Every 5 years or on compromise suspicion | Manual ceremony; publish root revocation; re-issue all intermediates |
| Intermediate CA key(s) | PKI service | Online HSM, service account | Every 1 year or on compromise | CRL + OCSP; re-issue downstream certs |
| Policy-signing key | Control-plane policy service | HSM-backed, quorum for rotation | Every 90 days or on compromise suspicion | CRL; nodes reject bundles signed after revocation timestamp |
| Release-signing key | Release authority | HSM-backed, multi-party (2-of-3) | Every 180 days or on compromise | Updater refuses releases signed after revocation; rollback to last known good |
| Per-device key | Device (agent) | Hardware-backed where available; software fallback | On re-enrolment or compromise suspicion | Device certificate revocation; decommissioning |

**Custody rules:** Private keys never leave their custody boundary. Root and release keys require multi-party quorum. Per-device keys are generated on-device and never exported. Software-fallback keys are stored in OS-protected keystores only.

---

## 3. Hardware-backed keys and trust levels (PRO-007)

| Level | Backing | Trust level | Permitted authority |
|---|---|---|---|
| L3 | TPM 2.0 (Windows/Linux) or Secure Enclave (Apple silicon) | High | Full T2/T3 authority subject to policy/corroboration |
| L2 | Software key in OS-protected keystore (no hardware) | Medium | T2 containment allowed only with corroboration quorum k+1; no T3 alone |
| L1 | Software key without OS protection | Low | T0/T1 only; no T2/T3 action authority |

**Rules:**
- Hardware-backed keys are preferred and required for T3 authority.
- Software-only keys (L2/L1) receive a lower trust level and are marked in the device certificate (extension) so peers and policy engine can weight them.
- Devices may upgrade from L2/L1 to L3 via re-enrolment with hardware attestation; trust level updates propagate via signed certificate.
- Apple silicon uses Secure Enclave; TPM 2.0 covers Windows and Linux. No hardware backing is assumed for other platforms (macOS on Intel = L2 max) [ASSUMPTION].

---

## 4. Message envelope and verification

### 4.1 Envelope fields (PRO-008)

| Field | Type | Description |
|---|---|---|
| version | uint | Envelope schema version |
| suite_id | enum | Algorithm suite selector (PRO-017) |
| tenant_id | UUID | Tenant scope |
| sender_id | UUID | Device or service identity |
| message_type | enum | OBSERVATION, CORROBORATION_REQUEST, DECISION_PROPOSAL, EXECUTION_DECISION, HUMAN_APPROVAL, POLICY_BUNDLE, UPDATE_MANIFEST, REMEDIATION_TOKEN, LEASE, REVOCATION, HEARTBEAT |
| nonce | 128-bit | Unique per sender within replay window |
| issued_at | timestamp (UTC) | Issuance time |
| expires_at | timestamp (UTC) | Expiry time |
| payload_hash | SHA-256 | Hash of canonicalised payload |
| signature | bytes | Signature over canonical envelope (excluding signature field) |
| signer_cert | certificate | Sender's certificate (or cert chain reference) |

### 4.2 Canonicalisation
Fields are serialised in a deterministic order (version, suite_id, tenant_id, sender_id, message_type, nonce, issued_at, expires_at, payload_hash) before hashing/signing. Payload is hashed separately and referenced by payload_hash.

The payload bytes for EXECUTION_DECISION and HUMAN_APPROVAL follow the [v1 execution binding contract](contracts/v1/ENFORCEMENT.md). Verify that the signing identity is authorised for the message type and tenant. The authenticated tenant, message type and validity interval also match the payload.

### 4.3 Verification order (PRO-009)

Verify(envelope):
1. Signature valid under certificate chain (root/intermediate trust, suite allow-listed).
2. tenant_id matches the receiver's tenant scope (or an authorised cross-tenant service).
3. issued_at and expires_at within clock-skew bound (TARGET ±60 s).
4. nonce unseen in the replay window for this sender.
5. Certificate not revoked (or within revocation grace for current mode).
6. payload_hash matches recomputed hash of received payload.
Any failure -> drop, write ledger REJECT with reason code, never act.

### 4.4 Replay analysis (per message type)
- **OBSERVATION:** Replay of a stale observation could re-trigger analysis. Mitigated by nonce + issued_at/expiry + replay window. Replayed observation with valid signature but stale nonce is dropped (R-REPLAY).
- **CORROBORATION_REQUEST:** Replay could inflate corroboration counts. Mitigated by nonce + request_id binding; duplicate request_id dropped.
- **DECISION_PROPOSAL:** Replay of an old proposal could cause stale action. Mitigated by nonce + expiry + policy version binding.
- **POLICY_BUNDLE:** Replay of an older bundle could downgrade policy. Mitigated by version monotonicity + anti-rollback (SEC-030) + expiry.
- **UPDATE_MANIFEST:** Replay could re-apply old update. Mitigated by version monotonicity + anti-rollback.
- **REMEDIATION_TOKEN:** Replay could re-execute remediation. Mitigated by single-use token_id + nonce + expiry.
- **LEASE:** Replay could extend offline authority. Mitigated by lease_id uniqueness + expiry.
- **REVOCATION:** Replay is idempotent and safe; duplicate revocation accepted.
- **HEARTBEAT:** Replay harmless; used for liveness only.

### 4.5 Forgery analysis (per message type)
- **OBSERVATION:** Forgery requires sender's private key or compromised CA issuing a cert for that sender_id. Mitigated by hardware-backed keys (L3) and tenant scoping.
- **CORROBORATION_REQUEST:** Forgery as above; additionally requires distinct device proof (§5).
- **DECISION_PROPOSAL:** Only action-proposer may sign; forgery requires proposer key. Policy engine verifies signer role in certificate.
- **POLICY_BUNDLE:** Only policy-signing key may sign; forgery requires HSM compromise (runbook §7).
- **UPDATE_MANIFEST:** Only release-signing key may sign; multi-party quorum.
- **REMEDIATION_TOKEN:** Only policy engine/control plane may issue; scoped to prevent over-broad action.
- **LEASE:** Issued by control plane; scope-limited and time-limited.
- **REVOCATION:** Issued by key owner or CA; must be authenticated.
- **HEARTBEAT:** Low impact; forgery only affects liveness metrics.

---

## 5. Peer corroboration (PRO-010)

### 5.1 Distinct-device proof
A corroborating peer proves distinctness by presenting:
- A valid device certificate with unique sender_id and tenant_id.
- A hardware attestation (TPM quote / Secure Enclave) bound to the public key and device_id at enrolment time.
- A fresh challenge-response (nonce from requester) signed by the device key.

Two peers sharing the same device_id, the same attestation, or the same intermediate issuance path beyond policy are treated as the same device and collapsed.

### 5.2 Reputation weighting
Each peer's contribution weight is a function of:
- Trust level (L3 > L2 > L1).
- Historical agreement with consensus outcomes.
- Recency of successful attestations.

Weights are computed locally by the policy engine using signed inputs; weights are advisory and cannot override distinctness requirements.

### 5.3 Collusion limits
- Corroboration requires k distinct devices (k is a TARGET/HYPOTHESIS, default 3) from at least 2 independent trust paths.
- Peers that cluster (same subnet prefix, same enrolment batch, or correlated timing) are flagged; cluster size above threshold reduces effective distinctness.
- Collusion of >= k peers is a residual risk (RR-01); mitigated by diversity requirements and anomaly detection (SEC-017).

---

## 6. Remediation tokens and offline leases (PRO-011, PRO-012)

### 6.1 Remediation token
Fields (in addition to envelope): token_id, decision_sha256, action_type, target_id, tier (T2/T3), scope, issued_by, max_uses=1.
- The control-plane authorisation service issues the token after verifying the effective execution decision and any required human approval. The token binds to the SHA-256 digest of that canonical execution decision. The policy evaluator returns a pure outcome. The [v1 execution binding contract](contracts/v1/ENFORCEMENT.md) defines the two signed payloads.
- Single-use; replay rejected (R-REPLAY).
- Expiry short (TARGET <= 5 minutes for T2; T3 requires fresh human approval).
- Clock disagreement: if |now - issued_at| > skew bound, reject (R-CLOCK-SKEW) and fail-closed for T2+.

### 6.2 Offline lease
- Issued while online by control plane; binds a device to a set of permitted autonomous actions under partition.
- Contains: lease_id, device_id, tenant_id, permitted actions and target scope, policy version, absolute expiry, max_actions count.
- Only partitioned mode can spend a lease. The controller permits only scoped, pre-authorised local T2 within lease bounds and with every other gate met. Fully offline and suspected-compromise modes deny T2+.
- Lease expiry is absolute; no extension under partition.
- On reconnection, lease is re-validated; if control plane suspected compromised, lease is ignored and cached policy supports only permitted non-privileged operation (ADR-008).

---

## 7. Revocation (PRO-013, PRO-014)

### 7.1 Revocation under partition
- Revocation lists (CRL) and OCSP responses are cached locally with a grace window (TARGET 24 h, HYPOTHESIS).
- Under partition: use cached revocation status; if cache older than grace window, fail-closed for T2+ (deny) while T0 continues.
- Revocation messages are idempotent and propagate via mesh gossip when online.
- Emergency revocation (key compromise) may be delivered via out-of-band channel (admin console) and takes precedence over cache.

### 7.2 Key-compromise runbook
1. Detect/suspect compromise (monitoring, audit anomaly, or report).
2. Revoke compromised key/certificate (CA or key owner) and publish revocation.
3. Issue replacement key/certificate via re-enrolment or key ceremony.
4. Nodes fetch revocation (online) or receive via gossip; under partition rely on grace window then fail-closed.
5. Investigate affected actions in evidence ledger; compensate if needed (R2/R4).
6. Post-incident review (G8) and update residual-risk register.

### 7.3 State machines

**Enrolment state machine:**
States: UNENROLLED -> TOKEN_ISSUED -> ATTESTATION_SUBMITTED -> PENDING_APPROVAL -> ENROLLED -> DECOMMISSIONED.
Transitions:
- UNENROLLED --(admin issues single-use token)--> TOKEN_ISSUED
- TOKEN_ISSUED --(device submits attestation)--> ATTESTATION_SUBMITTED
- ATTESTATION_SUBMITTED --(admin approves)--> ENROLLED (issue cert)
- ATTESTATION_SUBMITTED --(admin rejects/timeout)--> UNENROLLED (token consumed)
- ENROLLED --(re-enrolment request)--> TOKEN_ISSUED (revoke prior cert)
- ENROLLED --(decommission)--> DECOMMISSIONED (revoke cert, remove from mesh)
- Any --(token expiry)--> UNENROLLED

**Revocation state machine:**
States: VALID -> REVOCATION_PENDING -> REVOKED -> (optional) SUPERSEDED.
Transitions:
- VALID --(revocation request authenticated)--> REVOCATION_PENDING
- REVOCATION_PENDING --(propagation/confirmation)--> REVOKED
- REVOKED --(replacement issued)--> SUPERSEDED (new key active)
- REVOKED --(no replacement)--> terminal (device unusable for T2+)

---

## 8. Message sequences (text form)

### 8.1 Enrolment
1. Admin -> Enrolment service: create single-use token (tenant_id, expiry, trust_level_cap).
2. Device -> Enrolment service: token + attestation (TPM quote/SE) + public key.
3. Enrolment service validates token (single-use, not expired) and attestation.
4. Admin approves (console, MFA).
5. Enrolment service issues device certificate + trust level; records in identity service.
6. Device stores cert + key; begins mesh participation.

### 8.2 Policy distribution
1. Control plane (policy-signing key) signs policy bundle.
2. Node receives bundle; verifies signature, tenant, version monotonicity, expiry.
3. Policy engine loads bundle; logs to evidence ledger.

### 8.3 Peer corroboration
1. Node A sends CORROBORATION_REQUEST (observation ref, nonce challenge) to peers.
2. Peer B verifies envelope; returns signed CORROBORATION with distinct-device proof.
3. Node A verifies each response (§4.3); counts distinct devices; applies weights.
4. If quorum met, proposal proceeds to policy engine.

### 8.4 Remediation under partition
1. Node detects partition (mesh-coordinator).
2. The policy engine evaluates lease eligibility. The node enforcement controller rechecks the lease and all execution gates before spending budget or invoking an adapter.
3. All actions logged to local evidence ledger; queued for sync.
4. On reconnection, leases re-validated; if control plane suspected compromised, leases ignored.

### 8.5 Revocation propagation
1. CA/key owner issues REVOCATION message.
2. Nodes receive and cache; update local revocation state.
3. Under partition, gossip propagates when peers reconnect; grace window applies.

---

## 9. What signatures prove and do not prove (PRO-015)

**What a valid signature proves:**
- The signer possessed the private key corresponding to the certified public key at signing time.
- The signed content (envelope + payload hash) was not altered after signing.
- The signer's identity is bound to a tenant (and device, for device keys) by a certificate chain rooted in a trusted root.
- The issuance/expiry times are within the stated skew bound (if verified).

**What a signature does NOT prove:**
- That the signer's host was uncompromised at signing time (a compromised device can sign validly).
- That the signed statement is true (a device can sign a false observation).
- That the signer is physically present or authorised beyond key possession.
- That the root CA or intermediate has not been compromised (trust anchor assumption).
- That the message was delivered confidentially (signatures provide integrity/authenticity, not confidentiality; use AEAD for confidentiality).
- That the action is safe or correct (signatures authorise identity, not policy outcome; policy engine decides).

---

## 10. Reason codes

| Code | Meaning |
|---|---|
| R-SIG-INVALID | Signature verification failed |
| R-CHAIN-INVALID | Certificate chain invalid/expired/untrusted |
| R-TENANT-MISMATCH | tenant_id mismatch |
| R-CLOCK-SKEW | issued_at/expiry outside skew bound |
| R-REPLAY | Nonce or token_id already seen |
| R-REVOKED | Certificate/key revoked (or grace expired) |
| R-HASH-MISMATCH | payload_hash mismatch |
| R-VERSION-OLD | Version not monotonic / rollback attempt |
| R-SUITE-UNSUPPORTED | suite_id not allow-listed |
| R-LEASE-EXPIRED | Offline lease expired |
| R-SCOPE-EXCEEDED | Action outside token/lease scope |
| R-DISTINCTNESS-FAIL | Corroborators not distinct |
| R-CLUSTER-SUSPECT | Collusion cluster detected |
| R-TRUST-LEVEL-LOW | Software-only key insufficient for action tier |
| R-GRACE-EXPIRED | Revocation cache grace window expired |

---

## 11. Negative test vectors (>=20)

| # | Input (description) | Expected rejection | Reason code |
|---|---|---|---|
| NV-01 | Envelope with corrupted signature byte | Drop, ledger REJECT | R-SIG-INVALID |
| NV-02 | Envelope signed by unknown root | Drop | R-CHAIN-INVALID |
| NV-03 | tenant_id differs from receiver tenant | Drop | R-TENANT-MISMATCH |
| NV-04 | issued_at 10 min in the future beyond skew | Drop | R-CLOCK-SKEW |
| NV-05 | expires_at in the past | Drop | R-CLOCK-SKEW |
| NV-06 | Replayed nonce from same sender | Drop | R-REPLAY |
| NV-07 | Replayed remediation token | Drop | R-REPLAY |
| NV-08 | Certificate on revocation list | Drop | R-REVOKED |
| NV-09 | Revocation cache older than grace window (partition) | Drop (T2+) | R-GRACE-EXPIRED |
| NV-10 | payload_hash altered | Drop | R-HASH-MISMATCH |
| NV-11 | Policy bundle with lower version than current | Drop | R-VERSION-OLD |
| NV-12 | Update manifest older version | Drop | R-VERSION-OLD |
| NV-13 | Envelope using deprecated suite_id | Drop | R-SUITE-UNSUPPORTED |
| NV-14 | Corroboration with same device twice | Reject count | R-DISTINCTNESS-FAIL |
| NV-15 | Corroborators from same cluster only | Reject quorum | R-CLUSTER-SUSPECT |
| NV-16 | L1 software key attempting T2 action | Drop | R-TRUST-LEVEL-LOW |
| NV-17 | L2 key attempting T3 action alone | Drop | R-TRUST-LEVEL-LOW |
| NV-18 | Remediation token used twice | Drop | R-REPLAY |
| NV-19 | Action outside token scope | Drop | R-SCOPE-EXCEEDED |
| NV-20 | Offline lease expired under partition | Drop | R-LEASE-EXPIRED |
| NV-21 | Enrolment token reused | Reject enrolment | R-REPLAY |
| NV-22 | Attestation mismatch at enrolment | Reject enrolment | R-CHAIN-INVALID |
| NV-23 | Clock disagreement beyond skew on token | Drop | R-CLOCK-SKEW |
| NV-24 | Revocation message from unauthorised sender | Drop | R-CHAIN-INVALID |

**Negative test vectors: 24 (>=20).**

---

## Contract Closure

1. **Deliverables produced:**
   - Device identity and enrolment (§1? §8.1) with state machine (§7.3)
   - Key hierarchy with custody/rotation/revocation (§2)
   - Hardware-backed keys and trust levels (§3)
   - Message envelope + verification order + replay/forgery analysis (§4)
   - Peer corroboration distinctness/reputation/collusion (§5)
   - Remediation tokens + offline leases (§6)
   - Revocation under partition + key-compromise runbook + state machines (§7)
   - What signatures prove/do not prove (§9)
   - Reason codes (§10) and 24 negative test vectors (§11)
   - Algorithm agility + post-quantum migration note (§1)

2. **Acceptance checks:**
   - Each message type has replay analysis: **PASS** (§4.4)
   - Each message type has forgery analysis: **PASS** (§4.5)
   - Each key has owner, rotation rule, revocation path: **PASS** (§2 table)
   - What-signatures-do-not-prove present: **PASS** (§9)
   - Standard primitives only: **PASS** (§1)
   - Algorithm agility + PQ note: **PASS** (§1)
   - Negative test vectors >=20: **PASS** (24)
   - Enrolment + revocation state machines: **PASS** (§7.3)

3. **Assumptions made:** [ASSUMPTION] skew bound ±60 s (TARGET), grace window 24 h (HYPOTHESIS), k=3 corroboration (TARGET), PQ migration window 2028–2030 (not a commitment), macOS Intel max L2, enrolment state machine derived from P0.2.

4. **Open questions:**
   - OQ-01: Exact skew bound and grace window values need measurement/validation (P0.6).
   - OQ-02: Corroboration k and cluster thresholds need validation (P0.6/P0.10).
   - OQ-03: Hardware attestation availability on all target platforms to be verified.

5. **Out-of-scope items noticed (not acted on):** policy semantics (P0.4), schemas beyond envelope (P0.5), cloud vendor choice, code, byte-level protocol framing (P0.3 covers identity/keys/envelopes/tokens only).

6. **Handoff:** Consumed by P0.4 (policy language), P0.5 (schemas), P0.6 (measurement/validation). Downstream must trace to PRO-xxx IDs. IDs to preserve: PRO-001..PRO-020, reason codes R-*, trust levels L1–L3, NV-01..NV-24.
