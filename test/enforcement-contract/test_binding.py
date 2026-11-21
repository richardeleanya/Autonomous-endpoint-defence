"""Conformance cases for the v1 binding contract at the verified-envelope boundary."""

import hashlib
import unittest
from dataclasses import asdict, replace

from contracts.v1.enforcement import BindingError, ExecutionScope, VerifiedPayload, encode_payload, validate_binding


TENANT = "00000000-0000-0000-0000-000000000001"
DEVICE = "00000000-0000-0000-0000-000000000002"
OTHER_TENANT = "00000000-0000-0000-0000-000000000003"
NOW = 1700000010
T2_SCOPE = ExecutionScope(
    tenant_id=TENANT,
    device_id=DEVICE,
    incident_id="case-1",
    proposal_id="proposal-1",
    proposal_sha256="a" * 64,
    requester_id="requester-1",
    action_id="A-01",
    tier="T2",
    target_id="target-1",
    parameters_sha256="b" * 64,
    policy_version="policy-4",
    policy_sha256="c" * 64,
)
RESTORE_SCOPE = replace(T2_SCOPE, tier="T3", action_id="A-18")


def decision_fields(scope, approval=None, **changes):
    return {
        "version": 1,
        "kind": "EXECUTION_DECISION",
        "scope": asdict(scope),
        "issued_at": NOW - 2,
        "expires_at": NOW + 2,
        "decision_id": "decision-1",
        "outcome": "ALLOW",
        "approval_sha256": hashlib.sha256(approval.payload).hexdigest() if approval else None,
        **changes,
    }


def approval_fields(scope, **changes):
    return {
        "version": 1,
        "kind": "HUMAN_APPROVAL",
        "scope": asdict(scope),
        "issued_at": NOW - 3,
        "expires_at": NOW + 3,
        "approval_id": "approval-1",
        "approver_id": "approver-1",
        "mfa": True,
        "max_uses": 1,
        **changes,
    }


def verified(fields):
    # The conformance suite starts after signature, issuer and envelope verification.
    return VerifiedPayload(
        fields["kind"], fields["scope"]["tenant_id"], fields["issued_at"], fields["expires_at"], encode_payload(fields)
    )


class BindingTests(unittest.TestCase):
    def check(self, scope, decision, approval=None, **context):
        validate_binding(
            scope,
            decision,
            approval,
            **{"now": NOW, "protected_target": False, "critical_asset": False, "bulk_action": False, **context},
        )

    def reject(self, reason, scope, decision, approval=None, **context):
        with self.assertRaises(BindingError) as error:
            self.check(scope, decision, approval, **context)
        self.assertEqual(str(error.exception), reason)

    def test_matching_decision_and_required_approval(self):
        self.check(T2_SCOPE, verified(decision_fields(T2_SCOPE)))
        for scope, context in ((RESTORE_SCOPE, {}), (T2_SCOPE, {"critical_asset": True}), (T2_SCOPE, {"bulk_action": True})):
            with self.subTest(scope=scope.action_id, context=context):
                approval = verified(approval_fields(scope))
                decision = verified(decision_fields(scope, approval))
                self.check(scope, decision, approval, **context)
                self.reject("HUMAN_APPROVAL_REQUIRED", scope, decision, **context)

    def test_canonical_wire_digests(self):
        approval = verified(approval_fields(RESTORE_SCOPE))
        decision = verified(decision_fields(RESTORE_SCOPE, approval))
        self.assertEqual(
            hashlib.sha256(approval.payload).hexdigest(),
            "b3fe4b36d66e215b58628db6be919c1756eb1b6260262096c63ecf1c93ece7fe",
        )
        self.assertEqual(
            hashlib.sha256(decision.payload).hexdigest(),
            "27cde7bf42dff48b1f263bada9d44cfa5af6923ea9d4329f78e51dabc869c448",
        )

    def test_protected_target_has_no_per_action_override(self):
        # POL-T-009, POL-T-027, POL-T-042 and INV-9.
        self.reject("PROTECTED_TARGET", T2_SCOPE, verified(decision_fields(T2_SCOPE)), protected_target=True)
        for expiry in (NOW + 3, NOW):
            with self.subTest(expiry=expiry):
                approval = verified(approval_fields(RESTORE_SCOPE, expires_at=expiry))
                decision = verified(decision_fields(RESTORE_SCOPE, approval))
                self.reject("PROTECTED_TARGET", RESTORE_SCOPE, decision, approval, protected_target=True)

    def test_every_scope_field_is_bound_in_both_messages(self):
        changes = {
            "tenant_id": OTHER_TENANT,
            "device_id": TENANT,
            "incident_id": "case-2",
            "proposal_id": "proposal-2",
            "proposal_sha256": "0" * 64,
            "requester_id": "requester-2",
            "action_id": "A-17",
            "tier": "T2",
            "target_id": "target-2",
            "parameters_sha256": "1" * 64,
            "policy_version": "policy-5",
            "policy_sha256": "2" * 64,
        }
        self.assertEqual(changes.keys(), asdict(RESTORE_SCOPE).keys())
        approval = verified(approval_fields(RESTORE_SCOPE))
        for field, value in changes.items():
            with self.subTest(field=field):
                different_scope = replace(RESTORE_SCOPE, **{field: value})
                different_decision = verified(decision_fields(different_scope, approval))
                different_decision = replace(different_decision, tenant_id=TENANT)
                self.reject("INVALID_DECISION_BINDING", RESTORE_SCOPE, different_decision, approval)

                different_approval = verified(approval_fields(different_scope))
                different_approval = replace(different_approval, tenant_id=TENANT)
                decision = verified(decision_fields(RESTORE_SCOPE, different_approval))
                self.reject("INVALID_APPROVAL_BINDING", RESTORE_SCOPE, decision, different_approval)

    def test_approval_digest_binds_the_exact_approval(self):
        approval = verified(approval_fields(RESTORE_SCOPE))
        decision = verified(decision_fields(RESTORE_SCOPE, approval))
        replacement = verified(approval_fields(RESTORE_SCOPE, approval_id="approval-2"))
        self.reject("INVALID_APPROVAL_BINDING", RESTORE_SCOPE, decision, replacement)
        self.reject("INVALID_APPROVAL_BINDING", T2_SCOPE, verified(decision_fields(T2_SCOPE, approval)))
        self.reject(
            "INVALID_APPROVAL_BINDING",
            T2_SCOPE,
            verified(decision_fields(T2_SCOPE)),
            verified(approval_fields(T2_SCOPE)),
        )

    def test_approval_actor_mfa_and_single_use_are_required(self):
        for changes in (
            {"approver_id": RESTORE_SCOPE.requester_id},
            {"mfa": False},
            {"mfa": 1},
            {"max_uses": 2},
            {"max_uses": True},
        ):
            with self.subTest(changes=changes):
                approval = verified(approval_fields(RESTORE_SCOPE, **changes))
                decision = verified(decision_fields(RESTORE_SCOPE, approval))
                self.reject("INVALID_APPROVAL_BINDING", RESTORE_SCOPE, decision, approval)

    def test_validity_bounds_and_approval_order(self):
        for changes in ({"issued_at": NOW + 1}, {"expires_at": NOW}):
            with self.subTest(changes=changes):
                self.reject("INVALID_DECISION_BINDING", T2_SCOPE, verified(decision_fields(T2_SCOPE, **changes)))
        self.check(T2_SCOPE, verified(decision_fields(T2_SCOPE, issued_at=NOW)))
        for changes in ({"issued_at": NOW - 1}, {"expires_at": NOW + 1}, {"expires_at": NOW}):
            with self.subTest(changes=changes):
                approval = verified(approval_fields(RESTORE_SCOPE, **changes))
                decision = verified(decision_fields(RESTORE_SCOPE, approval))
                self.reject("INVALID_APPROVAL_BINDING", RESTORE_SCOPE, decision, approval)

    def test_verified_envelope_metadata_must_match_payload(self):
        decision = verified(decision_fields(T2_SCOPE))
        for changes in (
            {"tenant_id": OTHER_TENANT},
            {"message_type": "DECISION_PROPOSAL"},
            {"issued_at": NOW - 1},
            {"expires_at": NOW + 3},
        ):
            with self.subTest(changes=changes):
                self.reject("INVALID_DECISION_BINDING", T2_SCOPE, replace(decision, **changes))
        approval = verified(approval_fields(RESTORE_SCOPE))
        decision = verified(decision_fields(RESTORE_SCOPE, approval))
        self.reject("INVALID_APPROVAL_BINDING", RESTORE_SCOPE, decision, replace(approval, tenant_id=OTHER_TENANT))

    def test_payload_schema_is_canonical_and_closed(self):
        decision = verified(decision_fields(T2_SCOPE))
        for content in (
            b" " + decision.payload,
            b'{"version":1,' + decision.payload[1:],
            b"[" * 2000 + b"]" * 2000,
            b"{}",
            b"x" * 4097,
            encode_payload(decision_fields(T2_SCOPE, version=True)),
            encode_payload(decision_fields(T2_SCOPE, version=2)),
            encode_payload(decision_fields(T2_SCOPE, override_token="unexpected")),
        ):
            with self.subTest(size=len(content)):
                self.reject("INVALID_DECISION_BINDING", T2_SCOPE, replace(decision, payload=content))

    def test_non_allow_and_unknown_context_fail_closed(self):
        for outcome in ("DENY", "DOWNGRADE", "ESCALATE"):
            with self.subTest(outcome=outcome):
                self.reject("DECISION_NOT_ALLOWED", T2_SCOPE, verified(decision_fields(T2_SCOPE, outcome=outcome)))
        decision = verified(decision_fields(T2_SCOPE))
        self.reject("INVALID_EXECUTION_CONTEXT", T2_SCOPE, decision, protected_target=None)
        self.reject("INVALID_EXECUTION_CONTEXT", T2_SCOPE, decision, now=True)
        self.reject("INVALID_DECISION_BINDING", T2_SCOPE, decision.payload)


if __name__ == "__main__":
    unittest.main()
