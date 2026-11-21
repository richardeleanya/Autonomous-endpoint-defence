"""Wire format and scope checks for authenticated enforcement payloads."""

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from uuid import UUID


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_MAX_TIMESTAMP = 253402300799  # Last Unix second in 9999 UTC.
_COMMON_FIELDS = {"version", "kind", "scope", "issued_at", "expires_at"}
_DECISION = "EXECUTION_DECISION"
_APPROVAL = "HUMAN_APPROVAL"
_FIELDS = {
    _DECISION: {"decision_id", "outcome", "approval_sha256"},
    _APPROVAL: {"approval_id", "approver_id", "mfa", "max_uses"},
}


class BindingError(ValueError):
    """A rejection with a reason code suitable for the controller's audit log."""


def _identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _timestamp(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_TIMESTAMP


@dataclass(frozen=True)
class ExecutionScope:
    """Resolved scope from the verified proposal, action catalogue and loaded policy."""

    tenant_id: str
    device_id: str
    incident_id: str
    proposal_id: str
    proposal_sha256: str
    requester_id: str
    action_id: str
    tier: str
    target_id: str
    parameters_sha256: str
    policy_version: str
    policy_sha256: str

    def __post_init__(self) -> None:
        for value in (self.tenant_id, self.device_id):
            if not isinstance(value, str):
                raise BindingError("INVALID_EXECUTION_SCOPE")
            try:
                canonical = str(UUID(value))
            except ValueError:
                raise BindingError("INVALID_EXECUTION_SCOPE") from None
            if canonical != value:
                raise BindingError("INVALID_EXECUTION_SCOPE")

        identifiers = (self.incident_id, self.proposal_id, self.requester_id, self.target_id, self.policy_version)
        digests = (self.proposal_sha256, self.parameters_sha256, self.policy_sha256)
        if (
            not all(map(_identifier, identifiers))
            or not all(map(_sha256, digests))
            or not isinstance(self.action_id, str)
            or re.fullmatch(r"A-[0-9]{2}", self.action_id) is None
            or self.tier not in ("T2", "T3")
        ):
            raise BindingError("INVALID_EXECUTION_SCOPE")


@dataclass(frozen=True)
class VerifiedPayload:
    """Output of the trusted PRO-009 verifier after issuer and tenant checks."""

    message_type: str
    tenant_id: str
    issued_at: int
    expires_at: int
    payload: bytes


def encode_payload(fields: dict[str, object]) -> bytes:
    """Encode the v1 JSON payload for signing or digest comparison."""
    return json.dumps(
        fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _read_payload(
    verified: VerifiedPayload,
    scope: ExecutionScope,
    kind: str,
    now: int,
    reason: str,
) -> dict[str, object]:
    if (
        not isinstance(verified, VerifiedPayload)
        or verified.tenant_id != scope.tenant_id
        or verified.message_type != kind
        or not _timestamp(verified.issued_at)
        or not _timestamp(verified.expires_at)
        or not isinstance(verified.payload, bytes)
        or not 0 < len(verified.payload) <= 4096
    ):
        raise BindingError(reason)
    try:
        body = json.loads(verified.payload.decode("ascii"))
        canonical = encode_payload(body)
    except (ValueError, RecursionError):
        raise BindingError(reason) from None

    if (
        not isinstance(body, dict)
        or canonical != verified.payload
        or body.keys() != _COMMON_FIELDS | _FIELDS[kind]
        or type(body["version"]) is not int
        or body["version"] != 1
        or body["kind"] != kind
        or body["scope"] != asdict(scope)
        or not _timestamp(body["issued_at"])
        or not _timestamp(body["expires_at"])
        or body["issued_at"] != verified.issued_at
        or body["expires_at"] != verified.expires_at
        or not body["issued_at"] <= now < body["expires_at"]
    ):
        raise BindingError(reason)
    return body


def validate_binding(
    scope: ExecutionScope,
    decision: VerifiedPayload,
    approval: VerifiedPayload | None,
    *,
    now: int,
    protected_target: bool,
    critical_asset: bool,
    bulk_action: bool,
) -> None:
    """Check scope, freshness and required approvals before controller state checks.

    The flags and time come from trusted local state. A successful check confers
    no execution authority and cannot spend a decision or approval.
    """
    if (
        not isinstance(scope, ExecutionScope)
        or not _timestamp(now)
        or any(type(flag) is not bool for flag in (protected_target, critical_asset, bulk_action))
    ):
        raise BindingError("INVALID_EXECUTION_CONTEXT")
    if protected_target:
        raise BindingError("PROTECTED_TARGET")

    body = _read_payload(decision, scope, _DECISION, now, "INVALID_DECISION_BINDING")
    approval_digest = body["approval_sha256"]
    if not _identifier(body["decision_id"]) or (approval_digest is not None and not _sha256(approval_digest)):
        raise BindingError("INVALID_DECISION_BINDING")
    if body["outcome"] != "ALLOW":
        raise BindingError("DECISION_NOT_ALLOWED")

    if approval is None:
        if scope.tier == "T3" or bulk_action or critical_asset:
            raise BindingError("HUMAN_APPROVAL_REQUIRED")
        if approval_digest is not None:
            raise BindingError("INVALID_APPROVAL_BINDING")
        return

    human = _read_payload(approval, scope, _APPROVAL, now, "INVALID_APPROVAL_BINDING")
    if (
        approval_digest != hashlib.sha256(approval.payload).hexdigest()
        or not _identifier(human["approval_id"])
        or not _identifier(human["approver_id"])
        or human["approver_id"] == scope.requester_id
        or human["mfa"] is not True
        or type(human["max_uses"]) is not int
        or human["max_uses"] != 1
        or human["issued_at"] > body["issued_at"]
        or human["expires_at"] < body["expires_at"]
    ):
        raise BindingError("INVALID_APPROVAL_BINDING")
