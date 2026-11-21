"""Transactional tenant lifecycle, approval references and usage reconciliation."""

import re
import time

from store import RequestError, audit


REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
APPROVAL_REFERENCES = ("contract_ref", "privacy_ref", "customer_authorisation_ref")
PRIVACY_OPERATIONS = {"privacy-hold", "retain-telemetry", "erase-telemetry"}
OPERATIONS = {"provision", "entitlement", "suspend", "resume", "retire", "reconcile"}


def account(db):
    return db.execute("SELECT * FROM customer_account WHERE id=1").fetchone()


def reference(body, field):
    value = body.get(field)
    if not isinstance(value, str) or not REFERENCE.fullmatch(value):
        raise RequestError(400, "invalid_approval_reference")
    return value


def limit(body):
    value = body.get("max_endpoints")
    if type(value) is not int or not 1 <= value <= 100000:
        raise RequestError(400, "invalid_endpoint_limit")
    return value


def require_enrollment_capacity(db):
    cap = account(db)["max_endpoints"]
    active = db.execute("SELECT COUNT(*) FROM device WHERE state='active'").fetchone()[0]
    if active >= cap:
        raise RequestError(409, "endpoint_limit_reached")


def check_capacity(db, cap):
    active = db.execute("SELECT COUNT(*) FROM device WHERE state='active'").fetchone()[0]
    if active > cap:
        raise RequestError(409, "limit_below_active_devices")


def activate(db, approval, references):
    if (
        not approval or not int(time.time()) < approval["expires_at"]
        or any(approval[field] != references[field] for field in APPROVAL_REFERENCES)
    ):
        raise RequestError(403, "verified_customer_approval_required")
    previous = account(db)["retention_days"]
    floor = int(time.time()) - previous * 86400 if previous else 0
    db.execute(
        "UPDATE customer_account SET approval_sha256=?,retention_days=?,"
        "retention_floor=MAX(retention_floor,?) WHERE id=1",
        (approval["approval_sha256"], approval["retention_days"], floor),
    )


def operations_route(db, actor, operation, body, approval=None):
    state = account(db)["state"]
    if operation == "reconcile":
        if state == "pending":
            raise RequestError(409, "invalid_customer_state")
        start, end = body.get("start"), body.get("end")
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= int(time.time()):
            raise RequestError(400, "invalid_closed_usage_period")
        case = reference(body, "case_ref")
        expected = body.get("expected_endpoints")
        if type(expected) is not int or not 0 <= expected < 2**63:
            raise RequestError(400, "invalid_expected_usage")
        counts = db.execute(
            "SELECT COUNT(*) AS accepted_events, COUNT(DISTINCT device) AS reporting_endpoints "
            "FROM event WHERE received >= ? AND received < ?", (start, end)
        ).fetchone()
        variance = counts["reporting_endpoints"] - expected
        status = "balanced" if variance == 0 else "mismatch"
        audit(db, actor, "customer_usage_" + status, f"{case}:{start}:{end}:{expected}:{counts['reporting_endpoints']}")
        return {
            "start": start, "end": end, **dict(counts),
            "expected_endpoints": expected, "variance": variance, "status": status,
        }

    if operation == "provision" and state == "pending":
        cap = limit(body)
        contract = reference(body, "contract_ref")
        privacy = reference(body, "privacy_ref")
        authority = reference(body, "customer_authorisation_ref")
        check_capacity(db, cap)
        activate(db, approval, dict(zip(APPROVAL_REFERENCES, (contract, privacy, authority))))
        db.execute(
            "UPDATE customer_account SET state='active',max_endpoints=?,contract_ref=?,privacy_ref=?,"
            "customer_authorisation_ref=? WHERE id=1", (cap, contract, privacy, authority)
        )
        audit(db, actor, "customer_provisioned", contract)
    elif operation == "entitlement" and state in ("active", "suspended"):
        change = reference(body, "case_ref")
        cap = limit(body)
        check_capacity(db, cap)
        db.execute("UPDATE customer_account SET max_endpoints=? WHERE id=1", (cap,))
        audit(db, actor, "customer_entitlement_changed", f"{change}:{cap}")
    elif (operation, state) in {("suspend", "active"), ("resume", "suspended"), ("retire", "suspended")}:
        case = reference(body, "case_ref")
        next_state = {"suspend": "suspended", "resume": "active", "retire": "offboarded"}[operation]
        if operation == "resume":
            references = account(db)
            if any(field in body for field in APPROVAL_REFERENCES):
                references = {field: reference(body, field) for field in APPROVAL_REFERENCES}
            activate(db, approval, references)
            db.execute(
                "UPDATE customer_account SET contract_ref=?,privacy_ref=?,customer_authorisation_ref=? WHERE id=1",
                tuple(references[field] for field in APPROVAL_REFERENCES),
            )
        if operation == "retire":
            db.execute("UPDATE device SET hash=NULL,state='offboarded'")
        if operation in ("suspend", "retire"):
            db.execute("DELETE FROM enrollment")
            db.execute("DELETE FROM elevation")
            db.execute("UPDATE job SET status='failed',error='customer_inactive' WHERE status='queued'")
        db.execute("UPDATE customer_account SET state=? WHERE id=1", (next_state,))
        audit(db, actor, "customer_" + operation, case)
    else:
        raise RequestError(409, "invalid_customer_state")
    status = account(db)
    return {"state": status["state"], "max_endpoints": status["max_endpoints"]}


def privacy_route(db, store, tenant, actor, operation, body):
    case = reference(body, "case_ref")
    current = account(db)
    if operation == "privacy-hold":
        held = body.get("held")
        if type(held) is not bool:
            raise RequestError(400, "invalid_hold")
        db.execute("UPDATE customer_account SET privacy_hold=? WHERE id=1", (held,))
        audit(db, actor, "telemetry_hold_set" if held else "telemetry_hold_released", case)
        return {"held": held}
    if current["privacy_hold"]:
        raise RequestError(409, "privacy_hold")
    erase = operation == "erase-telemetry"
    if not erase and current["retention_days"] is None:
        raise RequestError(409, "retention_policy_required")
    if erase and current["state"] != "offboarded":
        raise RequestError(409, "customer_offboarding_required")
    cutoff = max(int(time.time()), store.cutoff(current)) if erase else store.cutoff(current)
    counts = store.remove_telemetry(db, tenant, cutoff, all_telemetry=erase)
    audit(db, actor, "telemetry_erased" if erase else "telemetry_retained", case)
    return {"case_ref": case, "cutoff": cutoff, **counts}
