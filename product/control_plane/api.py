"""HTTPS control-plane application, served through Gunicorn."""

import json
import logging
import os
import re
import secrets
import sqlite3
import time
from http import HTTPStatus

from customer_ops import (
    OPERATIONS, PRIVACY_OPERATIONS, account, operations_route, privacy_route, require_enrollment_capacity,
)
from store import RequestError, Store, audit, new_id, secret_digest, uid


STORE = Store(os.environ["ADA_CONFIG"], os.environ["ADA_DATA"], os.environ["ADA_ARTIFACTS"])
TOKEN = re.compile(r"Bearer ([0-9a-f]{64})")
BUILD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
LOG = logging.getLogger(__name__)


def payload(environ):
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
        if not 0 <= length <= 4096:
            raise ValueError
        body = json.loads(environ["wsgi.input"].read(length)) if length else {}
        if not isinstance(body, dict):
            raise ValueError
        return body
    except (ValueError, RecursionError):
        raise RequestError(400, "invalid_body") from None


def enrollment(db, digest, body):
    platform, arch = body.get("platform"), body.get("arch")
    if platform not in ("windows", "linux") or arch not in ("amd64", "arm64"):
        raise RequestError(400, "unsupported_platform")
    grant = db.execute("SELECT expires FROM enrollment WHERE hash=?", (digest,)).fetchone()
    if not grant or grant["expires"] <= int(time.time()):
        raise RequestError(403, "invalid_enrollment")
    require_enrollment_capacity(db)
    device, credential = new_id(), secrets.token_hex(32)
    db.execute("DELETE FROM enrollment WHERE hash=?", (digest,))
    db.execute(
        "INSERT INTO device VALUES (?,?,?,?,'active')", (device, platform, arch, secret_digest(credential))
    )
    audit(db, device, "device_enrolled", device)
    return 201, {"device": device, "credential": credential, "mode": "observe-only"}


def ingest(db, digest, body):
    device = db.execute("SELECT id FROM device WHERE hash=? AND state='active'", (digest,)).fetchone()
    if not device:
        raise RequestError(403, "forbidden")
    if body.keys() != {"id", "build"} or not isinstance(body["build"], str) or not BUILD.fullmatch(body["build"]):
        raise RequestError(400, "invalid_heartbeat")
    identifier = uid(body["id"])
    stored = db.execute("SELECT device,build FROM event WHERE id=?", (identifier,)).fetchone()
    if stored:
        if (stored["device"], stored["build"]) != (device["id"], body["build"]):
            raise RequestError(409, "event_conflict")
    else:
        db.execute(
            "INSERT INTO event VALUES (?,?,?,?)", (identifier, device["id"], body["build"], int(time.time()))
        )
    return 202, {"id": identifier}


def operator_write(db, tenant, actor, operation, resource, body):
    now = int(time.time())
    if operation == "enrollments":
        grant = secrets.token_hex(32)
        db.execute("DELETE FROM enrollment WHERE expires <= ?", (now,))
        db.execute("INSERT INTO enrollment VALUES (?,?)", (secret_digest(grant), now + 600))
        audit(db, actor, "enrollment_issued", "-")
        return 201, {"grant": grant, "expires": now + 600}
    if operation in ("revoke", "offboard"):
        previous, state = ("active", "revoked") if operation == "revoke" else ("revoked", "offboarded")
        updated = db.execute("UPDATE device SET hash=NULL,state=? WHERE id=? AND state=?", (state, resource, previous))
        if updated.rowcount != 1:
            raise RequestError(404, "not_found")
        audit(db, actor, "device_" + state, resource)
        return 200, {"state": state}
    if operation in ("export", "backup", "restore"):
        identifier = STORE.enqueue(db, tenant, actor, operation, resource)
        return 202, {"id": identifier}
    if operation == "support":
        if not any(role == "support" and subject == resource for role, subject, _ in STORE.principals.values()):
            raise RequestError(404, "not_found")
        ttl = body.get("seconds")
        if type(ttl) is not int or not 0 <= ttl <= 900:
            raise RequestError(400, "invalid_grant_duration")
        if ttl:
            db.execute("INSERT OR REPLACE INTO elevation VALUES (?,?)", (resource, now + ttl))
        else:
            db.execute("DELETE FROM elevation WHERE subject=?", (resource,))
        audit(db, actor, "support_granted" if ttl else "support_revoked", resource)
        return 200, {"expires": now + ttl if ttl else None}
    raise RequestError(404, "not_found")


def operator_read(db, tenant, actor, operation, resource, query):
    if operation in ("devices", "audit"):
        # Opaque numeric cursor from the same tenant partition.
        try:
            cursor = int(query or "0")
            if not 0 <= cursor < 2**63:
                raise ValueError
        except ValueError:
            raise RequestError(400, "invalid_cursor") from None
        if operation == "devices":
            rows = db.execute(
                "SELECT rowid AS cursor,id,platform,arch,state FROM device "
                "WHERE state!='offboarded' AND rowid>? ORDER BY rowid LIMIT 200", (cursor,)
            )
        else:
            rows = db.execute(
                "SELECT id AS cursor,at,actor,action,resource FROM audit WHERE id>? ORDER BY id LIMIT 200", (cursor,)
            )
        items = [dict(row) for row in rows]
        audit(db, actor, operation + "_read", "-")
        return 200, {"items": items}
    job = db.execute("SELECT * FROM job WHERE id=?", (resource,)).fetchone()
    if not job:
        raise RequestError(404, "not_found")
    if operation == "jobs":
        audit(db, actor, "job_read", resource)
        return 200, dict(job)
    if operation == "results" and job["status"] == "complete" and job["kind"] in ("export", "restore"):
        document = STORE.fetch(tenant, resource, job["kind"], cutoff=STORE.cutoff(account(db)))
        audit(db, actor, job["kind"] + "_read", resource)
        return 200, document
    raise RequestError(404, "not_found")


def dispatch(environ):
    method, path = environ["REQUEST_METHOD"], environ["PATH_INFO"]
    if method == "GET" and path == "/health":
        for tenant in STORE.keys:
            with STORE.transaction(tenant) as db:
                db.execute("SELECT id FROM device LIMIT 1").fetchone()
        return 200, {"mode": "observe-only"}
    parts = path.split("/")
    if len(parts) not in (5, 6) or parts[:3] != ["", "v1", "tenants"]:
        raise RequestError(404, "not_found")
    tenant, operation = uid(parts[3]), parts[4]
    resource = uid(parts[5]) if len(parts) == 6 else None
    match = TOKEN.fullmatch(environ.get("HTTP_AUTHORIZATION", ""))
    if not match or tenant not in STORE.keys:
        raise RequestError(403, "forbidden")
    digest = secret_digest(match[1])
    body = payload(environ) if method == "POST" else {}
    with STORE.transaction(tenant) as db:
        if method == "POST" and resource is None and operation in PRIVACY_OPERATIONS:
            principal = STORE.principals.get(digest)
            if not principal or principal[0] != "privacy-operations":
                raise RequestError(403, "forbidden")
            return 200, privacy_route(db, STORE, tenant, principal[1], operation, body)
        if method == "POST" and resource is None and operation in OPERATIONS:
            principal = STORE.principals.get(digest)
            if not principal or principal[0] != "customer-operations":
                raise RequestError(403, "forbidden")
            return 200, operations_route(db, principal[1], operation, body, STORE.approvals.get(tenant))
        customer = account(db)
        state = customer["state"]
        if state == "suspended" and method == "POST" and operation == "revoke" and resource is not None:
            actor = STORE.actor(db, tenant, digest)
            return operator_write(db, tenant, actor, operation, resource, body)
        if not STORE.active_customer(tenant, customer):
            raise RequestError(403, "customer_inactive")
        if method == "POST" and resource is None and operation == "enroll":
            return enrollment(db, digest, body)
        if method == "POST" and resource is None and operation == "events":
            return ingest(db, digest, body)
        listing = method == "GET" and resource is None and operation in ("devices", "audit")
        result = method == "GET" and resource is not None and operation in ("jobs", "results")
        if listing or result:
            actor = STORE.actor(db, tenant, digest, support=operation == "devices")
            return operator_read(db, tenant, actor, operation, resource, environ.get("QUERY_STRING"))
        if method == "POST":
            if (resource is None and operation in ("enrollments", "export", "backup")) or (
                resource is not None and operation in ("revoke", "offboard", "restore", "support")
            ):
                actor = STORE.actor(db, tenant, digest)
                return operator_write(db, tenant, actor, operation, resource, body)
        raise RequestError(404, "not_found")


def application(environ, start_response):
    try:
        status, body = dispatch(environ)
    except RequestError as error:
        status, body = error.status, {"error": error.code}
    except sqlite3.OperationalError:
        LOG.warning("Tenant database temporarily unavailable")
        status, body = 503, {"error": "storage_unavailable"}
    except Exception:
        LOG.error("Control-plane request failed")
        status, body = 500, {"error": "internal_error"}
    encoded = json.dumps(body, separators=(",", ":")).encode("utf-8")
    start_response(f"{status} {HTTPStatus(status).phrase}", [
        ("Content-Type", "application/json"), ("Content-Length", str(len(encoded))), ("Cache-Control", "no-store")
    ])
    return [encoded]
