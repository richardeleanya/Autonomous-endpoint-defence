"""Tenant-local storage, queues and authenticated recovery artifacts."""

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import UUID, uuid4


SNAPSHOT_LIMIT = 25000
ARTIFACT_LIMIT = 16 * 1024 * 1024
STAGING_FILE = re.compile(r"(?:telemetry-staging-|tmp)[a-z0-9_]{8}")
ARTIFACT_FILE = re.compile(r"(backup|export|restore)-([0-9a-f-]{36})\.sealed")

SCHEMA = """
CREATE TABLE IF NOT EXISTS enrollment(hash TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS device(
    id TEXT PRIMARY KEY, platform TEXT NOT NULL, arch TEXT NOT NULL,
    hash TEXT UNIQUE, state TEXT NOT NULL CHECK(state IN ('active','revoked','offboarded'))
);
CREATE TABLE IF NOT EXISTS event(
    id TEXT PRIMARY KEY, device TEXT NOT NULL REFERENCES device(id),
    build TEXT NOT NULL, received INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS event_device ON event(device);
CREATE TABLE IF NOT EXISTS elevation(subject TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit(
    id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL,
    action TEXT NOT NULL, resource TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS job(
    id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK(kind IN ('export','backup','restore')),
    source TEXT, status TEXT NOT NULL CHECK(status IN ('queued','complete','failed')),
    error TEXT
);
CREATE INDEX IF NOT EXISTS job_queue ON job(status);
PRAGMA user_version = 1;
"""


class RequestError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code
        super().__init__(code)


def uid(value):
    try:
        valid = isinstance(value, str) and str(UUID(value)) == value
    except ValueError:
        valid = False
    if not valid:
        raise RequestError(400, "invalid_id")
    return value


def new_id():
    return str(uuid4())


def secret_digest(secret):
    return hashlib.sha256(secret.encode("ascii")).hexdigest()


def key(value):
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError("Expected a 32-byte hexadecimal key or digest")
    raw = bytes.fromhex(value)
    if len(raw) != 32 or raw.hex() != value:
        raise ValueError("Expected a lowercase hexadecimal key or digest")
    return raw


def audit(db, actor, action, resource):
    db.execute(
        "INSERT INTO audit(at,actor,action,resource) VALUES (?,?,?,?)",
        (int(time.time()), actor, action, resource),
    )


class Store:
    def __init__(self, config_path, data, artifacts):
        self.data, self.artifacts = Path(data), Path(artifacts)
        configuration = json.loads(Path(config_path).read_text(encoding="utf-8"))
        self.keys, self.principals, self.approvals = {}, {}, {}
        for tenant, settings in configuration["tenants"].items():
            uid(tenant)
            self.keys[tenant] = key(settings["backup_key"])
            if "approved_activation" in settings:
                approval = settings["approved_activation"]
                if (
                    approval["tenant"] != tenant or approval["mode"] != "observe-only"
                    or type(approval["retention_days"]) is not int or not 1 <= approval["retention_days"] <= 3650
                    or type(approval["expires_at"]) is not int or not 0 < approval["expires_at"] < 2**63
                ):
                    raise ValueError("Invalid verified activation")
                key(approval["approval_sha256"])
                self.approvals[tenant] = approval
            for subject, digest in settings["operators"].items():
                self.register(digest, "operator", uid(subject), tenant)
        if not self.keys or len(set(self.keys.values())) != len(self.keys):
            raise ValueError("Configure a distinct backup key for each tenant")
        operator_subjects = {subject for _, subject, _ in self.principals.values()}
        for subject, digest in configuration["support"].items():
            if subject in operator_subjects:
                raise ValueError("Support and operator identities must be distinct")
            self.register(digest, "support", uid(subject), None)

        known_subjects = {subject for _, subject, _ in self.principals.values()}
        for subject, digest in configuration.get("customer_operations", {}).items():
            if subject in known_subjects:
                raise ValueError("Customer Operations requires a distinct identity")
            self.register(digest, "customer-operations", uid(subject), None)

        known_subjects = {subject for _, subject, _ in self.principals.values()}
        for subject, digest in configuration.get("privacy_operations", {}).items():
            if subject in known_subjects:
                raise ValueError("Privacy Operations requires a distinct identity")
            self.register(digest, "privacy-operations", uid(subject), None)

        for tenant in self.keys:
            (self.artifacts / tenant).mkdir(mode=0o700, parents=True, exist_ok=True)
            with self.transaction(tenant) as db:
                version = db.execute("PRAGMA user_version").fetchone()[0]
                if version == 0:
                    db.executescript(SCHEMA)
                    version = 1
                if version == 1:
                    if not db.in_transaction:
                        db.execute("BEGIN IMMEDIATE")
                    db.execute("""
                        CREATE TABLE IF NOT EXISTS customer_account(
                            id INTEGER PRIMARY KEY CHECK(id=1),
                            state TEXT NOT NULL CHECK(state IN ('pending','active','suspended','offboarded')),
                            max_endpoints INTEGER NOT NULL DEFAULT 0,
                            contract_ref TEXT, privacy_ref TEXT, customer_authorisation_ref TEXT
                        )
                    """)
                    db.execute("INSERT OR IGNORE INTO customer_account(id,state) VALUES(1,'pending')")
                    db.execute("DELETE FROM enrollment")
                    db.execute("DELETE FROM elevation")
                    db.execute("UPDATE job SET status='failed',error='customer_inactive' WHERE status='queued'")
                    db.execute("PRAGMA user_version = 2")
                    version = 2
                if version == 2:
                    db.execute("ALTER TABLE customer_account ADD COLUMN approval_sha256 TEXT")
                    db.execute("ALTER TABLE customer_account ADD COLUMN retention_days INTEGER")
                    db.execute("ALTER TABLE customer_account ADD COLUMN retention_floor INTEGER NOT NULL DEFAULT 0")
                    db.execute("ALTER TABLE customer_account ADD COLUMN privacy_hold INTEGER NOT NULL DEFAULT 0")
                    db.execute("UPDATE customer_account SET state='pending' WHERE state='active'")
                    db.execute("DELETE FROM enrollment")
                    db.execute("DELETE FROM elevation")
                    db.execute("UPDATE job SET status='failed',error='customer_inactive' WHERE status='queued'")
                    db.execute("PRAGMA user_version = 3")
                elif version != 3:
                    raise RuntimeError("Unsupported tenant datastore version")

    def register(self, digest, role, subject, tenant):
        key(digest)
        if digest in self.principals:
            raise ValueError("Credentials must be unique")
        self.principals[digest] = (role, subject, tenant)

    @contextmanager
    def transaction(self, tenant):
        if tenant not in self.keys:
            raise RequestError(404, "not_found")
        db = sqlite3.connect(self.data / (tenant + ".sqlite"), timeout=8)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            db.execute("PRAGMA secure_delete = ON")
            db.execute("BEGIN IMMEDIATE")
            with db:
                yield db
        finally:
            db.close()

    def actor(self, db, tenant, digest, *, support=False):
        principal = self.principals.get(digest)
        if principal:
            role, subject, assigned_tenant = principal
            if role == "operator" and assigned_tenant == tenant:
                return subject
            if support and role == "support":
                grant = db.execute("SELECT expires FROM elevation WHERE subject=?", (subject,)).fetchone()
                if grant and grant["expires"] > int(time.time()):
                    return subject
        raise RequestError(403, "forbidden")

    def enqueue(self, db, tenant, actor, kind, source=None):
        if kind == "restore" and not self.artifact_path(tenant, source, "backup").is_file():
            raise RequestError(404, "not_found")
        if db.execute("SELECT COUNT(*) FROM job WHERE status='queued'").fetchone()[0] >= 100:
            raise RequestError(429, "queue_full")
        identifier = new_id()
        db.execute("INSERT INTO job VALUES (?,?,?,'queued',NULL)", (identifier, kind, source))
        audit(db, actor, kind + "_requested", identifier)
        return identifier

    def active_customer(self, tenant, account):
        approval = self.approvals.get(tenant)
        return (
            account["state"] == "active" and approval is not None
            and account["approval_sha256"] == approval["approval_sha256"]
            and int(time.time()) < approval["expires_at"]
        )

    @staticmethod
    def cutoff(account):
        days = account["retention_days"]
        return max(account["retention_floor"], int(time.time()) - days * 86400 if days else 0)

    def remove_telemetry(self, db, tenant, cutoff, *, all_telemetry):
        files, missing = [], []
        for item in (self.artifacts / tenant).iterdir():
            match = ARTIFACT_FILE.fullmatch(item.name)
            if not match:
                if not STAGING_FILE.fullmatch(item.name) or not item.is_file() or item.is_symlink():
                    raise RequestError(409, "unclassified_artifact")
                files.append((item, None))
                continue
            if not item.is_file() or item.is_symlink():
                raise RequestError(409, "unclassified_artifact")
            kind, identifier = match.groups()
            if not all_telemetry:
                try:
                    self.fetch(tenant, identifier, kind, cutoff=cutoff)
                except RequestError as error:
                    if error.code not in ("artifact_expired", "artifact_unavailable"):
                        raise
                    if error.code == "artifact_unavailable":
                        missing.append(identifier)
                        continue
                else:
                    continue
            files.append((item, identifier))
        for item, _ in files:
            item.unlink(missing_ok=True)
        if files:
            self.sync_artifacts(tenant)
        for identifier in [identifier for _, identifier in files if identifier] + missing:
            db.execute("UPDATE job SET status='failed',error='artifact_removed' WHERE id=?", (identifier,))
        if all_telemetry:
            removed = db.execute("DELETE FROM event").rowcount
            db.execute("DELETE FROM device")
            db.execute("DELETE FROM job")
        else:
            removed = db.execute("DELETE FROM event WHERE received < ?", (cutoff,)).rowcount
        db.execute("UPDATE customer_account SET retention_floor=MAX(retention_floor,?) WHERE id=1", (cutoff,))
        return {"events_removed": removed, "artifacts_removed": len(files)}

    def sync_artifacts(self, tenant):
        directory = os.open(self.artifacts / tenant, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def artifact_path(self, tenant, identifier, kind):
        return self.artifacts / tenant / (kind + "-" + uid(identifier) + ".sealed")

    def publish(self, tenant, identifier, kind, events):
        message = json.dumps(
            {"version": 1, "tenant": tenant, "id": identifier, "kind": kind, "events": events},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(message) > ARTIFACT_LIMIT:
            raise RequestError(422, "artifact_limit")
        tag = hmac.digest(self.keys[tenant], message, "sha256")
        path = self.artifact_path(tenant, identifier, kind)
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix="telemetry-staging-", delete=False) as stream:
            staging = Path(stream.name)
            try:
                stream.write(tag)
                stream.write(message)
                stream.flush()
                os.fsync(stream.fileno())
                os.replace(staging, path)
                self.sync_artifacts(tenant)
            finally:
                staging.unlink(missing_ok=True)

    def fetch(self, tenant, identifier, kind, *, cutoff=0):
        try:
            with self.artifact_path(tenant, identifier, kind).open("rb") as stream:
                tag = stream.read(32)
                message = stream.read(ARTIFACT_LIMIT + 1)
        except FileNotFoundError:
            raise RequestError(409, "artifact_unavailable") from None
        if len(message) > ARTIFACT_LIMIT or not hmac.compare_digest(
            tag, hmac.digest(self.keys[tenant], message, "sha256")
        ):
            raise RequestError(409, "artifact_integrity")
        document = json.loads(message)
        if (document["version"], document["tenant"], document["id"], document["kind"]) != (
            1, tenant, identifier, kind
        ):
            raise RequestError(409, "artifact_scope")
        if any(event["received"] < cutoff for event in document["events"]):
            raise RequestError(409, "artifact_expired")
        return document

    def work(self, tenant):
        with self.transaction(tenant) as db:
            account = db.execute("SELECT * FROM customer_account WHERE id=1").fetchone()
            if not self.active_customer(tenant, account):
                return False
            cutoff = self.cutoff(account)
            job = db.execute("SELECT * FROM job WHERE status='queued' ORDER BY rowid LIMIT 1").fetchone()
            if not job:
                return False
            identifier, kind = job["id"], job["kind"]
            try:
                if kind == "restore":
                    events = self.fetch(tenant, job["source"], "backup", cutoff=cutoff)["events"]
                else:
                    events = [dict(row) for row in db.execute(
                        "SELECT id,device,build,received FROM event WHERE received >= ? ORDER BY rowid LIMIT ?",
                        (cutoff, SNAPSHOT_LIMIT + 1),
                    )]
                    if len(events) > SNAPSHOT_LIMIT:
                        raise RequestError(422, "snapshot_limit")
                self.publish(tenant, identifier, kind, events)
            except RequestError as error:
                db.execute("UPDATE job SET status='failed',error=? WHERE id=?", (error.code, identifier))
                audit(db, "worker", kind + "_failed", identifier)
            else:
                db.execute("UPDATE job SET status='complete' WHERE id=?", (identifier,))
                audit(db, "worker", kind + "_complete", identifier)
            return True
