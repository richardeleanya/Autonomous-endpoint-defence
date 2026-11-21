"""Internal observe-only control plane for synthetic lifecycle verification."""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import uuid
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def audit(db, tenant, actor, action, device=None):
    db.execute(
        "INSERT INTO audit(tenant, actor, action, device) VALUES (?, ?, ?, ?)",
        (tenant, actor, action, device),
    )


def authenticated(db, query, token):
    row = db.execute(query, (digest(token),)).fetchone()
    if row is None:
        raise Rejected(403)
    return row


class Rejected(Exception):
    pass


class Lifecycle:
    def __init__(self, path, bootstrap):
        self.path = path
        self.bootstrap = digest(bootstrap)
        with closing(sqlite3.connect(path)) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS tenant(
                    id TEXT PRIMARY KEY, operator TEXT UNIQUE NOT NULL,
                    grant_hash TEXT UNIQUE
                );
                CREATE TABLE IF NOT EXISTS device(
                    id TEXT PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenant(id),
                    platform TEXT NOT NULL, token TEXT UNIQUE,
                    state TEXT NOT NULL CHECK(state IN ('active','revoked','offboarded'))
                );
                CREATE TABLE IF NOT EXISTS telemetry(
                    seq INTEGER PRIMARY KEY, device TEXT NOT NULL REFERENCES device(id),
                    event TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit(
                    seq INTEGER PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenant(id),
                    actor TEXT NOT NULL, action TEXT NOT NULL, device TEXT
                );
            """)

    def request(self, path, token, body):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            db.execute("BEGIN IMMEDIATE")
            if path == "/tenants":
                if not hmac.compare_digest(digest(token), self.bootstrap):
                    raise Rejected(403)
                tenant = uuid.uuid4().hex
                operator, grant = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                db.execute("INSERT INTO tenant VALUES (?, ?, ?)", (tenant, digest(operator), digest(grant)))
                audit(db, tenant, "bootstrap", "tenant_created")
                return 201, {"tenant": tenant, "operator": operator, "grant": grant}
            if path == "/enroll":
                tenant, = authenticated(db, "SELECT id FROM tenant WHERE grant_hash = ?", token)
                platform = body.get("platform")
                if platform not in ("windows", "linux"):
                    raise Rejected(400)
                device, credential = uuid.uuid4().hex, secrets.token_urlsafe(32)
                db.execute("UPDATE tenant SET grant_hash = NULL WHERE id = ?", (tenant,))
                db.execute(
                    "INSERT INTO device VALUES (?, ?, ?, ?, 'active')",
                    (device, tenant, platform, digest(credential)),
                )
                audit(db, tenant, "enrollment", "device_enrolled", device)
                return 201, {"device": device, "credential": credential, "mode": "observe-only"}
            if path == "/telemetry":
                device, tenant = authenticated(
                    db, "SELECT id, tenant FROM device WHERE token = ? AND state = 'active'", token
                )
                if body != {"event": "synthetic-heartbeat"}:
                    raise Rejected(400)
                db.execute("INSERT INTO telemetry(device, event) VALUES (?, ?)", (device, body["event"]))
                audit(db, tenant, "device", "telemetry_ingested", device)
                return 202, {"accepted": True}
            if path in ("/inventory", "/audit", "/revoke", "/offboard"):
                tenant, = authenticated(db, "SELECT id FROM tenant WHERE operator = ?", token)
                if body.get("tenant") != tenant:
                    raise Rejected(403)
                if path == "/inventory":
                    rows = db.execute("""
                        SELECT d.id, d.platform, d.state, COUNT(t.seq) AS event_count
                        FROM device d LEFT JOIN telemetry t ON t.device = d.id
                        WHERE d.tenant = ? AND d.state != 'offboarded'
                        GROUP BY d.id ORDER BY d.id
                    """, (tenant,))
                    return 200, {"devices": [dict(row) for row in rows]}
                if path == "/audit":
                    rows = db.execute("""
                        SELECT actor, action, device FROM audit WHERE tenant = ? ORDER BY seq
                    """, (tenant,))
                    return 200, {"events": [dict(row) for row in rows]}
                device = body.get("device")
                if not isinstance(device, str):
                    raise Rejected(400)
                previous, current = ("active", "revoked") if path == "/revoke" else ("revoked", "offboarded")
                row = db.execute(
                    "SELECT state FROM device WHERE tenant = ? AND id = ?", (tenant, device)
                ).fetchone()
                if row is None:
                    raise Rejected(404)
                if row["state"] != previous:
                    raise Rejected(409)
                db.execute("UPDATE device SET state = ?, token = NULL WHERE id = ?", (current, device))
                audit(db, tenant, "operator", f"device_{current}", device)
                return 200, {"state": current}
            raise Rejected(404)


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, payload):
        encoded = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        if self.path != "/health":
            self.respond(404, {"error": 404})
            return
        self.respond(200, {"mode": "observe-only"})

    def do_POST(self):
        try:
            scheme, _, token = self.headers.get("Authorization", "").partition(" ")
            if scheme != "Bearer" or not token:
                raise Rejected(403)
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4096:
                raise Rejected(400)
            body = json.loads(self.rfile.read(size))
            if not isinstance(body, dict):
                raise Rejected(400)
            status, payload = self.server.lifecycle.request(self.path, token, body)
        except Rejected as error:
            status = error.args[0]
            payload = {"error": status}
        except (ValueError, UnicodeError):
            status, payload = 400, {"error": 400}
        self.respond(status, payload)

    def log_request(self, code="-", size="-"):
        print(f"http_status={code}", flush=True)

    def log_message(self, format_string, *args):
        # Ignore parser diagnostics that could contain raw request data.
        pass


if __name__ == "__main__":
    lifecycle = Lifecycle(os.environ["OBSERVE_DB"], os.environ["OBSERVE_BOOTSTRAP"])
    with ThreadingHTTPServer(("0.0.0.0", 8080), Handler) as server:
        server.lifecycle = lifecycle
        server.serve_forever()
