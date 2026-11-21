"""Black-box qualification of the deployable API, native Linux agent and job worker."""

import hashlib
import json
import os
import secrets
import sqlite3
import shutil
import ssl
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from uuid import uuid4

from customer_ops import operations_route, privacy_route
from store import SCHEMA, RequestError, Store


ORIGIN = "https://api:8443"
AGENT = "/native/ada-agent-linux-amd64"
CA = "/checks/ca.crt"
PROVISION = {
    "max_endpoints": 1, "contract_ref": "LAB-CONTRACT",
    "privacy_ref": "LAB-DPIA", "customer_authorisation_ref": "LAB-OBSERVE-ONLY",
}


def lab_activation(tenant):
    fields = {
        **{key: value for key, value in PROVISION.items() if key != "max_endpoints"},
        "version": 1, "tenant": tenant, "mode": "observe-only", "retention_days": 30,
        "expires_at": int(time.time()) + 1800,
    }
    payload = json.dumps(fields)
    return {**fields, "signed_payload": payload, "approval_sha256": hashlib.sha256(payload.encode()).hexdigest()}


class ProductIsolation(unittest.TestCase):
    def setUp(self):
        tls = ssl.create_default_context(cafile=CA)
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=tls)
        )
        self.clients = json.loads(Path("/checks/clients.json").read_text())

    def test_two_tenants_with_native_enrollment_and_worker(self):
        left, right = self.clients["tenants"][:2]
        support = self.clients["support"]
        ops = self.clients["customer_operations"]["token"]
        for tenant in (left, right):
            self.request(tenant["id"], "provision", 200, PROVISION, ops)

        def request(tenant, path, status, body=None, token=None):
            return self.request(tenant["id"], path, status, body, token or tenant["token"])

        with tempfile.TemporaryDirectory() as temporary:
            agents = {}
            for tenant in (left, right):
                enrollment = request(tenant, "enrollments", 201, {})
                self.agent(tenant, temporary, "--enroll", grant=enrollment["grant"])
                request(tenant, "enroll", 403, {"platform": "linux", "arch": "amd64"}, enrollment["grant"])
                self.agent(tenant, temporary, "--once")
                agents[tenant["id"]] = json.loads((Path(temporary) / tenant["id"]).read_text())
            left_agent, right_agent = [agents[tenant["id"]] for tenant in (left, right)]
            self.assertNotEqual(left_agent["device"], right_agent["device"])
            self.assertEqual(
                [(row["id"], row["platform"]) for row in request(left, "devices", 200)["items"]],
                [(left_agent["device"], "linux")],
            )
            request(right, "devices", 403, token=left["token"])
            request(left, "devices", 403, token=right["token"])
            request(right, "events", 403, {"id": left_agent["device"], "build": "0.1.0"}, left_agent["credential"])
            request(right, "revoke/" + left_agent["device"], 404, {})
            request(left, "enforce", 404, {})
            print("PASS native Linux agents, TLS, tenant-scoped API and observe-only routes", flush=True)

            request(left, "devices", 403, token=support["token"])
            request(left, "support/" + support["subject"], 200, {"seconds": 60})
            self.assertEqual(request(left, "devices", 200, token=support["token"])["items"][0]["id"], left_agent["device"])
            request(right, "devices", 403, token=support["token"])
            request(left, "audit", 403, token=support["token"])
            request(left, "export", 403, {}, support["token"])
            request(left, "support/" + support["subject"], 200, {"seconds": 0})
            request(left, "devices", 403, token=support["token"])
            request(left, "support/" + support["subject"], 200, {"seconds": 1})
            time.sleep(1.05)
            request(left, "devices", 403, token=support["token"])
            self.assertTrue(any(
                event["actor"] == support["subject"] and event["action"] == "devices_read"
                for event in request(left, "audit", 200)["items"]
            ))
            self.assertFalse(any(
                event["actor"] == support["subject"] for event in request(right, "audit", 200)["items"]
            ))
            print("PASS granted, audited and revoked tenant support access", flush=True)

            left_export = request(left, "export", 202, {})["id"]
            right_export = request(right, "export", 202, {})["id"]
            left_backup = request(left, "backup", 202, {})["id"]
            right_backup = request(right, "backup", 202, {})["id"]
            for tenant, agent, export, backup in (
                (left, left_agent, left_export, left_backup), (right, right_agent, right_export, right_backup)
            ):
                self.wait(tenant, export)
                self.wait(tenant, backup)
                document = request(tenant, "results/" + export, 200)
                self.assertEqual(document["tenant"], tenant["id"])
                self.assertEqual([event["device"] for event in document["events"]], [agent["device"]])
                request(tenant, "results/" + backup, 404)
            request(right, "jobs/" + left_export, 404)
            request(right, "results/" + left_export, 404)
            request(left, "results/" + right_export, 404)
            print("PASS independent background jobs and tenant-scoped export results", flush=True)

            self.agent(left, temporary, "--once")
            request(right, "restore/" + left_backup, 404, {})
            request(left, "restore/" + right_backup, 404, {})
            restored = request(left, "restore/" + left_backup, 202, {})["id"]
            self.wait(left, restored)
            document = request(left, "results/" + restored, 200)
            self.assertEqual(document["kind"], "restore")
            self.assertEqual(document["events"], request(left, "results/" + left_export, 200)["events"])
            request(right, "results/" + restored, 404)
            current = request(left, "export", 202, {})["id"]
            self.wait(left, current)
            self.assertEqual(len(request(left, "results/" + current, 200)["events"]), 2)
            print("PASS authenticated point-in-time recovery and foreign snapshot rejection", flush=True)

            for tenant, agent in ((left, left_agent), (right, right_agent)):
                request(tenant, "revoke/" + agent["device"], 200, {})
                result = self.agent(tenant, temporary, "--once", success=False)
                self.assertIn("HTTP 403", result.stderr)
                request(tenant, "offboard/" + agent["device"], 200, {})
                self.assertEqual(request(tenant, "devices", 200)["items"], [])
            print("PASS native credentials revoked and agents offboarded", flush=True)

    def test_recover_from_separate_artifacts_with_fresh_datastore(self):
        left, right, actor, device, event = (str(uuid4()) for _ in range(5))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, recovered, artifacts = (root / name for name in ("original", "recovered", "artifacts"))
            original.mkdir()
            recovered.mkdir()
            config = root / "tenants.json"
            config.write_text(json.dumps({
                "tenants": {
                    tenant: {"backup_key": secrets.token_hex(32), "operators": {}, "approved_activation": lab_activation(tenant)}
                    for tenant in (left, right)
                },
                "support": {},
            }))
            received = int(time.time())
            original_store = Store(config, original, artifacts)
            with original_store.transaction(left) as db:
                operations_route(db, actor, "provision", PROVISION, original_store.approvals[left])
                db.execute("INSERT INTO device VALUES (?, 'linux', 'amd64', NULL, 'revoked')", (device,))
                db.execute("INSERT INTO event VALUES (?, ?, '0.1.0', ?)", (event, device, received))
                backup = original_store.enqueue(db, left, actor, "backup")
            self.assertTrue(original_store.work(left))

            cold_store = Store(config, recovered, artifacts)
            with cold_store.transaction(left) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM job").fetchone()[0], 0)
                operations_route(db, actor, "provision", PROVISION, cold_store.approvals[left])
                restore = cold_store.enqueue(db, left, actor, "restore", backup)
            with cold_store.transaction(right) as db:
                with self.assertRaises(RequestError) as error:
                    cold_store.enqueue(db, right, actor, "restore", backup)
                self.assertEqual(error.exception.status, 404)

            # A misplaced backup is rejected even at the artifact verification boundary.
            shutil.copyfile(
                original_store.artifact_path(left, backup, "backup"),
                cold_store.artifact_path(right, backup, "backup"),
            )
            with cold_store.transaction(right) as db:
                operations_route(db, actor, "provision", PROVISION, cold_store.approvals[right])
                rejected = cold_store.enqueue(db, right, actor, "restore", backup)
            self.assertTrue(cold_store.work(left))
            self.assertTrue(cold_store.work(right))
            result = cold_store.fetch(left, restore, "restore")
            self.assertEqual(result["events"], [{"id": event, "device": device, "build": "0.1.0", "received": received}])
            with cold_store.transaction(left) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM device").fetchone()[0], 0)
            with cold_store.transaction(right) as db:
                state = db.execute("SELECT status,error FROM job WHERE id=?", (rejected,)).fetchone()
                self.assertEqual(tuple(state), ("failed", "artifact_integrity"))
            self.assertFalse(cold_store.artifact_path(right, rejected, "restore").exists())
            print("PASS fresh datastore recovery and misplaced tenant backup rejection", flush=True)

    def test_customer_operations_and_incident_drill(self):
        tenant = self.clients["tenants"][2]
        ops, support = self.clients["customer_operations"]["token"], self.clients["support"]

        def call(path, status, body=None, credential=None):
            return self.request(tenant["id"], path, status, body, credential or tenant["token"])

        call("enrollments", 403, {})
        call("provision", 403, PROVISION)
        call("provision", 400, {**PROVISION, "privacy_ref": ""}, ops)
        call("provision", 400, {**PROVISION, "customer_authorisation_ref": ""}, ops)
        call("provision", 403, {**PROVISION, "customer_authorisation_ref": "UNVERIFIED-REFERENCE"}, ops)
        self.assertEqual(call("provision", 200, PROVISION, ops), {"state": "active", "max_endpoints": 1})
        call("provision", 409, PROVISION, ops)
        call("devices", 403, credential=ops)
        first = call("enrollments", 201, {})["grant"]
        device = call("enroll", 201, {"platform": "linux", "arch": "amd64"}, first)
        spare = call("enrollments", 201, {})["grant"]
        call("enroll", 409, {"platform": "linux", "arch": "amd64"}, spare)
        call("entitlement", 200, {"max_endpoints": 2, "case_ref": "LAB-AMENDMENT"}, ops)
        second = call("enroll", 201, {"platform": "linux", "arch": "amd64"}, spare)
        call("entitlement", 409, {"max_endpoints": 1, "case_ref": "LAB-AMENDMENT-2"}, ops)
        event = {"id": str(uuid4()), "build": "0.1.0"}
        call("events", 202, event, device["credential"])
        call("events", 202, event, device["credential"])
        call("events", 202, {**event, "id": str(uuid4())}, second["credential"])
        time.sleep(1.05)
        period = {"start": 0, "end": int(time.time())}
        reconciliation = {**period, "case_ref": "LAB-USAGE", "expected_endpoints": 2}
        expected = {
            **period, "accepted_events": 2, "reporting_endpoints": 2,
            "expected_endpoints": 2, "variance": 0, "status": "balanced",
        }
        comparison = call("reconcile", 200, {**reconciliation, "expected_endpoints": 1}, ops)
        self.assertEqual((comparison["status"], comparison["variance"]), ("mismatch", 1))
        self.assertEqual(call("reconcile", 200, reconciliation, ops), expected)
        self.assertEqual(call("reconcile", 200, reconciliation, ops), expected)
        call("reconcile", 400, {**reconciliation, "end": int(time.time()) + 60}, ops)
        print("PASS provision approval references, endpoint entitlements, and deduplicated closed-period usage", flush=True)

        exported = call("export", 202, {})["id"]
        self.wait(tenant, exported)
        self.assertEqual(len(call("results/" + exported, 200)["events"]), 2)
        call("devices", 403, credential=support["token"])
        call("support/" + support["subject"], 200, {"seconds": 60})
        call("devices", 200, credential=support["token"])
        old_grant = call("enrollments", 201, {})["grant"]
        call("retire", 409, {"case_ref": "LAB-EXIT"}, ops)
        call("suspend", 200, {"case_ref": "LAB-INCIDENT"}, ops)
        call("events", 403, {**event, "id": str(uuid4())}, device["credential"])
        call("devices", 403, credential=support["token"])
        call("results/" + exported, 403)
        call("revoke/" + device["device"], 200, {})
        call("resume", 200, {"case_ref": "LAB-INCIDENT-CLOSED"}, ops)
        call("enroll", 403, {"platform": "linux", "arch": "amd64"}, old_grant)
        call("devices", 403, credential=support["token"])
        call("events", 403, event, device["credential"])
        call("events", 202, {**event, "id": str(uuid4())}, second["credential"])
        actions = [item["action"] for item in call("audit", 200)["items"]]
        for action in ("support_granted", "devices_read", "customer_suspend", "device_revoked", "customer_resume"):
            self.assertIn(action, actions)
        print("PASS support and incident drills with suspension, revocation, and controlled recovery", flush=True)

        call("suspend", 200, {"case_ref": "LAB-EXIT"}, ops)
        self.assertEqual(call("retire", 200, {"case_ref": "LAB-EXIT"}, ops)["state"], "offboarded")
        call("resume", 409, {"case_ref": "LAB-INVALID-RESUME"}, ops)
        call("provision", 409, PROVISION, ops)
        call("devices", 403)
        call("events", 403, {**event, "id": str(uuid4())}, second["credential"])
        call("results/" + exported, 403)
        self.assertEqual(call("reconcile", 200, reconciliation, ops), expected)
        print("PASS terminal customer offboarding and restricted final reconciliation", flush=True)
        privacy = self.clients["privacy_operations"]["token"]
        call("erase-telemetry", 403, {"case_ref": "LAB-ERASE"}, ops)
        call("privacy-hold", 200, {"case_ref": "LAB-HOLD", "held": True}, privacy)
        call("erase-telemetry", 409, {"case_ref": "LAB-ERASE"}, privacy)
        call("privacy-hold", 200, {"case_ref": "LAB-HOLD-CLOSED", "held": False}, privacy)
        receipt = call("erase-telemetry", 200, {"case_ref": "LAB-ERASE"}, privacy)
        self.assertEqual((receipt["events_removed"], receipt["artifacts_removed"]), (3, 1))
        retry = call("erase-telemetry", 200, {"case_ref": "LAB-ERASE"}, privacy)
        self.assertEqual((retry["events_removed"], retry["artifacts_removed"]), (0, 0))
        self.assertEqual(call("reconcile", 200, reconciliation, ops)["reporting_endpoints"], 0)
        print("PASS hold blocks erasure, authorised telemetry deletion and retry are evidenced", flush=True)

    def test_existing_database_migrates_to_pending_without_losing_usage(self):
        tenant, device, event = (str(uuid4()) for _ in range(3))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.json"
            config.write_text(json.dumps({
                "tenants": {tenant: {"backup_key": secrets.token_hex(32), "operators": {}, "approved_activation": lab_activation(tenant)}},
                "support": {},
            }))
            with sqlite3.connect(root / (tenant + ".sqlite")) as db:
                db.executescript(SCHEMA)
                db.execute("INSERT INTO device VALUES (?, 'linux', 'amd64', NULL, 'active')", (device,))
                db.execute("INSERT INTO event VALUES (?, ?, '0.1.0', 1)", (event, device))
                db.execute("INSERT INTO enrollment VALUES ('old', 5000000000)")
                db.execute("INSERT INTO job VALUES (?, 'export', NULL, 'queued', NULL)", (str(uuid4()),))
            store = Store(config, root, root / "artifacts")
            with store.transaction(tenant) as db:
                self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 3)
                self.assertEqual(db.execute("SELECT state FROM customer_account").fetchone()[0], "pending")
                self.assertEqual(db.execute("SELECT COUNT(*) FROM enrollment").fetchone()[0], 0)
                self.assertEqual(db.execute("SELECT status FROM job").fetchone()[0], "failed")
                self.assertEqual(db.execute("SELECT COUNT(*) FROM event").fetchone()[0], 1)
            self.assertFalse(store.work(tenant))
            with store.transaction(tenant) as db:
                operations_route(db, "ops", "provision", PROVISION, store.approvals[tenant])
                queued = store.enqueue(db, tenant, "operator", "export")
                operations_route(db, "ops", "suspend", {"case_ref": "LAB-INCIDENT"})
            self.assertFalse(store.work(tenant))
            with store.transaction(tenant) as db:
                self.assertEqual(db.execute("SELECT status FROM job WHERE id=?", (queued,)).fetchone()[0], "failed")
                operations_route(db, "ops", "resume", {"case_ref": "LAB-INCIDENT-CLOSED"}, store.approvals[tenant])
            self.assertFalse(store.work(tenant))
            self.assertFalse(store.artifact_path(tenant, queued, "export").exists())
            print("PASS v1 migration preserves usage and suspension cancels queued work", flush=True)

    def test_retention_in_live_store_artifacts_and_restore(self):
        tenant, device, event, backup = (str(uuid4()) for _ in range(4))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.json"
            config.write_text(json.dumps({
                "tenants": {tenant: {"backup_key": secrets.token_hex(32), "operators": {},
                                      "approved_activation": lab_activation(tenant)}}, "support": {},
            }))
            store = Store(config, root, root / "artifacts")
            with store.transaction(tenant) as db:
                operations_route(db, "ops", "provision", PROVISION, store.approvals[tenant])
                db.execute("INSERT INTO device VALUES (?, 'linux', 'amd64', NULL, 'active')", (device,))
                db.execute("INSERT INTO event VALUES (?, ?, '0.1.0', 1)", (event, device))
                current = str(uuid4())
                db.execute("INSERT INTO event VALUES (?, ?, '0.1.0', ?)", (current, device, int(time.time())))
                store.publish(tenant, backup, "backup", [{"id": event, "device": device, "build": "0.1.0", "received": 1}])
                stale_restore = store.enqueue(db, tenant, "operator", "restore", backup)
            self.assertTrue(store.work(tenant))
            with store.transaction(tenant) as db:
                self.assertEqual(db.execute("SELECT error FROM job WHERE id=?", (stale_restore,)).fetchone()[0], "artifact_expired")
                receipt = privacy_route(db, store, tenant, "privacy", "retain-telemetry", {"case_ref": "LAB-RETENTION"})
                self.assertEqual((receipt["events_removed"], receipt["artifacts_removed"]), (1, 1))
                self.assertEqual([row["id"] for row in db.execute("SELECT id FROM event")], [current])
                self.assertFalse(store.artifact_path(tenant, backup, "backup").exists())
            print("PASS expiry blocks restore and retention removes only expired telemetry and affected artifacts", flush=True)

    def test_changed_activation_and_scheduled_retention_under_hold(self):
        tenant, device, event = (str(uuid4()) for _ in range(3))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.json"
            activation = lab_activation(tenant)
            settings = {"backup_key": secrets.token_hex(32), "operators": {}, "approved_activation": activation}
            configuration = {"tenants": {tenant: settings}, "support": {}}
            settings["approved_activation"] = {**activation, "expires_at": activation["expires_at"] + 60}
            config.write_text(json.dumps(configuration))
            with self.assertRaisesRegex(ValueError, "differs from the verified signed payload"):
                Store(config, root, root / "artifacts")
            settings["approved_activation"] = activation
            config.write_text(json.dumps(configuration))
            store = Store(config, root, root / "artifacts")
            with store.transaction(tenant) as db:
                operations_route(db, "ops", "provision", PROVISION, store.approvals[tenant])
                db.execute("INSERT INTO device VALUES (?, 'linux', 'amd64', NULL, 'active')", (device,))
                db.execute("INSERT INTO event VALUES (?, ?, '0.1.0', 1)", (event, device))
                privacy_route(db, store, tenant, "privacy", "privacy-hold", {"case_ref": "LAB-HOLD", "held": True})
            self.assertIsNone(store.apply_scheduled_retention(tenant))
            with store.transaction(tenant) as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM event").fetchone()[0], 1)
                privacy_route(db, store, tenant, "privacy", "privacy-hold", {"case_ref": "LAB-RELEASE", "held": False})
            self.assertEqual(store.apply_scheduled_retention(tenant), {"events_removed": 1, "artifacts_removed": 0})
            self.assertEqual(store.apply_scheduled_retention(tenant), {"events_removed": 0, "artifacts_removed": 0})
            with store.transaction(tenant) as db:
                self.assertEqual(db.execute(
                    "SELECT COUNT(*) FROM audit WHERE action='telemetry_retention_scheduled'"
                ).fetchone()[0], 1)
            print("PASS changed activation metadata rejected; scheduled retention respects holds and records removals", flush=True)

    def request(self, tenant, path, expected, body, token):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            ORIGIN + "/v1/tenants/" + tenant + "/" + path,
            data,
            {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        )
        try:
            response = self.opener.open(request, timeout=8)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            self.assertEqual(response.code, expected, path.split("/")[0])
            return json.load(response)

    def wait(self, tenant, identifier):
        for _ in range(60):
            job = self.request(tenant["id"], "jobs/" + identifier, 200, None, tenant["token"])
            if job["status"] == "complete":
                return
            self.assertEqual(job["status"], "queued", job.get("error"))
            time.sleep(0.2)
        self.fail("worker did not complete job")

    def agent(self, tenant, temporary, flag, *, grant=None, success=True):
        command = [
            AGENT, "--url", ORIGIN, "--ca", CA, "--tenant", tenant["id"],
            "--state", str(Path(temporary) / tenant["id"]), flag,
        ]
        environment = os.environ.copy()
        if grant:
            environment["ADA_ENROLLMENT_GRANT"] = grant
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=15)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result


if __name__ == "__main__":
    unittest.main()
