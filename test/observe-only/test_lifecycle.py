import os
import platform
import unittest
from concurrent.futures import ThreadPoolExecutor

from agent import Agent, Client


class ObserveOnly(unittest.TestCase):
    def test_two_tenant_lifecycle(self):
        self.assertEqual(platform.system(), "Linux")
        client = Client("http://api:8080")

        def call(path, token, body, expected):
            status, payload = client.request(path, token, body)
            self.assertEqual(status, expected, path)
            return payload

        bootstrap = os.environ["OBSERVE_BOOTSTRAP"]
        call("/tenants", "invalid", {}, 403)
        windows, linux = [call("/tenants", bootstrap, {}, 201) for _ in range(2)]
        self.assertNotEqual(windows["tenant"], linux["tenant"])
        tenants = (windows, linux)
        agents = (Agent(client, "windows"), Agent(client, platform.system().lower()))

        for tenant, agent in zip(tenants, agents):
            agent.enroll(tenant["grant"])
            call("/enroll", tenant["grant"], {"platform": agent.platform}, 403)
            self.assertEqual(agent.heartbeat(), (202, {"accepted": True}))
            call("/inventory", agent.credential, {"tenant": tenant["tenant"]}, 403)
            call("/enforce", tenant["operator"], {"device": agent.device}, 404)
            call("/telemetry", tenant["operator"], {"event": "synthetic-heartbeat"}, 403)
        print("PASS two tenants, Windows-labelled and Linux-hosted enrollment, single-use grants, telemetry, observe-only boundary", flush=True)

        for index, (tenant, agent) in enumerate(zip(tenants, agents)):
            other_tenant, other_agent = tenants[1 - index], agents[1 - index]
            operator = tenant["operator"]
            scope = {"tenant": tenant["tenant"]}
            target = {**scope, "device": agent.device}
            for path in ("/inventory", "/audit", "/revoke", "/offboard"):
                call(path, operator, {"tenant": other_tenant["tenant"], "device": other_agent.device}, 403)
            for path in ("/revoke", "/offboard"):
                call(path, operator, {**scope, "device": other_agent.device}, 404)
            call("/telemetry", agent.credential, {"event": "synthetic-heartbeat", "device": other_agent.device}, 400)
            self.assertEqual(
                call("/inventory", operator, scope, 200)["devices"],
                [{"id": agent.device, "platform": agent.platform, "state": "active", "event_count": 1}],
            )
            call("/offboard", operator, target, 409)
            with ThreadPoolExecutor(max_workers=2) as pool:
                attempts = list(pool.map(lambda _: client.request("/revoke", operator, target)[0], range(2)))
            self.assertEqual(sorted(attempts), [200, 409])
            self.assertEqual(agent.heartbeat()[0], 403)
            self.assertEqual(call("/inventory", operator, scope, 200)["devices"][0]["state"], "revoked")
            self.assertEqual(call("/offboard", operator, target, 200), {"state": "offboarded"})
            self.assertEqual(agent.heartbeat()[0], 403)
            self.assertEqual(call("/inventory", operator, scope, 200)["devices"], [])
            events = call("/audit", operator, scope, 200)["events"]
            self.assertEqual(
                [(event["actor"], event["action"], event["device"]) for event in events],
                [
                    ("bootstrap", "tenant_created", None),
                    ("enrollment", "device_enrolled", agent.device),
                    ("device", "telemetry_ingested", agent.device),
                    ("operator", "device_revoked", agent.device),
                    ("operator", "device_offboarded", agent.device),
                ],
            )
        print("PASS tenant isolation, concurrent revocation, both offboards, retained tenant-scoped audit", flush=True)


if __name__ == "__main__":
    unittest.main()
