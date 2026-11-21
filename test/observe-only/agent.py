"""Portable synthetic test agent with enrollment and heartbeat calls only."""

import json
import urllib.error
import urllib.request


class Client:
    def __init__(self, origin):
        self.origin = origin
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, path, token, body):
        request = urllib.request.Request(
            self.origin + path,
            json.dumps(body).encode(),
            {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            response = self.opener.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.code, json.load(response)


class Agent:
    def __init__(self, client, platform):
        self.client = client
        self.platform = platform
        self.device = self.credential = None

    def enroll(self, grant):
        status, payload = self.client.request("/enroll", grant, {"platform": self.platform})
        if status != 201 or payload.get("mode") != "observe-only":
            raise RuntimeError(f"Enrollment failed or mode mismatch (HTTP {status})")
        self.device, self.credential = payload["device"], payload["credential"]

    def heartbeat(self):
        return self.client.request("/telemetry", self.credential, {"event": "synthetic-heartbeat"})
