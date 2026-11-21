# Observe-only lifecycle milestone

From the repository root:

```bash
OBSERVE_BOOTSTRAP="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  ./scripts/docker-release-check.sh integration test/observe-only/compose.yaml api
```

The runner builds the control-plane fixture and portable test agent into images. It starts the API and a fresh SQLite volume on an internal Compose network with no published ports. The bootstrap credential is generated per run. The two tenants receive separate operator credentials, one-use enrollment grants and device credentials. The fixture accepts only a synthetic heartbeat. It records enrollment, telemetry ingestion, revocation and offboarding in each tenant's audit view.

The test exercises both tenants through the HTTP API. It checks cross-tenant inventory, audit and lifecycle denials, verifies that the device credential cannot act as an operator, and checks that concurrent revocation has exactly one successful transition. It verifies that heartbeats are rejected after revocation and offboarding, that offboarded devices disappear from inventory, and that the tenant-scoped audit history is retained. The runner prints the evidence directory.

The Linux agent runs in a Linux container. The Windows-labelled instance runs the same portable client in that container and exercises the Windows enrollment payload. Native Windows execution, platform sensors and installer behavior require separate VM evidence. The internal fixture uses synthetic bearer credentials and SQLite audit storage. Production identity, certificate enrolment, telemetry collection and immutable audit storage are outside this milestone.

The fixture is observe-only by construction. The test checks that no enforcement endpoint is available. Adding autonomous enforcement requires closing [P2.G](../../P2.G_Gate_P2_Report.md) and producing [controller rejection and recovery evidence](../../P2.2_Enforcement_Controller_v1.md#4-sign-off-evidence).
