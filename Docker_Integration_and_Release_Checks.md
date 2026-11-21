# Docker integration and release checks

Run from the existing checkout with Bash, Git, Docker Engine and Docker Compose v2. GitHub Actions and live credentials are unnecessary for these checks.

```bash
./scripts/docker-release-check.sh fixture
./scripts/docker-release-check.sh integration path/to/compose.yaml api datastore queue identity
./scripts/docker-release-check.sh release path/to/compose.yaml api datastore queue identity
```

The fixture runs a digest-pinned container without networking. It exercises image retrieval, execution, evidence capture and cleanup. The other commands are the interface for product code when it lands. The service names shown are examples. Pass the actual Compose dependency names.

## Product Compose contract

- Define an `integration-tests` service that exits nonzero on failure or when no required checks ran. It should report test names and passed, failed and skipped counts. Its exit code is the runner's test result.
- Give each required dependency a readiness health check. Pass all long-lived dependencies on the command line so the runner starts them and waits for readiness before running the suite. Use a disposable datastore, queue and local identity issuer, and seed at least two synthetic tenants. Exercise the API from the test container over the project network.
- Use test-only credentials and generated or disposable keys. Keep credentials and sensitive payloads out of logs. Compose skips implicit `.env` loading, but still inherits exported variables and honours explicit Compose environment files. Supply only test values. Use project-scoped resources. Avoid external volumes or networks, fixed container names, host bind mounts outside the checkout and published ports unless specifically needed.
- Pin pulled dependencies and base images by digest and use frozen dependency locks. Build the actual candidate application image in this Compose project and run the tests against it. Preserve test and dependency logs for troubleshooting.

## Evidence and release handoff

The command prints its private evidence directory under `TMPDIR` or `/tmp`. It records the full Git SHA, dirty status, Compose input hash, Docker versions, stage logs, test exit, image IDs and available registry digests. Locally built images can have an image ID before they have a registry digest. The run removes its containers and project volumes after collecting evidence. Its status is nonzero for a failing command or for evidence collection or cleanup failure.

Check the evidence with `sha256sum -c SHA256SUMS` from the printed directory. Archive it with the corresponding build record before disposing of the runner. Fixture evidence verifies the runner only. Integration evidence from a dirty checkout reports the base commit and dirty status. Use release mode for candidate evidence. It requires a clean checkout, a tracked Compose input and the same clean revision at completion.

Production promotion remains a separate controlled operation under the [Secure SDLC handbook](Secure_SDLC_Handbook_v1.md). A release owner verifies the candidate evidence, produces the SBOM and provenance, publishes the candidate to a controlled registry, and correlates its registry digest with the tested image. Authorised signing and promotion use the approved signing service and promote the same verified digest through canary and rollout. This repository currently has no product images, signing service or promotion target.
