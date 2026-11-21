# Observe-only endpoint agent and tenant control plane

`product/agent` builds a native Go client for Windows and Linux amd64. The client enrolls with a one-use grant, persists the issued identity in a private file, and sends only an identified heartbeat over verified HTTPS. It reloads that identity in later processes and exits when the server rejects a revoked credential. Failed network sends retry with the same event ID while the process is alive.

The deployable HTTPS API and worker use separate SQLite files and artifact namespaces for each configured tenant. The API authorizes the principal and tenant before operator reads or writes. A support principal starts without data access and can read only device inventory for the granting tenant while its approved elevation lasts. Grants, reads and revocations are audited. The API exposes observe-only operations.

## Build, sign and qualify

Run from the checkout root. Build output directories are private and should be empty.

```bash
native=$(mktemp -d)
signed=$(mktemp -d)
./scripts/build-native-agents.sh "$native"
./scripts/sign-native-lab.sh "$native" "$signed"
./scripts/qualify-observe-product.sh "$signed"
```

The Go build uses a digest-pinned Docker image and works without a Go toolchain on the host. Lab signing uses host OpenSSL and `dpkg-deb`, and osslsigncode in Docker. It generates a short-lived test certificate, verifies Authenticode on the Windows PE, and creates and verifies detached CMS signatures for the Linux ELF and Debian package. The package ships the same executable as the standalone ELF. The output contains the public signer certificate, a signing transcript and SHA-256 manifest. Production signing and certificate trust are release qualification requirements.

The qualification command downloads hash-locked wheels through the host's configured HTTPS trust path. The images install from that wheel directory offline. It generates a private temporary TLS CA and disposable identities, starts the actual API and worker, then runs the signed Linux build through enrollment, telemetry, revocation and offboarding in two tenants. A separate scenario covers customer activation, entitlement, usage reconciliation, support, incident suspension and customer retirement. Docker records the test results, image IDs, and cleanup status. It also runs a storage recovery check with a fresh datastore and deliberately misplaced synthetic tenant backup.

## Run the hosted configuration on a test host

Provide the private inputs through mounted files. Use the same runtime UID as the owner of the credential files.

| Input | Contents |
|---|---|
| `ADA_CONFIG_DIR/tenants.json` | A JSON object with `tenants` and `support` maps. Each tenant key is a UUID. Its object contains a unique 32-byte hexadecimal `backup_key` and an `operators` map from principal UUIDs to SHA-256 bearer credential digests. The `support` map uses distinct support principal UUIDs and digests. |
| `ADA_CONFIG_DIR/tls.key`, `tls.crt`, `ca.crt` | HTTPS key, serving certificate chain, and trust bundle for the internal readiness probe. The certificate covers `ADA_API_HOSTNAME` and the name used by endpoint clients. |
| `ADA_WHEELHOUSE` | Absolute directory prepared with `python3 -m pip download --only-binary=:all: --require-hashes -r product/control_plane/requirements.txt --dest "$ADA_WHEELHOUSE"`. |
| `ADA_RUNTIME_UID` | Non-root service UID with permission to read the config and certificate files. The default is 10001. Set it before initializing the data volumes. |

```bash
docker compose --env-file /dev/null -f deploy/compose.yaml -f deploy/compose.hosted.yaml up --build -d --wait api worker
```

The host overlay binds HTTPS to loopback. `ADA_PORT` defaults to 8443. The worker remains on the internal network. Persist and protect both volumes. The lab qualification command uses its own short-lived project and cleans up its disposable volumes at completion.

Use the native client with an HTTPS origin, tenant UUID and private state location. Pass the one-use enrollment grant in `ADA_ENROLLMENT_GRANT` for the `--enroll` invocation. Subsequent invocations read state using the same origin and tenant. Use `--once` for a smoke heartbeat, or run with the configured interval. Choose a service-account-owned state directory. On Windows, restrict the filesystem ACL to that account. Use `--ca` for a private HTTPS trust bundle.

## Tenant operations

Configured tenants start pending. Activation requires verified Privacy, Legal and customer approval, plus Customer Operations activation with the matching references. See [customer approvals, lifecycle API and runbooks](CUSTOMER_OPERATIONS.md) before provisioning or migrating an existing installation.

The API prefix is `/v1/tenants/{tenant}`. Use bearer credentials from the approved tenant provisioning path. Enrollment and device credentials are issued independently.

| Role | Operations |
|---|---|
| Tenant operator | `POST enrollments`, `GET devices`, `GET audit`, `POST revoke/{device}`, `POST offboard/{device}`. Inventory and audit are limited to 200 records per response. Use the last returned numeric cursor as the query string to fetch the next page. |
| Tenant operator | `POST support/{principal}` with `{"seconds": N}` where 1–900 grants temporary device-inventory access and 0 revokes it. |
| Tenant operator | `POST export`, `POST backup` or `POST restore/{backup}`; poll `GET jobs/{id}` and read completed exports or restores from `GET results/{id}`. |
| Enrollment grant | `POST enroll` with platform and architecture. The grant expires after ten minutes and is consumed transactionally. |
| Active device | `POST events` with heartbeat ID and build string. A retry reuses the existing event ID. |

Backups contain point-in-time heartbeat data and are written to a separate volume with a tenant-specific integrity tag. Recovery verifies artifact version, tenant, ID, kind and authentication tag, then publishes a tenant-scoped recovery result. A fresh datastore can enqueue recovery using a known backup ID, retained artifact volume and the corresponding trusted key. Recovery leaves live device identities, credentials, grants and audit data outside the imported dataset. Each snapshot is bounded to 25,000 events and 16 MiB. The storage design requires separate encrypted backup and disaster recovery qualification before customer use.

## Qualification boundary

The local checks cover a native Linux userspace build, Windows executable format and lab signature, two-tenant API and worker behavior, limited support access, and offline telemetry recovery into a fresh datastore. The control plane uses configured bearer principals and per-tenant files on one host. Production managed operator identity and device attestation, KMS-backed encryption, immutable audit and a highly available data plane require additional integration and qualification.

The Windows and Linux VM matrix is required for native execution and installer lifecycle, driver and kernel capabilities, security-tool coexistence, platform trust and resource overhead. Non-production cloud access is required for managed identity and signing, deployment permissions, storage restore and regional failover and load checks. The release gate remains [NO-GO](../Release_Qualification_and_Evidence_Pack.md). Autonomous enforcement requires [P2.G closure](../P2.G_Gate_P2_Report.md).
