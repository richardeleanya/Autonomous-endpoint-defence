# Protected branches and candidate promotion

Use the release tools from a trusted operator installation. Keep runner identities, pinned approval keys, trust policy and deployment permissions outside code submitted for review. Untrusted PR workloads run in an isolated test worker with no GitHub App write, signing or deployment credentials.

## GitHub controls

The ruleset covers `main` and `release/*`, including nested release branches. It requires a PR, two approvals, Code Owner review, dismissal of stale approvals, review of the last push, resolved threads, verified signatures and an up-to-date status check from one GitHub App. Force pushes and deletion are blocked. The two-approval minimum applies across the protected refs to enforce the TCB threshold without relying on a path classifier.

Repository administrators must assign the actual security and architecture owners in CODEOWNERS and install the external CI App. The App publishes the `ada/pr-verify` Check Run on the immutable PR head only after its isolated required tests complete successfully. Use the GitHub App ID for `ADA_CHECK_APP_ID`. GitHub Actions is unnecessary. A separate least-privilege process publishes the check from trusted test results.

Generate the ruleset and review it against the repository's active rules. Confirm the App can publish the required check and the owner teams can review before enabling it. With repository administration permission, create it through the GitHub rulesets API.

```bash
python3 -B release/github_ruleset.py --status-app-id "$ADA_CHECK_APP_ID" > ruleset.json
gh api --method POST repos/richardeleanya/Autonomous-endpoint-defence/rulesets --input ruleset.json
```

Use a read-only GitHub App to collect post-merge evidence. The collector checks live rules, the selected protected ref and merge commit, verification of the merge and every PR commit, two current non-author approvals, and the configured App's successful Check Run for the reviewed head.

```bash
python3 -B release/github_review.py \
  --repository richardeleanya/Autonomous-endpoint-defence --ref refs/heads/main \
  --pull-request "$PR_NUMBER" --commit "$MERGED_SHA" --status-app-id "$ADA_CHECK_APP_ID" \
  > "$BUNDLE/review.json"
```

The managed Git transport can have access independent of GitHub's administration API. This checkout's branch-protection API read was forbidden. Live ruleset activation, CODEOWNERS assignment and authenticated App check publication require repository or organisation access.

## Reproducible payloads

Run both builders from the selected clean commit with separate identities and workspaces. Record their run IDs, source commit, and identical recipe digests covering source inputs, toolchain, base images, build configuration and locked dependencies. Compare exact payload checksums before distribution signing. Embed native code signatures through the approved signing workflow, then record the final signed bytes and their reproducible source in the manifest. Lab keys are only for isolated qualification.

Build the unsigned Windows and Linux payloads with `scripts/build-native-agents.sh`. Build the Linux amd64 control-plane OCI archive with `scripts/build-control-plane-oci.sh`. The latter uses an OCI-capable Buildx builder, a local layout exported from the digest-pinned Python image, hash-locked Python wheels installed offline, and a timestamp derived from the selected Git commit. Compose project metadata stays outside the artifact build.

```bash
docker buildx create --name ada-release-builder --driver docker-container \
  --driver-opt image=moby/buildkit@sha256:baf6138eb8c37644800c7c913fba051e840ebb9ba13eaf92d92ef9a1712d0b4c
export BUILDX_BUILDER=ada-release-builder
python3 -m pip download --only-binary=:all: --require-hashes \
  -r product/control_plane/requirements.txt --dest "$WHEELHOUSE"
./scripts/build-native-agents.sh "$NATIVE_OUT"
./scripts/build-control-plane-oci.sh "$WHEELHOUSE" "$OCI_OUT"
```

The two output directories must already exist and be empty. Use a distinct, appropriately pinned builder for the second production run. Compare native file digests and the OCI archive SHA-256. Verify the OCI manifest SHA-256 when copying it to the controlled registry. Registry publication must preserve the digest, including media type and blob descriptors. Promote by the digest that matches the verified OCI archive.

## Bundle layout and trust

```text
candidate/
  manifest.json
  review.json
  builder-a.json
  builder-b.json
  tests.json
  tests.log
  deployment.json
  payloads/
  artifacts/
  signatures/
    source-review.sig
    tests.sig
    builder-a.sig
    builder-b.sig
    release.sig
```

Use UTF-8 JSON without duplicate keys. Digests are lowercase SHA-256 hex strings, and commit IDs are full 40-character Git SHA-1s. Every signature covers the original bytes of `manifest.json`, which seals the digest of each evidence record and the final artifacts. Every role independently reviews its evidence before signing the same manifest. Release Engineering verifies the distribution signatures and the mapping to reproducible payloads, then signs the manifest after the release approvals in the qualification pack.

| JSON file | Required fields |
|---|---|
| `manifest.json` | `version` = 1, `repository`, `ref`, `commit`, `review_sha256`, `deployment_sha256`, `tests_sha256`, `builds` mapping `builder-a` and `builder-b` to their JSON digests, and `artifacts` mapping each published filename to `{"sha256": "...", "payload": "source filename"}`. |
| `review.json` | Output of the authenticated GitHub collector. Retain the original live API evidence in the review job's auditable records. |
| `builder-a.json`, `builder-b.json` | `commit`, distinct `run_id`, matching `recipe_sha256`, and `payloads` mapping every reproducible filename to its digest. Keep each builder's raw logs and provenance with its run. |
| `tests.json` | `commit`, `deployment_sha256`, `artifacts` mapping every published filename to the exact digest tested, `cases` mapping mandatory test IDs to `pass`, and `log_sha256` for `tests.log`. The test authority signs from actual completed tests and retains raw outputs. Missing, failed and skipped required results block promotion. |
| `deployment.json` | A standalone resolved Compose plan with a fixed project `name`, exact expected services and images using `registry/repository@sha256:...`. Use absolute bind paths, explicit environment values and named secret references. Keep runtime secret values out of the signed plan. Protect and version the actual files and secret bindings separately. No overlays, build definitions or interpolation. |

The independently administered trust policy is outside the bundle and has the following JSON keys.

- `repository`, `ref` and `check_app_id` select the approved GitHub repository, protected ref and installed status-check App ID.
- `keys` maps the five signature roles to distinct OpenSSH Ed25519 public keys in `ssh-ed25519 BASE64` form. Deploy and review jobs pin these keys externally.
- `required_tests` lists the mandatory test IDs for this release class. Include the applicable controller, isolation, package-signature, native VM, hosted, supply-chain and recovery checks from the qualification pack. Keep the policy under separate approval.
- `payloads` lists the expected unsigned native files and OCI archives. `artifacts` maps each required final artifact filename to its reproducible payload filename. This can include the signed builds and their detached distribution signatures.
- `services` maps each required service name to `{"repository": "registry/repository", "payload": "control-plane.oci.tar"}`. The verifier validates the OCI manifest, config and layer digests and requires this exact image reference in the resolved plan.

Sign with trusted keys using the `ada-release-v1` namespace. Each signer has access to its own key only.

```bash
ssh-keygen -Y sign -f "$SIGNER_KEY" -n ada-release-v1 < "$BUNDLE/manifest.json" > "$BUNDLE/signatures/$ROLE.sig"
```

## Verify and promote

The trusted deployment job receives the exact expected commit and manifest digest from release coordination. It verifies signatures, all required tests, both reproducibility attestations, final artifact bytes and the exact deployment plan. The default command only verifies. `--emit-compose` outputs the original verified plan bytes.

```bash
python3 -B release/verify_candidate.py --bundle "$BUNDLE" --trust-policy "$TRUST_POLICY" \
  --commit "$MERGED_SHA" --manifest-sha256 "$APPROVED_MANIFEST_SHA256"
```

Use `--deploy` only on the authorised deployment identity with the intended Docker context. On success it pipes the verified config directly to Compose and pulls by digest with rebuilds disabled. Scope Docker and registry permissions so the approved release job is the deployment path. Runtime secret files and volumes remain managed by that environment. Installation of the GitHub App, protection of those credentials and enforcement of deployment permissions are hosted governance tasks.

The checks run locally with disposable SSH keys and simulated GitHub responses.

```bash
python3 -B -m unittest discover -s test/release-controls -v
```

Customer rollout remains [NO-GO](../Release_Qualification_and_Evidence_Pack.md). P2.G, native and hosted evidence still govern candidate eligibility.
