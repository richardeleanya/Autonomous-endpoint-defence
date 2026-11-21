#!/usr/bin/env python3
"""Fail-closed release evidence verifier. Run from a trusted installation."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


ROLES = ("source-review", "tests", "builder-a", "builder-b", "release")
NAMESPACE = "ada-release-v1"
REQUIRED_CHECK = "ada/pr-verify"
HEX64 = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
PUBLIC_KEY = re.compile(r"ssh-ed25519 [A-Za-z0-9+/]{68}")
IMAGE_REPOSITORY = re.compile(r"[a-z0-9][a-z0-9.:-]*(/[a-z0-9][a-z0-9._-]*)+")
META_LIMIT = 1024 * 1024


class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def sha(value):
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def object_fields(document, fields, description):
    require(isinstance(document, dict) and document.keys() == fields, f"Invalid {description} fields")


def decode(content):
    def unique(pairs):
        document = dict(pairs)
        require(len(document) == len(pairs), "Duplicate JSON keys")
        return document

    return json.loads(content.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject_constant)


def reject_constant(_):
    raise Rejected("Non-finite JSON value")


def plain_file(root, *parts):
    path = root.joinpath(*parts)
    require(path.resolve(strict=True) == path and path.is_file(), "Expected a regular bundle file")
    return path


def read_meta(path):
    with path.open("rb") as stream:
        content = stream.read(META_LIMIT + 1)
    require(len(content) <= META_LIMIT, "Release metadata exceeds size limit")
    return content


def digest_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_signatures(root, manifest_bytes, keys, *, roles=ROLES, namespace=NAMESPACE):
    require(isinstance(keys, dict) and keys.keys() == set(roles), "Configure the required signer roles")
    require(
        all(isinstance(key, str) and PUBLIC_KEY.fullmatch(key) for key in keys.values())
        and len(set(keys.values())) == len(roles),
        "Each signer role requires a distinct pinned Ed25519 key",
    )
    with tempfile.TemporaryDirectory(prefix="ada-release-signers.") as working:
        signers = Path(working) / "allowed-signers"
        signers.write_text(
            "".join(f'{role} namespaces="{namespace}" {keys[role]}\n' for role in roles), encoding="ascii"
        )
        for role in roles:
            signature = plain_file(root, "signatures", role + ".sig")
            result = subprocess.run(
                ["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", role, "-n", namespace, "-s", str(signature)],
                input=manifest_bytes, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15,
            )
            require(result.returncode == 0, f"Invalid manifest signature for {role}")


def verified_record(root, name, expected):
    require(sha(expected), f"Invalid digest for {name}")
    content = read_meta(plain_file(root, name))
    require(hashlib.sha256(content).hexdigest() == expected, f"Digest mismatch for {name}")
    return decode(content)


def filenames(names):
    return all(isinstance(name, str) and FILENAME.fullmatch(name) for name in names)


def verify_review(review, trust, commit):
    object_fields(review, {
        "repository", "ref", "commit", "pull_request", "head", "author_id", "approver_ids",
        "verified_signatures", "required_check", "check_app_id", "check_head", "check_state",
    }, "source review")
    require(
        review["repository"] == trust["repository"] and review["ref"] == trust["ref"]
        and review["commit"] == commit and review["verified_signatures"] is True,
        "Review must attest the selected signed merge commit on the protected ref",
    )
    approvers = review["approver_ids"]
    require(
        type(review["pull_request"]) is int and review["pull_request"] > 0
        and isinstance(review["head"], str) and COMMIT.fullmatch(review["head"])
        and type(review["author_id"]) is int and review["author_id"] > 0
        and isinstance(approvers, list)
        and all(type(approver) is int and approver > 0 for approver in approvers)
        and len(set(approvers)) >= 2 and review["author_id"] not in approvers,
        "A pull request and two distinct non-author approvals are required",
    )
    require(
        type(trust["check_app_id"]) is int and trust["check_app_id"] > 0
        and type(review["check_app_id"]) is int and review["check_app_id"] == trust["check_app_id"]
        and review["check_head"] == review["head"] and review["check_state"] == "success"
        and review["required_check"] == REQUIRED_CHECK,
        "Required check must succeed on the reviewed head from the configured GitHub App",
    )


def verify_builds(root, manifest, trust, commit):
    records = manifest["builds"]
    object_fields(records, {"builder-a", "builder-b"}, "build references")
    first, second = (verified_record(root, role + ".json", records[role]) for role in ("builder-a", "builder-b"))
    for record in (first, second):
        object_fields(record, {"commit", "run_id", "recipe_sha256", "payloads"}, "builder record")
        require(
            record["commit"] == commit and isinstance(record["run_id"], str)
            and FILENAME.fullmatch(record["run_id"]) and sha(record["recipe_sha256"]),
            "Builders must identify the selected commit, run and build recipe",
        )
    require(
        first["run_id"] != second["run_id"] and first["recipe_sha256"] == second["recipe_sha256"]
        and first["payloads"] == second["payloads"],
        "Independent builds must use the same recipe and produce identical payload digests",
    )
    payloads = first["payloads"]
    require(
        isinstance(trust["payloads"], list) and trust["payloads"] and filenames(trust["payloads"])
        and len(set(trust["payloads"])) == len(trust["payloads"]),
        "Configure the expected reproducible payloads in trusted policy",
    )
    object_fields(payloads, set(trust["payloads"]), "reproducible payload")
    for name, expected in payloads.items():
        require(sha(expected) and digest_file(plain_file(root, "payloads", name)) == expected, f"Payload mismatch for {name}")
    return payloads


def verify_artifacts(root, manifest, trust, payloads):
    expected = trust["artifacts"]
    require(isinstance(expected, dict) and expected and filenames(expected), "Configure expected signed artifacts")
    object_fields(manifest["artifacts"], expected.keys(), "signed artifact")
    digests = {}
    for name, artifact in manifest["artifacts"].items():
        object_fields(artifact, {"payload", "sha256"}, "artifact record")
        require(
            isinstance(artifact["payload"], str) and artifact["payload"] in payloads
            and artifact["payload"] == expected[name],
            f"Missing reproducible source for {name}",
        )
        actual = digest_file(plain_file(root, "artifacts", name))
        require(actual == artifact["sha256"], f"Signed artifact mismatch for {name}")
        digests[name] = actual
    return digests


def verify_tests(root, manifest, trust, commit, artifacts):
    tests = verified_record(root, "tests.json", manifest["tests_sha256"])
    object_fields(tests, {"commit", "deployment_sha256", "artifacts", "cases", "log_sha256"}, "test evidence")
    require(
        tests["commit"] == commit and tests["deployment_sha256"] == manifest["deployment_sha256"]
        and tests["artifacts"] == artifacts,
        "Tests must cover this exact build and deployment configuration",
    )
    required = trust["required_tests"]
    cases = tests["cases"]
    require(
        isinstance(required, list) and required and filenames(required)
        and isinstance(cases, dict) and set(required).issubset(cases) and all(status == "pass" for status in cases.values()),
        "All required tests must pass with zero failed or skipped cases",
    )
    require(
        digest_file(plain_file(root, "tests.log")) == tests["log_sha256"],
        "Test transcript digest mismatch",
    )


def oci_digest(archive):
    with tarfile.open(archive, "r:") as image:
        members = image.getmembers()
        files = {item.name: item for item in members}
        require(len(files) == len(members), "Duplicate OCI archive entries")

        def read_blob(name, limit, expected_size=None):
            member = files.get(name)
            require(member and member.isfile() and member.size <= limit, "Invalid OCI archive member")
            require(expected_size is None or member.size == expected_size, "OCI blob size mismatch")
            return image.extractfile(member)

        def verify_descriptor(descriptor, *, metadata=False):
            digest = descriptor["digest"]
            size = descriptor["size"]
            require(
                isinstance(digest, str) and digest.startswith("sha256:") and sha(digest[7:])
                and type(size) is int and size >= 0,
                "Invalid OCI descriptor",
            )
            with read_blob("blobs/sha256/" + digest[7:], META_LIMIT if metadata else size, size) as stream:
                if metadata:
                    content = stream.read()
                    actual = hashlib.sha256(content).hexdigest()
                else:
                    content = None
                    actual = hashlib.file_digest(stream, "sha256").hexdigest()
            require(digest[7:] == actual, "OCI blob digest mismatch")
            return content

        with read_blob("index.json", META_LIMIT) as stream:
            index = decode(stream.read())
        entries = index["manifests"]
        require(index["schemaVersion"] == 2 and len(entries) == 1, "Expected one platform image in OCI payload")
        descriptor = entries[0]
        require(
            descriptor["mediaType"] == "application/vnd.oci.image.manifest.v1+json",
            "Expected a direct OCI image manifest",
        )
        manifest = decode(verify_descriptor(descriptor, metadata=True))
        require(manifest["schemaVersion"] == 2 and isinstance(manifest["layers"], list), "Invalid OCI image manifest")
        config = decode(verify_descriptor(manifest["config"], metadata=True))
        require(config["os"] == "linux" and config["architecture"] == "amd64", "Expected Linux amd64 candidate")
        for layer in manifest["layers"]:
            verify_descriptor(layer)
    return descriptor["digest"]


def literal_configuration(value):
    if isinstance(value, str):
        return "$" not in value
    if isinstance(value, dict):
        return all(literal_configuration(key) and literal_configuration(item) for key, item in value.items())
    if isinstance(value, list):
        return all(literal_configuration(item) for item in value)
    return True


def verify_deployment(root, manifest, trust, payloads):
    content = read_meta(plain_file(root, "deployment.json"))
    require(hashlib.sha256(content).hexdigest() == manifest["deployment_sha256"], "Deployment configuration digest mismatch")
    config = decode(content)
    require(
        isinstance(config, dict) and config.keys() <= {"name", "services", "networks", "volumes", "secrets"}
        and isinstance(config.get("name"), str) and re.fullmatch(r"[a-z0-9][a-z0-9_-]*", config["name"])
        and literal_configuration(config),
        "Deploy a standalone literal Compose configuration with an explicit project name",
    )
    services = trust["services"]
    require(isinstance(services, dict) and services, "Configure expected deployment services")
    object_fields(config["services"], services.keys(), "deployment service")
    verified_images = {}
    for name, specification in services.items():
        object_fields(specification, {"repository", "payload"}, "trusted image mapping")
        repository, payload = specification["repository"], specification["payload"]
        require(
            isinstance(repository, str) and IMAGE_REPOSITORY.fullmatch(repository)
            and isinstance(payload, str) and payload in payloads,
            "Invalid trusted image mapping",
        )
        if payload not in verified_images:
            verified_images[payload] = oci_digest(plain_file(root, "payloads", payload))
        service = config["services"][name]
        require(
            isinstance(service, dict) and service.get("image") == f"{repository}@{verified_images[payload]}"
            and not service.keys() & {"build", "extends", "env_file", "label_file", "profiles", "develop", "provider"},
            f"Service {name} must use the exact verified OCI digest without overlays or rebuilds",
        )
        environment = service.get("environment", {})
        require(
            isinstance(environment, dict) and all(isinstance(value, str) for value in environment.values()),
            f"Service {name} cannot inherit ambient environment values",
        )
        mounts = service.get("volumes", [])
        require(
            isinstance(mounts, list)
            and all(
                isinstance(mount, dict) and (
                    mount.get("type") in ("volume", "tmpfs")
                    or mount.get("type") == "bind" and isinstance(mount.get("source"), str) and mount["source"].startswith("/")
                )
                for mount in mounts
            ),
            f"Service {name} must use explicit named volumes or absolute bind paths",
        )
    secrets = config.get("secrets", {})
    require(
        isinstance(secrets, dict) and all(
            isinstance(secret, dict) and "environment" not in secret
            and ("file" not in secret or isinstance(secret["file"], str) and secret["file"].startswith("/"))
            for secret in secrets.values()
        ),
        "Secrets must use explicit absolute files or external references",
    )
    return content


def verify(root, policy_path, commit, expected_manifest):
    require(COMMIT.fullmatch(commit) and sha(expected_manifest), "Expected a full commit SHA and manifest SHA-256")
    require(not policy_path.is_relative_to(root), "Trust policy must be outside the candidate bundle")
    trust = decode(read_meta(policy_path))
    object_fields(trust, {
        "repository", "ref", "check_app_id", "keys", "required_tests", "services", "payloads", "artifacts"
    }, "trust policy")
    require(
        isinstance(trust["ref"], str) and (
            trust["ref"] == "refs/heads/main" or trust["ref"].startswith("refs/heads/release/")
        ),
        "Trust policy must select a protected branch",
    )
    raw = read_meta(plain_file(root, "manifest.json"))
    require(hashlib.sha256(raw).hexdigest() == expected_manifest, "Unexpected candidate manifest digest")
    verify_signatures(root, raw, trust["keys"])
    manifest = decode(raw)
    object_fields(manifest, {
        "version", "repository", "ref", "commit", "review_sha256", "deployment_sha256", "tests_sha256",
        "builds", "artifacts",
    }, "manifest")
    require(
        type(manifest["version"]) is int and manifest["version"] == 1 and manifest["commit"] == commit
        and manifest["repository"] == trust["repository"] and manifest["ref"] == trust["ref"],
        "Manifest scope differs from the selected repository, ref or commit",
    )
    verify_review(verified_record(root, "review.json", manifest["review_sha256"]), trust, commit)
    payloads = verify_builds(root, manifest, trust, commit)
    artifacts = verify_artifacts(root, manifest, trust, payloads)
    deployment = verify_deployment(root, manifest, trust, payloads)
    verify_tests(root, manifest, trust, commit, artifacts)
    return deployment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--emit-compose", action="store_true", help="Write only the verified deployment bytes")
    action.add_argument("--deploy", action="store_true", help="Deploy the verified Compose bytes via the trusted Docker context")
    args = parser.parse_args()
    try:
        deployment = verify(
            args.bundle.resolve(strict=True), args.trust_policy.resolve(strict=True), args.commit, args.manifest_sha256
        )
    except (OSError, ValueError, TypeError, KeyError, RecursionError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"Release rejected: {error}", file=sys.stderr)
        return 1
    if args.emit_compose:
        sys.stdout.buffer.write(deployment)
    elif args.deploy:
        environment = {key: value for key, value in os.environ.items() if not key.startswith("COMPOSE_")}
        environment["COMPOSE_DISABLE_ENV_FILE"] = "1"
        try:
            return subprocess.run(
                ["docker", "compose", "--project-name", decode(deployment)["name"], "--env-file", "/dev/null",
                 "--file", "-", "up", "--no-build", "--pull", "always", "--detach", "--wait", "--wait-timeout", "120"],
                input=deployment, env=environment,
            ).returncode
        except OSError as error:
            print(f"Could not invoke the deployment engine: {error}", file=sys.stderr)
            return 1
    else:
        print(f"Release evidence verified for {args.commit} at manifest {args.manifest_sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
