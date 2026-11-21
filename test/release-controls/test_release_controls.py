import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "release"))

from github_review import collect
from github_ruleset import ruleset
from verify_candidate import NAMESPACE, REQUIRED_CHECK, ROLES, Rejected, verify


COMMIT = "1" * 40
HEAD = "2" * 40
APP = 56789
REPOSITORY = "example/ada"
REF = "refs/heads/main"
VERIFIER = Path(__file__).resolve().parents[2] / "release/verify_candidate.py"


def encode(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def write(path, data):
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


class ReleaseGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        storage = tempfile.TemporaryDirectory()
        cls.addClassCleanup(storage.cleanup)
        cls.key_dir = Path(storage.name)
        cls.keys = {}
        for role in ROLES:
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(cls.key_dir / role)], check=True
            )
            cls.keys[role] = " ".join((cls.key_dir / (role + ".pub")).read_text().split()[:2])

    def setUp(self):
        storage = tempfile.TemporaryDirectory()
        self.addCleanup(storage.cleanup)
        base = Path(storage.name)
        self.bundle = base / "candidate"
        self.bundle.mkdir()
        for subdirectory in ("payloads", "artifacts", "signatures"):
            (self.bundle / subdirectory).mkdir()
        self.policy = base / "trust.json"
        self.trust = {
            "repository": REPOSITORY, "ref": REF, "check_app_id": APP,
            "keys": self.keys.copy(), "payloads": ["image.oci.tar", "windows.exe"],
            "artifacts": {"signed.exe": "windows.exe"},
            "required_tests": ["tenant-isolation", "windows-native-signature"],
            "services": {"api": {"repository": "registry.example/ada", "payload": "image.oci.tar"}},
        }
        write(self.policy, encode(self.trust))
        image_config = encode({"os": "linux", "architecture": "amd64"})
        config_digest = hashlib.sha256(image_config).hexdigest()
        candidate_image = encode({
            "schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "layers": [],
            "config": {"digest": "sha256:" + config_digest, "size": len(image_config)},
        })
        digest = hashlib.sha256(candidate_image).hexdigest()
        index = encode({"schemaVersion": 2, "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": "sha256:" + digest,
            "size": len(candidate_image),
        }]})
        archive = self.bundle / "payloads/image.oci.tar"
        with tarfile.open(archive, "w") as tar:
            for name, contents in (
                ("index.json", index),
                ("blobs/sha256/" + digest, candidate_image),
                ("blobs/sha256/" + config_digest, image_config),
            ):
                member = tarfile.TarInfo(name)
                member.size = len(contents)
                tar.addfile(member, io.BytesIO(contents))
        payloads = {
            "windows.exe": write(self.bundle / "payloads/windows.exe", b"windows build"),
            "image.oci.tar": hashlib.sha256(archive.read_bytes()).hexdigest(),
        }
        artifact_digest = write(self.bundle / "artifacts/signed.exe", b"signed windows distribution")
        self.artifact = {"sha256": artifact_digest, "payload": "windows.exe"}
        self.deployment = {"name": "ada-staging", "services": {"api": {"image": "registry.example/ada@sha256:" + digest}}}
        self.builds = {
            role: {"commit": COMMIT, "run_id": role + "-119", "recipe_sha256": "c" * 64, "payloads": payloads.copy()}
            for role in ("builder-a", "builder-b")
        }
        self.review = {
            "repository": REPOSITORY, "ref": REF, "commit": COMMIT, "pull_request": 3, "head": HEAD,
            "author_id": 17, "approver_ids": [18, 19], "verified_signatures": True, "required_check": REQUIRED_CHECK,
            "check_app_id": APP, "check_head": HEAD, "check_state": "success",
        }
        self.results = {
            "commit": COMMIT, "artifacts": {"signed.exe": artifact_digest},
            "cases": {"tenant-isolation": "pass", "windows-native-signature": "pass"},
            "log_sha256": write(self.bundle / "tests.log", b"two approved cases passed\n"),
        }

    def seal(self):
        deployment = write(self.bundle / "deployment.json", encode(self.deployment))
        manifest = {
            "version": 1, "repository": REPOSITORY, "ref": REF, "commit": COMMIT,
            "review_sha256": write(self.bundle / "review.json", encode(self.review)),
            "deployment_sha256": deployment,
            "tests_sha256": write(self.bundle / "tests.json", encode({
                **self.results, "deployment_sha256": self.results.get("deployment_sha256", deployment)
            })),
            "artifacts": {"signed.exe": self.artifact},
            "builds": {role: write(self.bundle / (role + ".json"), encode(record)) for role, record in self.builds.items()},
        }
        data = encode(manifest)
        self.manifest_sha = write(self.bundle / "manifest.json", data)
        for role in ROLES:
            signature = subprocess.check_output(
                ["ssh-keygen", "-Y", "sign", "-f", str(self.key_dir / role), "-n", NAMESPACE],
                input=data, stderr=subprocess.DEVNULL,
            )
            write(self.bundle / "signatures" / (role + ".sig"), signature)

    def check(self):
        return verify(self.bundle, self.policy, COMMIT, self.manifest_sha)

    def test_approved_bundle_emits_exact_configuration_bytes(self):
        self.seal()
        self.assertEqual(self.check(), encode(self.deployment))
        result = subprocess.run(
            [sys.executable, "-B", str(VERIFIER), "--bundle", str(self.bundle), "--trust-policy", str(self.policy),
             "--commit", COMMIT, "--manifest-sha256", self.manifest_sha, "--emit-compose"],
            check=True, capture_output=True,
        )
        self.assertEqual(result.stdout, encode(self.deployment))

    def test_wrong_signature_and_duplicate_identity_are_rejected(self):
        self.seal()
        wrong = self.bundle / "signatures/source-review.sig"
        write(self.bundle / "signatures/release.sig", wrong.read_bytes())
        with self.assertRaisesRegex(Rejected, "Invalid manifest signature for release"):
            self.check()
        self.trust["keys"]["builder-b"] = self.keys["builder-a"]
        write(self.policy, encode(self.trust))
        with self.assertRaisesRegex(Rejected, "distinct pinned"):
            self.check()

    def test_deploy_calls_docker_only_after_verification(self):
        self.seal()
        bin_path = self.policy.parent / "bin"
        bin_path.mkdir()
        docker = bin_path / "docker"
        docker.write_text(
            "#!/bin/sh\n"
            'test "$COMPOSE_DISABLE_ENV_FILE" = 1 && test -z "$COMPOSE_FILE" || exit 87\n'
            'printf "%s\\n" "$@" > "$OUT_ARGS"\n'
            'cat > "$OUT_PLAN"\n'
        )
        docker.chmod(0o700)
        plan, arguments = self.policy.parent / "emitted.json", self.policy.parent / "args"
        environment = {
            **os.environ, "PATH": f"{bin_path}:{os.environ['PATH']}", "COMPOSE_FILE": "ignored.yaml",
            "OUT_PLAN": str(plan), "OUT_ARGS": str(arguments),
        }
        command = [
            sys.executable, "-B", str(VERIFIER), "--bundle", str(self.bundle), "--trust-policy", str(self.policy),
            "--commit", COMMIT, "--manifest-sha256", self.manifest_sha, "--deploy",
        ]
        (self.bundle / "signatures/release.sig").unlink()
        rejected = subprocess.run(command, env=environment, capture_output=True)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertFalse(plan.exists())
        self.seal()
        subprocess.run(command, env=environment, check=True, capture_output=True)
        self.assertEqual(plan.read_bytes(), encode(self.deployment))
        self.assertIn("--no-build\n--pull\nalways\n", arguments.read_text())

    def test_unreviewed_source_is_rejected(self):
        self.review["approver_ids"] = [17, 18]
        self.seal()
        with self.assertRaisesRegex(Rejected, "two distinct non-author"):
            self.check()
        self.review["approver_ids"] = [18, 19]
        self.review["verified_signatures"] = False
        self.seal()
        with self.assertRaisesRegex(Rejected, "selected signed merge"):
            self.check()

    def test_mismatched_builds_are_rejected(self):
        self.builds["builder-b"]["payloads"]["windows.exe"] = "f" * 64
        self.seal()
        with self.assertRaisesRegex(Rejected, "identical payload"):
            self.check()

    def test_wrong_image_is_rejected_even_when_all_roles_signed(self):
        self.deployment["services"]["api"]["image"] = "registry.example/ada@sha256:" + "f" * 64
        self.seal()
        with self.assertRaisesRegex(Rejected, "exact verified OCI digest"):
            self.check()

    def test_tampering_with_signed_bytes_is_rejected(self):
        self.seal()
        write(self.bundle / "artifacts/signed.exe", b"other artifact")
        with self.assertRaisesRegex(Rejected, "Signed artifact mismatch"):
            self.check()
        self.seal()
        write(self.bundle / "artifacts/signed.exe", b"signed windows distribution")
        write(self.bundle / "deployment.json", b"{}")
        with self.assertRaisesRegex(Rejected, "configuration digest mismatch"):
            self.check()

    def test_missing_failed_or_stale_test_evidence_is_rejected(self):
        self.results["cases"]["windows-native-signature"] = "skipped"
        self.seal()
        with self.assertRaisesRegex(Rejected, "required tests must pass"):
            self.check()
        self.results["cases"]["windows-native-signature"] = "pass"
        self.results["deployment_sha256"] = "e" * 64
        self.seal()
        with self.assertRaisesRegex(Rejected, "exact build and deployment"):
            self.check()


class GitHubReviewTests(unittest.TestCase):
    def provider(self, *, reviewed_head=HEAD, signed=True, app_id=APP):
        def get(endpoint, *, paginate=False):
            if endpoint.endswith("/rules/branches/main"):
                return ruleset(APP)["rules"]
            if endpoint.endswith("/pulls/3"):
                return {
                    "number": 3, "merged": True, "merge_commit_sha": COMMIT, "commits": 1,
                    "base": {"ref": "main", "repo": {"full_name": REPOSITORY}}, "head": {"sha": HEAD},
                    "user": {"id": 17},
                }
            if endpoint.endswith("/commits/" + COMMIT):
                return {"sha": COMMIT, "commit": {"verification": {"verified": signed}},
                        "parents": [{"sha": "3" * 40}, {"sha": HEAD}]}
            self.assertTrue(paginate)
            if "/pulls/3/commits?" in endpoint:
                return [[{"sha": HEAD, "commit": {"verification": {"verified": True}}}]]
            if "/pulls/3/reviews?" in endpoint:
                return [[
                    {"state": "APPROVED", "commit_id": digest, "user": {"id": actor}, "author_association": "MEMBER"}
                    for actor, digest in ((17, HEAD), (18, HEAD), (19, reviewed_head))
                ]]
            self.assertIn("/check-runs?", endpoint)
            return [{"check_runs": [{
                "head_sha": HEAD, "name": REQUIRED_CHECK, "app": {"id": app_id},
                "status": "completed", "conclusion": "success",
            }]}]

        return get

    def test_requires_verified_merge_two_current_approvals_and_app_check(self):
        record = collect(self.provider(), REPOSITORY, REF, 3, COMMIT, APP)
        self.assertEqual(record["approver_ids"], [18, 19])
        for settings, reason in (
            ({"reviewed_head": "9" * 40}, "two distinct non-author"),
            ({"signed": False}, "verified merge"),
            ({"app_id": APP + 1}, "Required check"),
        ):
            with self.subTest(settings=settings), self.assertRaisesRegex(Rejected, reason):
                collect(self.provider(**settings), REPOSITORY, REF, 3, COMMIT, APP)


if __name__ == "__main__":
    unittest.main()
