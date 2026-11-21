#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || ! -x "$1/ada-agent-linux-amd64" ]]; then
  echo "Usage: $0 NATIVE_BUILD_DIRECTORY" >&2
  exit 2
fi
umask 077
export ADA_NATIVE_DIR
ADA_NATIVE_DIR=$(realpath -e -- "$1")
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
export ADA_CONFIG_DIR ADA_RUNTIME_UID COMPOSE_PROFILES ADA_WHEELHOUSE ADA_API_HOSTNAME
ADA_CONFIG_DIR=$(mktemp -d)
ADA_RUNTIME_UID=$(id -u)
COMPOSE_PROFILES=qualification
ADA_API_HOSTNAME=api
trap 'rm -rf -- "$ADA_CONFIG_DIR"' EXIT
ADA_WHEELHOUSE="$ADA_CONFIG_DIR/wheels"
python3 -m pip download --only-binary=:all: --require-hashes \
  -r "$repo/product/control_plane/requirements.txt" --dest "$ADA_WHEELHOUSE"
python3 -B - "$repo" <<'PY'
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path
from uuid import uuid4

directory = Path(os.environ["ADA_CONFIG_DIR"])
clients = {"tenants": []}
configuration = {"tenants": {}, "support": {}}
sys.path.insert(0, str(Path(sys.argv[1]) / "release"))
from verify_customer_approval import NAMESPACE, ROLES, verify

trust = {}
for role in ROLES:
    identity = directory / role
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(identity)], check=True)
    trust[role] = " ".join(identity.with_suffix(".pub").read_text().split()[:2])
trust_path = directory / "approval-trust.json"
trust_path.write_text(json.dumps(trust))

for _ in range(3):
    tenant, subject = str(uuid4()), str(uuid4())
    operator = secrets.token_hex(32)
    clients["tenants"].append({"id": tenant, "subject": subject, "token": operator})
    bundle = directory / tenant
    (bundle / "signatures").mkdir(parents=True)
    document = json.dumps({
        "version": 1, "tenant": tenant, "mode": "observe-only", "expires_at": int(time.time()) + 3600,
        "contract_ref": "LAB-CONTRACT", "privacy_ref": "LAB-DPIA",
        "customer_authorisation_ref": "LAB-OBSERVE-ONLY", "retention_days": 30,
    }).encode()
    (bundle / "approval.json").write_bytes(document)
    for role in ROLES:
        signature = subprocess.check_output(
            ["ssh-keygen", "-Y", "sign", "-f", str(directory / role), "-n", NAMESPACE],
            input=document, stderr=subprocess.DEVNULL,
        )
        (bundle / "signatures" / (role + ".sig")).write_bytes(signature)
    approval = verify(bundle, trust_path, tenant)
    (bundle / "approval.json").write_bytes(document.replace(b"LAB-DPIA", b"BYPASSED"))
    try:
        verify(bundle, trust_path, tenant)
    except ValueError:
        pass
    else:
        raise RuntimeError("Tampered approval unexpectedly passed")
    (bundle / "approval.json").write_bytes(document)
    configuration["tenants"][tenant] = {
        "approved_activation": approval,
        "backup_key": secrets.token_hex(32),
        "operators": {subject: hashlib.sha256(operator.encode()).hexdigest()},
    }

support, subject = secrets.token_hex(32), str(uuid4())
clients["support"] = {"subject": subject, "token": support}
configuration["support"][subject] = hashlib.sha256(support.encode()).hexdigest()

operator, subject = secrets.token_hex(32), str(uuid4())
clients["customer_operations"] = {"subject": subject, "token": operator}
configuration["customer_operations"] = {subject: hashlib.sha256(operator.encode()).hexdigest()}

operator, subject = secrets.token_hex(32), str(uuid4())
clients["privacy_operations"] = {"subject": subject, "token": operator}
configuration["privacy_operations"] = {subject: hashlib.sha256(operator.encode()).hexdigest()}
for role in ROLES:
    (directory / role).unlink()
print("PASS independent lab Privacy, Legal and customer signatures; tampering rejected")

for file, document in (("tenants.json", configuration), ("clients.json", clients)):
    (directory / file).write_text(json.dumps(document), encoding="utf-8")
PY
openssl req -x509 -newkey rsa:2048 -noenc -days 2 -subj '/CN=ADA qualification CA' \
  -keyout "$ADA_CONFIG_DIR/ca.key" -out "$ADA_CONFIG_DIR/ca.crt" > "$ADA_CONFIG_DIR/openssl.log" 2>&1
openssl req -new -newkey rsa:2048 -noenc -subj '/CN=api' \
  -keyout "$ADA_CONFIG_DIR/tls.key" -out "$ADA_CONFIG_DIR/api.csr" >> "$ADA_CONFIG_DIR/openssl.log" 2>&1
printf 'subjectAltName=DNS:api\nextendedKeyUsage=serverAuth\n' > "$ADA_CONFIG_DIR/api.ext"
openssl x509 -req -in "$ADA_CONFIG_DIR/api.csr" -CA "$ADA_CONFIG_DIR/ca.crt" \
  -CAkey "$ADA_CONFIG_DIR/ca.key" -CAcreateserial -days 2 -extfile "$ADA_CONFIG_DIR/api.ext" \
  -out "$ADA_CONFIG_DIR/tls.crt" >> "$ADA_CONFIG_DIR/openssl.log" 2>&1
rm -- "$ADA_CONFIG_DIR/ca.key"
printf 'Linux agent SHA-256 '
sha256sum -- "$ADA_NATIVE_DIR/ada-agent-linux-amd64"
"$repo/scripts/docker-release-check.sh" integration "$repo/deploy/compose.yaml" api worker
