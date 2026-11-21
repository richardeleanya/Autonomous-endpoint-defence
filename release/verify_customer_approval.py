"""Verify independent customer, Privacy and Legal signatures before activation."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from uuid import UUID

from verify_candidate import decode, object_fields, plain_file, read_meta, require, verify_signatures


ROLES = ("privacy", "legal", "customer")
NAMESPACE = "ada-customer-approval-v1"
REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def verify(bundle, trust, tenant):
    require(str(UUID(tenant)) == tenant, "Invalid tenant UUID")
    require(not trust.is_relative_to(bundle), "Trust policy must be outside the document bundle")
    keys = decode(read_meta(trust))
    raw = read_meta(plain_file(bundle, "approval.json"))
    verify_signatures(bundle, raw, keys, roles=ROLES, namespace=NAMESPACE)
    record = decode(raw)
    object_fields(record, {
        "version", "tenant", "mode", "contract_ref", "privacy_ref", "customer_authorisation_ref",
        "retention_days", "expires_at",
    }, "customer approval")
    require(
        type(record["version"]) is int and record["version"] == 1 and record["tenant"] == tenant
        and record["mode"] == "observe-only",
        "Approval must apply to this tenant and observe-only service",
    )
    for field in ("contract_ref", "privacy_ref", "customer_authorisation_ref"):
        require(isinstance(record[field], str) and REFERENCE.fullmatch(record[field]), f"Invalid {field}")
    require(
        type(record["retention_days"]) is int and 1 <= record["retention_days"] <= 3650
        and type(record["expires_at"]) is int and int(time.time()) < record["expires_at"] < 2**63,
        "Approval must have a finite retention policy and current validity",
    )
    return {**record, "approval_sha256": hashlib.sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--trust-policy", type=Path, required=True)
    parser.add_argument("--tenant", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.bundle.resolve(strict=True), args.trust_policy.resolve(strict=True), args.tenant)))
    except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.SubprocessError) as error:
        print(f"Customer approval rejected: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
