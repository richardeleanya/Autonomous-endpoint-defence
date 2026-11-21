#!/usr/bin/env python3
"""Collect post-merge source evidence with an authenticated read-only GitHub App."""

import argparse
import json
import re
import subprocess
from urllib.parse import quote

from verify_candidate import COMMIT, REQUIRED_CHECK, Rejected, require, verify_review


REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def github_get(endpoint, *, paginate=False):
    command = ["gh", "api", "--method", "GET", "-H", "X-GitHub-Api-Version: 2022-11-28"]
    if paginate:
        command += ["--paginate", "--slurp"]
    return json.loads(subprocess.check_output([*command, endpoint], timeout=60))


def active_rules(get, base, branch, app_id):
    rules = get(f"{base}/rules/branches/{quote(branch, safe='')}")
    types = {rule["type"] for rule in rules}
    require({"deletion", "non_fast_forward", "required_signatures"} <= types, "Required branch protections are inactive")
    require(
        any(
            rule["type"] == "pull_request"
            and rule["parameters"]["required_approving_review_count"] >= 2
            and rule["parameters"]["dismiss_stale_reviews_on_push"] is True
            and rule["parameters"]["require_code_owner_review"] is True
            and rule["parameters"]["require_last_push_approval"] is True
            and rule["parameters"]["required_review_thread_resolution"] is True
            for rule in rules
        ),
        "Required PR review rules are inactive",
    )
    require(
        any(
            rule["type"] == "required_status_checks"
            and rule["parameters"]["strict_required_status_checks_policy"] is True
            and {"context": REQUIRED_CHECK, "integration_id": app_id} in rule["parameters"]["required_status_checks"]
            for rule in rules
        ),
        "Required status check is inactive or bound to a different GitHub App",
    )


def collect(get, repository, ref, pull_request, commit, app_id):
    require(REPOSITORY.fullmatch(repository) and COMMIT.fullmatch(commit), "Invalid repository or target commit")
    require(ref == "refs/heads/main" or ref.startswith("refs/heads/release/"), "Select a protected ref")
    require(type(pull_request) is int and pull_request > 0 and type(app_id) is int and app_id > 0, "Invalid PR or App ID")
    base, branch = f"repos/{repository}", ref.removeprefix("refs/heads/")
    active_rules(get, base, branch, app_id)
    pr_path = f"{base}/pulls/{pull_request}"
    pr = get(pr_path)
    require(
        pr["number"] == pull_request and pr["merged"] is True and pr["merge_commit_sha"] == commit
        and pr["base"]["ref"] == branch and pr["base"]["repo"]["full_name"].lower() == repository.lower(),
        "PR must have merged the selected commit to the protected repository and ref",
    )
    head = pr["head"]["sha"]
    require(isinstance(head, str) and COMMIT.fullmatch(head), "Invalid reviewed PR head")
    merged = get(f"{base}/commits/{commit}")
    require(
        merged["sha"] == commit and merged["commit"]["verification"]["verified"] is True
        and len(merged["parents"]) == 2 and merged["parents"][1]["sha"] == head,
        "Selected commit must be a verified merge of the reviewed PR head",
    )
    commits = [item for page in get(f"{pr_path}/commits?per_page=100", paginate=True) for item in page]
    require(
        len(commits) == pr["commits"] and commits and commits[-1]["sha"] == head
        and all(item["commit"]["verification"]["verified"] is True for item in commits),
        "Every commit on the reviewed PR must have a verified signature",
    )
    latest = {}
    for page in get(f"{pr_path}/reviews?per_page=100", paginate=True):
        for review in page:
            if review["state"] in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
                latest[review["user"]["id"]] = review
    approvers = sorted(
        identifier for identifier, review in latest.items()
        if review["state"] == "APPROVED" and review["commit_id"] == head
        and review["author_association"] in ("OWNER", "MEMBER", "COLLABORATOR")
        and identifier != pr["user"]["id"]
    )
    checks_path = f"{base}/commits/{head}/check-runs?check_name={quote(REQUIRED_CHECK, safe='')}&filter=latest&per_page=100"
    checks = [
        item for page in get(checks_path, paginate=True) for item in page["check_runs"]
        if item["name"] == REQUIRED_CHECK and item.get("app") and item["app"]["id"] == app_id
    ]
    require(
        len(checks) == 1 and checks[0]["head_sha"] == head and checks[0]["status"] == "completed"
        and checks[0]["conclusion"] == "success",
        "Required check on the reviewed SHA is missing, ambiguous, or failed",
    )
    record = {
        "repository": repository, "ref": ref, "commit": commit, "pull_request": pull_request, "head": head,
        "author_id": pr["user"]["id"], "approver_ids": approvers, "verified_signatures": True,
        "required_check": REQUIRED_CHECK, "check_app_id": app_id, "check_head": head, "check_state": "success",
    }
    verify_review(record, {"repository": repository, "ref": ref, "check_app_id": app_id}, commit)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--pull-request", type=int, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--status-app-id", type=int, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(
            collect(github_get, args.repository, args.ref, args.pull_request, args.commit, args.status_app_id),
            sort_keys=True, indent=2,
        ))
    except (Rejected, KeyError, TypeError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Source evidence rejected: {error}\n")


if __name__ == "__main__":
    main()
