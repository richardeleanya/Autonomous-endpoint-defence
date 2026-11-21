#!/usr/bin/env python3
"""Render the GitHub ruleset for the approved external PR checker."""

import argparse
import json


def ruleset(app_id):
    if type(app_id) is not int or app_id <= 0:
        raise ValueError("An installed GitHub App ID is required")
    return {
        "name": "ADA protected release branches",
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {
            "ref_name": {"include": ["refs/heads/main", "refs/heads/release/*", "refs/heads/release/**/*"], "exclude": []}
        },
        "rules": [
            {"type": "deletion"},
            {"type": "non_fast_forward"},
            {"type": "required_signatures"},
            {"type": "pull_request", "parameters": {
                "required_approving_review_count": 2,
                "dismiss_stale_reviews_on_push": True,
                "require_code_owner_review": True,
                "require_last_push_approval": True,
                "required_review_thread_resolution": True,
                "allowed_merge_methods": ["merge"],
            }},
            {"type": "required_status_checks", "parameters": {
                "strict_required_status_checks_policy": True,
                "do_not_enforce_on_create": False,
                "required_status_checks": [{"context": "ada/pr-verify", "integration_id": app_id}],
            }},
        ],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status-app-id", required=True, type=int)
    args = parser.parse_args()
    try:
        print(json.dumps(ruleset(args.status_app_id), indent=2))
    except ValueError as error:
        parser.error(str(error))
