#!/usr/bin/env python3
"""
change_script_template.py -- TEMPLATE for all generated F5 XC change scripts.

Contract (see xc-waf-config SKILL.md):
  dry-run default -> unified diff -> --apply with resource_version -> backup -> rollback.

Claude: copy this file to changes/<ns>_<object>_<date>_<slug>.py, fill mutate(),
OBJECT_PATH, and DESCRIPTION. Do not weaken the safety rails.
"""
from __future__ import annotations

import argparse
import copy
import difflib
import json
import os
import pathlib
import sys
import time

# Shared client lives in the xc-security-events skill.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "xc-security-events" / "scripts"))
from xc_client import XCClient  # noqa: E402

# ----------------------------------------------------------------------------
DESCRIPTION = "EDIT ME: one line describing the change and the evidence behind it."
NAMESPACE = os.environ.get("F5XC_NAMESPACE", "EDIT-ME")
OBJECT_PATH = f"/api/config/namespaces/{NAMESPACE}/http_loadbalancers/EDIT-ME"
# ----------------------------------------------------------------------------


def mutate(spec: dict) -> dict:
    """Apply the change to the spec. Must be idempotent."""
    # EXAMPLE: append a narrowly-scoped exclusion rule if not already present.
    # rule = {...}
    # rules = spec.setdefault("waf_exclusion_rules", [])
    # if not any(r.get("metadata", {}).get("name") == rule["metadata"]["name"] for r in rules):
    #     rules.append(rule)
    raise NotImplementedError("fill in mutate()")


def diff(a: dict, b: dict) -> str:
    return "".join(
        difflib.unified_diff(
            json.dumps(a, indent=2, sort_keys=True).splitlines(keepends=True),
            json.dumps(b, indent=2, sort_keys=True).splitlines(keepends=True),
            fromfile="current", tofile="proposed",
        )
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=DESCRIPTION)
    ap.add_argument("--apply", action="store_true", help="perform the PUT (default: dry run)")
    ap.add_argument("--rollback", metavar="BACKUP_JSON", help="restore a pre-change backup")
    a = ap.parse_args()

    c = XCClient(allow_write=a.apply or bool(a.rollback))

    if a.rollback:
        backup = json.loads(pathlib.Path(a.rollback).read_text())
        cur = c.get(OBJECT_PATH + "?response_format=2")
        body = {"metadata": backup["metadata"], "spec": backup["spec"],
                "resource_version": cur["resource_version"]}
        r = c._request("PUT", OBJECT_PATH, json=body)
        r.raise_for_status()
        print(f"ROLLED BACK from {a.rollback}")
        return 0

    obj = c.get(OBJECT_PATH + "?response_format=2")
    current = obj["replace_form"]
    proposed = copy.deepcopy(current)
    proposed["spec"] = mutate(copy.deepcopy(current["spec"]))

    d = diff(current["spec"], proposed["spec"])
    if not d:
        print("NO-OP: change already applied.")
        return 0
    print(f"# {DESCRIPTION}\n# target: {OBJECT_PATH}\n")
    print(d)

    if not a.apply:
        print("\nDRY RUN. Re-run with --apply to push.")
        return 0

    bdir = pathlib.Path("changes/backups"); bdir.mkdir(parents=True, exist_ok=True)
    bfile = bdir / f"{OBJECT_PATH.rsplit('/',1)[-1]}_{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
    bfile.write_text(json.dumps(current, indent=2))
    print(f"backup: {bfile}")

    body = {"metadata": proposed["metadata"], "spec": proposed["spec"],
            "resource_version": obj["resource_version"]}
    r = c._request("PUT", OBJECT_PATH, json=body)
    if r.status_code == 409:
        print("409 conflict: object changed since read. Re-run to re-diff. NOT retrying blindly.")
        return 1
    r.raise_for_status()
    print("APPLIED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
