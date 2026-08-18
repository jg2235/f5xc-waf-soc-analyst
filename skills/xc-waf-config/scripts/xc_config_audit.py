#!/usr/bin/env python3
"""
xc_config_audit.py -- read-only WAF posture audit across namespaces.

Usage:
    python3 xc_config_audit.py [--ns prod --ns staging] [--json findings.json]

Implements references/audit-checklist.md. Read-only; emits a markdown table and
optional JSON findings for run-over-run trending.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "xc-security-events" / "scripts"))
from xc_client import XCClient, obj_name  # noqa: E402


def audit_lb(ns: str, lb: dict) -> list[dict]:
    f: list[dict] = []
    name = obj_name(lb)
    spec = lb.get("spec") or lb.get("get_spec") or {}

    def add(grade, check, detail=""):
        f.append({"ns": ns, "lb": name, "grade": grade, "check": check, "detail": detail})

    if "disable_waf" in spec or not any(k in spec for k in ("app_firewall",)):
        add("HIGH", "no app_firewall attached")
    excl = spec.get("waf_exclusion_rules", []) or []
    for r in excl:
        rspec = r.get("spec", r)
        rname = (r.get("metadata") or {}).get("name", "?")
        if "waf_skip_processing" in rspec:
            add("HIGH", "waf_skip_processing exclusion", rname)
        dc = rspec.get("app_firewall_detection_control", {})
        for s in dc.get("exclude_signature_contexts", []):
            if s.get("signature_id", 1) == 0 and s.get("context") in (None, "CONTEXT_ANY"):
                add("HIGH", "bypass-equivalent exclusion (sig 0 + CONTEXT_ANY)", rname)
    if len(excl) > 25:
        add("MED", f"exclusion count {len(excl)} > 25 (tuning debt)")
    if spec.get("trusted_clients"):
        add("MED", f"trusted_clients present ({len(spec['trusted_clients'])})")
    for bc in spec.get("blocked_clients", []) or []:
        if not bc.get("expiration_timestamp"):
            add("LOW", "blocked client without expiry",
                (bc.get("metadata") or {}).get("name") or bc.get("ip_prefix", "?"))
    if "disable_rate_limit" in spec or not any(k in spec for k in ("rate_limit", "api_rate_limit")):
        add("LOW", "no rate limiting configured")
    if "enable_api_discovery" not in spec:
        add("INFO", "API discovery not enabled")
    if "enable_malicious_user_detection" not in spec:
        add("LOW", "malicious-user detection not enabled")
    if "bot_defense" not in spec:
        add("INFO", "bot defense not configured")
    return f


def audit_fw(ns: str, fw: dict) -> list[dict]:
    f: list[dict] = []
    name = obj_name(fw)
    spec = fw.get("spec") or fw.get("get_spec") or {}
    if "monitoring" in spec:
        f.append({"ns": ns, "lb": f"fw:{name}", "grade": "MED",
                  "check": "app_firewall in monitoring mode", "detail": ""})
    return f


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ns", action="append", default=[])
    ap.add_argument("--json", default=None)
    a = ap.parse_args()
    c = XCClient()
    namespaces = a.ns or [n for n in c.namespaces() if n not in ("system", "shared", "ves-io-shared")]

    findings: list[dict] = []
    for ns in namespaces:
        try:
            # LIST items carry metadata:null and NO spec -- GET each object fully.
            for lb_item in c.http_lbs(ns):
                lname = obj_name(lb_item)
                lb = c.get(f"/api/config/namespaces/{ns}/http_loadbalancers/{lname}")
                lb.setdefault("name", lname)
                findings += audit_lb(ns, lb)
            for fw_item in c.get(f"/api/config/namespaces/{ns}/app_firewalls").get("items", []):
                fname = obj_name(fw_item)
                fw = c.get(f"/api/config/namespaces/{ns}/app_firewalls/{fname}")
                fw.setdefault("name", fname)
                findings += audit_fw(ns, fw)
        except Exception as e:  # noqa: BLE001
            findings.append({"ns": ns, "lb": "-", "grade": "INFO",
                             "check": "namespace audit error", "detail": str(e)[:120]})

    order = {"HIGH": 0, "MED": 1, "LOW": 2, "INFO": 3}
    findings.sort(key=lambda x: (order.get(x["grade"], 9), x["ns"], x["lb"]))
    print("| Grade | NS | LB | Check | Detail |\n|---|---|---|---|---|")
    for x in findings:
        print(f"| {x['grade']} | {x['ns']} | {x['lb']} | {x['check']} | {x['detail']} |")
    print(f"\nTotal: {len(findings)} findings "
          f"({sum(1 for x in findings if x['grade']=='HIGH')} HIGH)")
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(findings, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
