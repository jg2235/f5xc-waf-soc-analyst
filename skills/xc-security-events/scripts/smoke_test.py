#!/usr/bin/env python3
"""
smoke_test.py -- validate every read endpoint the f5xc-waf-skills plugin uses
against a live tenant. Run ONCE after install:

    export F5XC_TENANT=... F5XC_API_TOKEN=...
    python3 smoke_test.py [--ns <namespace>] [--dump-sample]

Prints PASS/FAIL per endpoint. Items marked [T] in the reference docs are the ones
whose exact path/field can drift between XC releases -- this script is how you
confirm them. All calls are read-only.
"""
from __future__ import annotations

import argparse
import json
import sys

from xc_client import XCClient, window


def check(label, fn):
    try:
        out = fn()
        print(f"PASS  {label}")
        return out
    except Exception as e:  # noqa: BLE001 -- report and continue
        print(f"FAIL  {label}: {type(e).__name__}: {str(e)[:200]}")
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ns", default=None)
    ap.add_argument("--dump-sample", action="store_true")
    a = ap.parse_args()
    c = XCClient()
    start, end = window(24)

    ns_list = check("GET /api/web/namespaces", c.namespaces) or []
    ns = a.ns or (ns_list[0] if ns_list else "default")
    print(f"      using namespace: {ns}")

    check(f"LIST app_firewalls ({ns})",
          lambda: c.get(f"/api/config/namespaces/{ns}/app_firewalls"))
    check(f"LIST service_policys ({ns})",
          lambda: c.get(f"/api/config/namespaces/{ns}/service_policys"))

    ev = check("POST app_security/events (aggs)",
               lambda: c.sec_events(ns, '{sec_event_type="waf_sec_event"}', start, end,
                                    aggs={"t": {"field_aggregation": {"field": "SRC_IP", "topk": 5}}}))
    check("POST app_security/all_ns_events",
          lambda: c.sec_events("system", '{sec_event_type=~".*"}', start, end,
                               aggs={"t": {"field_aggregation": {"field": "SEC_EVENT_TYPE", "topk": 10}}},
                               all_ns=True))
    check("POST access_logs",
          lambda: c.post(f"/api/data/namespaces/{ns}/access_logs",
                         {"namespace": ns, "query": "{}", "scroll": False,
                          "start_time": start, "end_time": end}))

    # ML endpoints -- a 404 has three possible causes; distinguish them:
    #   (a) feature not enabled on the LB  -> SKIP, with the enable hint
    #   (b) feature enabled, still 404     -> genuine path drift OR entitlement gap
    #   (c) no LBs at all                  -> nothing to probe
    from xc_client import obj_name
    lbs = check(f"LIST http_loadbalancers ({ns})", lambda: c.http_lbs(ns)) or []
    for lb_item in lbs:
        lb = obj_name(lb_item)
        # LIST items carry metadata:null and no spec -- GET the object for its config.
        full = check(f"GET http_loadbalancer {lb}",
                     lambda: c.get(f"/api/config/namespaces/{ns}/http_loadbalancers/{lb}"))
        spec = ((full or {}).get("spec")) or {}
        vh = f"ves-io-http-loadbalancer-{lb}"

        if "enable_api_discovery" not in spec:
            print(f"SKIP  ML api_endpoints ({lb}): enable_api_discovery not set on LB")
        else:
            check(f"ML api_endpoints ({lb}) [T -- feature IS enabled; 404 = path drift/entitlement]",
                  lambda: c.post(f"/api/ml/data/namespaces/{ns}/virtual_hosts/{vh}/api_endpoints",
                                 {"namespace": ns}))

        if "enable_malicious_user_detection" not in spec:
            print(f"SKIP  ML malicious_users ({lb}): enable_malicious_user_detection not set on LB")
        else:
            check(f"ML malicious_users ({lb}) [T -- feature IS enabled; 404 = path drift/entitlement]",
                  lambda: c.post(f"/api/ml/data/namespaces/{ns}/virtual_hosts/{vh}/malicious_users",
                                 {"namespace": ns, "start_time": start, "end_time": end}))

    if a.dump_sample and ev:
        for e in c.sec_events_iter(ns, '{sec_event_type="waf_sec_event"}', start, end, max_events=1):
            print("\n# sample event record (field-name ground truth):")
            print(json.dumps(e, indent=2)[:6000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
