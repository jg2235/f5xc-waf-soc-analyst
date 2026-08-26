#!/usr/bin/env python3
"""
xc_events.py -- CLI runner for F5 XC security-event queries.

Examples:
  # Top 20 blocked source IPs, prod namespace, last 24h
  ./xc_events.py --ns prod --query '{sec_event_type="waf_sec_event", action="block"}' \
      --agg SRC_IP:20 --hours 24

  # Several namespaces at once (comma-separated); results are labelled per namespace
  ./xc_events.py --ns prod,staging,payments --query '{sec_event_type="waf_sec_event"}' \
      --agg SIGNATURE_ID:50 --agg VH_NAME:20 --hours 168

  # Default scope can come from the environment instead of --ns
  export F5XC_NAMESPACES=prod,staging
  ./xc_events.py --query '{sec_event_type="waf_sec_event"}' --agg SRC_IP:20

  # Tenant-wide sweeps are opt-in and must be acknowledged explicitly
  ./xc_events.py --all-ns --confirm-all-ns --query '{sec_event_type="waf_sec_event"}' \
      --agg SIGNATURE_ID:50 --hours 168

  # Sample 25 raw events for evidence on one signature+path
  ./xc_events.py --ns prod --query '{signatures.id="200002147", req_path="/api/login"}' \
      --sample 25 --hours 24

  # Support-ID lookup (trailing-digit match within +/- window)
  ./xc_events.py --ns prod --support-id 17423986100987654321 --hours 2
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from xc_client import XCClient, window


def _resolve_namespaces(a, ap) -> list:
    """Scope is always explicit: --ns, $F5XC_NAMESPACES, or an acknowledged --all-ns."""
    if a.all_ns:
        return ["system"]
    raw = a.ns or os.environ.get("F5XC_NAMESPACES", "")
    namespaces = [n.strip() for n in raw.split(",") if n.strip()]
    if not namespaces:
        ap.error(
            "no namespace scope. Pass --ns <namespace>[,<namespace>...], set "
            "F5XC_NAMESPACES, or use --all-ns --confirm-all-ns for a tenant-wide sweep."
        )
    return namespaces


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ns", default=None,
                    help="namespace, or comma-separated list (e.g. prod,staging). "
                         "Defaults to $F5XC_NAMESPACES.")
    ap.add_argument("--all-ns", action="store_true",
                    help="tenant-wide sweep across every namespace; requires --confirm-all-ns")
    ap.add_argument("--confirm-all-ns", action="store_true",
                    help="acknowledge that --all-ns reads every namespace in the tenant")
    ap.add_argument("--query", default='{sec_event_type="waf_sec_event"}')
    ap.add_argument("--agg", action="append", default=[], metavar="FIELD:K",
                    help="server-side field aggregation, repeatable")
    ap.add_argument("--hours", type=float, default=24.0)
    ap.add_argument("--sample", type=int, default=0, help="pull N raw events (evidence sampling)")
    ap.add_argument("--support-id", default=None)
    ap.add_argument("--json", action="store_true", help="raw JSON output")
    a = ap.parse_args()

    if a.all_ns and not a.confirm_all_ns:
        ap.error(
            "--all-ns reads every namespace in the tenant, which on a shared tenant is "
            "mostly other people's traffic. Re-run with --confirm-all-ns if that is really "
            "what you want, or scope the query with --ns <namespace>[,<namespace>...]."
        )

    namespaces = _resolve_namespaces(a, ap)
    start, end = window(a.hours)
    c = XCClient()

    if a.support_id:
        tail = a.support_id[-10:]
        for ns in namespaces:
            hits = [e for e in c.sec_events_iter(ns, '{action="block"}', start, end, max_events=5000)
                    if tail in json.dumps(e)]
            print(f"# [{ns}] support-id tail match '{tail}': {len(hits)} event(s)")
            for e in hits[:5]:
                print(json.dumps(e, indent=2)[:4000])
        return 0

    aggs = {}
    for spec in a.agg:
        field, _, k = spec.partition(":")
        aggs[f"top_{field.lower()}"] = {"field_aggregation": {"field": field, "topk": int(k or 10)}}

    results = {}
    for ns in namespaces:
        results[ns] = c.sec_events(ns, a.query, start, end, aggs=aggs or None,
                                   scroll=bool(a.sample), all_ns=a.all_ns)

    if a.json:
        print(json.dumps(results if len(results) > 1 else next(iter(results.values())), indent=2))
        return 0

    print(f"# window {start} .. {end}  query {a.query}")
    print(f"# scope: {', '.join(namespaces)}")
    for ns, resp in results.items():
        print(f"\n{'=' * 60}\n# namespace: {ns}")
        print(f"# total_hits: {resp.get('total_hits', 'n/a')}")
        for name, agg in (resp.get("aggs") or {}).items():
            print(f"\n## {name}")
            buckets = agg.get("field_aggregation", {}).get("buckets", []) or agg.get("buckets", [])
            for b in buckets:
                print(f"  {str(b.get('key')):<45} {b.get('count', b.get('doc_count', ''))}")
        if a.sample:
            print(f"\n## sample (max {a.sample})")
            for ev in c.sec_events_iter(ns, a.query, start, end, max_events=a.sample):
                print(json.dumps(ev)[:2000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
