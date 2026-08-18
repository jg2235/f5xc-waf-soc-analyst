#!/usr/bin/env python3
"""
xc_client.py -- shared F5 Distributed Cloud API client for f5xc-waf-skills.

Security posture:
  * Credentials from env vars only (F5XC_TENANT, F5XC_API_TOKEN). Never accepts a
    token as an argument; never logs headers or token material.
  * Read-only by default: POST is permitted only to known read/query endpoints
    unless the caller passes allow_write=True (used only by generated change
    scripts after human review, with --apply).

Performance:
  * One pooled requests.Session per process.
  * 429/5xx retry with exponential backoff + jitter, honoring Retry-After.
  * Batch aggregations; scroll helper for paged event pulls.
"""
from __future__ import annotations

import json
import os
import random
import sys
import time
from typing import Any, Dict, Iterator, List, Optional

import requests

READ_POST_PREFIXES = (
    "/api/data/",        # events, access logs, metrics
    "/api/ml/data/",     # API discovery, malicious users, suspicious traffic
)

MAX_RETRIES = 5
BACKOFF_BASE = 1.0
BACKOFF_CAP = 32.0
TIMEOUT = (10, 120)  # connect, read


class XCClient:
    def __init__(self, tenant: Optional[str] = None, allow_write: bool = False):
        self.tenant = tenant or os.environ.get("F5XC_TENANT")
        token = os.environ.get("F5XC_API_TOKEN")
        if not self.tenant or not token:
            sys.exit("ERROR: set F5XC_TENANT and F5XC_API_TOKEN environment variables.")
        # Tenant consoles resolve at console.ves.volterra.io; F5XC_API_URL overrides
        # entirely (e.g. staging or region-specific endpoints).
        self.base = os.environ.get(
            "F5XC_API_URL", f"https://{self.tenant}.console.ves.volterra.io"
        ).rstrip("/")
        self.allow_write = allow_write
        self.s = requests.Session()
        self.s.headers.update(
            {"Authorization": f"APIToken {token}", "Content-Type": "application/json"}
        )
        self._inventory_cache: Dict[str, Any] = {}

    # ---------------- core request with retry ----------------
    def _request(self, method: str, path: str, **kw) -> requests.Response:
        if method in ("POST", "PUT", "DELETE", "PATCH") and not self.allow_write:
            if method != "POST" or not path.startswith(READ_POST_PREFIXES):
                raise PermissionError(
                    f"Write blocked (read-only client): {method} {path}. "
                    "Generated change scripts must construct XCClient(allow_write=True) "
                    "and be run with --apply."
                )
        for attempt in range(MAX_RETRIES + 1):
            r = self.s.request(method, self.base + path, timeout=TIMEOUT, **kw)
            if r.status_code == 429 or r.status_code >= 500:
                if attempt == MAX_RETRIES:
                    break
                retry_after = r.headers.get("Retry-After")
                delay = (
                    float(retry_after)
                    if retry_after and retry_after.isdigit()
                    else min(BACKOFF_CAP, BACKOFF_BASE * 2 ** attempt)
                )
                time.sleep(delay + random.uniform(0, 0.5))
                continue
            return r
        return r

    def get(self, path: str, **kw) -> Dict[str, Any]:
        r = self._request("GET", path, **kw)
        r.raise_for_status()
        return r.json()

    def post(self, path: str, body: Dict[str, Any], **kw) -> Dict[str, Any]:
        r = self._request("POST", path, json=body, **kw)
        if r.status_code == 400:
            # Surface the validation message -- it names bad agg fields / query syntax.
            raise ValueError(f"400 from {path}: {r.text[:800]}")
        r.raise_for_status()
        return r.json()

    # ---------------- inventory (cached) ----------------
    def namespaces(self) -> List[str]:
        if "ns" not in self._inventory_cache:
            items = self.get("/api/web/namespaces").get("items", [])
            self._inventory_cache["ns"] = [i["name"] for i in items]
        return self._inventory_cache["ns"]

    def http_lbs(self, ns: str) -> List[Dict[str, Any]]:
        key = f"lb:{ns}"
        if key not in self._inventory_cache:
            items = self.get(f"/api/config/namespaces/{ns}/http_loadbalancers").get(
                "items", []
            )
            self._inventory_cache[key] = items
        return self._inventory_cache[key]

    # ---------------- security events ----------------
    def sec_events(
        self,
        ns: str,
        query: str,
        start: str,
        end: str,
        aggs: Optional[Dict[str, Any]] = None,
        scroll: bool = False,
        all_ns: bool = False,
    ) -> Dict[str, Any]:
        path = (
            "/api/data/namespaces/system/app_security/all_ns_events"
            if all_ns
            else f"/api/data/namespaces/{ns}/app_security/events"
        )
        body: Dict[str, Any] = {
            "namespace": "system" if all_ns else ns,
            "query": query,
            "scroll": scroll,
            "start_time": start,
            "end_time": end,
        }
        if aggs:
            body["aggs"] = aggs
        return self.post(path, body)

    def sec_events_iter(
        self, ns: str, query: str, start: str, end: str, max_events: int = 5000
    ) -> Iterator[Dict[str, Any]]:
        """Scroll through raw events, yielding parsed records. Hard cap max_events."""
        resp = self.sec_events(ns, query, start, end, scroll=True)
        yielded = 0
        while True:
            for ev in resp.get("events", []):
                # events arrive as stringified JSON
                yield json.loads(ev) if isinstance(ev, str) else ev
                yielded += 1
                if yielded >= max_events:
                    return
            sid = resp.get("scroll_id")
            if not sid:
                return
            resp = self.post(
                f"/api/data/namespaces/{ns}/app_security/events/scroll",
                {"namespace": ns, "scroll_id": sid},
            )


def obj_name(item: Dict[str, Any]) -> str:
    """Name of an XC object regardless of endpoint shape.

    LIST endpoints return {"name": "...", "metadata": null}; GET (esp. with
    ?response_format=2) populates metadata.name. `"metadata" in item` being True
    while the value is None is the trap -- use this helper everywhere.
    """
    return item.get("name") or (item.get("metadata") or {}).get("name") or "?"


def iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def window(hours: float):
    now = time.time()
    return iso(now - hours * 3600), iso(now)
