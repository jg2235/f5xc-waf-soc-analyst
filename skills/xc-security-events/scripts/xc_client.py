#!/usr/bin/env python3
"""
xc_client.py -- shared F5 Distributed Cloud API client for f5xc-waf-skills.

Security posture:
  * Never accepts a token as an argument; never logs headers or token material.
  * Token resolution, in order of preference:
      1. $F5XC_TOKEN_CMD -- a shell command that prints the token on stdout. This is
         the recommended enterprise path: the secret lives in a vault / secret
         manager / OS keyring and never lands in a file or in shell history. e.g.
             export F5XC_TOKEN_CMD='vault read -field=token secret/f5xc/readonly'
             export F5XC_TOKEN_CMD='op read op://infra/f5xc/api-token'
             export F5XC_TOKEN_CMD='aws secretsmanager get-secret-value --secret-id f5xc --query SecretString --output text'
             export F5XC_TOKEN_CMD='secret-tool lookup service f5xc'
      2. $F5XC_API_TOKEN -- direct env var. Acceptable for CI with a masked
         secret; discouraged on shared or long-lived workstations.
    A token is never read from a path this client is told about, and the resolved
    value is held in memory only.
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
import shlex
import subprocess
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


def _resolve_token() -> str:
    """Resolve the API token without ever touching a plaintext file we manage."""
    cmd = os.environ.get("F5XC_TOKEN_CMD")
    if cmd:
        try:
            out = subprocess.run(shlex.split(cmd), capture_output=True, text=True,
                                 timeout=30, check=True)
        except FileNotFoundError:
            sys.exit("ERROR: F5XC_TOKEN_CMD executable not found. Check the command.")
        except subprocess.TimeoutExpired:
            sys.exit("ERROR: F5XC_TOKEN_CMD timed out after 30s.")
        except subprocess.CalledProcessError as e:
            # stderr may carry vault/1password diagnostics but never the secret itself.
            sys.exit(f"ERROR: F5XC_TOKEN_CMD failed (exit {e.returncode}): "
                     f"{(e.stderr or '').strip()[:200]}")
        token = out.stdout.strip()
        if not token:
            sys.exit("ERROR: F5XC_TOKEN_CMD produced no output.")
        return token

    token = os.environ.get("F5XC_API_TOKEN", "").strip()
    if not token:
        sys.exit(
            "ERROR: no API token. Set F5XC_TOKEN_CMD to a command that prints the "
            "token (preferred -- keeps the secret in your vault/keyring), or set "
            "F5XC_API_TOKEN directly. See docs/credentials.md."
        )
    return token


class XCClient:
    def __init__(self, tenant: Optional[str] = None, allow_write: bool = False):
        self.tenant = tenant or os.environ.get("F5XC_TENANT")
        if not self.tenant and not os.environ.get("F5XC_API_URL"):
            sys.exit(
                "ERROR: set F5XC_TENANT (the label in your console URL, "
                "https://<tenant>.console.ves.volterra.io) or F5XC_API_URL."
            )
        token = _resolve_token()
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
