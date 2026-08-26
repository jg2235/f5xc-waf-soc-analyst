---
name: xc-security-events
author: Jeff Granieri <jgranieri22@outlook.com>
description: >-
  Query, hunt, and aggregate F5 Distributed Cloud (XC) security events and access logs. Use
  any time the user wants to search, count, triage, or hunt WAF security events, bot events,
  API security events, service-policy events, malicious-user events, or L7 access logs on an
  F5 XC tenant. Trigger on: "security events", "WAF events", "sec events", "who is attacking",
  "top attackers", "top signatures", "blocked requests", "support ID", "req_id", "access
  logs", "attack traffic", "event query", "hunt", or any question answerable from XC
  app_security telemetry ("show me SQLi attempts on the prod LB last 24h", "which IPs tripped
  the most signatures this week"). Uses the app_security events API with label-filter query
  syntax and server-side aggregations. NOT for config changes (xc-waf-config) or full
  investigations with verdicts (xc-waf-investigator).
---

# F5 XC Security Events

The XC data plane emits per-request **security events** (WAF, bot, API, service policy,
malicious user, IP reputation) and **access logs**. This skill is the query primitive: it
writes correct, efficient event queries, runs them read-only, and returns aggregated or
sampled results.

Compatibility: pairs with the `f5xc-api` skill (object model, CRUD patterns, boilerplate).
Credentials: `F5XC_TENANT`, `F5XC_API_TOKEN` env vars — never inline tokens.

## Workflow

1. **Scope first — namespace scope is mandatory and explicit.** Every query runs against
   one namespace, or an explicit list the user supplied. There is no implicit default and
   no implicit tenant-wide sweep. Resolve scope in this order:
   1. namespace(s) named in the request;
   2. `$F5XC_NAMESPACES` (comma-separated) as the user's standing scope;
   3. otherwise **ask** which namespace(s) to use — do not guess, and do not substitute a
      tenant-wide query for an unanswered scope question.

   Tenant-wide (`--all-ns` / `all_ns_events`) is opt-in only, when the user explicitly asks
   to look across the whole tenant. On a shared tenant it is mostly other tenants' users'
   traffic, and it buries the namespaces the user actually owns. When you do run it, say so
   and report which namespaces the hits came from.

   Then fix the time window (default 24h; never default to 30d) and, if the user names an
   app, resolve LB name → virtual-host label (`ves-io-http-loadbalancer-<lb-name>`) via the
   session inventory cache.
2. **Aggregate before you sample.** Answer count/top-N questions entirely with server-side
   `aggs`. Pull raw events only to show evidence (small `limit`, specific filter).
3. **Run it.** Use `scripts/xc_events.py` (canonical runner) or generate an equivalent
   snippet from `scripts/xc_client.py`. Read-only endpoints only.
4. **Iterate on errors.** 400 = malformed query string or agg field (check
   `references/event-schema.md` field names); empty result is a legitimate finding — check
   window and vh_name label before loosening the filter.
5. **Explain briefly**, cite the fields relied on, and keep the exact query for the report
   appendix.

## Endpoints (read-only)

| Purpose | Endpoint |
|---|---|
| Events, one namespace | `POST /api/data/namespaces/{ns}/app_security/events` |
| Events, all namespaces | `POST /api/data/namespaces/system/app_security/all_ns_events` |
| Event aggregations only | same endpoints — supply `aggs`, set `scroll:false` |
| Access logs | `POST /api/data/namespaces/{ns}/access_logs` |
| Access log aggregation | `POST /api/data/namespaces/{ns}/access_logs/aggregation` |
| Scroll continuation | `POST .../app_security/events/scroll` with `scroll_id` |

Request body shape:

```json
{
  "namespace": "prod",
  "query": "{sec_event_type=\"waf_sec_event\", vh_name=\"ves-io-http-loadbalancer-prod-web\"}",
  "aggs": {
    "top_signatures": {"field_aggregation": {"field": "SIGNATURE_ID", "topk": 20}}
  },
  "scroll": false,
  "start_time": "2026-08-16T00:00:00Z",
  "end_time": "2026-08-17T00:00:00Z"
}
```

## Query syntax (label filter DSL)

`{key="value", key2=~"regex", key3!="value"}` — comma = AND. Common keys:

| Key | Values / notes |
|---|---|
| `sec_event_type` | `waf_sec_event`, `bot_defense_sec_event`, `api_sec_event`, `svc_policy_sec_event`, `malicious_user_sec_event`, `ip_reputation_sec_event` |
| `vh_name` | `ves-io-http-loadbalancer-<lb>` — omit for all LBs in the namespace |
| `src_ip` | source IP |
| `signatures.id` | numeric WAF signature — **dotted nested key**. `signature_id=` is NOT valid and returns **0 hits silently instead of an error**; it will read as "this signature never fired". Aggregation uses `SIGNATURE_ID`; only the *filter* key is dotted. |
| `sec_event_name` | e.g. `waf-signature-triggered`, `policy-blocked` |
| `action` | `block`, `report` (report = monitoring mode hit) |
| `req_path` / `method` / `rsp_code` | request attributes; `=~` regex supported |
| `country` / `asn` | GeoIP attributes |

Full field list, agg-field names (upper-snake, e.g. `SRC_IP`, `SIGNATURE_ID`,
`ATTACK_TYPE`, `URI`, `VH_NAME`, `COUNTRY`, `ACTION`, `SEC_EVENT_TYPE`), and event
record anatomy: `references/event-schema.md`. Endpoint bodies, scroll paging, date-math,
and confirmed gotchas: `references/event-query-api.md`.

## Standard hunt patterns

- **Top attackers**: aggs on `SRC_IP` topk 20, filter `action="block"`. Follow with per-IP
  `ATTACK_TYPE` agg to profile each.
- **Signature noise ranking** (tuning feed): aggs `SIGNATURE_ID` topk 50 over 7d, then per
  top signature (filter `{signatures.id="<id>"}`) aggs on `URI` + `SRC_IP` — a signature
  firing on one path from many IPs smells like FP; one IP across many paths smells like an
  attack.
- **Monitoring-mode preview**: filter `action="report"` on a staging LB to see what
  blocking mode WOULD block before flipping enforcement.
- **Campaign detection**: same `signatures.id`+`req_path` across multiple `vh_name` values
  via `all_ns_events`.
- **Infrastructure clustering**: aggs on `JA4_TLS_FINGERPRINT` per source. An exact JA4
  match across different ASNs is the strongest link available and survives IP rotation.
- **Support-ID lookup**: user pastes a blocking-page support ID → filter on it (see
  `references/event-query-api.md` for the field and truncation gotcha) → retrieve the full
  event record.

## Performance rules

- One aggregation request beats a thousand raw events. `topk` caps at 1000; use 10–50.
- Scroll for raw pulls > 500 events; hard-stop and ask before pulling > 50k raw events.
- Long windows: parallel time slices (e.g. 7×24h) with a shared `Session`, merge locally.
- Back off on 429: exponential + jitter, max 5 retries (built into `xc_client.py`).
- Cache namespace/LB inventory once per session.
- Multiple namespaces = one request per namespace, run in parallel and labelled per
  namespace in the output. Do NOT collapse them into a tenant-wide sweep and filter
  client-side: that reads every namespace to answer a question about a few.

## Scripts

- `scripts/xc_client.py` — auth session, retry/backoff, GET/POST helpers. Import, don't copy.
- `scripts/xc_events.py` — CLI: `--ns ns1[,ns2,...]` (or `$F5XC_NAMESPACES`), `--query`,
  `--agg FIELD:K`, `--hours`, `--sample N`. Prints agg tables or JSONL samples, labelled
  per namespace. Refuses to run with no scope; `--all-ns` additionally requires
  `--confirm-all-ns`.
- `scripts/smoke_test.py` — validates every endpoint this plugin uses against the live
  tenant; run once after install (see plugin README).
