# Event Query API — request anatomy, paging, gotchas

Verification status: endpoints marked [V] match the public `app_security` swagger
(`docs-cloud-f5-com...app_security.ves-swagger.json`) and the f5xc-api skill's schema set.
Items marked [T] should be confirmed once with `scripts/smoke_test.py` against your tenant
(minor field-name drift exists across XC releases).

## Endpoints

[V] `POST /api/data/namespaces/{namespace}/app_security/events`
[V] `POST /api/data/namespaces/system/app_security/all_ns_events`
[V] `POST /api/data/namespaces/{namespace}/app_security/events/scroll` — body `{"namespace": ns, "scroll_id": "<id>"}`
[V] `POST /api/data/namespaces/{namespace}/access_logs`
[T] `POST /api/data/namespaces/{namespace}/access_logs/aggregation`
[V] `POST /api/data/namespaces/{namespace}/app_security/events/aggregation` — aggs-only variant; the plain events endpoint also accepts `aggs`.

## Request body

```json
{
  "namespace": "prod",
  "query": "{sec_event_type=\"waf_sec_event\"}",
  "aggs": {
    "<label>": {"field_aggregation": {"field": "SRC_IP", "topk": 20}},
    "<label2>": {"date_aggregation": {"step": "1h"}}
  },
  "scroll": true,
  "start_time": "2026-08-16T00:00:00Z",
  "end_time": "2026-08-17T00:00:00Z"
}
```

- `start_time`/`end_time`: RFC3339 UTC. Both required for deterministic results; without
  them the server applies a default window — never rely on it.
- `scroll:true` returns `scroll_id` when more pages exist; keep POSTing to the scroll
  endpoint until `scroll_id` is empty. Scroll IDs expire (~minutes) — consume promptly.
- Response events arrive as **stringified JSON inside the `events[]` array** — each element
  needs `json.loads()`. This is the #1 parsing surprise. `xc_client.py` handles it.
- `total_hits` in the response gives the match count without pulling all rows — use it for
  counts instead of paging.

## Aggregation types

| Agg | Shape | Notes |
|---|---|---|
| `field_aggregation` | `{"field": "SRC_IP", "topk": 20}` | top-N distinct values with counts; field names are UPPER_SNAKE |
| `date_aggregation` | `{"step": "1h"}` (no `field`; units s/m/h only — `1d` is rejected, use `24h`) | time histogram; combine with a field agg as `date_field_aggregation` [T] for per-bucket top-N |
| `metric_aggregation` [T] | count/cardinality style | prefer `total_hits` for plain counts |

Multiple aggs per request are allowed and cheaper than N requests — batch them.

## Query DSL notes

- Operators: `=` exact, `!=` negate, `=~` RE2 regex, `!~` negated regex.
- Values always double-quoted; the whole expression wrapped in `{}`.
- No OR across keys. OR within one key: regex alternation `{src_ip=~"1.2.3.4|5.6.7.8"}`.
- `vh_name` for an HTTP LB is `ves-io-http-loadbalancer-<metadata.name>`. TCP LBs:
  `ves-io-tcp-loadbalancer-<name>`. Get exact values from a `VH_NAME` agg if unsure —
  don't guess.

## Support ID gotcha

The blocking page shows a long numeric support ID. The event field carrying it is
`req_id` on some releases and a dedicated support-id field on others [T], and consoles
have historically matched on the **trailing digits**. Reliable method: filter the time
window to ±5 min of the block, agg nothing, filter `{action="block"}`, pull raw events,
and match the trailing 10+ digits of the pasted ID against event IDs locally.
`xc_events.py --support-id <id>` implements exactly this.

## Access logs vs security events

Security events exist only for requests that tripped a security feature. For "all traffic
to path X" questions (baselines, FP denominator rates), use access logs. Access-log query
uses the same label DSL with keys like `method`, `req_path`, `rsp_code`, `vh_name`.

## Rate limits

Data-plane query APIs are rate limited per tenant (429 + `Retry-After`). The client's
backoff honors the header; if absent, exponential 1s→32s with jitter. Do not parallelize
more than 4 concurrent slices.
