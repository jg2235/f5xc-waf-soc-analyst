# API Discovery / ML Endpoints — bodies and shapes

Entitlement: Advanced WAAP / API Security add-on. All [T] items are confirmed per-tenant
by `smoke_test.py`; if it FAILs with 403/404, check licensing before assuming path drift.

## Endpoint inventory [T]

POST /api/ml/data/namespaces/{ns}/virtual_hosts/{vh}/api_endpoints
Body: {"namespace": "<ns>"}  (some releases accept time bounds)

Response items (per endpoint) commonly include:
- collapsed_url    e.g. /api/users/DYN  (path params collapsed to DYN)
- method
- request/response schema summaries (learned params, types)
- authentication state (authenticated / unauthenticated / mixed)
- sensitive_data[] categories detected
- risk_score, pii_score fields (release-dependent naming)
- traffic counters (req rate, last seen)

## Per-endpoint drilldown [T]

Same base with an endpoint selector in the body (collapsed_url + method) — returns full
learned schema: parameter names, locations (query/body/header), types, example ranges.
Use for schema-drift diffs against the team's OpenAPI file.

## Learned OpenAPI spec export [T]

Console: LB -> API Endpoints -> download spec. The REST path for programmatic export has
moved across releases; if smoke_test can't find it, generate the spec locally instead:
build OpenAPI 3.0 JSON from the inventory + drilldown responses (paths -> methods ->
parameters). Deterministic and version-controlled — arguably better for the DaC-style
workflow anyway.

## Config-side objects (read + change scripts)

- LB spec: enable_api_discovery {discovered_api_settings {purge_duration_for_inactive_discovered_apis}}
- LB spec: api_specification {api_definition ref, validation_all_spec_endpoints |
  validation_custom_list {...}, fall_through_mode {allow|report|block-ish oneof}}
- api_definitions object: holds swagger_specs[] refs to uploaded spec files (stored as
  swagger objects in the namespace)
- LB spec: api_protection_rules {api_endpoint_rules[], api_groups_rules[]} with per-rule
  action allow/deny and client matchers
- LB spec: api_rate_limit {api_endpoint_rules[]: {api_endpoint_path, api_endpoint_method,
  rate_limiter}}

Exact oneof names vary slightly by release — always GET a live LB with
?response_format=2 and mirror the shapes you see rather than trusting docs from memory.

## Sensitive-data / events correlation

api_sec_event records carry the endpoint, violation (schema mismatch class), and
recommended_action. NOTE: `API_ENDPOINT` and `CALCULATED_ACTION` are BOTH rejected by
the event agg enum — aggregate by `URI` instead, and read `recommended_action` by
sampling raw events. The report-mode measurement query:

  {sec_event_type="api_sec_event", vh_name="ves-io-http-loadbalancer-<lb>"}
  aggs: URI topk 50   (then sample raw events for recommended_action)

Endpoints with high would-be-block counts before enforcement = spec gaps to fix first.
