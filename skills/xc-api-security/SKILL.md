---
name: xc-api-security
author: Jeff Granieri <jgranieri22@outlook.com>
description: >-
  F5 Distributed Cloud API Security: ML-driven API discovery, shadow-API detection, schema
  learning, OpenAPI validation posture, sensitive-data findings, and per-endpoint
  protection. Use when the user asks about: "API discovery", "discovered endpoints",
  "shadow APIs", "undocumented endpoints", "API inventory", "OpenAPI validation", "schema
  validation", "swagger enforcement", "API protection rules", "sensitive data in APIs",
  "PII in API responses", "API rate limiting per endpoint", or wants to compare discovered
  traffic against a spec, generate an OpenAPI spec from discovery, or roll out validation
  enforcement. This is the AI-powered-WAF surface: discovery and risk scoring are ML-driven
  server-side. Read-only; enforcement changes are emitted as change scripts via
  xc-waf-config's contract.
---

# F5 XC API Security (AI-powered discovery & enforcement)

XC's ML pipeline learns each LB's API surface from live traffic: endpoint inventory,
schemas (parameters, types), auth posture, sensitive-data detection, and risk scores. This
skill reads that intelligence and drives the discovery → spec → validation → enforcement
lifecycle.

## Prerequisite

`enable_api_discovery` must be set on the LB (with `discovered_api_settings` as desired).
If it's off, say so and offer the enable change script — do not fabricate discovery data.

## Read operations

| Task | Endpoint |
|---|---|
| Discovered endpoint inventory | `POST /api/ml/data/namespaces/{ns}/virtual_hosts/{vh}/api_endpoints` [T] |
| Per-endpoint detail (schema, PII, auth) | `POST .../api_endpoints/{collapsed_url}` or detail body param [T] |
| Downloadable learned OpenAPI spec | console export; API path is release-dependent [T] — smoke-test confirms |
| API security events | `xc-security-events` with `{sec_event_type="api_sec_event"}` |

`vh` = `ves-io-http-loadbalancer-<lb-name>`. ML endpoints are entitlement-gated (Advanced
WAAP / API Security); a 404/403 usually means licensing, not a wrong path — check
`smoke_test.py` output first. Endpoint bodies and response shapes:
`references/api-discovery-endpoints.md`.

## Analysis playbooks

**Shadow API detection** — the highest-value question. Inputs: discovered inventory +
the app team's published OpenAPI spec (ask for the file). Diff:
- In traffic, not in spec → **shadow endpoints** (rank by risk score, auth status,
  sensitive-data flags, request volume).
- In spec, not in traffic → zombie/unused endpoints (attack surface with no owner
  watching).
- In both but schema drift (new params in traffic) → spec staleness.
Output a three-section table with per-endpoint evidence and volumes.

**Sensitive-data exposure** — enumerate endpoints flagged for PII/PCI patterns
(card numbers, SSNs, emails) in responses; cross-join with auth posture: unauthenticated +
sensitive = HIGH finding. FSI framing: map to PCI-DSS 6.6 / GLBA safeguards when the user
is presenting to a bank.

**Validation posture** — read LB `api_specification` / OpenAPI validation config:
`validation_all_spec_endpoints` vs `validation_custom_list` vs disabled; fall-through
setting (what happens to non-spec traffic: allow / report / block). Report the enforcement
gaps.

## Enforcement lifecycle (scripts only, never direct)

1. **Learn**: discovery enabled ≥ 2 weeks of representative traffic.
2. **Spec**: export/settle the OpenAPI spec (learned or team-provided); store in repo.
3. **Report mode**: change script sets validation with fall-through `report` — measure
   would-be blocks via `api_sec_event` + `recommended_action` (record field only —
   sample raw events; it is not aggregatable, and `calculated_action` does not exist).
4. **Enforce**: after a clean report window, script flips fall-through to `block`
   (custom rules can stage endpoint-by-endpoint).
5. **Protect**: per-endpoint `api_protection_rules` (deny lists, per-endpoint rate limits
   via `api_rate_limit.api_endpoint_rules[]`) generated from the discovered inventory.

Each step's change script follows the `xc-waf-config` contract (dry-run, diff,
resource_version, backup). The full staged rollout is packaged as a solution:
`xc-waf-solutions/references/api-protection.md`.
