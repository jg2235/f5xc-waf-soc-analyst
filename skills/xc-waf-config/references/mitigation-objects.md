# Mitigation Objects — spec fragments for generated change scripts

All fragments mutate the http_loadbalancer spec or referenced objects. Change scripts must
follow the read-modify-write contract in SKILL.md.

## Blocked clients (fastest single-source mitigation)

`spec.blocked_clients[]` on the LB:

```json
{
  "metadata": {"name": "blk-203-0-113-7"},
  "ip_prefix": "203.0.113.7/32",
  "expiration_timestamp": "2026-08-24T00:00:00Z",
  "actions": []
}
```

Matchers: `ip_prefix` | `as_number` | `http_header` (name + regex value) | `user_identifier`.
Always set `expiration_timestamp` for incident blocks (default the script to +7d); permanent
blocks belong in a service policy where they're reviewable as policy.
`trusted_clients[]` is the same shape and SKIPS WAF/bot processing — audit it as risk.

## Service policy (reviewable, ordered policy)

Object: `service_policys` (note spelling). Attach via LB
`spec.active_service_policies.policies[]` ref list; LB default is
`service_policies_from_namespace` (namespace-level policy set).

```json
{
  "metadata": {"name": "deny-known-bad", "namespace": "prod"},
  "spec": {
    "algo": "FIRST_MATCH",
    "any_server": {},
    "rule_list": {
      "rules": [
        {
          "metadata": {"name": "deny-scanner-asns"},
          "spec": {
            "action": "DENY",
            "asn_list": {"as_numbers": [64496]},
            "any_client": {},
            "waf_action": {"none": {}}
          }
        },
        {
          "metadata": {"name": "geo-block"},
          "spec": {"action": "DENY", "country_list": ["COUNTRY_XX"], "any_client": {}}
        }
      ]
    }
  }
}
```

Rule match dimensions: ip_prefix_list / ip_matcher, asn, country_list, tls fingerprint,
http path/method/headers/args/cookies, client name/label. `FIRST_MATCH` ordering — put
narrow ALLOW carve-outs before broad DENY.

## Rate limiting

LB `spec.rate_limit`:

```json
{
  "rate_limiter": {"total_number": 100, "unit": "MINUTE", "burst_multiplier": 2},
  "no_ip_allowed_list": {},
  "no_policies": {}
}
```

Per-API rate limits: `spec.api_rate_limit.api_endpoint_rules[]` with per-endpoint
`rate_limiter` — pair with API discovery output (`xc-api-security`) to rate-limit the
actual endpoint inventory.

## Malicious-user detection & mitigation

LB toggles: `spec.enable_malicious_user_detection: {}` (oneof vs
`disable_malicious_user_detection`), plus optional `user_id_client_ip` or cookie/header
user identifier for per-user (not per-IP) tracking.

Mitigation object `malicious_user_mitigations` maps ML threat levels to actions:

```json
{
  "spec": {
    "rules": [
      {"threat_level": {"low": {}},    "mitigation_action": {"alert": {}}},
      {"threat_level": {"medium": {}}, "mitigation_action": {"javascript_challenge": {"js_script_delay": 5000}}},
      {"threat_level": {"high": {}},   "mitigation_action": {"block_temporarily": {}}}
    ]
  }
}
```

Attach on LB via `spec.enable_challenge` / malicious-user-mitigation ref. Verify the
attach-point field name against your tenant's `views.http_loadbalancer` swagger [T] — it
has moved across releases (`malicious_user_mitigation` ref vs policy-based challenge).

## App firewall enforcement flip

`app_firewalls/{name}` spec oneof: `blocking: {}` vs `monitoring: {}`. The flip script
must (a) print the last-7d `recommended_action=block` summary from `xc-waf-tuning` staging
analysis, (b) require `--apply --acknowledge-staging-reviewed`.

## Roll-back

Every change script's diff output doubles as the rollback record. Scripts also write the
pre-change object JSON to `changes/backups/<name>_<ts>.json` before any `--apply` PUT, and
support `--rollback <backup-file>` (PUT of the backup with fresh resource_version).
