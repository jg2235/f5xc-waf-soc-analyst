# WAF Posture Audit Checklist

Run via `scripts/xc_config_audit.py`. Findings graded HIGH / MED / LOW / INFO.

## Per-LB checks

| Check | Grade if failed |
|---|---|
| app_firewall attached (`disable_waf` not set) | HIGH — unprotected LB |
| app_firewall in `blocking` (prod namespaces) | MED — monitoring-only in prod |
| `waf_skip_processing` exclusion present | HIGH — full bypass path exists |
| Exclusion with `signature_id: 0` + `CONTEXT_ANY` | HIGH — bypass-equivalent |
| Exclusion count > 25 | MED — tuning debt; likely stale rules |
| `trusted_clients[]` non-empty | MED — WAF-skipping allowlist; verify each entry |
| Blocked client without `expiration_timestamp` | LOW — should be service policy |
| No rate limit and no API rate limit | LOW (MED for auth/login paths) |
| API discovery off on an API-serving LB | MED |
| Malicious-user detection off | LOW (MED for authenticated apps) |
| Bot defense absent on login/checkout paths | MED |
| `https` without `http_redirect` / HSTS | LOW |
| Default cert or `no_mtls` where mTLS expected | context-dependent |

## Per-app_firewall checks

- Detection setting = default vs custom; custom with low-accuracy signatures disabled is
  GOOD (note it); everything-off custom is HIGH.
- Threat campaigns disabled → MED (cheap high-fidelity signal).
- `allowed_response_codes` unusually broad → INFO.

## Cross-object checks

- Same app_firewall shared by prod and staging LBs → INFO (tuning coupling).
- Service policy rule shadowing: DENY after broad ALLOW in FIRST_MATCH → MED.
- Namespace with `service_policies_from_namespace` but zero namespace policies → INFO.
- Exclusion rules with zero matching events in 30d (needs xc-security-events join) →
  LOW stale-exclusion candidates list.

Output: markdown table per namespace + JSON findings file for trending run-over-run.
