# WAF Exclusion Rules — grammar and scoping doctrine

Exclusion rules are entries in `spec.waf_exclusion_rules[]` on the **http_loadbalancer**
object. Each rule = match criteria (when) + exclusion action (what to skip).

## Rule shape

```json
{
  "metadata": {"name": "excl-login-sig-200002147"},
  "spec": {
    "any_domain": {},                      // or "exact_value": "app.example.com" / "suffix_value"
    "path_regex": "^/api/login$",          // or "path_prefix" / exact path via regex anchor
    "methods": ["POST"],                   // omit = any method
    "app_firewall_detection_control": {
      "exclude_signature_contexts": [
        {
          "signature_id": 200002147,       // 0 = all signatures (avoid)
          "context": "CONTEXT_PARAMETER",  // CONTEXT_ANY | CONTEXT_HEADER | CONTEXT_PARAMETER | CONTEXT_URL | CONTEXT_COOKIE | CONTEXT_BODY
          "context_name": "redirect_url"   // the specific param/header/cookie name
        }
      ],
      "exclude_attack_type_contexts": [
        {"exclude_attack_type": "ATTACK_TYPE_SQL_INJECTION", "context": "CONTEXT_PARAMETER", "context_name": "q"}
      ],
      "exclude_violation_contexts": [
        {"exclude_violation": "VIOL_HTTP_PROTOCOL", "context": "CONTEXT_ANY"}
      ]
    }
  }
}
```

Alternative action: `"waf_skip_processing": {}` — full WAF bypass for matched traffic.

## Scoping doctrine (narrowest wins)

Preference order when converting an FP finding into a rule:

1. `signature_id` + specific `context` + `context_name` + exact path + method — surgical.
2. `signature_id` + context, path-scoped.
3. attack-type context exclusion, path-scoped — only when many sibling signatures FP on
   the same field (document why).
4. violation context exclusion — protocol-violation FPs (nonstandard clients), path-scoped.
5. `waf_skip_processing` — LAST RESORT; requires explicit user acceptance of full bypass,
   and the summary must state the residual risk in one sentence.

Never emit `signature_id: 0` (all signatures) combined with `CONTEXT_ANY` — that is
skip-processing with extra steps.

## Evidence-to-rule mapping

From a sampled event's `signatures[]` entry:

| Event field | Rule field |
|---|---|
| `signatures[].id` | `signature_id` |
| `signatures[].context` (`parameter`/`header`/`uri`/`cookie`) | `context` (map to `CONTEXT_*`) |
| `signatures[].matching_info` / detection context name | `context_name` |
| event `req_path` | `path_regex` (anchor it: `^...$`) |
| event `method` | `methods` |
| event `domain` | domain matcher (use `any_domain` only for single-domain LBs) |

## Ordering & interaction

- Rules are evaluated per request against match criteria; keep the list short and audited —
  every rule is attack surface. The audit script flags rules with no matching `report`
  events in 30d as candidates for removal (stale exclusions).
- Exclusions apply to the LB's attached app_firewall processing; route-level
  `app_firewall` overrides (per-route WAF in `routes[]`) still honor LB-level exclusions —
  verify per release with a monitoring-mode test if a route override is present.

## App firewall vs exclusion

Turning a signature off tenant-wide belongs in the app_firewall's detection settings
(signature selection), not in per-LB exclusions. Rule of thumb: FP on one app/path →
LB exclusion rule; FP everywhere from a broken signature for your stack → app_firewall
signature setting; either way record signature accuracy (`high`/`medium`/`low`) from the
event — low-accuracy signatures FP by design and are the first candidates.
