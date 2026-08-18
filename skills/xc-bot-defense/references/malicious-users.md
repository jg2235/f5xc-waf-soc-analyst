# Malicious User Detection — signals, scoring, configuration

## User identity

Scoring is per "user", where user = one of (LB spec oneof):
- client IP (default) — WARNING: corporate NAT / CGNAT aggregates many humans into one
  scored identity; a single abuser can get an office challenged. Note this in every
  per-IP-scoring review.
- cookie name — score per session/user cookie value.
- HTTP header — score per header value (e.g. authenticated user id header).

## Contributing signals (per-user, rolling window)

- WAF security-event rate (signature hits attributable to the user)
- Forbidden-access attempts (401/403 rates, denied paths)
- Error-rate anomalies (4xx/5xx patterns vs app baseline)
- Access-pattern anomalies (scan-like breadth, unusual sequencing/rate)
- IP-reputation and bot signals when present

The ML combines these into threat level LOW / MEDIUM / HIGH. Levels are relative to the
app's learned baseline, not absolute thresholds — a noisy app raises the bar.

## Mitigation mapping

malicious_user_mitigations object: rules[] of {threat_level -> mitigation_action}:
  alert {} | javascript_challenge {js_script_delay} | captcha_challenge {} |
  block_temporarily {} (persistent block escalation is release-dependent [T])

Sane starting map: low->alert, medium->JS challenge, high->temporary block. Never map
low->block.

## ML read endpoints [T]

POST /api/ml/data/namespaces/{ns}/virtual_hosts/{vh}/malicious_users
  body {namespace, start_time, end_time} -> user list w/ threat level + signal breakdown
Suspicious-traffic / per-user timeline variants exist under the same /api/ml/data prefix;
smoke_test.py probes and prints what your tenant exposes. 403/404 = check Advanced WAAP
entitlement first.

## Event correlation

malicious_user_sec_event fires on mitigation actions (challenged/blocked). Join key:
src_ip or the configured identifier. For a user under review, pull:
1. their malicious_user events (what mitigation fired, when)
2. their waf_sec_events (what raised the score)
3. their access-log slice (what they were actually doing)
Present as a single timeline — that is the reviewable evidence packet.

## Bot Defense config surface (for coverage diffs)

LB spec bot_defense: {regional_endpoint, policy {protected_app_endpoints[]:
  {metadata.name, path {prefix|path}, http_methods[], mitigation {continue|redirect|block},
   flow_label (e.g. login/signup categories)}, js_insert_all_pages | js_insertion_rules},
  timeout}
Protected-endpoint coverage should include: login, token issuance, password reset, signup,
checkout/payment, gift-card/points redemption, search (scraping), any promo-code endpoint.
