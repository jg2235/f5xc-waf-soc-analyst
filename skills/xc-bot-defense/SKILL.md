---
name: xc-bot-defense
author: Jeff Granieri <jgranieri22@outlook.com>
description: >-
  F5 Distributed Cloud Bot Defense and Malicious User (UEBA-style) analysis. Use when the
  user asks about: "bot traffic", "bot defense", "automation detection", "credential
  stuffing", "account takeover", "ATO", "scraping", "carding", "malicious users",
  "suspicious users", "user threat level", "JS challenge", "captcha challenge", "client
  fingerprint", "JA3", or wants to analyze bot classifications, review malicious-user ML
  scores, tune challenge/mitigation actions, or protect specific endpoints (login,
  checkout, gift-card) from automation. Covers both signature/behavior bot events and the
  per-user ML threat scoring that makes this the AI-powered-WAF behavioral layer.
  Read-only; mitigation changes go out as change scripts.
---

# F5 XC Bot Defense & Malicious Users

Two distinct AI systems — keep them straight:

1. **Bot Defense** (`bot_defense` on the LB): client-side signal collection (JS/mobile
   SDK) + F5 backend classification per protected endpoint. Verdicts: human / good bot /
   malicious bot / suspicious automation. Config selects protected endpoints and per-verdict
   mitigation (continue/redirect/block).
2. **Malicious User Detection** (`enable_malicious_user_detection`): tenant-side ML that
   scores each user identity (IP or configured user-id cookie/header) on behavior across
   WAF hits, forbidden-access rate, error rates, scan-like access patterns → threat level
   low/medium/high, mapped to mitigations (alert / JS challenge / captcha / temp block)
   via `malicious_user_mitigations`.

## Read operations

| Task | How |
|---|---|
| Bot event analysis | `xc-security-events`, `{sec_event_type="bot_defense_sec_event"}`; aggs on `BOT_CLASSIFICATION`, `SRC_IP`, `URI`, `BROWSER_TYPE` (note: `REQ_PATH` and `USER_AGENT` are rejected by the event agg enum) |
| Malicious/suspicious user list | `POST /api/ml/data/namespaces/{ns}/virtual_hosts/{vh}/malicious_users` [T]; per-user detail includes contributing signals |
| Malicious-user events | `{sec_event_type="malicious_user_sec_event"}` |
| Current mitigation config | GET LB spec (`bot_defense`, malicious-user fields) + `malicious_user_mitigations` object via `xc-waf-config` |

Signal anatomy, threat-level semantics, and user-identifier configuration:
`references/malicious-users.md`.

## Analysis playbooks

**Credential-stuffing triage** (login endpoint): bot events filtered to the login path →
classification split; failed-auth rate from access logs (rsp 401/403 ratio per src);
distinct-username fan-out per IP if a username field is loggable; JA3/UA diversity per IP
(one IP rotating UAs = automation). Verdict per the investigator gate — bot classification
alone is one corroborator, not a conviction.

**ATO exposure review**: is bot defense actually covering the auth endpoints? Diff
`bot_defense.policy.protected_app_endpoints[]` against discovered auth endpoints from
`xc-api-security` — uncovered login/token/password-reset paths are findings.

**Malicious-user review loop**: weekly pull of high/medium users → sample each user's
event history → classify (attacker / broken client / pentest / partner integration) →
recommend: keep mitigation, add trusted-client carve-out script, or tune the identifier
(per-IP scoring behind a corporate NAT punishes whole offices — switch to cookie/header
user-id; change script provided).

**Scraper economics**: suspicious-automation volume on catalog/pricing paths; per-ASN
concentration; recommendation ladder: JS challenge → per-endpoint rate limit → block, each
as a change script with expected collateral estimated from event data.

## Mitigation change scripts

All via `xc-waf-config` contract. Common: add endpoint to
`bot_defense.policy.protected_app_endpoints[]` with per-verdict action; adjust
`malicious_user_mitigations` threat-level→action map; enable malicious-user detection with
a proper user identifier. Blast-radius note required in each script header: challenges
affect real users on false positives — always start `alert`/JS-challenge before captcha or
block, and state the rollback file.
