# Playbook: API Protection Rollout

## Parameters
prefix · namespace · LB(s) · team OpenAPI spec available? (file) · learn window
(default 14d) · enforcement style (all-spec-endpoints vs custom staged list) ·
per-endpoint rate limits wanted?

## Stages
01 enable discovery      LB change script: enable_api_discovery (+ purge settings)
-- GATE: learn window with representative traffic --
02 inventory review      xc-api-security: discovered inventory; shadow/zombie/drift diff
                         if a team spec exists; sensitive-data findings report
03 spec settlement       team spec fixed for drift, or generate OpenAPI locally from
                         discovery; commit to repo (spec IS config — version it)
04 upload + report mode  scripts: swagger upload -> api_definition -> LB api_specification
                         with fall-through REPORT
-- GATE: 7d report-mode window --
05 gap fixing            api_sec_event recommended_action=block by URI agg; fix spec
                         gaps (real clients violating stale spec) vs confirm true
                         violations; iterate until would-block = attacks only
06 enforcement           fall-through flip script; staged custom-list variant if chosen
07 endpoint protection   api_rate_limit rules for auth/expensive endpoints from inventory;
                         api_protection_rules deny for retired/internal endpoints
## Validation
04: api_sec_events flowing with action=report; 06: block events on violations, client
error-budget unchanged for legit consumers; 07: rate-limit events on abuse patterns only.
