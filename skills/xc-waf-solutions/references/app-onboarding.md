# Playbook: App Onboarding Behind WAF

## Parameters (one question set)
prefix (default ns) · namespace · app domain(s) · origin (IP/DNS + port + TLS?) ·
existing LB or new · cert path (auto_cert default) · observation window (default 14d) ·
advertise (public default VIP unless told otherwise)

## Stages
01 origin_pool           render assets/origin_pool.template.json; healthcheck included
02 app_firewall          monitoring mode, default detection + threat campaigns ON,
                         render assets/app_firewall.template.json
03 http_loadbalancer     render assets/http_lb.template.json: domains, auto_cert,
                         pool ref, app_firewall ref, enable_api_discovery,
                         enable_malicious_user_detection (per-IP initially), no bot yet
-- GATE: apply 01-03, confirm traffic flows (access-log count > 0), start window --
04 observation           no changes; scheduled validation queries: event pulse, top
                         signatures, recommended_action=block summary building the
                         staging dataset
05 tuning pass           xc-waf-tuning staging analysis over the window; exclusion
                         scripts as needed (each its own numbered script)
-- GATE: staging go/no-go report clean --
06 enforcement flip      app_firewall monitoring->blocking script with
                         --acknowledge-staging-reviewed
07 hardening (optional)  rate limit, bot-defense on auth paths (hand to bot-hardening
                         playbook), API validation (hand to api-protection playbook)

## Validation per stage
02/03: GET objects match rendered spec; 03: access logs flowing; 05: post-exclusion
verification queries (scoped-to-path zero, elsewhere unchanged); 06: action=block events
appear, error-budget check (5xx/4xx rate unchanged vs pre-flip baseline from access logs).
