# Playbook: Bot & Malicious-User Hardening

## Parameters
prefix · namespace · LB(s) · auth/checkout/redemption paths (confirm against
xc-api-security inventory) · user-identifier choice (cookie/header vs IP — ask; per-IP
behind NAT warning) · mitigation ladder start point (default: alert/JS-challenge)

## Stages
01 coverage diff         bot_defense.protected_app_endpoints vs discovered auth/checkout/
                         signup/reset/redemption endpoints; findings table
02 bot-defense config    change script: protected endpoints w/ flow labels, JS insert,
                         per-verdict mitigation (malicious=block, suspicious=continue+
                         monitor initially)
03 malicious-user setup  enable detection with the chosen identifier; mitigation object
                         low->alert / medium->JS / high->temp-block
-- GATE: 7d observation --
04 verdict review        bot classification split on protected endpoints; malicious-user
                         list triage (attacker/broken client/partner) per xc-bot-defense
                         review loop; carve-out or escalation scripts as evidence dictates
05 ladder escalation     suspicious->challenge where evidence supports; captcha only after
                         JS-challenge data reviewed
## Recurring
Weekly malicious-user review; monthly coverage re-diff (new endpoints appear).
## Validation
02: bot events on protected paths; 03: malicious_user_sec_events on mitigations;
04+: challenge solve-rates sane (mass failures = real users being challenged — back off).
