---
name: xc-waf-solutions
author: Jeff Granieri <jgranieri22@outlook.com>
description: >-
  Deploy packaged, repeatable F5 Distributed Cloud WAF solutions from one prompt. Use when
  the user wants to roll out a whole solution end to end, not a one-off query or single
  config change. Catalog: (1) app onboarding behind WAF (LB + origin pool + app_firewall in
  monitoring, observe, tune, flip to blocking); (2) FP-reduction program (noise ranking,
  evidence-gated exclusions, staging go/no-go, weekly cadence); (3) API protection rollout
  (discovery -> spec -> report-mode validation -> enforcement -> per-endpoint protection);
  (4) bot & malicious-user hardening (coverage diff, mitigation ladder, review loop).
  Triggers: "onboard this app behind the WAF", "get us to blocking mode", "roll out API
  protection", "harden against bots/ATO", "set up a tuning program", "deploy the WAF
  solution". Orchestrates the primitive skills; NOT for single queries (xc-security-events)
  or single investigations (xc-waf-investigator).
---

# F5 XC WAF Solutions (orchestrator)

Orchestration layer only: collects parameters, previews everything, drives the primitive
skills in dependency order, validates, and summarizes. It does not reimplement query,
config, or tuning mechanics. **All tenant writes remain generated change scripts** — the
"deployment" this skill performs is producing the ordered, reviewed script set + runbook,
then (after the human applies each stage) running the validation queries.

## Catalog

| Solution | What it delivers | Playbook |
|---|---|---|
| App onboarding behind WAF | New/existing app fronted by an HTTP LB with app_firewall in monitoring, DNS/origin wiring, baseline observation window, tuning pass, evidence-gated flip to blocking | `references/app-onboarding.md` |
| FP-reduction program | One-time cleanup + recurring cadence: noise ranking, evidence-gated exclusion scripts, staging analysis, stale-exclusion pruning, weekly delta report | `references/fp-reduction.md` |
| API protection rollout | Discovery enablement, learn window, spec settlement (learned or team spec), report-mode validation, gap fixing, enforcement flip, per-endpoint rate limits + protection rules | `references/api-protection.md` |
| Bot & malicious-user hardening | Endpoint coverage diff vs API inventory, bot-defense config for auth/checkout paths, malicious-user detection with correct user identifier, mitigation ladder, weekly review loop | `references/bot-hardening.md` |

## How a deployment runs (always this loop)

1. **Pick the solution.** Named → use it; otherwise show the catalog, ask once.
2. **Collect parameters** in one compact question set with defaults prefilled (namespace,
   LB/app, domains, observation-window length, deployment prefix). Never start before
   confirmation.
3. **Confirm the environment.** Resolve names against the live inventory (fuzzy match LB
   names); read current object versions; state tenant/namespace back to the user.
4. **Render and preview.** Fill `assets/` templates; show every rendered spec/script and
   the projected end state BEFORE producing the final script set. Dry run, always.
5. **Emit the staged script set** to `changes/<prefix>/NN_<step>.py` in dependency order,
   each script per the `xc-waf-config` contract, plus `RUNBOOK.md` listing order, gates
   between stages (e.g. "apply 01–03, wait 14 days of traffic, then run stage-2
   validation"), and rollback per step.
6. **Validate per stage** (after the human applies): the playbook's verification queries
   via `xc-security-events`; report actuals vs expected. A stage is not complete until its
   validation passes — mirror this in the runbook.
7. **Summarize** artifacts (paths, target objects, namespace) and schedule the recurring
   cadence if the solution has one.

## Conventions

- **Prefix everything** (`<prefix>` defaults to the namespace): script dirs, object names
  in rendered specs (`<prefix>-fw`, `excl-<prefix>-...`), report files. Parallel
  deployments must coexist.
- **Idempotence**: scripts detect already-applied state and no-op; re-running a stage is
  always safe.
- **Preview before emit; validate after apply.** No silent stages.
- **Evidence gates carry over**: any tuning inside a solution uses the full
  `xc-waf-tuning` FP gate; any verdict uses the `xc-waf-investigator` gates. Orchestration
  never relaxes primitive-skill discipline.

## Dependencies

Load as the playbook calls for: `xc-security-events` (all validation queries),
`xc-waf-config` (script contract + spec shapes), `xc-waf-tuning` (FP loop, staging
go/no-go), `xc-api-security` (discovery/validation lifecycle), `xc-bot-defense`
(coverage + mitigation ladder), `f5xc-api` (object model for LB/pool creation specs).

## Templates

`assets/` holds `{{TOKEN}}`-parameterized templates: `http_lb.template.json`,
`app_firewall.template.json`, `origin_pool.template.json`, `RUNBOOK.template.md`.
