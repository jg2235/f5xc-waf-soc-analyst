---
name: xc-waf-tuning
author: Jeff Granieri <jgranieri22@outlook.com>
description: >-
  False-positive reduction and WAF policy tuning for F5 Distributed Cloud. Use when the
  user says: "false positive", "FP", "WAF is blocking legit traffic", "tune the WAF",
  "customer got a support ID / blocking page", "exclusion for signature", "too noisy",
  "can we go to blocking mode", "staging analysis", "monitoring mode review", or wants a
  data-driven exclusion recommendation, a noise ranking, or a go/no-go for flipping
  enforcement. Runs the evidence-gated tuning loop: aggregate -> sample raw events ->
  classify FP vs TP -> generate narrowest-scope exclusion change scripts -> verify.
  Read-only; all changes are dry-run scripts per the xc-waf-config contract.
---

# F5 XC WAF Tuning — False-Positive Reduction

The tuning loop, evidence-gated end to end. Never recommend an exclusion from counts
alone; never widen scope beyond what the evidence supports.

## Namespace scope

Scope is explicit and mandatory: one namespace, or a list the user supplied. Resolve from
(1) the request, (2) `$F5XC_NAMESPACES`, (3) otherwise **ask** — never guess, and never
substitute a tenant-wide query for an unanswered scope question. Multiple namespaces means
one request per namespace, labelled per namespace in the output. Tenant-wide sweeps are
opt-in only. Full contract: `docs/namespace-scope.md`.

## The loop

1. **Rank the noise.** 7d (default) aggregation: `SIGNATURE_ID` topk 50, per-LB. For
   each top signature use filter `{signatures.id="<id>"}` — `signature_id=` is invalid
   and silently returns 0 hits, which reads as "never fired". Sub-aggs: `URI`, `SRC_IP`,
   `COUNTRY`, `BROWSER_TYPE`.
2. **Apply the spread heuristic.** One path × many distinct IPs × normal geo/UA mix →
   FP-candidate. Few IPs × many paths/signatures × hostile geo or automation UA →
   attack-candidate (route to `xc-waf-investigator`, not tuning). Mixed → sample more.
3. **Sample evidence.** Pull 10–25 raw events per FP-candidate (signature+path filter).
   Read `signatures[].context`, `matching_info`, the matched value, and signature
   `accuracy`. Confirm the matched value is plausible legitimate app data (e.g. free-text
   field containing `select`, a URL param carrying a redirect URL). If the matched value
   looks like an actual payload — it is not an FP; stop and say so.
4. **Classify with the FP gate.** FALSE-POSITIVE requires ALL of: legitimate-looking
   matched values in sampled events; distributed benign source profile; app-owner
   confirmation of the field's purpose (ask the user if unknown — mark "Assumption:" if
   proceeding without it). Otherwise SUSPICIOUS → investigator.
5. **Generate the exclusion script.** Narrowest scope per
   `xc-waf-config/references/exclusion-rules.md` doctrine (signature+context+context_name+
   path+method). One rule per script, named `excl-<path-slug>-sig-<id>`, full change-script
   contract, evidence summary in the script docstring (counts, sample matched values,
   date range) so the reviewer sees the why.
6. **Verify after apply.** Same aggregation post-change: the signature's count on that
   path should go to ~0 while remaining nonzero elsewhere (proving scope held). Report
   both numbers.

## Staging / enforcement-flip analysis (monitoring → blocking)

For a LB or app_firewall in monitoring mode:

1. Pull 7–14d of events; the field that matters is `recommended_action` — every event
   with `recommended_action=block` WOULD be blocked. Two traps here:
   **(a)** there is no `calculated_action` field — that name reads null;
   **(b)** `recommended_action` is **not aggregatable**, so it cannot be counted with
   `aggs` and must be read by sampling raw events (`sec_events_iter`, small `max_events`).
   In monitoring mode `action` reads `allow`, not `report`, so filtering on
   `action="report"` can return nothing — check `WAF_MODE` instead, which IS aggregatable.
2. Aggregate would-blocks by `SIGNATURE_ID` × `URI`; run the loop above on the top
   would-block sources until the residual would-block set is attack-classified only.
3. Go/no-go report: total would-block rate vs total traffic (access-log denominator),
   residual FP risk list (empty or accepted), the exclusion scripts applied, and the flip
   script (`--acknowledge-staging-reviewed` gate).

## Continuous tuning cadence

Weekly: noise ranking delta vs last run (persist the JSON), stale-exclusion check (rules
with zero matched `report` events in 30d → removal-candidate scripts), new-signature-
release review (F5 signature updates can introduce fresh FPs — check top new signature IDs
since last run). Methodology detail and worked examples: `references/fp-methodology.md`.
