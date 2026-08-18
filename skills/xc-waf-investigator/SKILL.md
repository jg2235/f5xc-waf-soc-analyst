---
name: xc-waf-investigator
author: Jeff Granieri <jgranieri22@outlook.com>
description: >-
  Autonomous WAF event investigation orchestrator for F5 Distributed Cloud. Use whenever
  the user wants to investigate, triage, or work an XC security event, source IP, support
  ID, signature spike, or suspected attack campaign: "investigate this IP", "is this a real
  attack", "triage this support ID", "what happened on the prod LB last night", "are we
  being targeted", "investigate this spike", "incident on the WAF". Interrogates for
  context, then runs SHORT (quick triage), MEDIUM (correlation sweep), or LONG (full
  campaign timeline) modes with strict evidence discipline, verdict gates, MITRE ATT&CK
  mapping, and a mandatory query appendix. Produces a calibrated verdict (attack /
  false-positive / suspicious-pending) plus recommended mitigations as generated change
  scripts. Trigger on "investigate", "triage", "incident", "attack", "who is", "campaign".
---

# XC WAF Investigator

Investigation orchestrator over the primitives (`xc-security-events`, `xc-waf-config`,
`xc-bot-defense`, `xc-api-security`). Read-only; recommended mitigations are emitted as
change scripts, never applied.

## Evidence discipline & verdict gates (non-negotiable)

Inherited from the plugin CLAUDE.md persona; essentials:

- A signature/event firing is a **lead, not a finding**. Findings trace to specific event
  records pulled this session. Absent evidence → "unconfirmed".
- No fabrication: every count, IP, path, signature, or percentage comes from a query run
  this session. Empty/zero/error results are reported as findings.
- **ATTACK / TRUE-POSITIVE gate** — requires ≥2 independent corroborators:
  multiple distinct attack types or a recon→exploit chain from the same source;
  `threat_campaigns[]` match; IP-reputation event; malicious-user ML high score; bot
  malicious classification; cross-LB/namespace repetition; or payload evidence
  (matched values that are unambiguous exploit strings). One signature class alone caps at
  SUSPICIOUS — Pending Confirmation.
- **FALSE-POSITIVE gate** — requires sampled raw events showing benign matched values plus
  a benign source profile; then hand off to `xc-waf-tuning` for the exclusion loop.
- Mark assumptions ("Assumption: … falsified by …"). Calibrated language: confirmed /
  consistent with / suggests / possible / no evidence of. Negatives are recorded
  explicitly.
- Hold findings to the end; a shared time window is not causation — assert links only when
  an entity (IP, JA3, UA, user-id, path set) bridges clusters.
- **Query appendix, mandatory**: every query executed (endpoint, body/filter, window,
  hits, representative excerpt), including empty and errored ones. A peer must be able to
  reproduce every number. Full rules: `references/evidence-discipline.md`.

## Stage 0 — Intake & tool discovery

Confirm available: xc-security-events, xc-waf-config, xc-bot-defense, xc-api-security
(+ entitlement state from the last smoke test). Display ✓/✗. Then collect: what triggered
the investigation (support ID / IP / spike / hunch), namespace/LB scope, time anchor, and
mode (default from ambiguity: SHORT).

## Modes

**SHORT — quick triage (≤5 queries).** Anchor entity profile: event summary aggs
(sec_event_type, signature, attack_type, path spread), 10-event evidence sample, geo/ASN/
UA snapshot. Verdict per gates + one-paragraph rationale + next step.

**MEDIUM — correlation sweep.** SHORT + pivots: same source across all LBs
(`all_ns_events`); JA3/UA pivot to sibling IPs; malicious-user + bot verdicts for the
source; access-log slice (what did non-blocked requests do — the scary part); timeline
histogram (date agg) for burst shape. Chain analysis: recon (scanner sigs, 404 spread) →
exploitation (targeted sigs on real paths) → post-exploit indicators (unusual 200s,
sensitive endpoints from api-security inventory).

**LONG — campaign timeline.** MEDIUM + 7–30d history for all correlated entities,
infrastructure clustering (ASN/geo/fingerprint groups), per-day evolution, target-path
analysis against API inventory (are they hitting real endpoints = informed attacker, or
spraying = commodity), config-exposure review (`xc-waf-config` audit of the targeted LBs:
would anything have gotten through — monitoring mode, exclusions, uncovered endpoints).
Full report with MITRE mapping (`references/mitre-mapping.md`), IOC table, and mitigation
scripts (blocked_clients w/ expiry, service-policy geo/ASN rules, bot-defense coverage,
rate limits) referenced by path.

## Output contract

Every mode ends with: Verdict + confidence + evidence count · findings table ·
recommended actions (script paths) · query appendix. LONG additionally offers .docx/.xlsx
export.
