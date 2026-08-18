# Playbook: FP-Reduction Program

## Parameters
prefix · namespaces in scope · ranking window (default 7d) · cadence (default weekly) ·
staging targets (LBs still in monitoring)

## One-time cleanup
1. xc_config_audit.py — exclusion-rule risk findings first (skip-processing, sig-0 rules
   get remediation-or-accept decisions before adding anything new)
2. Noise ranking (xc-waf-tuning loop) across scope; evidence-gated exclusion scripts,
   one per finding, batched into changes/<prefix>/cleanup/
3. Stale-exclusion pruning: rules with zero report-mode matches in 30d -> removal scripts
4. Staging go/no-go per monitoring-mode LB

## Recurring cadence (each run produces a delta report)
- New top-10 noise vs persisted last-run JSON (regressions = new FPs or new attacks —
  classify before touching)
- New signature IDs since last run (F5 signature-update FP watch)
- Stale-exclusion recheck
- Metrics: exclusion count trend, would-block trend on staging LBs, mean evidence-packet
  completeness (every exclusion has one — audit it)

## Report
Weekly md: noise delta table, actions taken (script paths), open SUSPICIOUS items handed
to investigator, metrics trend, query appendix.
