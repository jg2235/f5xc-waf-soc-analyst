# Evidence Discipline — full rules

## Ground truth hierarchy

1. Raw event records pulled this session (json.loads'd, quoted)
2. Server-side aggregation results (counts, topk) from this session
3. Config objects GET'd this session
4. ML verdicts (bot classification, malicious-user level) -- treat as one corroborator,
   never as sole proof; they are model outputs, not observations
5. User-supplied context (mark as "reported by user")
Anything not in 1-5 does not appear as fact in a report.

## Query appendix entry format

  [Q7] Purpose: profile attack types for 203.0.113.7
       Endpoint: POST /api/data/namespaces/prod/app_security/events
       Filter: {src_ip="203.0.113.7", sec_event_type="waf_sec_event"}
       Window: 2026-08-16T00:00Z .. 2026-08-17T00:00Z   Hits: 412
       Aggs: ATTACK_TYPE topk 10 -> SQLI 301, XSS 88, CMDEXEC 23
       Evidence: 2 sample records (trimmed to probative fields)

Include every query, in execution order, including 0-hit and errored ones. Curating the
appendix down to "interesting" queries is falsification by omission.

## Correlation rules

- Entity bridge required: IP, CIDR/ASN+fingerprint combo, JA3, UA+behavior pair, user-id,
  or identical payload string. Time proximity alone never links clusters.
- Cross-source counting: the same request can emit multiple sec_event_types; dedupe by
  req_id before summing "total malicious requests".
- Access logs are the blind-spot check: what the source did that DIDN'T trip security
  events. An attacker profile without the access-log slice is incomplete for MEDIUM+.

## Verdict ladder

  ATTACK (confirmed)        gate met, >=2 corroborators, evidence quoted
  SUSPICIOUS - pending      one corroborator or ambiguous evidence; list what would confirm
  FALSE POSITIVE            FP gate met -> hand to xc-waf-tuning
  BENIGN / NO EVIDENCE      profiled clean; recorded as a real result
Confidence: high / moderate / low, justified by evidence count and independence.
