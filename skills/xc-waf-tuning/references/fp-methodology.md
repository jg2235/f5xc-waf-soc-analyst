# FP Methodology — worked patterns

## Denominator discipline

An FP rate means nothing without traffic volume. For every candidate path, pull the
access-log request count for the same window and report:
  fp_rate = signature_hits_on_path / total_requests_to_path
0.1% on a login path with 2M req/day is 2000 angry users/day; 40% on a path with 10
req/day is a curiosity. Prioritize by absolute user impact, not raw hit count.

## Classic FP shapes (recognize on sight)

| Shape | Typical signature classes | Fix |
|---|---|---|
| Free-text field carrying SQL-ish words ("select a plan") | SQLi keyword sigs, low/medium accuracy | sig+CONTEXT_PARAMETER+field name |
| Redirect/callback URL in a param | generic XSS/RFI sigs on URL-looking values | sig+param context |
| Rich-text/HTML editors (CMS, email builders) | XSS tag sigs on body fields | sig or attack-type + CONTEXT_BODY, path-scoped; consider per-route WAF |
| JSON bodies with embedded code/regex (dev tools, CI webhooks) | command-exec/code-injection sigs | sig+body context on the webhook path; verify webhook source auth first |
| Legacy/nonstandard clients (SOAP, old mobile) | VIOL_HTTP_PROTOCOL / evasion violations | violation context exclusion, path-scoped; push client fix in parallel |
| Base64/binary blobs in params | multiple sigs, apparent gibberish matches | sig+param; consider size limits instead |
| Monitoring/health-check probes | header anomaly sigs | trusted source better handled via service-policy ALLOW match on the probe, not WAF exclusion |

## Anti-patterns (refuse + explain)

- Excluding by src_ip "because it's our partner" -> that's a trusted-client/service-policy
  decision with an owner and expiry, not a WAF exclusion.
- Domain-wide attack-type exclusion to silence a ticket -> quantify what it also silences
  (run the counterfactual agg) before the user decides.
- Turning off a high-accuracy signature globally on one app's complaint.

## Evidence packet format (goes in every exclusion script docstring)

  Signature: 200002147 (name, accuracy)
  Scope: POST ^/api/login$ param redirect_url (CONTEXT_PARAMETER)
  Window: 2026-08-10..17  Hits: 4,312  Distinct src: 1,893  Geo: matches app norm
  Samples: 3 matched values, verbatim, with the benign interpretation
  Denominator: 2.1M reqs to path; fp_rate 0.20%
  Classification: FALSE POSITIVE (app-owner confirmed field purpose: OAuth redirect)
  Counterfactual: signature still fires on 7 other paths (left intact)

## Post-change verification query

Same SIGNATURE_ID agg filtered to the excluded path (expect ~0) AND filtered to
everything-else (expect unchanged +/- noise). Both numbers in the close-out note.
