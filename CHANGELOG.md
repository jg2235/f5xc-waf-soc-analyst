# Changelog

All notable changes to this project are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-08-18

Documentation-accuracy release. Every field name below was verified against a live
tenant; the previous docs named fields the API rejects, and two of them failed
*silently* — producing confidently wrong analysis rather than an error.

### Fixed
- **`signature_id=` filter key was wrong and failed silently.** The event-query label
  key is `signatures.id` (dotted, nested). The documented `signature_id=` returns
  **0 hits instead of an error**, which reads as "this signature never fired" and
  causes tuning to be performed against an empty set. This was the highest-severity
  defect in the set.
- **`calculated_action` does not exist.** The staging-analysis field is
  `recommended_action`. It is a record field only and is **not aggregatable**, so it
  must be read by sampling raw events. Corrected across `xc-waf-tuning`,
  `xc-api-security`, `xc-waf-config`, and `xc-waf-solutions`.
- **7 of 20 documented aggregation fields were invalid.** `CALCULATED_ACTION`,
  `REQ_PATH`, `RSP_CODE`, `USER_AGENT`, `APP_FIREWALL_NAME`, `API_ENDPOINT` and
  `TIMESTAMP` are rejected by the event agg enum (HTTP 400). Request path is `URI`;
  client is `BROWSER_TYPE`.
- **Monitoring-mode filter guidance was wrong.** In monitoring mode `action` reads
  `allow`, not `report`, so the documented `action="report"` staging filter returns
  nothing. Use `WAF_MODE`, which is aggregatable.
- `scripts/build.sh` required the `zip` binary and failed on stock WSL/Ubuntu images.
  It now falls back to Python's `zipfile`, producing identical archives.
- `.claude-plugin/marketplace.json` was missing a description; `claude plugin validate`
  now passes with no warnings.
- `plugin.json` declared `MIT` while the project ships Apache-2.0; corrected to
  `Apache-2.0` to match `LICENSE` and `NOTICE`.

### Added
- 10 previously undocumented but valid aggregation fields: `URI`, `BROWSER_TYPE`,
  `DOMAIN`, `USER`, `VIOLATION_RATING`, `WAF_MODE`, `BOT_NAME`, `THREAT_LEVEL`,
  `JA4_TLS_FINGERPRINT`, `TLS_FINGERPRINT`.
- Date-aggregation shape documented: `{"date_aggregation": {"step": "24h"}}`.
  `step` is required and takes `s`/`m`/`h` units only — `1d` and `1w` are rejected
  (use `24h`), as are `P1D` and bare numbers. Buckets return `time` as
  epoch-millisecond strings.
- Explicit warning that **access logs use a different field enum** from security
  events — `REQ_PATH` and `RSP_CODE` are valid there and invalid for events.
- JA4 infrastructure-clustering hunt pattern in `xc-security-events`.
- Regression test (`tests/test_docs.py`) that fails the build if any known-bad field
  name reappears in the skill documentation.

### Unchanged (deliberately)
- `signature_id` is retained in `xc-waf-config` exclusion-rule documentation and in
  `xc_config_audit.py`. There it names the `waf_exclusion_rules[].signature_id`
  **configuration object field**, which is correct and unrelated to the event-query
  filter key. A blanket rename would have corrupted the change-script generator.

## [1.0.1] - 2026-08-18

### Fixed
- **Tenant console base URL was unresolvable.** `xc_client.py` built
  `https://<tenant>.console.ves.io`, which is NXDOMAIN — every API call failed. Now
  defaults to `https://<tenant>.console.ves.volterra.io`, overridable end-to-end with
  `F5XC_API_URL` for staging or region-specific endpoints.
- `smoke_test.py` crashed with a traceback instead of reporting `FAIL`, and assumed
  `metadata.name` on LIST responses. LIST endpoints return `name` at the top level with
  `metadata: null` — `"metadata" in item` is `True` while the value is `None`.

### Added
- `obj_name()` helper in `xc_client.py`, generalizing the `metadata: null` trap so
  every call site is protected rather than one script.
- `smoke_test.py` now probes every load balancer and reads `enable_api_discovery` /
  `enable_malicious_user_detection` per LB, distinguishing "feature not enabled"
  (SKIP) from genuine API path drift or an entitlement gap (FAIL).

## [1.0.0] - 2026-08-17

### Added
- Initial release: seven skills — `xc-security-events`, `xc-waf-config`,
  `xc-api-security`, `xc-bot-defense`, `xc-waf-tuning`, `xc-waf-investigator`,
  `xc-waf-solutions`.
- Read-only tenant posture with all configuration changes emitted as dry-run-default
  Python scripts (unified diff → `--apply` with optimistic concurrency → backup →
  `--rollback`).
- `CLAUDE.md` analyst persona with evidence discipline and two-corroborator verdict
  gates.

[1.0.2]: https://github.com/OWNER/f5xc-waf-skills/releases/tag/v1.0.2
[1.0.1]: https://github.com/OWNER/f5xc-waf-skills/releases/tag/v1.0.1
[1.0.0]: https://github.com/OWNER/f5xc-waf-skills/releases/tag/v1.0.0
