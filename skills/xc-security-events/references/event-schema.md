# Security Event Record Anatomy

Each element of `events[]` (after `json.loads`) is a flat-ish JSON record (~66 top-level
fields on current releases; validated against a live enterprise tenant, 2026-08). Fields
marked [V] below were confirmed in a live sample; enrichment fields vary by entitlement.
Re-confirm per tenant with `smoke_test.py --dump-sample`.

## Core request fields

| Field | Meaning |
|---|---|
| `time` | event timestamp (RFC3339) |
| `req_id` | unique request ID — the correlation key to access logs |
| `src_ip`, `src_port` | client |
| `dst_ip`, `dst_port` | VIP side |
| `method`, `req_path`, `domain`, `authority` | request line |
| `user_agent` | raw UA string |
| `rsp_code` | response status actually returned |
| `vh_name`, `vhost_id` | virtual host (LB) identity |
| `namespace`, `tenant` | scope |
| `site` | RE/CE site that processed the request |

## Security decision fields

| Field | Meaning |
|---|---|
| `sec_event_type` | which engine fired (waf/bot/api/svc_policy/malicious_user/ip_reputation) |
| `sec_event_name` | specific rule/event name |
| `action` | `block` or `report` (report = monitoring mode / logging-only) |
| `recommended_action` | what enforcement WOULD do — differs from `action` in monitoring mode; the key field for staging analysis. **Record field only — NOT aggregatable**, so read it by sampling raw events. (There is no `calculated_action` field; that name returns null.) |
| `waf_mode` | `block` / `monitoring` on the firing policy |
| `app_firewall_name` | which app_firewall object matched |
| `policy_hits` / `policy.results` | per-policy rule outcomes |

## WAF detail fields (sec_event_type = waf_sec_event)

| Field | Meaning |
|---|---|
| `signatures[]` | array of `{id, name, accuracy, attack_type, context, matching_info, state}` — one event can carry multiple signature hits |
| `attack_types[]` | e.g. `ATTACK_TYPE_SQL_INJECTION`, `ATTACK_TYPE_CROSS_SITE_SCRIPTING`, `ATTACK_TYPE_COMMAND_EXECUTION`, `ATTACK_TYPE_PATH_TRAVERSAL` |
| `violations[]` | protocol/RFC violations (e.g. `VIOL_HTTP_PROTOCOL`, `VIOL_EVASION`, `VIOL_FILETYPE`) |
| `threat_campaigns[]` | matched named campaigns — a strong true-positive corroborator |
| `detection_events` | per-detection context incl. matched value/context (header, param, uri, body, cookie) — the field you MUST read before writing an exclusion |
| `bot_info` | client classification when bot signals present on a WAF event |
| `violation_rating` [V] | engine's 0–5 severity/confidence rating for the request |
| `req_risk` / `risk_score_info` [V] | AI risk scoring for the request — corroborator-grade signal, same rules as ML verdicts |
| `enforcement_mode` [V] | policy enforcement state at event time (pairs with `waf_mode`) |
| `recommended_action` [V] | engine's suggested disposition — advisory; never auto-acted on |

Signature `context` values (`parameter`, `header`, `uri`, `cookie`, `request` body) map
1:1 to `exclude_signature_contexts` in exclusion rules — capture context + the specific
parameter/header name when sampling FP evidence.

## Enrichment fields

| Field | Meaning |
|---|---|
| `country`, `city`, `region`, `latitude`, `longitude` | GeoIP |
| `asn`, `as_org` | network owner |
| `ip_reputation` / threat categories | present when IP intel matched |
| `ja4_tls_fingerprint` [V, verified 2026-08] | client TLS fingerprint (JA4) — powerful cross-IP pivot |
| `device_type`, `browser_type` | derived client info |

## Aggregation field names

Aggs use UPPER_SNAKE keys, not the record field names. **The agg enum is narrower than
the record schema — a field existing on the event record does NOT mean it can be
aggregated.** Verified against a live enterprise tenant, 2026-08:

`ACTION`, `ASN`, `ATTACK_TYPE`, `BOT_CLASSIFICATION`, `BOT_NAME`, `BROWSER_TYPE`,
`COUNTRY`, `DOMAIN`, `JA4_TLS_FINGERPRINT`, `METHOD`, `SEC_EVENT_NAME`, `SEC_EVENT_TYPE`,
`SIGNATURE_ID`, `SRC_IP`, `THREAT_CAMPAIGN_NAME`, `THREAT_LEVEL`, `TLS_FINGERPRINT`,
`URI`, `USER`, `VH_NAME`, `VIOLATION`, `VIOLATION_RATING`, `WAF_MODE`.

**Rejected by the enum — do not use** (each returns HTTP 400):
`API_ENDPOINT`, `APP_FIREWALL_NAME`, `APP_TYPE`, `AUTHORITY`, `CALCULATED_ACTION`,
`REQ_PATH`, `RSP_CODE`, `SITE`, `TIMESTAMP`, `USER_AGENT`.

Two substitutions catch most mistakes: **request path is `URI`, not `REQ_PATH`**, and
**client is `BROWSER_TYPE`, not `USER_AGENT`**.

**Access logs use a DIFFERENT enum** (`ves.io.schema.log.access_log.KeyField`), where
`REQ_PATH` and `RSP_CODE` *are* valid. Confirmed there: `REQ_PATH`, `RSP_CODE`,
`RSP_CODE_CLASS`, `SRC_IP`, `VH_NAME`, `METHOD`, `AUTHORITY`. Do not carry a field name
from one endpoint to the other.

**Date aggregation** shape is `{"d": {"date_aggregation": {"step": "24h"}}}`.
`step` is REQUIRED (omitting it errors "step not specified"), and `interval` is not a
recognised key. The unit suffix must be **`s`, `m`, or `h`** — verified accepted:
`5m`, `30m`, `1h`, `3600s`, `24h`, `1440m`, `86400s`. Verified rejected: `1d` and `1w`
(day/week units are NOT supported — use `24h`), `P1D` (ISO-8601), and a bare number
`3600` (unit required). A `field` key is accepted but has no effect and can be omitted.
Buckets return `time` as epoch-millisecond strings.

Unknown field in `aggs` → HTTP 400 naming the field — self-correcting; fix and retry,
never loop blindly.

## Anomaly checklist (apply to every result set)

Frequency (rate vs baseline) · timing (off-hours, burst shape) · geo (new country/ASN for
this app) · volume (bytes/req size outliers) · new entity (first-seen IP/UA/JA3/path) ·
privilege (auth endpoints, admin paths) · chain (recon → exploit → exfil sequencing across
event types) · spread (one path/many IPs = FP smell; one IP/many paths = attack smell).
