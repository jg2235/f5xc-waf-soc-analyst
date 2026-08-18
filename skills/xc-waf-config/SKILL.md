---
name: xc-waf-config
author: Jeff Granieri <jgranieri22@outlook.com>
description: >-
  Read, audit, and generate change scripts for F5 Distributed Cloud WAF and LB security
  configuration. Use when the user wants to: review an app_firewall or HTTP LB security
  posture; list/compare WAF policies across LBs or namespaces; understand or author
  exclusion rules, service policies, blocked/trusted clients, rate limits, malicious-user
  mitigation, or bot-defense config; or produce a change script for any of these. Trigger
  on: "app firewall", "WAF policy", "exclusion rule", "waf_exclusion_rules", "service
  policy", "blocklist", "block this IP", "blocked clients", "rate limit", "monitoring vs
  blocking", "WAF audit", "policy drift", "compare WAF configs". READ-ONLY against the
  tenant: every change is emitted as a dry-run-default Python script for human review,
  never pushed directly. NOT for event queries (xc-security-events).
---

# F5 XC WAF Configuration

Config primitive: read and audit the security config surface, and generate reviewed change
scripts. Builds on the `f5xc-api` skill for the object model, CRUD URL patterns, and the
atomic read-modify-write pattern — load it for anything not covered here.

## Read/audit operations (run freely)

| Task | How |
|---|---|
| WAF posture inventory | LIST `app_firewalls` + LIST `http_loadbalancers` per ns; join: which LB uses which firewall, blocking vs monitoring, exclusion count, bot/API/malicious-user toggles |
| Single-object deep read | GET with `?response_format=2` (replace-ready spec + `resource_version`) |
| Policy drift / comparison | GET N objects, normalized diff of specs (ignore `system_metadata`, timestamps) |
| Exclusion-rule audit | enumerate `waf_exclusion_rules[]` per LB; flag broad rules (`waf_skip_processing`, domain-wide `any_path`) as risk findings |
| Service-policy review | GET `service_policys`; map rule order, match criteria, actions |

Security posture heuristics for audits are in `references/audit-checklist.md`.

**LIST vs GET trap (validated on live tenant):** LIST endpoints return items with
top-level `name`, `metadata: null`, and NO spec. Only a per-object GET (and especially
`?response_format=2`) populates `metadata` and the spec. Never read `metadata.name` or
audit a spec off a LIST item — use `xc_client.obj_name()` and GET the object first.

## Config surface map

All change-relevant spec shapes with exact JSON fragments are in
`references/mitigation-objects.md` (blocked/trusted clients, service policies, rate
limits, malicious-user mitigation) and `references/exclusion-rules.md` (the
`waf_exclusion_rules` grammar: match criteria + `app_firewall_detection_control` with
`exclude_signature_contexts` / `exclude_attack_type_contexts` /
`exclude_violation_contexts`, vs `waf_skip_processing`). Key facts:

- **Exclusion rules live on the HTTP LB spec**, not on the app_firewall object.
- **app_firewall** spec toggles: `blocking`/`monitoring` (oneof), detection settings
  (signature selection, threat campaigns, violation controls, bot protection level),
  `allowed_response_codes`, custom blocking page.
- **blocked_clients[] / trusted_clients[]** on the LB spec: `ip_prefix`, `as_number`, or
  `http_header` matchers with optional expiry (`expiration_timestamp`) — the fastest
  targeted mitigation, prefer over service-policy edits for single-IP blocks.
- **service_policys**: ordered rules over ip_prefix_list/asn/country/headers/path with
  ALLOW/DENY; attached to the LB via `active_service_policies`.
- **Enforcement-mode flip** (monitoring→blocking) is an app_firewall spec change; treat as
  high-blast-radius — always precede with a staging analysis (`xc-waf-tuning`).

## Change-script contract (mandatory)

Every generated script:

1. Loads creds from env vars; constructs `XCClient(allow_write=True)` (imports the shared
   client from `xc-security-events/scripts/xc_client.py`).
2. GETs the target with `?response_format=2`, captures `resource_version`.
3. Applies the mutation to the spec **in code, visibly** — no opaque blobs.
4. Prints a unified diff of current vs proposed spec, then exits (`--dry-run` default).
5. `--apply` performs the PUT carrying `resource_version`; on 409, re-GET and re-diff,
   never blind-retry.
6. Idempotent: re-running detects "already applied" and no-ops.
7. Never deletes unless the user explicitly asked for a delete script; delete scripts
   additionally require `--yes-delete <object-name>` echoing the name.

Template: `scripts/change_script_template.py`. Audit runner: `scripts/xc_config_audit.py`.
Write generated scripts to `changes/<ns>_<object>_<yyyymmdd>_<slug>.py` and reference the
path in your summary.
