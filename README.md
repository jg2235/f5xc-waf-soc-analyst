# F5 XC WAF Skills — AI Analyst for F5 Distributed Cloud WAAP

A full-stack AI WAF analyst for F5 Distributed Cloud, built as a set of Claude skills and
an operating persona (CLAUDE.md), 'secops-skills`
architecture. Install once and Claude can hunt security events, triage attacks, run
evidence-gated false-positive tuning, audit WAF posture, analyze ML-driven API discovery
and bot/malicious-user intelligence, and roll out whole WAF solutions — entirely from
natural language.

**Design stance: read-only against the tenant.** Every proposed configuration change is
emitted as a standalone, dry-run-default Python script (unified diff → `--apply` with
optimistic concurrency → automatic backup → `--rollback`). Analysis identity and change
identity stay separate (see `docs/credentials.md`).

## Architecture

```
CLAUDE.md                 Principal WAF Analyst persona: session-init protocol,
                          evidence discipline, verdict gates, change-control rules
      │ invokes
      ▼
xc-waf-solutions          Umbrella orchestrator: app onboarding, FP-reduction program,
                          API protection rollout, bot/malicious-user hardening
      │ orchestrates
      ▼
Primitive skills
  xc-security-events      Event/access-log query + aggregation (the query primitive)
  xc-waf-config           Config read/audit + change-script generation
  xc-api-security         ML API discovery, shadow APIs, OpenAPI validation lifecycle
  xc-bot-defense          Bot classification + malicious-user ML analysis
  xc-waf-tuning           Evidence-gated FP reduction and staging go/no-go
  xc-waf-investigator     SHORT/MEDIUM/LONG investigations, MITRE mapping, verdicts
      │ call
      ▼
F5 XC REST API            /api/data (events, logs) · /api/ml/data (AI insights)
                          /api/config (read + human-applied change scripts)
```
## Environment

Set these before starting a session. Exports pass parent→child only, so put them in your
shell profile — setting them in another terminal will not reach a running session.

**Required**

| Variable | Purpose |
|---|---|
| `F5XC_TENANT` | Tenant label from your console URL — `https://<tenant>.console.ves.volterra.io`. Bare label, no domain. |
| one of `F5XC_TOKEN_CMD` / `F5XC_API_TOKEN` | The API token. Startup fails if neither is set. |

**Recommended**

| Variable | Purpose |
|---|---|
| `F5XC_NAMESPACES` | Standing namespace scope, comma-separated. Without it every query needs an explicit `--ns`, because the tooling refuses to guess (`docs/namespace-scope.md`). |

**Optional**

| Variable | Purpose |
|---|---|
| `F5XC_API_URL` | Full base-URL override for staging/regional endpoints. Replaces the tenant-derived URL — set this *or* `F5XC_TENANT`. |
| `F5XC_NAMESPACE` | Singular. Read only by `change_script_template.py` as a generated script's target namespace; unused by queries. |

```bash
# --- identity -------------------------------------------------------------
export F5XC_TENANT="your-tenant"

# --- token: pick ONE ------------------------------------------------------
# preferred — the secret stays in your vault/keyring and never lands on disk
export F5XC_TOKEN_CMD='secret-tool lookup service f5xc'               # Linux keyring
# export F5XC_TOKEN_CMD='op read op://infra/f5xc/api-token'           # 1Password
# export F5XC_TOKEN_CMD='vault read -field=token secret/f5xc/readonly'
# export F5XC_TOKEN_CMD='aws secretsmanager get-secret-value --secret-id f5xc --query SecretString --output text'
# export F5XC_TOKEN_CMD='security find-generic-password -w -s f5xc'   # macOS Keychain

# fallback — CI with a masked secret, or a short-lived session
# read -rs F5XC_API_TOKEN && export F5XC_API_TOKEN

# --- scope ----------------------------------------------------------------
export F5XC_NAMESPACES="prod,staging"
```

Verify before working:

```bash
python3 -c "
import sys;sys.path.insert(0,'skills/xc-security-events/scripts')
from xc_client import XCClient
print('OK —', len(XCClient().get('/api/web/namespaces')['items']), 'namespaces visible')"
```

Two failure modes that look alike but are not:

- **`302` → `/login/start`** with a `not-found ... cname` body — `F5XC_TENANT` is wrong;
  the hostname does not resolve to a tenant, and your token was never evaluated.
- **`401 credential invalid`** — the tenant resolved and the credential was rejected.
  Check expiry (90d max), and that you created an *API Token*, not an API Certificate.

Never put the token in a file the tooling reads. If it has been in a plaintext file,
treat it as disclosed and rotate it. Full guidance: `docs/credentials.md`.


## Install

1. `export F5XC_TENANT=... F5XC_API_TOKEN=...` (least-privilege read token —
   `docs/credentials.md`).
2. Install the plugin (or individual `.skill` files from `dist/` after
   `./scripts/build.sh`).
3. **Validate against your tenant** (the S1 stack ships live-validated schemas; this
   plugin validates at install instead):
   `python3 skills/xc-security-events/scripts/smoke_test.py --dump-sample`
   PASS/FAIL per endpoint; `[T]`-marked ML endpoints failing with 403/404 usually means
   the Advanced WAAP / API Security entitlement, not a wrong path.
4. Optional: create a project named `PrincipalWAFAnalyst`, drop `CLAUDE.md` in its folder.
   Every session then auto-runs tenant inventory + a 24h event pulse.

## Example session starters

```
Give me the 24h security pulse across all namespaces
Investigate 203.0.113.7 — is this a real attack?
A customer got blocked, support ID 17423986...— find it and tell me why
Rank WAF noise for the prod namespace and propose exclusions
Are we ready to flip prod-web to blocking mode?
What shadow APIs is the ML seeing on api-gw that aren't in our OpenAPI spec?
Harden the login endpoint against credential stuffing
Onboard checkout.example.com behind the WAF end to end
```

## Layout

```
.claude-plugin/plugin.json    manifest + SessionStart creds hook
.claude-plugin/marketplace.json  local marketplace descriptor
CLAUDE.md                     persona / operating layer
docs/credentials.md           least-privilege token setup
skills/<name>/SKILL.md        skill instructions
skills/<name>/references/     API anatomy, schemas, doctrine
skills/<name>/scripts/        shared client, runners, audit, smoke test, change template
scripts/build.sh              package .skill + .plugin into dist/
tests/test_docs.py            regression guard for API field-naming defects
changes/                      generated change scripts   (gitignored — tenant data)
reports/                      investigation output       (gitignored — tenant data)
dist/                         build artifacts            (gitignored — release assets)
```

## Development

```bash
pip install -r requirements.txt
python3 tests/test_docs.py       # doc/API-naming regression suite
bash scripts/build.sh            # build dist/*.skill and the .plugin bundle
claude plugin validate .         # manifest + frontmatter check
```

Field names in this project are verified against a live tenant before they are
documented, and frozen as regressions in `tests/test_docs.py`. Several past defects
were names the API **silently** rejects — a wrong filter key returns zero hits rather
than an error, which reads as a clean finding. See `CONTRIBUTING.md` before changing
any documented field, filter key, or endpoint.

## Data handling

`reports/` and `changes/` are gitignored and must stay that way. They hold live
tenant identifiers, customer hostnames, support IDs, and source IP addresses.
See `SECURITY.md`.

## Project docs

| File | Purpose |
|---|---|
| `CONTRIBUTING.md` | how to develop, test, and cut a release |
| `SECURITY.md` | vulnerability reporting, credential and output handling |
| `CHANGELOG.md` | version history |
| `CODE_OF_CONDUCT.md` | participation expectations |
 
## Screenshots
<img width="1213" height="890" alt="image" src="https://github.com/user-attachments/assets/00b776ad-6ca4-4911-b93e-f2fbe16fb308" />

<img width="757" height="691" alt="image" src="https://github.com/user-attachments/assets/7de78edc-98cf-4f98-95f9-7ff7c17535dc" />

<img width="737" height="457" alt="image" src="https://github.com/user-attachments/assets/6dda896d-d0ef-4138-b6df-4dab266fbb02" />

<img width="702" height="599" alt="image" src="https://github.com/user-attachments/assets/fcc916d4-933c-4fc8-bf85-0380e8ca2553" />



## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
