# Contributing

## Ground rule: verify field names against a live tenant

Most defects in this project's history were **documentation naming fields the API
rejects** — and two of them failed *silently*, returning zero results instead of an
error. A wrong filter key does not look like a bug; it looks like a clean finding of
"no events".

So: **if you document a field name, prove it first.**

```bash
export F5XC_TENANT=... F5XC_API_TOKEN=...
python3 skills/xc-security-events/scripts/smoke_test.py --ns <namespace>
```

To check a single aggregation field:

```python
c.sec_events(ns, '{sec_event_type=~".*"}', start, end,
             aggs={"x": {"field_aggregation": {"field": "URI", "topk": 1}}})
```

An unknown field returns HTTP 400 naming the offender — that is the confirmation.
Note the traps already catalogued in `skills/xc-security-events/references/event-schema.md`:

- Security events and access logs use **different field enums**. `REQ_PATH` and
  `RSP_CODE` are valid for access logs and invalid for events.
- The event filter key is `signatures.id`; `signature_id=` returns 0 hits silently.
- `recommended_action` exists on the record but is **not aggregatable**.
- `signature_id` *is* correct in `waf_exclusion_rules` — that is a config object
  field, not a query key. Do not "fix" it.

`tests/test_docs.py` enforces these as regressions. Run it before opening a PR.

## Non-negotiable design constraints

1. **Read-only against the tenant.** Skills query; they never write. Any capability
   that mutates tenant state must be emitted as a generated script for human review.
2. **Generated change scripts** must: read credentials from environment variables
   only; `GET` with `?response_format=2` and carry `resource_version`; default to a
   dry run printing a unified diff; require `--apply` to write; back up before
   mutating; support `--rollback`; and be idempotent. Never weaken these rails.
3. **Narrowest-scope exclusions.** signature-ID + context + path beats path-only
   beats domain-wide. Never generate `waf_skip_processing` unless the user has
   explicitly accepted a full bypass.
4. **Evidence discipline.** A signature firing is a lead, not a finding. Claims in
   skill documentation should be reproducible from a query.

## Development

```bash
pip install -r requirements.txt
python3 -m pytest tests/ -q          # or: python3 tests/test_docs.py
bash scripts/build.sh                # builds dist/*.skill and the .plugin bundle
claude plugin validate .             # manifest + skill frontmatter check
```

`build.sh` uses the `zip` binary when present and falls back to Python's `zipfile`,
so it works on stock WSL/Ubuntu images without extra packages.

## Making a change

1. Branch from `main`.
2. Make the change; add or update a regression test if you fixed a naming defect.
3. Run the test suite, `build.sh`, and `claude plugin validate .`.
4. Update `CHANGELOG.md` under a new or existing `Unreleased` heading.
5. Open a PR against `main` and fill in the template.

**Never commit** anything under `reports/` or `changes/` — they hold live tenant and
personal data and are gitignored. See `SECURITY.md`.

## Cutting a release

1. Bump `version` in `.claude-plugin/plugin.json`.
2. Move the `Unreleased` section of `CHANGELOG.md` under the new version with a date.
3. `bash scripts/build.sh`
4. Tag `vX.Y.Z` and attach `dist/f5xc-waf-skills-vX.Y.Z.plugin` plus the `.skill`
   bundles to the GitHub Release. `dist/` is gitignored — release assets are the
   distribution channel.
5. Consumers update with:
   `claude plugin update f5xc-waf-skills@f5xc-waf`
   (the bare plugin name fails with "not found" — the marketplace-qualified id is
   required), then restart the session.
