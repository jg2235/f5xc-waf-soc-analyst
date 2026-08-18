## What changed

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- What was broken or missing. For a field-naming fix, paste the API error or
     the zero-result query that proved it. -->

## Verification

- [ ] `python3 tests/test_docs.py` passes
- [ ] `bash scripts/build.sh` succeeds
- [ ] `claude plugin validate .` passes
- [ ] Ran against a live tenant (`smoke_test.py --ns <ns>`) — **required for any
      change that names an API field, filter key, or endpoint**

<!-- If you documented a field name, show the proof: -->
```
paste the query and its result / the HTTP 400 that confirms the enum
```

## Checklist

- [ ] `CHANGELOG.md` updated
- [ ] No tenant, customer, or personal data in the diff (no source IPs, hostnames,
      support IDs, tenant identifiers)
- [ ] Nothing under `reports/` or `changes/` is staged
- [ ] Read-only stance preserved — no skill writes to the tenant
- [ ] Any generated change script keeps the full contract (dry-run default, diff,
      `--apply`, `resource_version`, backup, `--rollback`)
