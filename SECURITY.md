# Security Policy

## Reporting a vulnerability

Do **not** open a public issue for a security vulnerability.

Report privately to the maintainer (`jgranieri22@outlook.com`) or via GitHub's
**Security → Report a vulnerability** advisory flow. Include reproduction steps,
affected version, and impact. Expect an acknowledgement within 5 business days.

If the finding concerns the F5 Distributed Cloud product itself rather than this
tooling, route it through F5's product security process instead.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.2 | ✅ |
| 1.0.1 | ⚠️ ships known-invalid field documentation — upgrade |
| 1.0.0 | ❌ unusable: unresolvable API base URL |

## Handling credentials

This project reads credentials **from environment variables only**:
`F5XC_TENANT`, `F5XC_API_TOKEN`, and optionally `F5XC_API_URL`.

- The client never accepts a token as a function argument and never logs headers
  or token material.
- Never paste a token into a skill file, a generated change script, an issue, or a
  pull request.
- Use a least-privilege, time-boxed API token. See `docs/credentials.md`.
- Rotate immediately if a token is exposed; XC tokens cannot be scoped down after
  creation.

## Handling engagement output

`reports/` and `changes/` are **gitignored by default and must stay that way.**

Analysis output routinely contains tenant identifiers, namespaces, customer
hostnames, support IDs, attacker source IPs, and — as observed in practice —
operator home/residential IP addresses. Treat these directories as an evidence
store, not as source. If output must be shared, scrub identifiers first and
distribute through an approved channel.

## Read-only design stance

The tooling is read-only against the tenant by construction:

- `XCClient` blocks write verbs unless explicitly constructed with
  `allow_write=True`, and permits `POST` only to known read/query endpoint
  prefixes.
- Every configuration change is emitted as a standalone script that defaults to a
  dry run, prints a unified diff, requires `--apply` to write, carries
  `resource_version` for optimistic concurrency, writes a backup before mutating,
  and supports `--rollback`.

Report any path that bypasses these guarantees as a security issue.
