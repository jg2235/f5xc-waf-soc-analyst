# Credentials — least privilege

Create a dedicated API token (Administration > Credentials > API Token) bound to a
service account, not your user. Role assignment for this plugin's read-only design:

- Monitor-scope role on target namespaces (security events, access logs, metrics)
- Read-only config role (ves-io-monitor or a custom role with GET on config APIs)
- NO write roles. The generated change scripts are executed by a HUMAN with their own
  (write-capable) token — keeping analysis and change authority on separate identities
  is the point of the read-only design.

Scope the token to the namespaces you actually work in. See `namespace-scope.md`: the
tooling refuses to run without an explicit namespace scope, and your token should not be
able to read the rest of the tenant either.

Set an expiry on the token (max 90d recommended).

## Supplying the token

**Never write the token to a file this tooling reads.** Plaintext credential files get
backed up, synced, and committed by accident, and they survive long after the operator
has forgotten them.

Preferred — `F5XC_TOKEN_CMD`, a command that prints the token on stdout. The secret stays
in your vault, secret manager, or OS keyring; the client executes the command, holds the
value in memory, and never persists it:

    export F5XC_TENANT="<tenant>"          # the label in your console URL:
    #                                        https://<tenant>.console.ves.volterra.io
    export F5XC_NAMESPACES="prod,staging"  # standing namespace scope

    # pick whichever your organization already uses
    export F5XC_TOKEN_CMD='vault read -field=token secret/f5xc/readonly'
    export F5XC_TOKEN_CMD='op read op://infra/f5xc/api-token'
    export F5XC_TOKEN_CMD='aws secretsmanager get-secret-value --secret-id f5xc --query SecretString --output text'
    export F5XC_TOKEN_CMD='az keyvault secret show --vault-name kv --name f5xc --query value -o tsv'
    export F5XC_TOKEN_CMD='secret-tool lookup service f5xc'          # Linux keyring
    export F5XC_TOKEN_CMD='security find-generic-password -w -s f5xc' # macOS Keychain

Acceptable — `F5XC_API_TOKEN` directly, for CI with a masked secret, or a short-lived
interactive session. Discouraged on shared or long-lived workstations.

    read -rs F5XC_API_TOKEN && export F5XC_API_TOKEN    # not echoed, not in history

`F5XC_API_URL` overrides the console URL entirely, for staging or region-specific
endpoints.

Never commit tokens; never paste tokens into chat; scripts never log headers. If a token
has been in a plaintext file, treat it as disclosed and rotate it.

Rotation: revoke via POST /api/web/namespaces/system/bulk_revoke/api_credentials.

## Engagement output

`reports/` and `changes/` hold live-tenant analysis — tenant ids, namespaces, source IPs,
support IDs, customer hostnames. Both are gitignored. Keep them local or move them to a
private evidence store; never commit them, and scrub tenant identifiers before sharing any
excerpt publicly.
