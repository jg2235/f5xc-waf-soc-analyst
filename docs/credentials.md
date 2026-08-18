# Credentials — least privilege

Create a dedicated API token (Administration > Credentials > API Token) bound to a
service account, not your user. Role assignment for this plugin's read-only design:

- Monitor-scope role on target namespaces (security events, access logs, metrics)
- Read-only config role (ves-io-monitor or a custom role with GET on config APIs)
- NO write roles. The generated change scripts are executed by a HUMAN with their own
  (write-capable) token — keeping analysis and change authority on separate identities
  is the point of the read-only design.

Set an expiry on the token (max 90d recommended). Export as env vars only:

    export F5XC_TENANT="<tenant>"          # e.g. f5-amer-ent
    # API base defaults to https://$F5XC_TENANT.console.ves.volterra.io
    # Override for staging/region endpoints:
    # export F5XC_API_URL="https://<tenant>.console.ves.volterra.io"
    export F5XC_API_TOKEN="$(security find-generic-password -w -s f5xc-token 2>/dev/null || cat ~/.f5xc/token)"

Never commit tokens; never paste tokens into chat; scripts never log headers.
Rotation: revoke via POST /api/web/namespaces/system/bulk_revoke/api_credentials.
