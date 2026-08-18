#!/usr/bin/env bash
# SessionStart hook: verify F5 XC credentials are present. Never prints secrets.
set -u
missing=()
[ -z "${F5XC_TENANT:-}" ] && missing+=("F5XC_TENANT")
[ -z "${F5XC_API_TOKEN:-}" ] && missing+=("F5XC_API_TOKEN")
if [ ${#missing[@]} -gt 0 ]; then
  echo "[f5xc-waf-skills] Missing env vars: ${missing[*]}. Live-tenant queries disabled;"
  echo "offline mode (script generation, pasted-config review) still available."
  echo "Least-privilege token guidance: docs/credentials.md"
else
  echo "[f5xc-waf-skills] Credentials present for tenant '${F5XC_TENANT}'. (Token not displayed.)"
fi
exit 0
