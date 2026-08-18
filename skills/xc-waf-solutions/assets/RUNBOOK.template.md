# {{PREFIX}} — {{SOLUTION}} Runbook
Tenant: {{TENANT}} · Namespace: {{NAMESPACE}} · Generated: {{DATE}}

Apply scripts in order. Every script: dry-run first, review diff, then --apply.
Do not cross a GATE until its validation passes.

{{STAGES_TABLE}}

Rollback: each applied script wrote changes/backups/<obj>_<ts>.json; restore with
`<script> --rollback <backup>`.
