# MITRE ATT&CK Mapping for XC WAF Telemetry

Map findings, not raw signature hits. Common mappings:

| Observation | Tactic | Technique |
|---|---|---|
| Broad 404/path spraying, scanner UA/sigs | Reconnaissance | T1595.002 Vulnerability Scanning |
| Directed probing of discovered API endpoints | Reconnaissance | T1595.003 Wordlist Scanning |
| SQLi attempts (ATTACK_TYPE_SQL_INJECTION) | Initial Access | T1190 Exploit Public-Facing Application |
| Command-injection / RCE payloads | Initial Access / Execution | T1190 -> T1059 |
| Path traversal / LFI | Initial Access | T1190 (collection follows: T1005) |
| XSS payloads at stored-content endpoints | Initial Access | T1189-adjacent / T1190 |
| Credential stuffing (bot, login path, UA rotation) | Credential Access | T1110.004 Credential Stuffing |
| Password spraying pattern (many users, few pwds) | Credential Access | T1110.003 |
| Session/token endpoint abuse | Credential Access | T1539 / T1550.004 |
| Scraping at scale | Collection | T1213-adjacent (note: business risk framing often fits better) |
| SSRF-pattern payloads (internal IP/metadata URLs in params) | Initial Access | T1190; cloud metadata theft T1552.005 |
| Deserialization / template-injection sigs | Execution | T1203 / T1190 |
| threat_campaigns[] named match | use the campaign's published mapping; cite the campaign name |

Rules: one row per finding in the report's MITRE table with technique ID + the evidence
reference [Qn]. Identify kill-chain gaps explicitly ("no post-exploitation indicators
observed" is a finding). Do not map monitoring-mode FP noise.
