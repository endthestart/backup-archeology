# Security

Backup Archeology works with file inventories and deletion plans, so reports can
contain sensitive path names. Treat generated CSV/JSON plans and manifests as
local artifacts unless you have reviewed them.

## Please Do Not Commit

- Real NAS listings or cleanup plans
- Local SQLite inventories
- Logs, shell history, or terminal transcripts
- API keys, credentials, tokens, private keys, or hostnames
- Personal machine paths

## Reporting Issues

Open a GitHub issue with a minimal synthetic fixture whenever possible. If a bug
requires private paths or backup details to explain, redact them before sharing.
