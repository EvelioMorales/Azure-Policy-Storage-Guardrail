# Security and Publication Notes

## Evidence Sanitization

Only screenshots that were verified not to display the following were included:

- Azure subscription or tenant IDs
- email addresses or user principal names
- object, principal, or client IDs
- access tokens, keys, connection strings, or passwords
- public IP addresses
- unrelated personal resource names

The storage account names, lab resource-group name, policy assignment name, and Microsoft built-in policy definition ID are not credentials. They are retained because they explain the implementation. Storage account names are still unique public DNS labels, so replace them if you prefer not to publish the original lab names.

## Before Publishing

Run these checks from the repository root:

```bash
grep -RInE '(subscriptions/[0-9a-fA-F-]{36}|@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|tenant[Ii]d|client[Ss]ecret|account[Kk]ey|SharedAccessSignature)' . \
  --exclude-dir=.git || true

git diff --cached
```

Visually inspect every image at full resolution before pushing. Never commit raw Cloud Shell transcripts because Azure CLI JSON output often embeds subscription IDs and identity metadata.

## Reporting

If you find sensitive information in a published revision, remove it from the current files, rotate any actual credential immediately, and rewrite Git history if the value remains in prior commits.

