# Changelog

## 2.0.0 — 2026-10-26

- **Installers first.** Updates now run in this order: Windows CA lists, winget, then package managers and their trust stores (pip, certifi, uv, Node, Git, PowerShell, gh), and only then apps.
- **Download trust.** New `trust-probe.ps1` checks each download client against forged and compromised certificate chains (eMudhra, Oct 2026). New `verify-download.ps1` vets manually downloaded installers. New `references/download-trust.md` describes a 4-layer defense against stolen certificates and impersonated sources.
- **You choose the updates.** Updates are sorted into critical, medium and app-only tiers, and nothing is installed until the user picks.
- **Deeper inventory, still without admin:** SMB share permissions, SYSTEM service binaries writable by non-admins, missing service binaries that could be re-created, loaded third-party kernel drivers with SHA256 hashes (BYOVD), and inbound firewall rules read from the registry, with orphaned rules flagged.
- **Fixes:** PowerShell 5.1 compatibility, administrators listed by SID on localized Windows, timestamped signatures with an expired signer certificate no longer flagged, and missing revocation checks no longer reported as a stale trust store.

## 1.0.0

- Initial release: inventory, threat research, 24-hour update rule, re-audit report.
