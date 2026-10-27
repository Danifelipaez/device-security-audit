# Download trust: defending against stolen certificates and impersonated sources

Read this before phase 3 (updates) and whenever the user downloads or installs anything outside winget.

## The threat, in one paragraph

"HTTPS + valid signature" is no longer proof of origin. Recent cases (current as of Oct 2026; search for newer CA compromises in phase 2, and treat the fix versions below as minimums):
- **eMudhra (Oct 2026):** eight intermediate CA keys were generated with weak randomness. Anyone holding them can mint a TLS certificate for *any* domain, so a look-alike or hijacked download site shows a padlock. Two of the intermediates chain to a Microsoft-trusted code-signing root (`emSign Root CS CA - G3`).
- **Fox Tempest (May 2026):** a signing-as-a-service crew used fake identities to get short-lived (≈72 h) Microsoft-issued code-signing certificates and sold them to ransomware gangs. They signed fake AnyDesk, Teams, PuTTY and Webex installers.
- **Stolen vendor certificates:** the Nvidia certificates leaked by Lapsus$ were used to sign Cobalt Strike and Mimikatz.

Browsers patched the eMudhra keys within hours. **The gap is everything that downloads code without a browser**: package managers, installers, auto-updaters, language runtimes and Electron apps. Each one ships its own copy of the trusted root certificates (its "trust store"). That is why installers get updated first.

## Layer 1: the tools that download must distrust bad CAs (do this first)

Run `scripts/trust-probe.ps1`. It points each download client at test endpoints that serve forged or revoked chains:
- **"ACCEPTS (vulnerable)"** means that client's trust store is stale. Update it before using it to install anything else.
- **"accepts (no revocation check)"** on `revoked.badssl.com` is normal for OpenSSL-based clients. Note it, but it is not a stale store.

Stores to keep in mind on Windows:

| Client | Trust store | Fixed in (eMudhra) |
|---|---|---|
| winget, PowerShell, curl.exe, browsers (Edge/Chrome), .NET | Windows root store plus the disallowed-certificates list (CTL), updated by Windows | Microsoft blocked the intermediates on 20 Oct 2026. Check that `DisallowedCertLastSyncTime` is recent and `DisableRootAutoUpdate` is unset. |
| pip | bundled `pip/_vendor/certifi` (ignores the user's certifi) | pip 26.2.2 |
| Python libraries (requests, httpx…) | `certifi`. Can exist twice: in base site-packages and in user site-packages | certifi 2026.10.19 |
| uv | bundled webpki roots | uv 0.13.4 |
| Node.js / npm / pnpm | bundled CA list | Node 22.23.4 / 24.22.1 / 26.12.1 |
| Electron apps (VS Code, Discord, Claude, Insomnia, Antigravity…) | Chromium's built-in list | Electron 42.11.16 / 43.8.1 / 44.9.1; update the apps |
| Git for Windows | `http.sslBackend`: `schannel` uses the Windows store, `openssl` uses the bundled `ca-bundle.crt` | Update Git, or set `schannel` |
| Java | JDK `cacerts` | vendor-dependent; treat as unpatched until confirmed |
| Bundled Pythons (gcloud, Azure CLI) | their own certifi | update the CLI |
| WSL / Docker images | distro `ca-certificates` | Ubuntu 20260816ubuntu0.*, Debian 20250419+deb13u1, Alpine 20261020-r0; rebuild images |

The safest default is to make clients use the OS store, which Microsoft updates centrally. The owner can opt in with:
- `git config --global http.sslBackend schannel`
- `pip install truststore`, then set `PIP_USE_FEATURE=truststore` (or `--use-feature=truststore`)
- `NODE_OPTIONS=--use-system-ca` (Node 23.8+)

These are configuration changes, so list them for the owner and don't apply them yourself.

## Layer 2: where the bytes come from

1. **Prefer a package manager that verifies a hash pinned in a reviewed manifest.** winget checks the installer's SHA256 against the manifest in `microsoft/winget-pkgs`. Even a perfectly signed impostor fails if its bytes differ. This is stronger than any certificate check.
2. **Never install from search ads, "download mirrors", links in DMs, or YouTube descriptions.** Impersonation campaigns buy ads for AnyDesk, Notepad++, 7-Zip, WinRAR, OBS and similar tools. Type the vendor domain, or use the winget ID.
3. **The 24 h rule** (SKILL.md) also catches this class of attack. Malicious releases and certificates are usually revoked or pulled within a day.
4. **Pin exact versions** when installing (`--version`, `pkg@x.y.z`, `pkg==x.y.z`). Otherwise, a newer release published between your check and your install slips through.

## Layer 3: verify anything installed by hand

Run `scripts/verify-download.ps1 -Path <file> -ExpectedPublisher '<company>' [-Sha256 <vendor hash>]`. It flags:
- Signature not `Valid`, or the signer does not match the expected publisher. A look-alike name (e.g. "AnyDesk Software GmbH" vs "AnyDesk Softvare GmbH") counts as a mismatch.
- A signing certificate valid for 7 days or less, or issued in the last 14 days. These are the Fox Tempest pattern. Some real vendors use short-lived Azure Artifact Signing certificates, so cross-check the publisher's history before trusting one.
- A chain through a disallowed CA, or through emSign/eMudhra.
- A missing timestamp, or a hash mismatch.
- Where the file came from: the Mark-of-the-Web `HostUrl`/`ReferrerUrl`. That shows the real download site even when the file name looks official.

A "DO NOT RUN" verdict goes in the report; don't argue it away.

## Layer 4: OS controls that block the payload even if the first three fail

These are owner commands (elevated PowerShell). Explain each in the report; don't run them.

| Control | Command | Why |
|---|---|---|
| Defender Network Protection | `Set-MpPreference -EnableNetworkProtection Enabled` | Blocks known-bad download and C2 domains for every process, not just the browser |
| PUA blocking | `Set-MpPreference -PUAProtection Enabled` | Blocks bundleware from fake download sites |
| ASR: block executables unless prevalent, old enough, or trusted | `Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled` | A freshly signed, never-seen binary is blocked even with a valid signature, which defeats the stolen-certificate case |
| ASR: block abuse of vulnerable signed drivers | `Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled` | Signed-but-vulnerable drivers (BYOVD), e.g. RTCore64.sys |
| Microsoft vulnerable driver blocklist | Windows Security → Device security → Core isolation → *Microsoft Vulnerable Driver Blocklist* | Same, enforced by the kernel |
| SmartScreen for apps | Windows Security → App & browser control → Reputation-based protection → on | Prompts on low-reputation downloads regardless of signature |
| Keep CTL auto-update on | make sure the `DisableRootAutoUpdate` policy is absent | This is how Windows receives distrust of compromised CAs |

On Windows 11, add Smart App Control. It blocks unknown apps by cloud reputation, not by signature.

## How to report it

In the report, add a **"Download trust"** section:
- The `trust-probe` table.
- Every client that ACCEPTS a bad chain, with the update that fixes it. Those updates go in the critical tier.
- The OS controls from layer 4 that are not yet enabled.
