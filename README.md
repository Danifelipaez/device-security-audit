<h1 align="center">device-security-audit</h1>

<p align="center">
  <b>An agent skill that audits and hardens a Windows PC like a security engineer would — and doesn't touch your security settings behind your back.</b>
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-2.0.0-blue">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6">
  <img alt="Claude Code" src="https://img.shields.io/badge/Claude%20Code-plugin-D97757">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
</p>

Ask your agent *"is my computer safe?"* or *"patch everything"*. It inventories what is exposed, checks whether any of it has been exploited in the wild, makes sure your installers can't be fooled by a stolen or forged certificate, asks you which updates to apply, installs them in a safe order, and re-audits to prove what changed.

**Key features:**

- **Real attack surface, not a checklist.** Listening ports with their owning process, SMB shares open to `Everyone`, an enabled Guest account, SYSTEM services whose binary any user can overwrite, unquoted service paths, orphaned firewall rules, and loaded vulnerable signed drivers (BYOVD), all without admin rights.
- **Exploitation research with sources.** Each exposed service, outdated program and third-party driver is checked against CISA KEV, vendor advisories and "exploited in the wild" reports. The report cites every claim.
- **Download trust.** `trust-probe.ps1` points every download client (Windows, Node, pip, certifi, Git) at test sites that serve forged or compromised certificate chains, such as the [eMudhra CA key compromise](https://blog.cloudflare.com/emudhra-certificate-compromise/). A client that connects anyway gets fixed before it downloads anything else.
- **Installers first.** winget, pip, uv, Node, Git and the other package managers are updated before any app, so every later update comes through a client that can tell a forged site from the real one.
- **24-hour rule.** Only versions that have been installable for at least 24 h, measured from the winget-pkgs manifest merge date rather than the vendor's release date. Every install is pinned to the exact version checked.
- **You choose.** Updates are grouped into **critical / medium / app-only** and nothing is installed until you pick.
- **Hands off your settings.** Firewall, ACLs, services, accounts, Defender/ASR and trust-store config are never changed by the agent. You get the exact elevated command and the risk it closes.

## Why this exists

"HTTPS + valid signature" stopped being proof of origin in 2026:

- **eMudhra (Oct 2026).** Eight intermediate CA keys were generated with weak randomness, so anyone could mint a padlock for any domain. Browsers patched within hours. pip, Node, uv, certifi, Git and Electron apps each ship **their own** list of trusted root certificates and needed separate updates.
- **Fox Tempest (May 2026).** A signing-as-a-service crew bought short-lived Microsoft code-signing certificates and signed fake AnyDesk, Teams and PuTTY installers for ransomware gangs.
- **Stolen vendor certificates.** Nvidia's leaked keys signed Cobalt Strike and Mimikatz.

The weak spot is everything that downloads code without a browser. An outdated package manager can hand you malware from a site that looks perfectly signed, and then every update after it is suspect too. This skill checks those clients first and verifies anything you install by hand.

## Installation

### Claude Code (plugin marketplace)

```
/plugin marketplace add Danifelipaez/device-security-audit
/plugin install device-security-audit@device-security-audit
```

### Claude.ai / Claude desktop

Download `device-security-audit.skill` from the [latest release](https://github.com/Danifelipaez/device-security-audit/releases/latest) and upload it under **Settings → Capabilities → Skills**.

### Manual (any agent that reads `SKILL.md`)

```bash
git clone https://github.com/Danifelipaez/device-security-audit
cp -r device-security-audit/skills/device-security-audit ~/.claude/skills/
```

## Requirements

| Needed | Why |
|---|---|
| Windows 10 or 11 | Every check is Windows-specific |
| PowerShell 7+ (5.1 works for the scripts) | Runs the bundled scripts |
| [winget](https://learn.microsoft.com/windows/package-manager/winget/) | Lists and installs updates |
| [GitHub CLI](https://cli.github.com/), authenticated (`gh auth login`) | Reads manifest merge dates from `microsoft/winget-pkgs` (unauthenticated calls are capped at 60/hour) |
| Python 3.11+ *(optional)* | Probes certifi and pip's bundled CA list |
| Internet access to `*.badssl.com` and `*.we-have-a-problem.com` | Test endpoints for the trust probe |
| Web search in the agent | Threat research |

The agent session doesn't need to be elevated. Installers raise UAC prompts; accept the ones you expect.

## Usage

Just ask, in any language:

```
Is my laptop safe? Audit it and tell me what to fix.
revisa la seguridad de este pc, NO instales nada, solo quiero el informe
is anything on this machine exposed to my home wifi that shouldn't be?
what updates are pending, and which have been out more than 24 hours?
check that this installer is legit: ~/Downloads/AnyDesk.exe
```

Say *"don't change anything"* and it stops after the report.

## How it works

```
1. Inventory      read-only   inventory.ps1 · update-age.ps1 · trust-probe.ps1 · npm/pip outdated · service configs
2. Research       read-only   CISA KEV, vendor advisories, "exploited in the wild", recent CA compromises
3. Ask → update               sort into critical / medium / app-only → you pick →
                              Windows CA lists → winget → package managers → re-probe → critical → medium → apps
4. Re-audit       read-only   re-run all three scripts, diff, write the report
```

The report is a Markdown file with these sections: executive summary, attack surface, known threats, download trust, updates applied, **pending for the owner** (each item with a copy-paste admin command, ranked by severity), skipped and why, and sources.

## The scripts work on their own

Every script is read-only and runs without the agent:

```powershell
pwsh -File skills/device-security-audit/scripts/inventory.ps1 > inventory.txt
pwsh -File skills/device-security-audit/scripts/update-age.ps1 -MinHours 24
pwsh -File skills/device-security-audit/scripts/trust-probe.ps1
pwsh -File skills/device-security-audit/scripts/verify-download.ps1 -Path .\setup.exe -ExpectedPublisher 'VideoLAN'
```

Sample `trust-probe.ps1` output on a machine that still needs a pip update:

```
Client                      Target                              Result
------                      ------                              ------
Windows (schannel/curl.exe) dv-g3b-emudhra.we-have-a-problem.com rejects
Node.js                     dv-g3b-emudhra.we-have-a-problem.com rejects
pip (vendored certifi)      dv-g3b-emudhra.we-have-a-problem.com ACCEPTS (vulnerable)
Node.js                     revoked.badssl.com                  accepts (no revocation check)
...
DisallowedCertLastSyncTime: 2026-10-26 09:14
DisableRootAutoUpdate policy: not set (good)
```

`verify-download.ps1` ends with `VERDICT: DO NOT RUN` (and the reasons) or `no red flags`. It flags an unexpected signer, a certificate valid for 7 days or less, one issued in the last 14 days, a chain through a distrusted CA, a missing timestamp, a hash mismatch, and the real download URL saved by Mark-of-the-Web.

## Safety model

| The agent does | The agent never does |
|---|---|
| Reads system state | Changes firewall rules, ACLs, services, accounts or the registry |
| Researches threats on the web | Changes Defender, ASR or SmartScreen settings |
| Installs the updates **you** selected, pinned to the checked version | Installs anything under 24 h old or that you didn't pick |
| Updates Defender signatures | Retries failed elevated actions in a loop |
| Writes the report and the commands for you to run | Kills processes or deletes your files |

## What's inside

```
.claude-plugin/          plugin + marketplace manifests
skills/device-security-audit/
├── SKILL.md             the four-phase workflow and ground rules
├── scripts/
│   ├── inventory.ps1        attack surface, no admin needed
│   ├── update-age.ps1       winget upgrades + age from winget-pkgs
│   ├── trust-probe.ps1      do download clients reject bad chains?
│   └── verify-download.ps1  is this installer what it claims to be?
└── references/
    └── download-trust.md    4-layer strategy against stolen certs and impersonation
evals/                   3 read-only test cases (claude plugin eval format)
```

## Evals

`evals/` holds three read-only cases (a full audit in Spanish, update eligibility, and LAN exposure in English) with machine-independent graders, in the [`claude plugin eval`](https://code.claude.com/docs) case format.

> **Windows note:** `claude plugin eval` refuses to grant PowerShell/Bash without an OS sandbox, and Windows has none yet, so the suite can't run there unattended. Benchmarks below were run with the [skill-creator](https://github.com/anthropics/skills/tree/main/skills/skill-creator) method instead: one agent with the skill and one without, per case, graded against the same assertions.

**v2.0.0 benchmark** (Opus 5.5, Windows 10 22H2, 1 run per case and configuration, 21 assertions):

| | With skill | Without skill |
|---|---|---|
| Assertions passed | **20 / 21 (96%)** | 19 / 21 (92%) |
| Mean time per task | 443 s | 299 s |
| Mean tokens per task | 137k | 102k |

The assertions check whether something was covered at all, and a strong model covers the obvious things without help. The full audit is where the two differ:
- **Download trust.** With the skill, every download client is probed. That run found a bundled Python (Azure CLI) that still trusts the compromised eMudhra CA. The baseline didn't check download trust at all.
- **Fix commands.** With the skill, every pending fix comes with an elevated PowerShell command. The baseline gave prose instructions.
- **Depth.** The skill run also found a leftover service that any user can start and that points to a missing binary in a writable folder, an immediate path to SYSTEM. It checked driver hashes against LOLDrivers and listed the Defender controls (Network Protection, ASR rules, vulnerable driver blocklist) that are not enabled.

The baseline made one wrong claim, which the skill run avoided: it read an account with no password as "password changed today".

The cost is about 45% more time and 35% more tokens.

## Limitations

- Windows only. macOS and Linux are not supported yet; PRs are welcome.
- Certificate-incident data (fix versions, ASR rule IDs) is current as of **October 2026**. The agent searches for newer incidents, but update `references/download-trust.md` when a new one lands.
- Microsoft Store apps and self-updating launchers (Steam, Epic, Battle.net) are reported, not updated.
- It is an audit aid, not a replacement for EDR or a professional pentest.

## Contributing

Issues and PRs are welcome, especially new checks for `inventory.ps1`, trust-probe targets for new CA incidents, and macOS/Linux ports. Keep every script read-only, and keep security-setting changes as commands for the owner to run.

To report a vulnerability in the skill itself, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Daniel Paez

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Danifelipaez/device-security-audit&type=Date)](https://star-history.com/#Danifelipaez/device-security-audit&Date)
