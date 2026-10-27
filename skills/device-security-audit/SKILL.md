---
name: device-security-audit
description: Audit and harden the local Windows machine like a security engineer. Inventories services, listening ports, shares, drivers, installed programs and CLIs; researches whether each has been exploited in the wild; checks that installers and package managers distrust compromised or stolen certificates (eMudhra-style CA compromise, signed-malware impersonation); asks the user which updates to apply, grouped by threat level; applies updates that have been public ≥24h via CLI, installers first; then re-audits and writes a report. Use this whenever the user asks to secure, harden, "blindar", patch, update everything, check attack surface, verify a download is legit, look for vulnerabilities, or audit their PC/laptop/device, even if they only say "actualiza todo" or "is my computer safe?".
compatibility: Windows 10/11, PowerShell 7+ (5.1 works for the scripts), winget; gh (authenticated) for update-age checks; Python 3.11+ for the Python trust probes; WebSearch for threat research; AskUserQuestion for the update choice (falls back to asking in chat).
---

# Device security audit & hardening (Windows)

The goal is a machine with a smaller attack surface, no known-exploited software, and download tools that can't be fooled by a forged certificate. It ends with an honest report of what changed and what still needs the owner. Work in four phases and keep a list of findings as you go. Every finding ends up in the report.

## Ground rules

- **Read-only until phase 3.** Inventory and research change nothing. If the user says "solo revisa" / "don't change anything", stop after phase 2 and write the report.
- **24-hour rule.** Only install a version that has been public for at least 24h. Brand-new releases sometimes get pulled, or turn out to be supply-chain attacks. A day lets that surface.
  - `scripts/update-age.ps1` measures age from the winget-pkgs manifest merge date. That date counts, not the vendor's release date: it is when the bytes became installable through this channel.
  - For npm: `npm view <pkg> "time[<ver>]"`. For PyPI: `https://pypi.org/pypi/<pkg>/<ver>/json`.
  - Pin the exact version you checked (`--version`, `pkg@ver`, `pkg==ver`). Otherwise a newer, unchecked release slips in between the check and the install.
- **Updating software is yours to do; changing security settings is the owner's.** Firewall rules, ACLs, service configs, accounts, registry policies, Defender/ASR settings, trust-store config: write the exact admin command in the report for the user to run. Software updates and signature updates are fine to run, once the user has picked them (phase 3).
- **The session is usually not elevated.** winget installers raise UAC prompts; tell the user up front to accept them. Things that fail for lack of admin go in the report, not in a retry loop. `Get-NetFirewallRule` is denied without admin, so the inventory reads rules from the registry instead.
- **Beware MSIX path virtualization.** Inside a packaged app (e.g. Claude desktop), files written under `%APPDATA%` may really live in `%LOCALAPPDATA%\Packages\<pkg>\LocalCache\Roaming\...`. If a script you just wrote "doesn't exist", look there.

## Phase 1: Inventory (read-only)

Run these three scripts:
1. `scripts/inventory.ps1` covers:
   - OS/build, admin status.
   - Listening TCP/UDP with the owning process.
   - Third-party services: unquoted paths, and **service binaries writable by non-admins**.
   - SMB shares and their permissions; local accounts (Guest!).
   - Loaded third-party **kernel drivers**, with hashes for BYOVD lookups.
   - Firewall profiles and third-party inbound allow rules (including orphans whose program no longer exists).
   - Defender, CLIs, hotfixes, pending Windows Update, startup entries.
2. `scripts/update-age.ps1` lists every winget upgrade with its age and whether it passes the 24h rule.
3. `scripts/trust-probe.ps1` checks whether each download client (Windows, Node, pip, certifi, Git) rejects forged/compromised TLS chains, and whether Windows is receiving CA distrust updates. Read `references/download-trust.md` to interpret it.

Also check:
- `npm outdated -g`, `python -m pip list --outdated`, WSL distros.
- For each **network-listening** service, its config: PostgreSQL `listen_addresses` and `pg_hba.conf`, Ollama `OLLAMA_HOST`, Docker exposed ports, and spacedesk/remote-desktop tools.

What actually gets people owned, roughly in order:
- **Anonymous file access.** Guest enabled plus shares granting `Everyone`, especially if SMB is allowed on the Public profile.
- **Writable paths in a SYSTEM service's chain.** These are local privilege escalations: a service binary or folder that Everyone/Users/Authenticated Users can modify, or an unquoted path whose parent is writable. A non-system drive root (`D:\`) often grants `Authenticated Users:(M)`. Leftover services from uninstalled software are common culprits. Check for planted files, and verify Authenticode signatures of service binaries.
- **Vulnerable signed drivers (BYOVD)** loaded from vendor utilities (RTCore64, WinIo, NTIOLib…). Match hashes against loldrivers.io.
- **Download clients with stale trust stores** (trust-probe "ACCEPTS").
- Anything listening on `0.0.0.0`/`::` that doesn't need to, plus firewall rules that let it through on Public networks.
- Windows itself: end-of-support/ESU status for the build.

## Phase 2: Threat research

For each exposed service, outdated program, and loaded driver, search for its exploitation history: CISA KEV listing, "exploited in the wild", vendor advisories, and the fixed version. Also search for recent CA compromises and code-signing abuse; `references/download-trust.md` has the known ones as of Oct 2026.

Prioritise by **exposure × exploitability**. A KEV-listed bug in a file archiver you open attachments with outranks a medium CVE in a game launcher.

Note your sources, since the report cites them. Treat aggregator sites as leads: prefer the vendor advisory or KEV for the final claim, and say when you couldn't confirm.

## Phase 3: Ask, then update

### 3a. Sort every eligible update into three tiers

- **Critical.** Actively exploited (KEV / in the wild), a vulnerability in a network-exposed service, or **any installer/package manager/runtime whose trust store accepts a bad chain or is outdated.** A stale downloader can be served malware from a forged-but-"valid" site, which poisons every update after it.
- **Medium.** A security fix with no known exploitation, or a local privilege-escalation fix.
- **App-only.** Feature or bug-fix releases with no security content.

### 3b. Ask the user what to apply

Use **one AskUserQuestion call** with up to three `multiSelect` questions, one per tier, in the order critical → medium → app-only, worded in the user's language. Skip any empty tier.
- Each option is one package, labeled `<name> <from>→<to>`, with a one-line reason in the description (CVE/KEV, "pip accepts the eMudhra chain", "no security changes"…).
- A question takes at most 4 options. If a tier has more items, bundle the lowest-priority ones into one option ("Remaining medium (5)") and list them in its description. The user can always answer with "Other".
- Without AskUserQuestion, ask the same three tiers in chat as numbered lists and wait for the answer.
- Mention below the question which updates were left out and why (under 24h, Store-only, self-updating launchers).

Don't install anything the user didn't pick. If they pick nothing, go straight to phase 4.

### 3c. Install in this order: downloaders first

Updating the tools that fetch and verify software first means everything after them is downloaded through a trustworthy channel:

1. **Windows CA lists.** Confirm `DisallowedCertLastSyncTime` is recent (trust-probe). Windows Update handles the rest.
2. **winget itself** (`Microsoft.AppInstaller`), if outdated.
3. **Package managers and their trust stores:** pip (plus base and user `certifi`), uv, Node/npm/pnpm, Git, PowerShell, gh, Docker CLI.
4. Then the selected **critical**, then **medium**, then **app-only** updates.

After step 3, **re-run `scripts/trust-probe.ps1`**. If a client still ACCEPTS a bad chain, don't use it to install anything else. Report it and give the owner the fix. Typical fixes: upgrading the base-install copy of a library, or switching to the OS store (see the reference).

```powershell
winget upgrade --id <Id> -e --version <checked-version> --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
```

For pip, touch only what the user picked. For a trust-store fix, upgrade both the user-site and the base-install copies, and run `pip check` after. Bulk-upgrading site-packages breaks projects. Update Defender signatures with `Update-MpSignature` (fallback: `MpCmdRun.exe -SignatureUpdate`). Run long installs in the background and log each result.

For anything that must be installed by hand (not via winget/npm/pip), run `scripts/verify-download.ps1` on the file first.

## Phase 4: Re-audit and report

Re-run the inventory, update-age and trust-probe scripts, and diff against phase 1:
- Confirm each update actually landed (the version changed).
- Note failures with the exit code/message.
- List what remains.

Write the report as a file in the working directory, with this structure. Translate the headings into the user's language:

```
# Security report — <hostname>, <date>
## Executive summary        (3–5 bullets: risk level before/after, top actions for the owner)
## Attack surface           (table: port/service/process/exposure/verdict; shares; accounts)
## Known threats            (table: software/driver/version/CVE/exploited?/fixed in/source)
## Download trust           (trust-probe table; clients that accept bad chains; OS controls missing)
## Updates applied          (table: tier/package/from/to/result)
## Pending — needs the owner (numbered, each with the exact admin command and why)
## Skipped and why
## Sources
```

Every "pending" item gets a copy-pasteable command for an elevated PowerShell, plus a one-line explanation of the risk it closes. Rank them by severity.
