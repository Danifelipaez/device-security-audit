# Security policy

This skill runs commands on the user's machine, so a bug in it is a security bug. Examples: a script that writes when it should only read, a probe that sends data somewhere unexpected, or an instruction that lets the agent change security settings or install something the user didn't pick.

**Please don't open a public issue for these.** Report them privately through [GitHub Security Advisories](https://github.com/Danifelipaez/device-security-audit/security/advisories/new). Include the affected file, the Windows version, and how to reproduce.

Outdated threat data, such as a new CA compromise that is missing from `references/download-trust.md`, is not a vulnerability. Open a regular issue or PR for it.
