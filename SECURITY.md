# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

If you discover a security vulnerability in Grippy Installer, **do not open a public issue.**

Please report it privately via [GitHub Security Advisories](https://github.com/Xoifail/grippy-installer/security/advisories/new) with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You should receive an acknowledgment within 48 hours. We will work with you to understand the issue and create a fix before any public disclosure.

## Scope

The following are in scope:

- Privilege escalation during install or uninstall
- Payload integrity bypass (hash or Authenticode verification)
- Symlink/junction attacks on the install directory
- Temp file prediction or race conditions
- Service misconfiguration leading to privilege escalation
- Log injection or log file tampering
- Any path that allows code execution as SYSTEM or Administrator

The following are out of scope:

- Vulnerabilities in upstream dependencies (Tauri, WiX, curl, WebView2) -- report those to the respective projects
- Denial of service against the installer process
- Attacks requiring pre existing administrator access on the target machine

## Disclosure policy

We follow coordinated disclosure. We ask that you give us 90 days to address the issue before any public disclosure.
