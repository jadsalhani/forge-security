# Contributing to forge-security

Thanks for your interest in contributing! This project aims to be the go-to hardening tool for Laravel Forge servers, and community input is what makes it better.

## How to Contribute

### Reporting Issues

- Use [GitHub Issues](https://github.com/jadsalhani/forge-security/issues) for bug reports and feature requests.
- Include your Ubuntu version, PHP version, and relevant output from `./harden.sh --check`.
- **Do NOT include** server IPs, passwords, or any credentials in issue reports.

### Submitting Pull Requests

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Make your changes to `harden.sh`.
4. Ensure ShellCheck passes: `shellcheck harden.sh`
5. Test on a **staging server** (never test hardening scripts on production first).
6. Submit a pull request with a clear description of what changed and why.

## Code Style

- All scripts must pass [ShellCheck](https://www.shellcheck.net/) with no errors.
- Use `set -euo pipefail` at the top.
- All changes must be **idempotent** -- running the script twice should produce the same result.
- Use the existing output functions: `info()`, `warn()`, `fail()`, `action()`, `dry()`, `skip()`.
- Support all three modes: default (apply), `--check` (audit), and `--dry-run` (preview).
- Wrap destructive commands with `run_sudo` so dry-run mode works correctly.

## Adding a New Hardening Module

If you're adding a new security check/fix:

1. Add a new numbered section in `harden.sh` following the existing pattern.
2. Handle all three modes (`--check`, `--dry-run`, and apply).
3. Skip gracefully if the relevant service isn't installed.
4. Update the README's "What It Hardens" table.
5. Add the check to the ShellCheck CI.

## Guidelines

- **Forge-aware**: Never make changes that would break Laravel Forge's provisioning, deployment, or management capabilities.
- **Conservative**: When in doubt, warn instead of auto-fixing. The `forge` user and Forge's root access must always keep working.
- **Test first**: Always test on a disposable server or staging environment before submitting.

## Security Vulnerabilities

If you discover a security vulnerability in this script, please report it responsibly. See [SECURITY.md](SECURITY.md) for details.
