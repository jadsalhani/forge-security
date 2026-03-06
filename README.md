# forge-security

**Server hardening for Laravel Forge provisioned Ubuntu servers.**

[![ShellCheck](https://github.com/jadsalhani/forge-security/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/jadsalhani/forge-security/actions/workflows/shellcheck.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A single, idempotent bash script that hardens Ubuntu servers provisioned by [Laravel Forge](https://forge.laravel.com). Safe to run multiple times. Designed for Forge's user model, directory structure, and service layout so it won't break your provisioning.

---

## What It Hardens

| Module | What it does |
|--------|-------------|
| **SSH** | Disables password authentication, restricts root login to key-only (`prohibit-password`) |
| **MySQL** | Binds to `127.0.0.1` only (prevents remote access) |
| **Firewall (UFW)** | Verifies firewall is active, warns about dangerous open ports (3306, 6379, etc.) |
| **PHP** | Sets `expose_php = Off` across all PHP versions (hides PHP from response headers) |
| **Nginx** | Disables `server_tokens`, creates reusable security header and sensitive file blocking snippets |
| **File Permissions** | Auto-detects all Laravel sites, sets `.env` to `600`, `storage/` to `775`, ensures `forge` ownership |
| **Auto-Updates** | Installs and enables `unattended-upgrades` for automatic security patches |

## Quick Start

### Audit your server first (read-only)

```bash
curl -sL https://raw.githubusercontent.com/jadsalhani/forge-security/main/harden.sh -o harden.sh
chmod +x harden.sh
./harden.sh --check
```

### Preview changes (dry run)

```bash
./harden.sh --dry-run
```

### Apply hardening

```bash
./harden.sh
```

### Or all-in-one

```bash
curl -sL https://raw.githubusercontent.com/jadsalhani/forge-security/main/harden.sh -o harden.sh
chmod +x harden.sh && ./harden.sh
```

## Requirements

- **OS:** Ubuntu 22.04 or 24.04 LTS
- **Provisioner:** Laravel Forge
- **User:** Must run as the `forge` user with sudo access
- **Services:** Works with Nginx, PHP-FPM, MySQL (all optional -- skips gracefully if not installed)

## Modes

| Flag | Description |
|------|-------------|
| _(none)_ | Apply all hardening changes (idempotent) |
| `--check` | Audit mode -- reports PASS/WARN/FAIL for each check, changes nothing |
| `--dry-run` | Preview mode -- shows what commands would run, changes nothing |
| `--help` | Show usage information |
| `--version` | Show version number |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed (or all changes applied successfully) |
| `1` | Failures found (in `--check` mode) or error during hardening |
| `2` | Warnings found but no failures |

## Manual Steps After Running

The script will remind you of these -- they require the Forge UI:

1. **Add Nginx snippet includes** to each site's server block (Forge > Site > Nginx Config):
   ```nginx
   include /etc/nginx/snippets/security-headers.conf;
   include /etc/nginx/snippets/block-sensitive-files.conf;
   ```

2. **Set production `.env` values** (Forge > Site > Environment):
   ```env
   APP_DEBUG=false
   APP_ENV=production
   SESSION_SECURE_COOKIE=true
   SESSION_ENCRYPT=true
   ```

3. **Test your SSL grade** at [ssllabs.com/ssltest](https://www.ssllabs.com/ssltest/)

## Why This Exists

There is no dedicated open-source hardening tool for Laravel Forge. Existing alternatives are either:

- **Commercial/narrow** (e.g., Forge Buddy -- firewall management only, closed-source)
- **General Ubuntu hardening** (e.g., konstruktoid/hardening, JShielder) that aren't Forge-aware and can conflict with Forge's user model, service layout, and provisioning

This script understands Forge's conventions: the `forge` user, `/home/forge/` site structure, Forge-managed Nginx/PHP-FPM/MySQL, and key-based root access requirements.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

To report a security vulnerability, please see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) -- Jad Salhani
