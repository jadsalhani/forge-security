#!/usr/bin/env bash
#
# forge-security — Server hardening for Laravel Forge provisioned Ubuntu servers
# ==============================================================================
# https://github.com/jadsalhani/forge-security
#
# Usage:
#   ./harden.sh              Apply all hardening (idempotent, safe to re-run)
#   ./harden.sh --dry-run    Show what would change without modifying anything
#   ./harden.sh --check      Audit current security posture (read-only)
#   ./harden.sh --help       Show usage information
#   ./harden.sh --version    Show version
#
# Quick install:
#   curl -sL https://raw.githubusercontent.com/jadsalhani/forge-security/main/harden.sh | bash
#
# What this script hardens:
#   1. SSH — Disable password auth, restrict root to key-only
#   2. MySQL — Bind to localhost only
#   3. UFW — Verify firewall rules, warn about dangerous ports
#   4. PHP — Disable version exposure (expose_php = Off)
#   5. Nginx — server_tokens off, security headers, block sensitive files
#   6. File Permissions — Secure .env (600), storage (775), ownership
#   7. Auto-Updates — Enable unattended security upgrades
#
# Requirements:
#   - Ubuntu 22.04 or 24.04
#   - Server provisioned by Laravel Forge
#   - Run as the 'forge' user with sudo access
#
# Safe to run multiple times (idempotent).
# Always test on a staging server first.
#

set -euo pipefail

VERSION="1.0.0"
DRY_RUN=false
CHECK_ONLY=false
WARNINGS=0
FAILURES=0

# ============================================
# COLORS & OUTPUT
# ============================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "  ${GREEN}[PASS]${NC} $1"; }
warn()  { echo -e "  ${YELLOW}[WARN]${NC} $1"; WARNINGS=$((WARNINGS + 1)); }
fail()  { echo -e "  ${RED}[FAIL]${NC} $1"; FAILURES=$((FAILURES + 1)); }
skip()  { echo -e "  ${BLUE}[SKIP]${NC} $1"; }
action(){ echo -e "  ${GREEN}[FIX]${NC}  $1"; }
dry()   { echo -e "  ${BLUE}[DRY]${NC}  $1"; }

section() {
    echo ""
    echo -e "${BOLD}── $1 ──${NC}"
}

# ============================================
# ARGUMENT PARSING
# ============================================
show_help() {
    cat << 'HELP'
forge-security — Server hardening for Laravel Forge provisioned Ubuntu servers

USAGE:
    ./harden.sh [OPTIONS]

OPTIONS:
    --dry-run    Show what would change without modifying anything
    --check      Audit current security posture (read-only report)
    --help       Show this help message
    --version    Show version number

MODES:
    (default)    Apply all hardening changes (idempotent, safe to re-run)
    --dry-run    Preview mode — prints what would be changed, touches nothing
    --check      Audit mode — reports pass/warn/fail for each security check

EXAMPLES:
    # Audit your server's current security posture
    ./harden.sh --check

    # Preview what the script would change
    ./harden.sh --dry-run

    # Apply hardening (safe to run multiple times)
    ./harden.sh

    # One-liner install and run
    curl -sL https://raw.githubusercontent.com/jadsalhani/forge-security/main/harden.sh -o harden.sh
    chmod +x harden.sh && ./harden.sh

REQUIREMENTS:
    - Ubuntu 22.04 or 24.04 LTS
    - Server provisioned by Laravel Forge
    - Run as the 'forge' user with sudo access

More info: https://github.com/jadsalhani/forge-security
HELP
}

for arg in "$@"; do
    case "$arg" in
        --dry-run)  DRY_RUN=true ;;
        --check)    CHECK_ONLY=true ;;
        --help|-h)  show_help; exit 0 ;;
        --version|-v) echo "forge-security v${VERSION}"; exit 0 ;;
        *)
            echo "Unknown option: $arg"
            echo "Run './harden.sh --help' for usage."
            exit 1
            ;;
    esac
done

# ============================================
# HELPERS
# ============================================

# Run a command, or print it in dry-run mode
run() {
    if $DRY_RUN; then
        dry "Would run: $*"
    else
        "$@"
    fi
}

# Run a command with sudo, or print it in dry-run mode
run_sudo() {
    if $DRY_RUN; then
        dry "Would run: sudo $*"
    else
        sudo "$@"
    fi
}

# ============================================
# PREFLIGHT CHECKS
# ============================================
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   forge-security v${VERSION}                      ║"
echo "║   Server Hardening for Laravel Forge         ║"
echo "╚══════════════════════════════════════════════╝"

if $DRY_RUN; then
    echo ""
    echo -e "  ${BLUE}Mode: DRY RUN — no changes will be made${NC}"
elif $CHECK_ONLY; then
    echo ""
    echo -e "  ${BLUE}Mode: AUDIT — read-only security check${NC}"
fi

# Check we're running as forge user
if [[ "$(whoami)" != "forge" ]]; then
    echo ""
    fail "This script must be run as the 'forge' user."
    echo "  Run: ssh forge@your-server"
    exit 1
fi

# Check sudo access (skip in check mode — some checks don't need sudo)
if ! $CHECK_ONLY; then
    if ! sudo -n true 2>/dev/null; then
        echo ""
        fail "The forge user needs passwordless sudo access."
        exit 1
    fi
fi

# ============================================
# 1. SSH HARDENING
# ============================================
section "SSH Configuration"

SSHD_CONFIG="/etc/ssh/sshd_config"
SSH_CHANGED=false

# Check password authentication
if sudo grep -qE "^PasswordAuthentication\s+no" "$SSHD_CONFIG" 2>/dev/null; then
    info "Password authentication is disabled"
elif sudo grep -qE "^PasswordAuthentication\s+yes" "$SSHD_CONFIG" 2>/dev/null; then
    if $CHECK_ONLY; then
        fail "Password authentication is ENABLED — should be disabled"
    else
        run_sudo sed -i 's/^PasswordAuthentication\s\+yes/PasswordAuthentication no/' "$SSHD_CONFIG"
        action "Disabled SSH password authentication"
        SSH_CHANGED=true
    fi
else
    if $CHECK_ONLY; then
        warn "PasswordAuthentication not explicitly set — defaults may vary"
    else
        echo "PasswordAuthentication no" | run_sudo tee -a "$SSHD_CONFIG" > /dev/null
        action "Added PasswordAuthentication no"
        SSH_CHANGED=true
    fi
fi

# Check root login
if sudo grep -qE "^PermitRootLogin\s+prohibit-password" "$SSHD_CONFIG" 2>/dev/null; then
    info "Root login restricted to key-only (prohibit-password)"
elif sudo grep -qE "^PermitRootLogin\s+no" "$SSHD_CONFIG" 2>/dev/null; then
    info "Root login is fully disabled"
elif sudo grep -qE "^PermitRootLogin\s+yes" "$SSHD_CONFIG" 2>/dev/null; then
    if $CHECK_ONLY; then
        fail "Root login with password is ENABLED — should be prohibit-password"
    else
        run_sudo sed -i 's/^PermitRootLogin\s\+yes/PermitRootLogin prohibit-password/' "$SSHD_CONFIG"
        action "Restricted root login to key-only (prohibit-password)"
        SSH_CHANGED=true
    fi
else
    if $CHECK_ONLY; then
        warn "PermitRootLogin not explicitly set — defaults may vary"
    else
        echo "PermitRootLogin prohibit-password" | run_sudo tee -a "$SSHD_CONFIG" > /dev/null
        action "Added PermitRootLogin prohibit-password"
        SSH_CHANGED=true
    fi
fi

# Restart SSH if changes were made
if $SSH_CHANGED && ! $DRY_RUN; then
    sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd 2>/dev/null || true
    info "SSH service restarted"
fi

# ============================================
# 2. MYSQL HARDENING
# ============================================
section "MySQL Configuration"

MYSQL_CONFIG="/etc/mysql/mysql.conf.d/mysqld.cnf"

if [[ -f "$MYSQL_CONFIG" ]]; then
    CURRENT_BIND=$(sudo grep -E "^bind-address" "$MYSQL_CONFIG" 2>/dev/null | head -1 | awk '{print $3}')

    if [[ "$CURRENT_BIND" == "127.0.0.1" ]]; then
        info "MySQL bound to 127.0.0.1 (localhost only)"
    elif [[ -n "$CURRENT_BIND" ]]; then
        if $CHECK_ONLY; then
            fail "MySQL bind-address is '$CURRENT_BIND' — should be 127.0.0.1"
        else
            run_sudo sed -i 's/^bind-address\s*=.*/bind-address = 127.0.0.1/' "$MYSQL_CONFIG"
            if ! $DRY_RUN; then
                sudo systemctl restart mysql
            fi
            action "Changed MySQL bind-address from '$CURRENT_BIND' to 127.0.0.1"
        fi
    else
        warn "No bind-address directive found in MySQL config"
    fi
else
    skip "MySQL config not found — MySQL may not be installed"
fi

# ============================================
# 3. UFW FIREWALL
# ============================================
section "Firewall (UFW)"

if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
    info "UFW firewall is active"

    # Check for dangerous open ports
    for PORT in 3306 6379 5432 27017; do
        if sudo ufw status | grep -qE "^${PORT}\s.*ALLOW"; then
            if $CHECK_ONLY; then
                fail "Port $PORT is open to the internet"
            else
                warn "Port $PORT is open — close it with: sudo ufw deny $PORT"
            fi
        fi
    done

    # Verify essential ports
    for PORT in 22 80 443; do
        if sudo ufw status | grep -qE "^${PORT}\s.*ALLOW"; then
            info "Port $PORT is open (required)"
        else
            warn "Port $PORT is NOT open — this may cause issues"
        fi
    done
else
    if $CHECK_ONLY; then
        fail "UFW firewall is NOT active"
    else
        run_sudo ufw default deny incoming
        run_sudo ufw default allow outgoing
        run_sudo ufw allow 22
        run_sudo ufw allow 80
        run_sudo ufw allow 443
        run_sudo ufw --force enable
        action "Enabled UFW with ports 22, 80, 443"
    fi
fi

# ============================================
# 4. PHP HARDENING
# ============================================
section "PHP Configuration"

PHP_CHANGED=false

for INI_FILE in $(sudo find /etc/php -name "php.ini" 2>/dev/null); do
    FILENAME=$(echo "$INI_FILE" | sed 's|/etc/php/||')

    if sudo grep -qE "^expose_php\s*=\s*Off" "$INI_FILE" 2>/dev/null; then
        info "expose_php = Off ($FILENAME)"
    elif sudo grep -qE "^expose_php\s*=\s*On" "$INI_FILE" 2>/dev/null; then
        if $CHECK_ONLY; then
            fail "expose_php = On ($FILENAME) — should be Off"
        else
            run_sudo sed -i 's/^expose_php\s*=\s*On/expose_php = Off/' "$INI_FILE"
            action "Set expose_php = Off ($FILENAME)"
            PHP_CHANGED=true
        fi
    fi
done

if $PHP_CHANGED && ! $DRY_RUN; then
    for FPM in $(systemctl list-units --type=service --state=running 2>/dev/null | grep php | awk '{print $1}'); do
        sudo systemctl restart "$FPM"
        info "Restarted $FPM"
    done
fi

if ! sudo find /etc/php -name "php.ini" 2>/dev/null | grep -q .; then
    skip "No PHP installations found"
fi

# ============================================
# 5. NGINX HARDENING
# ============================================
section "Nginx Configuration"

NGINX_CONF="/etc/nginx/nginx.conf"

if [[ -f "$NGINX_CONF" ]]; then
    # Check server_tokens
    if sudo grep -qE "^\s*server_tokens\s+off" "$NGINX_CONF" 2>/dev/null; then
        info "server_tokens is off"
    elif sudo grep -qE "^\s*server_tokens" "$NGINX_CONF" 2>/dev/null; then
        if $CHECK_ONLY; then
            fail "server_tokens is NOT off — server version is exposed"
        else
            run_sudo sed -i 's/server_tokens\s\+.*/server_tokens off;/' "$NGINX_CONF"
            action "Set server_tokens off"
        fi
    else
        if $CHECK_ONLY; then
            warn "server_tokens not explicitly configured"
        else
            run_sudo sed -i '/http\s*{/a \    server_tokens off;' "$NGINX_CONF"
            action "Added server_tokens off"
        fi
    fi

    # Create security headers snippet
    SECURITY_SNIPPET="/etc/nginx/snippets/security-headers.conf"
    if [[ -f "$SECURITY_SNIPPET" ]]; then
        info "Security headers snippet exists"
    else
        if $CHECK_ONLY; then
            warn "Security headers snippet not found at $SECURITY_SNIPPET"
        else
            run_sudo tee "$SECURITY_SNIPPET" > /dev/null << 'SNIPPET'
# Security Headers — managed by forge-security
# Include in site server blocks: include /etc/nginx/snippets/security-headers.conf;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
SNIPPET
            action "Created security headers snippet at $SECURITY_SNIPPET"
        fi
    fi

    # Create sensitive file blocking snippet
    BLOCK_SNIPPET="/etc/nginx/snippets/block-sensitive-files.conf"
    if [[ -f "$BLOCK_SNIPPET" ]]; then
        info "Sensitive file blocking snippet exists"
    else
        if $CHECK_ONLY; then
            warn "Sensitive file blocking snippet not found at $BLOCK_SNIPPET"
        else
            run_sudo tee "$BLOCK_SNIPPET" > /dev/null << 'SNIPPET'
# Block sensitive files — managed by forge-security
# Include in site server blocks: include /etc/nginx/snippets/block-sensitive-files.conf;

# Block access to hidden files (.env, .git, etc.) but allow .well-known (needed for SSL/ACME)
location ~ /\.(?!well-known) {
    deny all;
    access_log off;
    log_not_found off;
}

# Block access to sensitive file types
# Note: .xml is intentionally NOT blocked — sitemap.xml, rss.xml, atom.xml,
# opensearch.xml, etc. are legitimately public files. Block specific XML
# files at the application level if needed.
location ~* \.(sql|sqlite|log|env|yml|yaml|ini|conf|bak|swp)$ {
    deny all;
    access_log off;
    log_not_found off;
}
SNIPPET
            action "Created sensitive file blocking snippet at $BLOCK_SNIPPET"
        fi
    fi

    # Test and reload nginx
    if ! $CHECK_ONLY && ! $DRY_RUN; then
        if sudo nginx -t 2>/dev/null; then
            sudo systemctl reload nginx
            info "Nginx tested and reloaded"
        else
            fail "Nginx config test failed — run: sudo nginx -t"
        fi
    fi
else
    skip "Nginx config not found — Nginx may not be installed"
fi

# ============================================
# 6. FILE PERMISSIONS
# ============================================
section "Laravel File Permissions"

SITES_FOUND=false
for SITE_DIR in /home/forge/*/; do
    if [[ -f "${SITE_DIR}artisan" ]]; then
        SITES_FOUND=true
        SITE_NAME=$(basename "$SITE_DIR")

        if $CHECK_ONLY; then
            # Check .env permissions
            if [[ -f "${SITE_DIR}.env" ]]; then
                ENV_PERMS=$(stat -c '%a' "${SITE_DIR}.env" 2>/dev/null || stat -f '%Lp' "${SITE_DIR}.env" 2>/dev/null)
                if [[ "$ENV_PERMS" == "600" ]]; then
                    info "$SITE_NAME: .env permissions are 600 (secure)"
                else
                    fail "$SITE_NAME: .env permissions are $ENV_PERMS — should be 600"
                fi
            fi

            # Check ownership
            OWNER=$(stat -c '%U' "${SITE_DIR}" 2>/dev/null || stat -f '%Su' "${SITE_DIR}" 2>/dev/null)
            if [[ "$OWNER" == "forge" ]]; then
                info "$SITE_NAME: owned by forge user"
            else
                fail "$SITE_NAME: owned by '$OWNER' — should be forge"
            fi
        else
            # Apply secure permissions
            run_sudo chown -R forge:forge "$SITE_DIR"
            run_sudo chmod -R 755 "$SITE_DIR"

            if [[ -d "${SITE_DIR}storage" ]]; then
                run_sudo chmod -R 775 "${SITE_DIR}storage"
            fi
            if [[ -d "${SITE_DIR}bootstrap/cache" ]]; then
                run_sudo chmod -R 775 "${SITE_DIR}bootstrap/cache"
            fi
            if [[ -f "${SITE_DIR}.env" ]]; then
                run chmod 600 "${SITE_DIR}.env"
            fi

            action "Secured permissions for $SITE_NAME"
        fi
    fi
done

if ! $SITES_FOUND; then
    skip "No Laravel sites found in /home/forge/"
fi

# ============================================
# 7. AUTOMATIC SECURITY UPDATES
# ============================================
section "Automatic Security Updates"

if dpkg -l 2>/dev/null | grep -q unattended-upgrades; then
    info "unattended-upgrades package is installed"
else
    if $CHECK_ONLY; then
        fail "unattended-upgrades is NOT installed"
    else
        run_sudo apt-get install -y unattended-upgrades > /dev/null 2>&1
        action "Installed unattended-upgrades"
    fi
fi

AUTO_UPGRADES="/etc/apt/apt.conf.d/20auto-upgrades"
if [[ -f "$AUTO_UPGRADES" ]] && grep -q 'Unattended-Upgrade "1"' "$AUTO_UPGRADES" 2>/dev/null; then
    info "Automatic security updates are enabled"
else
    if $CHECK_ONLY; then
        fail "Automatic security updates are NOT enabled"
    else
        run_sudo tee "$AUTO_UPGRADES" > /dev/null << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
        action "Enabled automatic security updates"
    fi
fi

# ============================================
# SUMMARY
# ============================================
echo ""
echo "╔══════════════════════════════════════════════╗"

if $CHECK_ONLY; then
    if [[ $FAILURES -gt 0 ]]; then
        echo -e "║  ${RED}Audit: $FAILURES issue(s) found, $WARNINGS warning(s)${NC}        ║"
    elif [[ $WARNINGS -gt 0 ]]; then
        echo -e "║  ${YELLOW}Audit: All passed, $WARNINGS warning(s)${NC}                  ║"
    else
        echo -e "║  ${GREEN}Audit: All checks passed${NC}                      ║"
    fi
elif $DRY_RUN; then
    echo -e "║  ${BLUE}Dry run complete — no changes were made${NC}      ║"
else
    echo -e "║  ${GREEN}Hardening complete${NC}                            ║"
fi

echo "╚══════════════════════════════════════════════╝"

if ! $CHECK_ONLY || [[ $WARNINGS -gt 0 ]] || [[ $FAILURES -gt 0 ]]; then
    echo ""
    echo "  Manual steps (do these in the Forge UI):"
    echo ""
    echo "  1. Add to each site's Nginx config (Forge > Site > Nginx):"
    echo "       include /etc/nginx/snippets/security-headers.conf;"
    echo "       include /etc/nginx/snippets/block-sensitive-files.conf;"
    echo ""
    echo "  2. Set production .env values (Forge > Site > Environment):"
    echo "       APP_DEBUG=false"
    echo "       APP_ENV=production"
    echo "       SESSION_SECURE_COOKIE=true"
    echo "       SESSION_ENCRYPT=true"
    echo ""
    echo "  3. Verify SSL grade: https://www.ssllabs.com/ssltest/"
    echo ""
fi

# Exit codes: 0=pass, 1=failures found, 2=warnings only
if [[ $FAILURES -gt 0 ]]; then
    exit 1
elif [[ $WARNINGS -gt 0 ]]; then
    exit 2
else
    exit 0
fi
