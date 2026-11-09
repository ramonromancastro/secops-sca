#!/usr/bin/env bash
# ==============================================================================
# SecOps Enterprise Security - SCA Dashboard Deployment Script
# ==============================================================================
set -euo pipefail

SCRIPT_VERSION="1.4.5"
GITHUB_REPO="ramonromancastro/secops-sca"

# Color setup (ANSI escape codes)
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_CYAN='\033[0;36m'
C_BOLD='\033[1m'
C_NC='\033[0m' # No Color

# Pre-parse for --no-color flag so it affects all output
for arg in "$@"; do
    if [[ "$arg" == "--no-color" ]]; then
        C_RED=''
        C_GREEN=''
        C_YELLOW=''
        C_BLUE=''
        C_CYAN=''
        C_BOLD=''
        C_NC=''
        break
    fi
done

# Default values
APP_DIR="/opt/secops-sca"
BACKEND_HOST="127.0.0.1"
BACKEND_PORT="8000"
BACKEND_SERVICE="secops-sca-backend.service"
BACKEND_CRON="/etc/cron.d/secops-sca-scanner"
ALIAS_PATH="/secops-sca"
UPGRADE_MODE="false"
DOWNLOAD_VERSION=""
MIN_PYTHON_VERSION="3.11"
PYTHON_BIN="python3"
APP_USER="secops-sca"
APP_GROUP="$APP_USER"

# ------------------------------------------------------------------------------
# Help, Version, and GitHub Functions
# ------------------------------------------------------------------------------
show_version() {
    echo -e "${C_BOLD}SecOps SCA Deploy Script v${SCRIPT_VERSION}${C_NC}"
}

show_help() {
    show_version
    echo ""
    echo -e "${C_BOLD}Usage:${C_NC} sudo $0 [options]"
    echo ""
    echo -e "${C_YELLOW}Installation Options:${C_NC}"
    echo "  --app-dir <path>    Installation directory (default: $APP_DIR)"
    echo "  --port <port>       Local port for the FastAPI backend (default: $BACKEND_PORT)"
    echo "  --alias <path>      Web alias path in Apache (default: $ALIAS_PATH)"
    echo "  --upgrade           Skip port and directory checks to upgrade"
    echo "  --python-bin <bin>  Python binary to use (default: $PYTHON_BIN)"
    echo ""
    echo -e "${C_YELLOW}Repository Options (GitHub):${C_NC}"
    echo "  --download <tag>    Download a repository version (e.g., 'latest' or 'v1.0.0')"
    echo "  --list-versions     List available versions on GitHub and exit"
    echo ""
    echo -e "${C_YELLOW}Other:${C_NC}"
    echo "  --no-color          Disable color output"
    echo "  --version           Show the version of this script"
    echo "  -h, --help          Show this help message"
    echo ""
}

list_github_versions() {
    echo -e "${C_CYAN}Querying available versions on GitHub ($GITHUB_REPO)...${C_NC}"
    # Use grep/sed to avoid extra dependencies like jq
    local tags=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/tags" | grep '"name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [[ -z "$tags" ]]; then
        echo -e "${C_YELLOW}No published versions found or the repository is private.${C_NC}"
    else
        echo -e "${C_GREEN}Available versions for download:${C_NC}"
        echo "  - latest (The most recent version)"
        echo "$tags" | while read -r v; do echo "  - $v"; done
    fi
    exit 0
}

# ------------------------------------------------------------------------------
# Parameter Parsing
# ------------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case $1 in
        --app-dir)
            if [[ -z "${2:-}" || "$2" == -* ]]; then
                echo -e "${C_RED}${C_BOLD}Error:${C_NC} --app-dir requires a path (e.g., /opt/secops-sca)" >&2
                exit 1
            fi
            if [[ "$2" != /* ]]; then
                echo -e "${C_RED}${C_BOLD}Error:${C_NC} --app-dir must be an absolute path (e.g., /opt/secops-sca)" >&2
                exit 1
            fi
            APP_DIR="$2"
            shift 2
            ;;
        --port)
            if [[ -z "${2:-}" || ! "$2" =~ ^[0-9]+$ ]]; then
                echo -e "${C_RED}${C_BOLD}Error:${C_NC} --port requires a valid port number (e.g., 8000)" >&2
                exit 1
            fi
            BACKEND_PORT="$2"
            shift 2
            ;;
        --alias)
            if [[ -z "${2:-}" || "$2" == -* ]]; then
                echo -e "${C_RED}${C_BOLD}Error:${C_NC} --alias requires a web path (e.g., /secops-sca)" >&2
                exit 1
            fi
            if [[ "$2" != /* ]]; then
                echo -e "${C_RED}${C_BOLD}Error:${C_NC} --alias must start with '/' (e.g., /secops-sca)" >&2
                exit 1
            fi
            ALIAS_PATH="$2"
            shift 2
            ;;
        --upgrade)
            UPGRADE_MODE="true"
            shift
            ;;
        --python-bin)
            if [[ -z "${2:-}" || "$2" == -* ]]; then
                echo -e "${C_RED}${C_BOLD}Error:${C_NC} --python-bin requires a binary name (e.g., python3.11)" >&2
                exit 1
            fi
            PYTHON_BIN="$2"
            shift 2
            ;;
        --download)
            if [[ -z "${2:-}" || "$2" == -* ]]; then
                echo -e "${C_RED}${C_BOLD}Error:${C_NC} --download requires a version (e.g., latest or v1.0.0)" >&2
                exit 1
            fi
            DOWNLOAD_VERSION="$2"
            shift 2
            ;;
        --list-versions)
            list_github_versions
            ;;
        --no-color)
            shift
            ;;
        --version)
            show_version
            exit 0
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${C_RED}${C_BOLD}Error:${C_NC} Unknown parameter '$1'" >&2
            show_help
            exit 1
            ;;
    esac
done

# ------------------------------------------------------------------------------
# MANDATORY PARAMETER VALIDATION
# ------------------------------------------------------------------------------
if [[ -z "$DOWNLOAD_VERSION" ]]; then
    echo -e "${C_RED}${C_BOLD}Error:${C_NC} The '--download <version>' parameter is REQUIRED." >&2
    echo -e "Use '${C_CYAN}--list-versions${C_NC}' to see available versions."
    echo -e "Example: sudo $0 --download latest"
    exit 1
fi

# ------------------------------------------------------------------------------
# Filesystem Security Checks
# ------------------------------------------------------------------------------
APP_DIR="${APP_DIR%/}"
if [[ -z "$APP_DIR" ]]; then APP_DIR="/"; fi

RESTRICTED_EXACT=("/" "/bin" "/boot" "/dev" "/etc" "/home" "/lib" "/lib64" "/opt" "/proc" "/root" "/run" "/sbin" "/sys" "/tmp" "/usr" "/var" "/var/www")
for dir in "${RESTRICTED_EXACT[@]}"; do
    if [[ "$APP_DIR" == "$dir" ]]; then
        echo -e "${C_RED}${C_BOLD}Security Error:${C_NC} The critical directory '$dir' cannot be used as APP_DIR." >&2
        echo -e "${C_YELLOW}Solution:${C_NC} Specify a subdirectory (e.g., ${dir}/secops-sca)" >&2
        exit 1
    fi
done

RESTRICTED_PREFIXES=("/bin/" "/boot/" "/dev/" "/etc/" "/lib/" "/lib64/" "/proc/" "/root/" "/run/" "/sbin/" "/sys/")
for prefix in "${RESTRICTED_PREFIXES[@]}"; do
    if [[ "$APP_DIR" == "$prefix"* ]]; then
        echo -e "${C_RED}${C_BOLD}Security Error:${C_NC} The path '$APP_DIR' belongs to a protected filesystem." >&2
        echo -e "${C_YELLOW}Solution:${C_NC} Use a safe application directory like /opt/secops-sca or /var/www/secops-sca." >&2
        exit 1
    fi
done

# ------------------------------------------------------------------------------
# Pre-Execution & Conflict Checks
# ------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
   echo -e "${C_RED}${C_BOLD}Error:${C_NC} This script must be run as root (sudo $0)" >&2
   exit 1
fi

if [[ "$UPGRADE_MODE" == "false" ]]; then
    echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Performing preliminary security checks..."
    if [[ -d "$APP_DIR" ]]; then
        echo -e "${C_RED}${C_BOLD}Error:${C_NC} The directory $APP_DIR already exists." >&2
        echo -e "       Use ${C_CYAN}--upgrade${C_NC} to skip this check and update/overwrite." >&2
        exit 1
    fi
    if command -v ss &> /dev/null; then
        if ss -tuln | grep -q ":$BACKEND_PORT "; then
            echo -e "${C_RED}${C_BOLD}Error:${C_NC} Port $BACKEND_PORT is already in use." >&2
            echo -e "       Free the port, choose another with ${C_CYAN}--port${C_NC}, or use ${C_CYAN}--upgrade${C_NC}." >&2
            exit 1
        fi
    fi
fi

# ------------------------------------------------------------------------------
# OS Detection & Dependency Installation
# ------------------------------------------------------------------------------

source /etc/os-release
echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Operating system detected: ${C_GREEN}$PRETTY_NAME${C_NC}"

if [[ "${ID_LIKE:-$ID}" == *"debian"* || "$ID" == "debian" || "$ID" == "ubuntu" ]]; then
    OS_FAMILY="debian"
    WEB_USER="www-data"
    WEB_SERVICE="apache2"
    CONF_PATH="/etc/apache2/conf-available/secops-sca.conf"

    echo -e "${C_CYAN}    -> Installing dependencies (Debian/Ubuntu)...${C_NC}"
    apt-get update
    apt-get install -y apache2 python3 python3-venv python3-pip curl iproute2 tar
    a2enmod proxy proxy_http rewrite headers alias
elif [[ "${ID_LIKE:-$ID}" == *"rhel"* || "${ID_LIKE:-$ID}" == *"fedora"* || "$ID" == "rhel" || "$ID" == "rocky" || "$ID" == "almalinux" ]]; then
    OS_FAMILY="rhel"
    WEB_USER="apache"
    WEB_SERVICE="httpd"
    CONF_PATH="/etc/httpd/conf.d/secops-sca.conf"

    echo -e "${C_CYAN}    -> Installing dependencies (RHEL/AlmaLinux/Rocky)...${C_NC}"
    dnf install -y httpd python3 python3-pip curl policycoreutils-python-utils iproute tar
else
    echo -e "${C_RED}${C_BOLD}Error:${C_NC} Distribution not automatically supported." >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# Python Version Validation
# ------------------------------------------------------------------------------
echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Verifying Python compatibility ($PYTHON_BIN >= $MIN_PYTHON_VERSION)..."

if ! command -v "$PYTHON_BIN" &>/dev/null; then
    echo -e "${C_RED}${C_BOLD}Error:${C_NC} Binary '$PYTHON_BIN' not found in the system." >&2
    echo -e "Use the '${C_CYAN}--python-bin <path_or_name>${C_NC}' parameter to specify an installed version (e.g., --python-bin python3.11)." >&2
    exit 1
fi

PY_VER=$($PYTHON_BIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")

if [[ "$(printf '%s\n' "$MIN_PYTHON_VERSION" "$PY_VER" | sort -V | head -n1)" != "$MIN_PYTHON_VERSION" ]]; then
    echo -e "${C_RED}${C_BOLD}==================================================================${C_NC}" >&2
    echo -e "${C_RED}${C_BOLD} CRITICAL ERROR: INCOMPATIBLE PYTHON VERSION${C_NC}" >&2
    echo -e "${C_RED}${C_BOLD}==================================================================${C_NC}" >&2
    echo -e " Python $MIN_PYTHON_VERSION or higher is required." >&2
    echo -e " Detected binary ('$PYTHON_BIN'): version $PY_VER" >&2
    echo "" >&2
    echo -e " If you have a higher version installed, indicate it with the parameter:" >&2
    echo -e "   ${C_CYAN}sudo $0 --download latest --python-bin python3.11${C_NC}" >&2
    echo -e "${C_RED}${C_BOLD}==================================================================${C_NC}" >&2
    exit 1
fi
echo -e "${C_GREEN}    -> OK: Valid binary detected: $PYTHON_BIN (v$PY_VER)${C_NC}"

# ------------------------------------------------------------------------------
# Stop Backend Service Before Installation / Upgrade
# ------------------------------------------------------------------------------

echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Checking backend service status..."
if systemctl is-active --quiet "$BACKEND_SERVICE"; then
    echo -e "${C_YELLOW}    -> Backend service is running. Stopping it before deployment...${C_NC}"
    systemctl stop "$BACKEND_SERVICE"
    echo -e "${C_GREEN}    -> Backend service stopped successfully.${C_NC}"
else
    echo -e "${C_CYAN}    -> Backend service is not running. Nothing to stop.${C_NC}"
fi

# ------------------------------------------------------------------------------
# Dedicated System User
# ------------------------------------------------------------------------------

if getent passwd "$APP_USER" >/dev/null; then
    echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Checking dedicated system user: ${C_GREEN}$APP_USER${C_NC}"
    CURRENT_HOME="$(getent passwd "$APP_USER" | cut -d: -f6)"
    if [[ "$CURRENT_HOME" != "$APP_DIR" ]]; then
        echo -e "${C_CYAN}    -> Home directory needs updating: $CURRENT_HOME -> $APP_DIR${C_NC}"
        # Check for running processes
        if PROCESS_LIST="$(pgrep -a -u "$APP_USER" '.*')"; then
            echo -e "${C_RED}${C_BOLD}Error:${C_NC} User $APP_USER has running processes." >&2
            echo -e "${C_YELLOW}Active processes:${C_NC}" >&2
            printf '%s\n' "$PROCESS_LIST" >&2
            echo -e "${C_YELLOW}Stop these processes before continuing.${C_NC}" >&2
            exit 1
        else
            PGREP_RC=$?
            # Exit code 1 means no processes found.
            # Other exit codes indicate an actual pgrep error.
            if (( PGREP_RC != 1 )); then
                echo -e "${C_RED}${C_BOLD}Error:${C_NC} Could not check running processes for $APP_USER (pgrep exit code: $PGREP_RC)." >&2
                exit 1
            fi
        fi
        # No processes found: safe to update account information
        echo -e "${C_CYAN}    -> No running processes found. Updating HOME directory...${C_NC}"
        usermod --home "$APP_DIR" "$APP_USER"
    else
        echo -e "${C_GREEN}    -> User configuration already correct.${C_NC}"
    fi
else
    echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Creating dedicated system user: ${C_GREEN}$APP_USER${C_NC}"
    useradd \
        --system \
        --no-create-home \
        --home-dir "$APP_DIR" \
        --shell /usr/sbin/nologin \
        --user-group \
        "$APP_USER"
fi

# ------------------------------------------------------------------------------
# Directory Creation
# ------------------------------------------------------------------------------
echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Creating structure in ${C_GREEN}$APP_DIR${C_NC}..."
mkdir -p "$APP_DIR"/{manifests,results,config,backend,frontend/dist}

# ------------------------------------------------------------------------------
# Download from GitHub
# ------------------------------------------------------------------------------
if [[ -n "$DOWNLOAD_VERSION" ]]; then
    echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Downloading source code from GitHub ($DOWNLOAD_VERSION)..."
    TAR_URL=""

    if [[ "$DOWNLOAD_VERSION" == "latest" ]]; then
        TAR_URL=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/tags" | grep '"tarball_url":' | head -n 1 | cut -d '"' -f 4)
    else
        TAR_URL="https://api.github.com/repos/$GITHUB_REPO/tarball/${DOWNLOAD_VERSION}"
    fi

    if [[ -z "$TAR_URL" ]]; then
        echo -e "${C_RED}${C_BOLD}Error:${C_NC} Could not determine the download URL for $DOWNLOAD_VERSION." >&2
        exit 1
    fi

    TEMP_DIR=$(mktemp -d)
    echo -e "${C_CYAN}    -> Fetching $TAR_URL${C_NC}"
    curl -L -s "$TAR_URL" -o "$TEMP_DIR/source.tar.gz"

    tar -xzf "$TEMP_DIR/source.tar.gz" -C "$TEMP_DIR" --exclude="source.tar.gz" --strip-components=1
    rm -f -- "$TEMP_DIR/source.tar.gz"
    
    echo -e "${C_CYAN}    -> Deploying files to $APP_DIR${C_NC}"

    if ! cp -a -- "$TEMP_DIR/." "$APP_DIR/"; then
        echo -e "${C_RED}${C_BOLD}Error:${C_NC} Failed to copy application files to $APP_DIR." >&2
        rm -rf -- "$TEMP_DIR"
        exit 1
    fi

    rm -rf "$TEMP_DIR"
fi

# ------------------------------------------------------------------------------
# Initialize user configuration and system-managed state separately
# ------------------------------------------------------------------------------
if [[ ! -f "$APP_DIR/config/settings.json" && ! -f "$APP_DIR/config/system_state.json" ]]; then
cat <<EOF > "$APP_DIR/config/settings.json"
{
  "cron_schedule": "0 */6 * * *",
  "scan_history_size": 15,
  "relative_url_root": "${ALIAS_PATH}",
  "scan_batch_size": 10
}
EOF
    (
        umask 077
        cat <<EOF > "$APP_DIR/config/system_state.json"
{
  "last_global_scan": null,
  "ignored_vulnerabilities_by_project": {},
  "scan_history": [],
  "api_token": "$(openssl rand -base64 16)",
  "upload_token": "$(openssl rand -base64 16)"
}
EOF
    )
elif [[ ! -f "$APP_DIR/config/settings.json" ]]; then
cat <<EOF > "$APP_DIR/config/settings.json"
{
  "cron_schedule": "0 */6 * * *",
  "scan_history_size": 15,
  "relative_url_root": "${ALIAS_PATH}",
  "scan_batch_size": 10
}
EOF
fi

if [[ -f "$APP_DIR/config/system_state.json" ]]; then
    chmod 600 "$APP_DIR/config/system_state.json"
fi

# ------------------------------------------------------------------------------
# Python Virtual Environment
# ------------------------------------------------------------------------------
echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Configuring Python venv using $PYTHON_BIN..."
"$PYTHON_BIN" -m venv "$APP_DIR/backend/venv"
"$APP_DIR/backend/venv/bin/pip" install --upgrade pip
if [[ -f "$APP_DIR/requirements.txt" ]]; then
    "$APP_DIR/backend/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
else
    echo -e "${C_YELLOW}Warning:${C_NC} $APP_DIR/requirements.txt not found. Install dependencies manually."
fi

# ------------------------------------------------------------------------------
# Adjust API endpoints in index.html
# ------------------------------------------------------------------------------
if [[ -f "$APP_DIR/frontend/dist/index.html" ]]; then
    echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Adjusting API endpoints in index.html to use alias $ALIAS_PATH..."
    sed -i "s|fetch('/api/|fetch('${ALIAS_PATH}/api/|g" "$APP_DIR/frontend/dist/index.html"
    sed -i "s|fetch(\`/api/|fetch(\`${ALIAS_PATH}/api/|g" "$APP_DIR/frontend/dist/index.html"
fi

# ------------------------------------------------------------------------------
# Strict Filesystem Permissions
# ------------------------------------------------------------------------------
echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Applying permissions for user $APP_USER..."
chown -R $APP_USER:"$APP_GROUP" "$APP_DIR"
chmod -R 750 "$APP_DIR"
# Para que Apache HTTP pueda acceder a los archivos estáticos del frontend, se requiere que el directorio raíz tenga permisos de ejecución para otros usuarios.
chown $APP_USER:"$APP_GROUP" "$APP_DIR"
chmod 755 "$APP_DIR"
chown -R "$APP_USER":"$WEB_USER" "$APP_DIR"/frontend

# ------------------------------------------------------------------------------
# SELinux and Firewalld (RHEL/Rocky/Alma exclusive)
# ------------------------------------------------------------------------------
if [[ "$OS_FAMILY" == "rhel" ]]; then
    if command -v getenforce &>/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
        echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Configuring SELinux contexts..."
        setsebool -P httpd_can_network_connect 1
        FC_PATTERN="$APP_DIR/frontend/dist(/.*)?"

        # Retrieve existing local SELinux file context rules
        if ! LOCAL_FCONTEXTS="$(semanage fcontext -l -C)"; then
            echo -e "${C_RED}${C_BOLD}Error:${C_NC} Could not retrieve SELinux file context rules." >&2
            exit 1
        fi
        # Check whether the exact rule already exists
        if printf '%s\n' "$LOCAL_FCONTEXTS" | awk -v pattern="$FC_PATTERN" \
            '$1 == pattern { found=1 } END { exit !found }'; then
            echo -e "${C_CYAN}    -> Updating existing SELinux file context rule...${C_NC}"
            semanage fcontext -m -t httpd_sys_content_t "$FC_PATTERN"
        else
            echo -e "${C_CYAN}    -> Creating SELinux file context rule...${C_NC}"
            semanage fcontext -a -t httpd_sys_content_t "$FC_PATTERN"
        fi
        restorecon -Rv "$APP_DIR" > /dev/null
    fi
    if systemctl is-active --quiet firewalld; then
        echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Opening ports in Firewalld..."
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --reload
    fi
fi

# ------------------------------------------------------------------------------
# Systemd Service for FastAPI
# ------------------------------------------------------------------------------
echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Creating systemd service ${BACKEND_SERVICE}..."
cat <<EOF > /etc/systemd/system/${BACKEND_SERVICE}
[Unit]
Description=SecOps SCA FastAPI Backend
After=network.target

[Service]
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR/backend
Environment="PATH=$APP_DIR/backend/venv/bin"
ExecStart=$APP_DIR/backend/venv/bin/uvicorn main:app --host $BACKEND_HOST --port $BACKEND_PORT --workers 2
Restart=always
RestartSec=3

# ==========================================
# HARDENING & SANDBOXING (Contención)
# ==========================================

# 1. Privileges and Filesystem
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$APP_DIR/manifests $APP_DIR/results $APP_DIR/config

# 2. Critical directories isolation
ProtectHome=true
PrivateTmp=true

# 3. Kernel and Hardware Protection
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Enabling and starting backend service..."
systemctl enable --now "${BACKEND_SERVICE}"

# ------------------------------------------------------------------------------
# Apache HTTP Configuration
# ------------------------------------------------------------------------------
echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Configuring Alias $ALIAS_PATH in $CONF_PATH..."
cat <<EOF > "$CONF_PATH"
# =====================================================================
# SecOps SCA Dashboard Configuration under Alias $ALIAS_PATH
# =====================================================================

ProxyPreserveHost On

# 1. Reverse Proxy for API and Swagger
ProxyPass ${ALIAS_PATH}/api/ http://${BACKEND_HOST}:${BACKEND_PORT}/api/
ProxyPassReverse ${ALIAS_PATH}/api/ http://${BACKEND_HOST}:${BACKEND_PORT}/api/

ProxyPass ${ALIAS_PATH}/docs http://${BACKEND_HOST}:${BACKEND_PORT}/docs
ProxyPassReverse ${ALIAS_PATH}/docs http://${BACKEND_HOST}:${BACKEND_PORT}/docs

ProxyPass ${ALIAS_PATH}/openapi.json http://${BACKEND_HOST}:${BACKEND_PORT}/openapi.json
ProxyPassReverse ${ALIAS_PATH}/openapi.json http://${BACKEND_HOST}:${BACKEND_PORT}/openapi.json

# 2. 15MB Upload limit properly applied to API endpoints
<Location "${ALIAS_PATH}/api/">
    LimitRequestBody 15728640
</Location>

# 3. Serve Vue Frontend (SPA)
Alias ${ALIAS_PATH} "$APP_DIR/frontend/dist"

<Directory "$APP_DIR/frontend/dist">
    Options -Indexes +FollowSymLinks
    AllowOverride None
    Require all granted

    # Redirect internal Vue routes to index (Prevents 404 on reload)
    FallbackResource ${ALIAS_PATH}/index.html

    # Security Headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
</Directory>
EOF

if [[ "$OS_FAMILY" == "debian" ]]; then
    echo -e "${C_CYAN}    -> Enabling Apache configuration...${C_NC}"
    a2enconf secops-sca
fi

# ------------------------------------------------------------------------------
# Apache Configuration Validation and Service Activation
# ------------------------------------------------------------------------------

echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Validating Apache configuration..."

if [[ "$OS_FAMILY" == "debian" ]]; then
    apache2ctl configtest
else
    httpd -t
fi

echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Enabling and starting Apache service..."
systemctl enable "$WEB_SERVICE"

if systemctl is-active --quiet "$WEB_SERVICE"; then
    echo -e "${C_CYAN}    -> Apache is running. Reloading configuration...${C_NC}"
    systemctl reload "$WEB_SERVICE"
else
    echo -e "${C_CYAN}    -> Apache is not running. Starting service...${C_NC}"
    systemctl start "$WEB_SERVICE"
fi

# ------------------------------------------------------------------------------
# Cron Job Configuration
# ------------------------------------------------------------------------------
echo -e "${C_BLUE}${C_BOLD}==>${C_NC} Configuring cron scheduled task..."
cat <<EOF > ${BACKEND_CRON}
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
0 */6 * * * $APP_USER curl -s -X POST http://${BACKEND_HOST}:$BACKEND_PORT/api/scan/all >/dev/null 2>&1
EOF
chmod 644 ${BACKEND_CRON}

# ------------------------------------------------------------------------------
# Successful Completion
# ------------------------------------------------------------------------------
echo -e "${C_GREEN}${C_BOLD}==================================================================${C_NC}"
echo -e "${C_GREEN}${C_BOLD} Deployment completed successfully ($OS_FAMILY).${C_NC}"
echo -e "${C_GREEN}${C_BOLD}==================================================================${C_NC}"
echo -e " ${C_BOLD}Base Directory:${C_NC}     ${APP_DIR}"
echo -e " ${C_BOLD}Backend Service:${C_NC}    ${BACKEND_SERVICE}"
echo -e " ${C_BOLD}Backend Cron:${C_NC}       ${BACKEND_CRON}"
echo -e " ${C_BOLD}Backend URL:${C_NC}        http://${BACKEND_HOST}:${BACKEND_PORT}"
echo -e " ${C_BOLD}Access URL:${C_NC}         http(s)://<SERVER-IP>${ALIAS_PATH}"
echo -e " ${C_BOLD}Apache HTTP Config:${C_NC} ${CONF_PATH}"
if [[ -n "$DOWNLOAD_VERSION" ]]; then
    echo -e " ${C_BOLD}Installed Version:${C_NC}  $DOWNLOAD_VERSION (From GitHub)"
fi
echo -e "${C_GREEN}${C_BOLD}==================================================================${C_NC}"

exit 0
