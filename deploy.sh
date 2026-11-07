#!/usr/bin/env bash
# ==============================================================================
# SecOps Enterprise Security - SCA Dashboard Deployment Script
# ==============================================================================
set -euo pipefail

SCRIPT_VERSION="1.3.0"
GITHUB_REPO="ramonromancastro/secops-sca"

# Valores por defecto
APP_DIR="/opt/secops-sca"
BACKEND_PORT="8000"
ALIAS_PATH="/secops-sca"
UPGRADE_MODE="false"
DOWNLOAD_VERSION=""
MIN_PYTHON_VERSION="3.11"
PYTHON_BIN="python3"

# ------------------------------------------------------------------------------
# Funciones de Ayuda, Versión y GitHub
# ------------------------------------------------------------------------------
show_version() {
    echo "SecOps SCA Deploy Script v${SCRIPT_VERSION}"
}

show_help() {
    show_version
    echo ""
    echo "Uso: sudo $0 [opciones]"
    echo ""
    echo "Opciones de Instalación:"
    echo "  --app-dir <ruta>    Directorio de instalación (defecto: $APP_DIR)"
    echo "  --port <puerto>     Puerto local para el backend FastAPI (defecto: $BACKEND_PORT)"
    echo "  --alias <ruta>      Ruta del alias web en Apache (defecto: $ALIAS_PATH)"
    echo "  --upgrade           Omite los controles de puerto y directorio para actualizar"
    echo "  --python-bin <bin>  Binario de Python a utilizar (defecto: $PYTHON_BIN)"
    echo ""
    echo "Opciones de Repositorio (GitHub):"
    echo "  --download <tag>    Descarga una versión del repo (ej. 'latest' o 'v1.0.0')"
    echo "  --list-versions     Muestra las versiones disponibles en GitHub"
    echo ""
    echo "Otros:"
    echo "  --version           Muestra la versión de este script"
    echo "  -h, --help          Muestra esta ayuda"
    echo ""
}

list_github_versions() {
    echo "Consultando versiones disponibles en GitHub ($GITHUB_REPO)..."
    # Usamos grep/sed para evitar dependencias adicionales como jq
    local tags=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/tags" | grep '"name":' | sed -E 's/.*"([^"]+)".*/\1/')

    if [[ -z "$tags" ]]; then
        echo "No se encontraron versiones publicadas o el repositorio es privado."
    else
        echo "Versiones disponibles para descargar:"
        echo "  - latest (La versión más reciente)"
        echo "$tags" | while read -r v; do echo "  - $v"; done
    fi
    exit 0
}

# ------------------------------------------------------------------------------
# Parseo de Parámetros
# ------------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case $1 in
        --app-dir)
            if [[ -z "${2:-}" || "$2" == -* ]]; then
                echo "Error: --app-dir requiere una ruta (ej. /opt/secops-sca)"
                exit 1
            fi
            # Opcional: Validar que sea una ruta absoluta
            if [[ "$2" != /* ]]; then
                echo "Error: --app-dir debe ser una ruta absoluta (ej. /opt/secops-sca)"
                exit 1
            fi
            APP_DIR="$2"
            shift 2
            ;;
        --port)
            if [[ -z "${2:-}" || ! "$2" =~ ^[0-9]+$ ]]; then
                echo "Error: --port requiere un número de puerto válido (ej. 8000)"
                exit 1
            fi
            BACKEND_PORT="$2"
            shift 2
            ;;
        --alias)
            if [[ -z "${2:-}" || "$2" == -* ]]; then
                echo "Error: --alias requiere una ruta web (ej. /secops-sca)"
                exit 1
            fi
            if [[ "$2" != /* ]]; then
                echo "Error: --alias debe comenzar con '/' (ej. /secops-sca)"
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
                echo "Error: --python-bin requiere el nombre del binario (ej. python3.11)"
                exit 1
            fi
            PYTHON_BIN="$2"
            shift 2
            ;;
        --download)
            if [[ -z "${2:-}" || "$2" == -* ]]; then
                echo "Error: --download requiere una versión (ej. latest o v1.0.0)"
                exit 1
            fi
            DOWNLOAD_VERSION="$2"
            shift 2
            ;;
        --list-versions)
            list_github_versions
            # list_github_versions ya contiene un exit 0
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
            echo "Error: Parámetro desconocido '$1'"
            show_help
            exit 1
            ;;
    esac
done

# ------------------------------------------------------------------------------
# VALIDACIÓN DE PARÁMETROS OBLIGATORIOS
# ------------------------------------------------------------------------------
if [[ -z "$DOWNLOAD_VERSION" ]]; then
    echo "Error: El parámetro '--download <versión>' es OBLIGATORIO."
    echo "Usa '--list-versions' para ver las versiones disponibles."
    echo "Ejemplo: sudo $0 --download latest"
    exit 1
fi

# ------------------------------------------------------------------------------
# Controles de Seguridad de Sistema de Archivos
# ------------------------------------------------------------------------------
# 1. Normalizar la ruta: Eliminar barra diagonal final si existe (ej. /opt/secops-sca/ -> /opt/secops-sca)
APP_DIR="${APP_DIR%/}"
if [[ -z "$APP_DIR" ]]; then APP_DIR="/"; fi # Si era solo "/", al limpiarlo queda vacío

# 2. Prohibir coincidencias exactas (Evita instalar en la raíz de estos directorios)
RESTRICTED_EXACT=("/" "/bin" "/boot" "/dev" "/etc" "/home" "/lib" "/lib64" "/opt" "/proc" "/root" "/run" "/sbin" "/sys" "/tmp" "/usr" "/var" "/var/www")
for dir in "${RESTRICTED_EXACT[@]}"; do
    if [[ "$APP_DIR" == "$dir" ]]; then
        echo "Error de Seguridad: No se permite usar el directorio crítico '$dir' como APP_DIR."
        echo "Solución: Especifica un subdirectorio (ej. ${dir}/secops-sca)"
        exit 1
    fi
done

# 3. Prohibir instalación DENTRO de subcarpetas críticas del core de Linux
RESTRICTED_PREFIXES=("/bin/" "/boot/" "/dev/" "/etc/" "/lib/" "/lib64/" "/proc/" "/root/" "/run/" "/sbin/" "/sys/")
for prefix in "${RESTRICTED_PREFIXES[@]}"; do
    if [[ "$APP_DIR" == "$prefix"* ]]; then
        echo "Error de Seguridad: La ruta '$APP_DIR' pertenece a un sistema de archivos protegido."
        echo "Solución: Utiliza un directorio de aplicaciones seguro como /opt/secops-sca o /var/www/secops-sca."
        exit 1
    fi
done

# ------------------------------------------------------------------------------
# Pre-Controles de Ejecución y Conflictos
# ------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
   echo "Error: Este script debe ejecutarse como root (sudo $0)"
   exit 1
fi

if [[ "$UPGRADE_MODE" == "false" ]]; then
    echo "==> Realizando controles de seguridad previos..."
    if [[ -d "$APP_DIR" ]]; then
        echo "Error: El directorio $APP_DIR ya existe."
        echo "       Usa --upgrade para omitir este control y actualizar/sobreescribir."
        exit 1
    fi
    if command -v ss &> /dev/null; then
        if ss -tuln | grep -q ":$BACKEND_PORT "; then
            echo "Error: El puerto $BACKEND_PORT ya está en uso."
            echo "       Libera el puerto, elige otro con --port, o usa --upgrade."
            exit 1
        fi
    fi
fi

# ------------------------------------------------------------------------------
# Detección de Sistema Operativo e Instalación de Dependencias
# ------------------------------------------------------------------------------
source /etc/os-release
echo "==> Detectado sistema operativo: $PRETTY_NAME"

if [[ "${ID_LIKE:-$ID}" == *"debian"* || "$ID" == "debian" || "$ID" == "ubuntu" ]]; then
    OS_FAMILY="debian"
    WEB_USER="www-data"
    WEB_SERVICE="apache2"
    CONF_PATH="/etc/apache2/conf-available/secops-sca.conf"

    echo "==> Instalando dependencias (Debian/Ubuntu)..."
    apt-get update
    apt-get install -y apache2 python3 python3-venv python3-pip curl iproute2 tar
    a2enmod proxy proxy_http rewrite headers alias
elif [[ "${ID_LIKE:-$ID}" == *"rhel"* || "${ID_LIKE:-$ID}" == *"fedora"* || "$ID" == "rhel" || "$ID" == "rocky" || "$ID" == "almalinux" ]]; then
    OS_FAMILY="rhel"
    WEB_USER="apache"
    WEB_SERVICE="httpd"
    CONF_PATH="/etc/httpd/conf.d/secops-sca.conf"

    echo "==> Instalando dependencias (RHEL/AlmaLinux/Rocky)..."
    dnf install -y httpd python3 python3-pip curl policycoreutils-python-utils iproute tar
else
    echo "Error: Distribución no soportada automáticamente."
    exit 1
fi

# ------------------------------------------------------------------------------
# Validación de Versión de Python
# ------------------------------------------------------------------------------
echo "==> Verificando compatibilidad de Python ($PYTHON_BIN >= $MIN_PYTHON_VERSION)..."

if ! command -v "$PYTHON_BIN" &>/dev/null; then
    echo "Error: No se encontró el binario '$PYTHON_BIN' en el sistema."
    echo "Usa el parámetro '--python-bin <ruta_o_nombre>' para especificar una versión instalada (ej. --python-bin python3.11)."
    exit 1
fi

# Extraer versión en formato Mayor.Menor
PY_VER=$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")

# Comparamos matemáticamente si la versión detectada es mayor o igual a la mínima
if [[ "$(printf '%s\n' "$MIN_PYTHON_VERSION" "$PY_VER" | sort -V | head -n1)" != "$MIN_PYTHON_VERSION" ]]; then
    echo "=================================================================="
    echo " ERROR CRÍTICO: VERSIÓN DE PYTHON INCOMPATIBLE"
    echo "=================================================================="
    echo " Se requiere Python $MIN_PYTHON_VERSION o superior."
    echo " Binario detectado ('$PYTHON_BIN'): versión $PY_VER"
    echo ""
    echo " Si tienes una versión superior instalada, indícala con el parámetro:"
    echo "   sudo $0 --download latest --python-bin python3.11"
    echo "=================================================================="
    exit 1
fi
echo "    -> OK: Binario válido detectado: $PYTHON_BIN (v$PY_VER)"

# ------------------------------------------------------------------------------
# Creación de Directorios
# ------------------------------------------------------------------------------
echo "==> Creando estructura en $APP_DIR..."
mkdir -p "$APP_DIR"/{manifests,results,config,backend,frontend/dist}

# ------------------------------------------------------------------------------
# Descarga desde GitHub (Si se especifica)
# ------------------------------------------------------------------------------
if [[ -n "$DOWNLOAD_VERSION" ]]; then
    echo "==> Descargando código fuente de GitHub ($DOWNLOAD_VERSION)..."
    TAR_URL=""

    if [[ "$DOWNLOAD_VERSION" == "latest" ]]; then
        # Extraer la URL del tarball de la versión más reciente a través de tags
        TAR_URL=$(curl -s "https://api.github.com/repos/$GITHUB_REPO/tags" | grep '"tarball_url":' | head -n 1 | cut -d '"' -f 4)
    else
        TAR_URL="https://api.github.com/repos/$GITHUB_REPO/tarball/${DOWNLOAD_VERSION}"
    fi

    if [[ -z "$TAR_URL" ]]; then
        echo "Error: No se pudo determinar la URL de descarga para $DOWNLOAD_VERSION."
        exit 1
    fi

    TEMP_DIR=$(mktemp -d)
    echo "    -> Obteniendo $TAR_URL"
    curl -L -s "$TAR_URL" -o "$TEMP_DIR/source.tar.gz"

    # Extraer obviando la carpeta raíz generada por GitHub (strip-components=1)
    tar -xzf "$TEMP_DIR/source.tar.gz" -C "$TEMP_DIR" --exclude="source.tar.gz" --strip-components=1

    # Mover el contenido descargado a la carpeta destino
    echo "    -> Desplegando archivos en $APP_DIR"
    cp -r "$TEMP_DIR"/* "$APP_DIR/" 2>/dev/null || true

    rm -rf "$TEMP_DIR"
fi

# ------------------------------------------------------------------------------
# Inicialización de Configuración (settings.json)
# ------------------------------------------------------------------------------
if [[ ! -f "$APP_DIR/config/settings.json" ]]; then
cat <<EOF > "$APP_DIR/config/settings.json"
{
  "cron_schedule": "0 */6 * * *",
  "last_global_scan": null,
  "ignored_vulnerabilities": [],
  "scan_history": [],
  "relative_url_root": "${ALIAS_PATH}",
  "api_token": "$(openssl rand -base64 16)",
  "upload_token": "$(openssl rand -base64 16)"
}
EOF
fi

# ------------------------------------------------------------------------------
# Entorno Virtual Python
# ------------------------------------------------------------------------------
echo "==> Configurando Python venv usando $PYTHON_BIN..."
"$PYTHON_BIN" -m venv "$APP_DIR/backend/venv"
"$APP_DIR/backend/venv/bin/pip" install --upgrade pip
if [[ -f "$APP_DIR/requirements.txt" ]]; then
    "$APP_DIR/backend/venv/bin/pip" install -r "$APP_DIR/requirements.txt"
else
    echo "Aviso: No se encontró $APP_DIR/requirements.txt. Instala las dependencias manualmente."
fi

# ------------------------------------------------------------------------------
# Ajuste automático de rutas en index.html
# ------------------------------------------------------------------------------
if [[ -f "$APP_DIR/frontend/dist/index.html" ]]; then
    echo "==> Ajustando endpoints API en index.html para usar el alias $ALIAS_PATH..."
    sed -i "s|fetch('/api/|fetch('${ALIAS_PATH}/api/|g" "$APP_DIR/frontend/dist/index.html"
    sed -i "s|fetch(\`/api/|fetch(\`${ALIAS_PATH}/api/|g" "$APP_DIR/frontend/dist/index.html"
fi

# ------------------------------------------------------------------------------
# Permisos Estrictos de Sistema de Archivos
# ------------------------------------------------------------------------------
echo "==> Aplicando permisos para usuario $WEB_USER..."
chown -R root:"$WEB_USER" "$APP_DIR"
chmod -R 750 "$APP_DIR"
chown -R "$WEB_USER":"$WEB_USER" "$APP_DIR"/{manifests,results,config}
chmod -R 770 "$APP_DIR"/{manifests,results,config}

# ------------------------------------------------------------------------------
# SELinux y Firewalld (Exclusivo RHEL/Rocky/Alma)
# ------------------------------------------------------------------------------
if [[ "$OS_FAMILY" == "rhel" ]]; then
    if command -v getenforce &>/dev/null && [[ "$(getenforce)" != "Disabled" ]]; then
        echo "==> Configurando contextos SELinux..."
        setsebool -P httpd_can_network_connect 1
        semanage fcontext -a -t httpd_sys_content_t "$APP_DIR/frontend/dist(/.*)?" || true
        semanage fcontext -a -t httpd_sys_rw_content_t "$APP_DIR/manifests(/.*)?" || true
        semanage fcontext -a -t httpd_sys_rw_content_t "$APP_DIR/results(/.*)?" || true
        semanage fcontext -a -t httpd_sys_rw_content_t "$APP_DIR/config(/.*)?" || true
        restorecon -Rv "$APP_DIR" > /dev/null
    fi
    if systemctl is-active --quiet firewalld; then
        echo "==> Abriendo puertos en Firewalld..."
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --reload
    fi
fi

# ------------------------------------------------------------------------------
# Servicio Systemd para FastAPI
# ------------------------------------------------------------------------------
echo "==> Creando servicio systemd secops-sca-backend.service..."
cat <<EOF > /etc/systemd/system/secops-sca-backend.service
[Unit]
Description=SecOps SCA FastAPI Backend
After=network.target

[Service]
User=$WEB_USER
Group=$WEB_USER
WorkingDirectory=$APP_DIR/backend
Environment="PATH=$APP_DIR/backend/venv/bin"
ExecStart=$APP_DIR/backend/venv/bin/uvicorn main:app --host 127.0.0.1 --port $BACKEND_PORT --workers 2
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vuln-backend.service

# ------------------------------------------------------------------------------
# Configuración de Apache HTTP
# ------------------------------------------------------------------------------
echo "==> Configurando Alias $ALIAS_PATH en $CONF_PATH..."
cat <<EOF > "$CONF_PATH"
# =====================================================================
# Configuración de SecOps SCA Dashboard bajo el Alias $ALIAS_PATH
# =====================================================================

ProxyPreserveHost On
ProxyPass ${ALIAS_PATH}/api/ http://127.0.0.1:${BACKEND_PORT}/api/
ProxyPassReverse ${ALIAS_PATH}/api/ http://127.0.0.1:${BACKEND_PORT}/api/
ProxyPass ${ALIAS_PATH}/docs http://127.0.0.1:${BACKEND_PORT}/docs
ProxyPassReverse ${ALIAS_PATH}/docs http://127.0.0.1:${BACKEND_PORT}/docs
ProxyPass ${ALIAS_PATH}/openapi.json http://127.0.0.1:${BACKEND_PORT}/openapi.json
ProxyPassReverse ${ALIAS_PATH}/openapi.json http://127.0.0.1:${BACKEND_PORT}/openapi.json

Alias ${ALIAS_PATH} "$APP_DIR/frontend/dist"

<Directory "$APP_DIR/frontend/dist">
    Options -Indexes +FollowSymLinks
    AllowOverride None
    Require all granted
    LimitRequestBody 15728640
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
</Directory>

<DirectoryMatch "^$APP_DIR/(manifests|results|config|backend)">
    Require all denied
</DirectoryMatch>
EOF

if [[ "$OS_FAMILY" == "debian" ]]; then
    a2dissite secops-sca.conf 2>/dev/null || true
    a2enconf secops-sca.conf
fi

systemctl enable --now "$WEB_SERVICE"
systemctl restart "$WEB_SERVICE"

# ------------------------------------------------------------------------------
# Configuración del Cron Job
# ------------------------------------------------------------------------------
echo "==> Configurando tarea programada cron..."
cat <<EOF > /etc/cron.d/secops-sca-scanner
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
0 */6 * * * $WEB_USER curl -s -X POST http://127.0.0.1:$BACKEND_PORT/api/scan/all >/dev/null 2>&1
EOF
chmod 644 /etc/cron.d/secops-sca-scanner

# ------------------------------------------------------------------------------
# Finalización Exitoso
# ------------------------------------------------------------------------------
echo "=================================================================="
echo " Despliegue completado con éxito ($OS_FAMILY)."
echo " Directorio Base: $APP_DIR"
echo " Puerto Interno:  $BACKEND_PORT"
echo " URL de acceso:   http://<IP-SERVIDOR>${ALIAS_PATH}"
if [[ -n "$DOWNLOAD_VERSION" ]]; then
    echo " Versión Instalada: $DOWNLOAD_VERSION (Desde GitHub)"
fi
echo "=================================================================="

exit 0
