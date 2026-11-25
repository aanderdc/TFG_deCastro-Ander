#!/usr/bin/env bash
# ==============================================================================
#  Instalador automático SIEM PYME (Librerías e Imprentas) — Raspberry Pi 4
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIHOLE_DIR="$ROOT_DIR/pihole"
ENV_FILE="$PIHOLE_DIR/.env"
CERT_DIR="$PIHOLE_DIR/nginx/certs"

echo "============================================================"
echo "  🛡️  SIEM PYME — Instalador para Librerías e Imprentas"
echo "============================================================"

# Detectar interfaz de red e IP por defecto
DEFAULT_IFACE="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -n1 || echo eth0)"
DEFAULT_IP="$(ip -o -4 addr show "$DEFAULT_IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo 192.168.1.100)"

read -rp "Nombre de tu negocio [Mi Librería / Imprenta]: " NEGOCIO_NOMBRE
NEGOCIO_NOMBRE="${NEGOCIO_NOMBRE:-Mi Librería / Imprenta}"

read -rp "Tipo (imprenta/libreria/copisteria/mixto) [imprenta]: " NEGOCIO_TIPO
NEGOCIO_TIPO="${NEGOCIO_TIPO:-imprenta}"

read -rp "Hora de apertura (HH:MM) [08:30]: " HORARIO_APERTURA
HORARIO_APERTURA="${HORARIO_APERTURA:-08:30}"

read -rp "Hora de cierre (HH:MM) [21:00]: " HORARIO_CIERRE
HORARIO_CIERRE="${HORARIO_CIERRE:-21:00}"

read -rp "Interfaz de red detectada [$DEFAULT_IFACE]: " NET_INTERFACE
NET_INTERFACE="${NET_INTERFACE:-$DEFAULT_IFACE}"

read -rp "IP estática de la Raspberry Pi [$DEFAULT_IP]: " RASPBERRY_IP
RASPBERRY_IP="${RASPBERRY_IP:-$DEFAULT_IP}"

read -rp "Usuario del panel SIEM [admin]: " DASHBOARD_USER
DASHBOARD_USER="${DASHBOARD_USER:-admin}"

read -rsp "Contraseña del panel SIEM (vacío = generar aleatoria segura): " DASHBOARD_PASSWORD
echo ""

gen_pass() {
    openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 20
}

DASHBOARD_PASSWORD="${DASHBOARD_PASSWORD:-$(gen_pass)}"
PIHOLE_PASSWORD="$(gen_pass)"
GRAFANA_PASSWORD="$(gen_pass)"
NTOPNG_PASSWORD="$(gen_pass)"
REDIS_PASSWORD="$(gen_pass)"
MITMWEB_PASSWORD="$(gen_pass)"
FLASK_SECRET_KEY="$(openssl rand -hex 32)"

# Generar certificado TLS autofirmado con SAN para la IP local y siem.local
mkdir -p "$CERT_DIR" "$PIHOLE_DIR/tshark_logs" "$PIHOLE_DIR/suricata/logs" "$PIHOLE_DIR/suricata/rules" "$ROOT_DIR/dashboard/data"
if [ ! -f "$CERT_DIR/siem.key" ] || [ ! -f "$CERT_DIR/siem.crt" ]; then
    echo "[+] Generando certificado TLS autofirmado para $RASPBERRY_IP y siem.local..."
    openssl req -x509 -nodes -days 1825 -newkey rsa:2048 \
        -keyout "$CERT_DIR/siem.key" \
        -out "$CERT_DIR/siem.crt" \
        -subj "/CN=siem.local/O=$NEGOCIO_NOMBRE" \
        -addext "subjectAltName=DNS:siem.local,IP:$RASPBERRY_IP,IP:127.0.0.1" >/dev/null 2>&1
    chmod 600 "$CERT_DIR/siem.key"
fi

cat > "$ENV_FILE" <<EOF
RASPBERRY_IP=$RASPBERRY_IP
NET_INTERFACE=$NET_INTERFACE
LOCAL_SUBNETS=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12
TZ=Europe/Madrid

NEGOCIO_NOMBRE=$NEGOCIO_NOMBRE
NEGOCIO_TIPO=$NEGOCIO_TIPO
HORARIO_APERTURA=$HORARIO_APERTURA
HORARIO_CIERRE=$HORARIO_CIERRE
DIAS_APERTURA=0,1,2,3,4,5
ALERTA_FUERA_HORARIO=true

DASHBOARD_USER=$DASHBOARD_USER
DASHBOARD_PASSWORD=$DASHBOARD_PASSWORD
FLASK_SECRET_KEY=$FLASK_SECRET_KEY

PIHOLE_PASSWORD=$PIHOLE_PASSWORD
GRAFANA_PASSWORD=$GRAFANA_PASSWORD
NTOPNG_USER=admin
NTOPNG_PASSWORD=$NTOPNG_PASSWORD
REDIS_PASSWORD=$REDIS_PASSWORD
MITMWEB_PASSWORD=$MITMWEB_PASSWORD

TELEGRAM_TOKEN=
TELEGRAM_CHAT_ID=
WIREGUARD_SERVERURL=
NGROK_AUTHTOKEN=
TSHARK_MAX_LOG_BYTES=20971520
EOF

chmod 600 "$ENV_FILE"

echo ""
echo "✅ Configuración guardada en $ENV_FILE (permisos 600)"
echo "------------------------------------------------------------"
echo "  Dashboard SIEM : https://$RASPBERRY_IP"
echo "  Usuario        : $DASHBOARD_USER"
echo "  Contraseña     : $DASHBOARD_PASSWORD"
echo "  Pi-hole Admin  : http://$RASPBERRY_IP:8080/admin (pass: $PIHOLE_PASSWORD)"
echo "  ntopng         : http://$RASPBERRY_IP:3001"
echo "------------------------------------------------------------"
echo "Para iniciar el sistema ejecuta:"
echo "  cd $PIHOLE_DIR && docker compose up -d --build"
