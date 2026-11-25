# -*- coding: utf-8 -*-
"""Configuración centralizada y validada para el SIEM PYME (Librerías e Imprentas)."""

import ipaddress
import logging
import os
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

import pytz

logger = logging.getLogger("siem.config")

# Puertos administrativos / críticos para movimiento lateral
CRITICAL_ADMIN_PORTS: Dict[str, str] = {
    "3389": "RDP",
    "445": "SMB",
    "22": "SSH",
    "23": "Telnet",
    "5900": "VNC",
    "1433": "MSSQL",
    "3306": "MySQL",
}

# Puertos de impresión industrial / oficina (imprentas, copisterías, librerías)
PRINTER_PORTS: Dict[str, str] = {
    "9100": "JetDirect/RAW",
    "515": "LPD",
    "631": "IPP/CUPS",
}

# Categorías de activos orientadas a librerías e imprentas
ASSET_CATEGORIES: Dict[str, Dict[str, object]] = {
    "TPV_CAJA": {
        "label": "TPV / Caja Registradora",
        "icon": "💳",
        "default_port": 80,
        "default_criticidad": "CRITICO",
    },
    "IMPRESORA_PLOTTER": {
        "label": "Impresora / Plotter / RIP",
        "icon": "🖨️",
        "default_port": 9100,
        "default_criticidad": "CRITICO",
    },
    "SERVIDOR_NAS": {
        "label": "Servidor / NAS Diseños",
        "icon": "🗄️",
        "default_port": 445,
        "default_criticidad": "CRITICO",
    },
    "PUESTO_TRABAJO": {
        "label": "PC Diseño / Oficina",
        "icon": "🖥️",
        "default_port": 445,
        "default_criticidad": "NORMAL",
    },
    "WIFI_CLIENTES": {
        "label": "Wi-Fi Clientes / Autoservicio",
        "icon": "📱",
        "default_port": 0,
        "default_criticidad": "INVITADO",
    },
    "RED_INFRA": {
        "label": "Router / Switch / AP",
        "icon": "📡",
        "default_port": 80,
        "default_criticidad": "CRITICO",
    },
    "OTRO": {
        "label": "Otro Dispositivo",
        "icon": "🔌",
        "default_port": 0,
        "default_criticidad": "NORMAL",
    },
}

DEFAULT_SENSITIVE_CATEGORIES = {"TPV_CAJA", "IMPRESORA_PLOTTER", "SERVIDOR_NAS"}


def _parse_subnets(raw: str) -> Tuple[ipaddress._BaseNetwork, ...]:
    nets: List[ipaddress._BaseNetwork] = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            logger.warning("Subred inválida ignorada en LOCAL_SUBNETS: %s", part)
    if not nets:
        nets = [
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
        ]
    return tuple(nets)


def _parse_bool(raw: str, default: bool = False) -> bool:
    if raw is None or raw == "":
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "si", "sí", "on"}


@dataclass
class SiemConfig:
    raspberry_ip: str = "127.0.0.1"
    net_interface: str = "eth0"
    local_subnets_raw: str = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
    tz_name: str = "Europe/Madrid"

    pihole_base_url: str = "http://127.0.0.1:8080/api"
    pihole_web_port: int = 8080
    pihole_password: str = ""

    ntopng_base: str = "http://127.0.0.1:3001"
    ntopng_user: str = "admin"
    ntopng_pass: str = ""

    node_exporter_url: str = "http://127.0.0.1:9100/metrics"
    docker_host: str = "tcp://127.0.0.1:2375"

    db_path: str = "data/historial_red.db"
    tshark_log_path: str = "/tshark_logs/tshark_capture.txt"
    ja3_log_path: str = "/tshark_logs/tshark_ja3.csv"
    suricata_eve_path: str = "/suricata/logs/eve.json"

    admin_user: str = "admin"
    admin_pass: str = ""
    flask_secret_key: str = ""
    session_cookie_secure: bool = False

    telegram_token: str = ""
    telegram_chat_id: str = ""

    negocio_nombre: str = "Mi Librería / Imprenta"
    negocio_tipo: str = "imprenta"
    horario_apertura: str = "08:30"
    horario_cierre: str = "21:00"
    dias_apertura: str = "0,1,2,3,4,5"
    alerta_fuera_horario: bool = True

    logger_interval_seconds: int = 30
    testing: bool = False

    local_subnets: Tuple[ipaddress._BaseNetwork, ...] = field(init=False)
    tz: object = field(init=False)

    def __post_init__(self) -> None:
        self.local_subnets = _parse_subnets(self.local_subnets_raw)
        try:
            self.tz = pytz.timezone(self.tz_name)
        except Exception:
            self.tz = pytz.timezone("Europe/Madrid")

        weak_secrets = {
            "",
            "cambia_esto_en_produccion",
            "cambia_esto_por_una_cadena_larga_y_aleatoria",
            "CAMBIA_ESTO_POR_64_CARACTERES_HEX_ALEATORIOS",
        }
        if self.flask_secret_key in weak_secrets or len(self.flask_secret_key) < 24:
            logger.warning(
                "FLASK_SECRET_KEY ausente o débil; generando clave efímera segura. "
                "Configura FLASK_SECRET_KEY en .env para persistir sesiones."
            )
            self.flask_secret_key = secrets.token_hex(32)

        if not self.admin_pass:
            logger.error(
                "DASHBOARD_PASSWORD no está configurada: el acceso al panel permanecerá "
                "bloqueado (fail-closed) hasta definir una contraseña en .env."
            )

    @classmethod
    def from_env(cls, overrides: dict | None = None) -> "SiemConfig":
        raspberry_ip = os.environ.get("RASPBERRY_IP", "127.0.0.1")
        pihole_port = int(os.environ.get("PIHOLE_WEB_PORT", "8080"))
        default_pihole_url = f"http://127.0.0.1:{pihole_port}/api"

        kwargs = dict(
            raspberry_ip=raspberry_ip,
            net_interface=os.environ.get("NET_INTERFACE", "eth0"),
            local_subnets_raw=os.environ.get(
                "LOCAL_SUBNETS", "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
            ),
            tz_name=os.environ.get("TZ", "Europe/Madrid"),
            pihole_base_url=os.environ.get("PIHOLE_BASE_URL", default_pihole_url),
            pihole_web_port=pihole_port,
            pihole_password=os.environ.get("PIHOLE_PASSWORD", ""),
            ntopng_base=os.environ.get("NTOPNG_BASE", "http://127.0.0.1:3001"),
            ntopng_user=os.environ.get("NTOPNG_USER", "admin"),
            ntopng_pass=os.environ.get("NTOPNG_PASSWORD", ""),
            node_exporter_url=os.environ.get(
                "NODE_EXPORTER_URL", "http://127.0.0.1:9100/metrics"
            ),
            docker_host=os.environ.get("DOCKER_HOST", "tcp://127.0.0.1:2375"),
            db_path=os.environ.get("DB_PATH", "data/historial_red.db"),
            tshark_log_path=os.environ.get(
                "TSHARK_LOG_PATH", "/tshark_logs/tshark_capture.txt"
            ),
            ja3_log_path=os.environ.get("JA3_LOG_PATH", "/tshark_logs/tshark_ja3.csv"),
            suricata_eve_path=os.environ.get(
                "SURICATA_EVE_PATH", "/suricata/logs/eve.json"
            ),
            admin_user=os.environ.get("DASHBOARD_USER", "admin"),
            admin_pass=os.environ.get("DASHBOARD_PASSWORD", ""),
            flask_secret_key=os.environ.get("FLASK_SECRET_KEY", ""),
            session_cookie_secure=_parse_bool(
                os.environ.get("SESSION_COOKIE_SECURE", "false"), False
            ),
            telegram_token=os.environ.get("TELEGRAM_TOKEN", ""),
            telegram_chat_id=os.environ.get("TELEGRAM_CHAT_ID", ""),
            negocio_nombre=os.environ.get("NEGOCIO_NOMBRE", "Mi Librería / Imprenta"),
            negocio_tipo=os.environ.get("NEGOCIO_TIPO", "imprenta"),
            horario_apertura=os.environ.get("HORARIO_APERTURA", "08:30"),
            horario_cierre=os.environ.get("HORARIO_CIERRE", "21:00"),
            dias_apertura=os.environ.get("DIAS_APERTURA", "0,1,2,3,4,5"),
            alerta_fuera_horario=_parse_bool(
                os.environ.get("ALERTA_FUERA_HORARIO", "true"), True
            ),
            logger_interval_seconds=int(os.environ.get("LOGGER_INTERVAL", "30")),
        )
        if overrides:
            kwargs.update(overrides)
        return cls(**kwargs)

    def is_local_ip(self, ip: str) -> bool:
        """Determina si una IP pertenece a las subredes locales configuradas."""
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
        if addr.is_multicast or addr.is_loopback or addr.is_unspecified:
            return False
        return any(addr in net for net in self.local_subnets)

    def is_external_ip(self, ip: str) -> bool:
        """Determina si una IP es pública/externa (no local, no multicast, no loopback)."""
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_multicast
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_unspecified
        ):
            return False
        return not any(addr in net for net in self.local_subnets)
