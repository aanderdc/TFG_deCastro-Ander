# -*- coding: utf-8 -*-
"""
Motor de detección de amenazas y anomalías operativas orientado a librerías e imprentas.
Cada alerta incluye una recomendación clara en español para personal no técnico.
"""

import html
import json
import logging
import statistics
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

from siem.collectors import (
    IncrementalFileReader,
    JA3Database,
    extract_dst_port,
    parse_tshark_line,
)
from siem.config import (
    CRITICAL_ADMIN_PORTS,
    DEFAULT_SENSITIVE_CATEGORIES,
    PRINTER_PORTS,
    SiemConfig,
)
from siem.database import Database

logger = logging.getLogger("siem.detector")

# Guías claras en lenguaje de negocio para cada tipo de alerta
ALERT_GUIDANCE: Dict[str, Dict[str, str]] = {
    "SCORE_ALTO": {
        "categoria": "SEGURIDAD",
        "recomendacion": "Revisa el equipo en 'Red Interna' y pásale un antivirus. Si es un dispositivo desconocido, bloquéalo en el router.",
    },
    "DISPOSITIVO_NUEVO": {
        "categoria": "INVENTARIO",
        "recomendacion": "Verifica si es un equipo legítimo (nuevo PC, móvil o impresora). Si lo reconoces, regístralo en 'Mi Negocio'; si no, cambia la clave Wi-Fi.",
    },
    "TRAFICO_ALTO": {
        "categoria": "RENDIMIENTO",
        "recomendacion": "Comprueba si ese equipo está descargando archivos pesados o actualizaciones que ralenticen el TPV o el envío de diseños a imprenta.",
    },
    "DNS_BLOQUEADAS": {
        "categoria": "SEGURIDAD",
        "recomendacion": "Se ha bloqueado un pico de dominios maliciosos o rastreadores. Revisa qué equipo tiene adware o extensiones sospechosas en el navegador.",
    },
    "FLOOD_DETECTADO": {
        "categoria": "SEGURIDAD",
        "recomendacion": "Número anómalo de conexiones simultáneas (posible malware o escaneo). Desconecta temporalmente el cable/Wi-Fi de ese equipo y revísalo.",
    },
    "RATIO_ANOMALO": {
        "categoria": "EXFILTRACION",
        "recomendacion": "Subida de datos muy superior a la bajada. Verifica que no se estén subiendo diseños de clientes o copias de la base de datos sin permiso.",
    },
    "LATERAL_SCAN": {
        "categoria": "INTRUSION",
        "recomendacion": "Un dispositivo está escaneando otros equipos de la tienda. Aíslalo de la red inmediatamente y revisa si es un móvil de un cliente en Wi-Fi.",
    },
    "LATERAL_PORT": {
        "categoria": "INTRUSION",
        "recomendacion": "Intento de acceso administrativo (RDP/SMB/SSH/VNC) interno. Confirma si tu soporte técnico está conectado; si no, aísla el equipo origen.",
    },
    "BEACONING": {
        "categoria": "MALWARE_C2",
        "recomendacion": "Tráfico periódico sospechoso hacia un servidor externo (posible malware o ransomware). Aísla el equipo y revisa las copias de seguridad.",
    },
    "DNS_OVER_HTTPS": {
        "categoria": "EVASION",
        "recomendacion": "Un dispositivo está sorteando el filtro DNS (Pi-hole) usando DNS cifrado externo. Revisa la configuración de DNS seguro del navegador o del equipo.",
    },
    "JA3_C2": {
        "categoria": "MALWARE_C2",
        "recomendacion": "Huella criptográfica asociada a herramientas de ataque/C2. Desconecta el equipo afectado de la red de inmediato y realiza un análisis forense.",
    },
    "SURICATA_IDS": {
        "categoria": "IDS",
        "recomendacion": "El sistema de detección de intrusiones (Suricata) ha disparado una firma de amenaza. Revisa origen/destino y aísla el equipo si no corresponde a tu actividad.",
    },
    # ── Reglas específicas para librerías e imprentas ──
    "ACCESO_ACTIVO_CRITICO": {
        "categoria": "NEGOCIO_CRITICO",
        "recomendacion": "Un dispositivo no autorizado o de Wi-Fi clientes ha contactado con tu TPV, impresora/plotter o NAS. Separa la red Wi-Fi de invitados y bloquea esta IP.",
    },
    "IMPRESION_NO_AUTORIZADA": {
        "categoria": "IMPRENTA",
        "recomendacion": "Un equipo no autorizado intentó conectarse a puertos de impresión (9100/631/515). Evita impresiones indebidas o desperdicio de tinta/papel restringiendo el acceso.",
    },
    "RANSOMWARE_SOSPECHOSO": {
        "categoria": "RANSOMWARE",
        "recomendacion": "URGENTE: Patrón compatible con propagación ransomware (múltiples conexiones SMB/445 o ráfaga anómala). Desconecta el equipo de la red y verifica tus copias de seguridad offline.",
    },
    "ACTIVIDAD_FUERA_HORARIO": {
        "categoria": "HORARIO",
        "recomendacion": "Se ha detectado actividad de red o acceso a equipos de la tienda fuera del horario comercial configurado. Comprueba si había alguien autorizado o un acceso remoto.",
    },
    "ACTIVO_CAIDO": {
        "categoria": "DISPONIBILIDAD",
        "recomendacion": "Un equipo crítico del negocio (Impresora, Plotter, TPV, NAS o Internet) no responde. Comprueba alimentación eléctrica, cable de red y estado del router.",
    },
}

RESOLVERS_DOH = {
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
}

SURICATA_FALSE_POSITIVES = {"duckdns", "DYNAMIC_DNS", "Spotify", "Telegram"}


def is_outside_business_hours(
    business_cfg: Dict[str, Any], now_dt: datetime
) -> bool:
    """Indica si `now_dt` está fuera del horario comercial configurado."""
    if not business_cfg.get("alerta_fuera_horario", True):
        return False
    try:
        open_days = {
            int(d.strip())
            for d in str(business_cfg.get("dias_apertura", "0,1,2,3,4,5")).split(",")
            if d.strip().isdigit()
        }
        if now_dt.weekday() not in open_days:
            return True
        open_h, open_m = [
            int(x) for x in str(business_cfg.get("horario_apertura", "08:30")).split(":")
        ]
        close_h, close_m = [
            int(x) for x in str(business_cfg.get("horario_cierre", "21:00")).split(":")
        ]
        now_mins = now_dt.hour * 60 + now_dt.minute
        open_mins = open_h * 60 + open_m
        close_mins = close_h * 60 + close_m
        if open_mins <= close_mins:
            return not (open_mins <= now_mins <= close_mins)
        # Horario nocturno cruzando medianoche
        return close_mins < now_mins < open_mins
    except Exception:
        return False


class AlertEngine:
    """Motor de alertas con deduplicación thread-safe, reglas SIEM y reglas de negocio."""

    def __init__(
        self,
        config: SiemConfig,
        db: Database,
        ja3_db: JA3Database,
        tshark_reader: IncrementalFileReader,
        ja3_reader: IncrementalFileReader,
        suricata_reader: IncrementalFileReader,
    ):
        self.config = config
        self.db = db
        self.ja3_db = ja3_db
        self.tshark_reader = tshark_reader
        self.ja3_reader = ja3_reader
        self.suricata_reader = suricata_reader
        self._dedup_lock = threading.Lock()
        self._recent_alerts: Dict[str, float] = {}

    def enviar_telegram(self, mensaje_html: str) -> bool:
        if not self.config.telegram_token or not self.config.telegram_chat_id:
            return False
        try:
            url = f"https://api.telegram.org/bot{self.config.telegram_token}/sendMessage"
            r = requests.post(
                url,
                json={
                    "chat_id": self.config.telegram_chat_id,
                    "text": mensaje_html,
                    "parse_mode": "HTML",
                },
                timeout=5,
            )
            return r.status_code == 200
        except Exception as e:
            logger.debug("[Telegram] Error al enviar: %s", e)
            return False

    def purge_dedup_cache(self, ttl_seconds: int = 600) -> None:
        cutoff = time.time() - ttl_seconds
        with self._dedup_lock:
            stale = [k for k, ts in self._recent_alerts.items() if ts < cutoff]
            for k in stale:
                self._recent_alerts.pop(k, None)

    def registrar_alerta(
        self,
        cursor,
        tipo: str,
        ip: str,
        descripcion: str,
        severidad: str = "MEDIA",
        dedup_seconds: int = 600,
    ) -> bool:
        clave = f"{tipo}|{ip}"
        now_ts = time.time()
        with self._dedup_lock:
            last_ts = self._recent_alerts.get(clave)
            if last_ts is not None and (now_ts - last_ts) < dedup_seconds:
                return False
            self._recent_alerts[clave] = now_ts

        ahora = self.db.now_str()
        guidance = ALERT_GUIDANCE.get(
            tipo,
            {
                "categoria": "SEGURIDAD",
                "recomendacion": "Revisa el evento en el panel de alertas y comprueba el equipo afectado.",
            },
        )
        cursor.execute(
            """INSERT INTO alertas
               (fecha, tipo, ip, descripcion, severidad, estado, recomendacion, categoria)
               VALUES (?, ?, ?, ?, ?, 'ABIERTA', ?, ?)""",
            (
                ahora,
                tipo,
                ip,
                descripcion,
                severidad,
                guidance["recomendacion"],
                guidance["categoria"],
            ),
        )

        if severidad in ("CRITICA", "ALTA"):
            icono = "🔴" if severidad == "CRITICA" else "🟠"
            msg = (
                f"{icono} <b>ALERTA {html.escape(severidad)}</b>\n"
                f"<b>Tipo:</b> {html.escape(tipo)}\n"
                f"<b>IP/Activo:</b> {html.escape(str(ip))}\n"
                f"<b>Detalle:</b> {html.escape(descripcion)}\n"
                f"<b>Qué hacer:</b> {html.escape(guidance['recomendacion'])}\n"
                f"<b>Hora:</b> {html.escape(ahora)}"
            )
            self.enviar_telegram(msg)

        logger.info("[ALERTA] %s — %s — %s — %s", severidad, tipo, ip, descripcion)
        return True

    def detectar_alertas_hosts(
        self,
        cursor,
        hosts: List[Dict[str, Any]],
        now_dt: Optional[datetime] = None,
    ) -> None:
        """
        Evalúa anomalías por dispositivo + pico DNS bloqueado + actividad fuera de horario.
        CORRIGE el bug crítico del TFG original (unpack de 3 columnas en 2 variables y regla DNS muerta).
        """
        now_dt = now_dt or datetime.now(self.config.tz)
        cutoff_24h = self.db.cutoff_str(hours=24)
        business_cfg = self.db.get_business_config(cursor.connection)
        assets_map = self.db.get_assets_map(cursor.connection)
        fuera_horario = is_outside_business_hours(business_cfg, now_dt)

        # IPs ya conocidas (histórico de tráfico o inventario de activos)
        ips_conocidas = {
            r[0]
            for r in cursor.execute(
                "SELECT DISTINCT ip FROM trafico_dispositivos"
            ).fetchall()
        } | set(assets_map.keys())

        # Media REAL de tráfico (delta por ciclo) en las últimas 24h por IP
        medias: Dict[str, float] = {}
        rows_media = cursor.execute(
            """SELECT ip, AVG(bytes_bajada) AS media_bajada
               FROM trafico_dispositivos
               WHERE fecha_hora >= ?
               GROUP BY ip""",
            (cutoff_24h,),
        ).fetchall()
        for row in rows_media:
            medias[row[0]] = float(row[1] or 0.0)

        # Regla DNS_BLOQUEADAS (antes era código muerto)
        dns_rows = cursor.execute(
            "SELECT ads_blocked FROM estadisticas_dns ORDER BY id DESC LIMIT 2"
        ).fetchall()
        if len(dns_rows) == 2:
            delta_blocked = int(dns_rows[0][0] or 0) - int(dns_rows[1][0] or 0)
            if delta_blocked > 50:
                self.registrar_alerta(
                    cursor,
                    "DNS_BLOQUEADAS",
                    self.config.raspberry_ip,
                    f"Pico de dominios bloqueados por Pi-hole: +{delta_blocked} en el último ciclo",
                    "ALTA",
                )

        for h in hosts:
            ip = h["ip"]
            score = int(h.get("score", 0) or 0)
            bajada_delta = float(h.get("delta_rcvd_mb", h.get("rcvd_mb", 0)) or 0.0)
            subida_delta = float(h.get("delta_sent_mb", h.get("sent_mb", 0)) or 0.0)
            bajada_total = float(h.get("rcvd_mb", 0) or 0.0)
            subida_total = float(h.get("sent_mb", 0) or 0.0)
            flows = int(h.get("flows", 0) or 0)

            asset = assets_map.get(ip)
            label = f"{asset['nombre']} ({ip})" if asset else ip

            # 1. Score alto en ntopng
            if score > 100:
                sev = "CRITICA" if score > 500 else "ALTA"
                self.registrar_alerta(
                    cursor, "SCORE_ALTO", ip, f"Score de amenaza en {label}: {score}", sev
                )

            # 2. Dispositivo nuevo no registrado
            if ip not in ips_conocidas and ip != self.config.raspberry_ip:
                sev = "ALTA" if fuera_horario else "MEDIA"
                extra = " (¡FUERA DE HORARIO COMERCIAL!)" if fuera_horario else ""
                self.registrar_alerta(
                    cursor,
                    "DISPOSITIVO_NUEVO",
                    ip,
                    f"Nuevo dispositivo detectado en la red: {ip} ({h.get('fabricante', 'Desconocido')}){extra}",
                    sev,
                )

            # 3. Tráfico inusualmente alto (> 5x media 24h y > 10 MB en ciclo)
            if ip in medias and medias[ip] > 0:
                if bajada_delta > medias[ip] * 5 and bajada_delta > 10:
                    self.registrar_alerta(
                        cursor,
                        "TRAFICO_ALTO",
                        ip,
                        f"Tráfico inusual en {label}: {bajada_delta:.1f} MB vs media {medias[ip]:.1f} MB",
                        "ALTA",
                    )

            # 4. Flood de conexiones
            if flows > 500:
                sev = "CRITICA" if flows > 2000 else "ALTA"
                self.registrar_alerta(
                    cursor,
                    "FLOOD_DETECTADO",
                    ip,
                    f"Posible flood desde {label}: {flows} flujos activos simultáneos",
                    sev,
                )

            # 5. Ratio subida/bajada anómalo (exfiltración de diseños/datos)
            if subida_total > 50 and bajada_total > 0 and (subida_total / bajada_total) > 10:
                sev = (
                    "CRITICA"
                    if asset and asset["categoria"] in ("SERVIDOR_NAS", "TPV_CAJA")
                    else "ALTA"
                )
                self.registrar_alerta(
                    cursor,
                    "RATIO_ANOMALO",
                    ip,
                    f"Posible exfiltración en {label}: ↑{subida_total:.1f} MB / ↓{bajada_total:.1f} MB",
                    sev,
                )

            # 6. NUEVA REGLA NEGOCIO: Actividad significativa fuera de horario comercial
            if (
                fuera_horario
                and ip != self.config.raspberry_ip
                and (bajada_delta + subida_delta) > 25.0
            ):
                self.registrar_alerta(
                    cursor,
                    "ACTIVIDAD_FUERA_HORARIO",
                    ip,
                    f"Transferencia de {bajada_delta + subida_delta:.1f} MB en {label} con el negocio cerrado ({now_dt.strftime('%H:%M')})",
                    "ALTA",
                )

    def analizar_trafico_lateral(
        self, cursor, now_dt: Optional[datetime] = None
    ) -> None:
        """
        Analiza nuevas líneas de tshark:
        - Escaneo lateral (LATERAL_SCAN)
        - Puertos administrativos críticos (LATERAL_PORT)
        - Acceso no autorizado a TPV/Impresoras/NAS (ACCESO_ACTIVO_CRITICO)
        - Impresión no autorizada en puertos 9100/515/631 (IMPRESION_NO_AUTORIZADA)
        - Propagación SMB / Ransomware sospechoso (RANSOMWARE_SOSPECHOSO)
        - Acceso a impresora o TPV fuera de horario comercial (ACTIVIDAD_FUERA_HORARIO)
        """
        nuevas = self.tshark_reader.read_new_lines()
        if not nuevas:
            return

        now_dt = now_dt or datetime.now(self.config.tz)
        ahora = self.db.now_str()
        cutoff_1m = self.db.cutoff_str(minutes=1)
        assets_map = self.db.get_assets_map(cursor.connection)
        business_cfg = self.db.get_business_config(cursor.connection)
        fuera_horario = is_outside_business_hours(business_cfg, now_dt)

        contactos_internos_por_src: Dict[str, set] = defaultdict(set)
        smb_destinos_por_src: Dict[str, set] = defaultdict(set)
        dedup_lote = set()

        for line in nuevas:
            p = parse_tshark_line(line)
            if not p:
                continue
            src = p.get("src", "")
            dst = p.get("dst", "")
            if not self.config.is_local_ip(src):
                continue

            proto = p.get("protocolo", "")
            info = p.get("info", "")
            puerto_dst = extract_dst_port(info)

            lote_key = (src, dst, proto, puerto_dst)
            if lote_key not in dedup_lote:
                dedup_lote.add(lote_key)
                existe = cursor.execute(
                    """SELECT id FROM lateral_connections
                       WHERE src_ip = ? AND dst_ip = ? AND protocolo = ?
                         AND puerto_dst = ? AND fecha >= ?""",
                    (src, dst, proto, puerto_dst, cutoff_1m),
                ).fetchone()
                if not existe:
                    cursor.execute(
                        """INSERT INTO lateral_connections
                           (fecha, src_ip, dst_ip, protocolo, puerto_dst, info)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (ahora, src, dst, proto, puerto_dst, info[:160]),
                    )

            dst_es_local = self.config.is_local_ip(dst)
            if dst_es_local and dst != src:
                contactos_internos_por_src[src].add(dst)

            # Detección de puertos administrativos críticos
            if dst_es_local and puerto_dst in CRITICAL_ADMIN_PORTS:
                nombre_proto = CRITICAL_ADMIN_PORTS[puerto_dst]
                self.registrar_alerta(
                    cursor,
                    "LATERAL_PORT",
                    src,
                    f"Conexión interna a puerto crítico {nombre_proto} ({puerto_dst}): {src} → {dst}",
                    "CRITICA",
                )
                if puerto_dst == "445":
                    smb_destinos_por_src[src].add(dst)

            # ── REGLAS ESPECÍFICAS PARA LIBRERÍAS E IMPRENTAS ──
            src_asset = assets_map.get(src)
            dst_asset = assets_map.get(dst)
            src_no_autorizado = (
                src != self.config.raspberry_ip
                and (
                    src_asset is None
                    or not src_asset["autorizado"]
                    or src_asset["categoria"] == "WIFI_CLIENTES"
                )
            )

            # A. Acceso desde equipo no autorizado / Wi-Fi clientes hacia TPV, Impresora/Plotter o NAS
            if (
                dst_asset is not None
                and dst_asset["categoria"] in DEFAULT_SENSITIVE_CATEGORIES
                and src_no_autorizado
            ):
                src_label = src_asset["nombre"] if src_asset else "Dispositivo desconocido"
                self.registrar_alerta(
                    cursor,
                    "ACCESO_ACTIVO_CRITICO",
                    src,
                    f"{src_label} ({src}) accedió al activo crítico {dst_asset['nombre']} ({dst}) puerto {puerto_dst or proto}",
                    "CRITICA",
                )

            # B. Conexión no autorizada a puertos de impresión (9100 JetDirect, 515 LPD, 631 IPP)
            if dst_es_local and puerto_dst in PRINTER_PORTS and src_no_autorizado:
                printer_name = dst_asset["nombre"] if dst_asset else dst
                self.registrar_alerta(
                    cursor,
                    "IMPRESION_NO_AUTORIZADA",
                    src,
                    f"Intento de impresión desde equipo no autorizado {src} hacia {printer_name} ({PRINTER_PORTS[puerto_dst]}:{puerto_dst})",
                    "ALTA",
                )

            # C. Acceso a impresora o TPV fuera de horario comercial
            if (
                fuera_horario
                and dst_es_local
                and src != self.config.raspberry_ip
                and (
                    puerto_dst in PRINTER_PORTS
                    or (dst_asset and dst_asset["categoria"] in ("TPV_CAJA", "IMPRESORA_PLOTTER"))
                )
            ):
                target = dst_asset["nombre"] if dst_asset else dst
                self.registrar_alerta(
                    cursor,
                    "ACTIVIDAD_FUERA_HORARIO",
                    src,
                    f"Acceso a {target} desde {src} fuera de horario comercial ({now_dt.strftime('%H:%M')})",
                    "ALTA",
                )

        # Escaneo lateral (solo destinos INTERNOS distintos!)
        for src_ip, dsts in contactos_internos_por_src.items():
            if len(dsts) >= 5:
                sev = "CRITICA" if len(dsts) >= 15 else "ALTA"
                self.registrar_alerta(
                    cursor,
                    "LATERAL_SCAN",
                    src_ip,
                    f"Posible escaneo interno: {src_ip} contactó {len(dsts)} equipos internos distintos en un ciclo",
                    sev,
                )

        # Propagación SMB sospechosa (Ransomware lateral)
        for src_ip, smb_dsts in smb_destinos_por_src.items():
            if len(smb_dsts) >= 3:
                self.registrar_alerta(
                    cursor,
                    "RANSOMWARE_SOSPECHOSO",
                    src_ip,
                    f"Posible propagación ransomware: {src_ip} abrió conexiones SMB (445) hacia {len(smb_dsts)} equipos internos",
                    "CRITICA",
                )

    def detectar_beaconing(self, cursor) -> None:
        cutoff_1h = self.db.cutoff_str(hours=1)
        rows = cursor.execute(
            """SELECT src_ip, dst_ip, fecha
               FROM lateral_connections
               WHERE fecha >= ?
               ORDER BY src_ip, dst_ip, fecha""",
            (cutoff_1h,),
        ).fetchall()

        grupos = defaultdict(list)
        for src, dst, fecha in rows:
            if not self.config.is_external_ip(dst):
                continue
            if src == self.config.raspberry_ip:
                continue
            try:
                grupos[(src, dst)].append(datetime.strptime(fecha, "%Y-%m-%d %H:%M:%S"))
            except ValueError:
                pass

        for (src, dst), tiempos in grupos.items():
            if len(tiempos) < 5:
                continue
            tiempos.sort()
            intervalos = [
                (tiempos[i + 1] - tiempos[i]).total_seconds()
                for i in range(len(tiempos) - 1)
            ]
            media = sum(intervalos) / len(intervalos)
            if media < 5:
                continue
            stdev = statistics.stdev(intervalos) if len(intervalos) > 1 else 0.0
            cv = stdev / media
            if cv < 0.3:
                sev = "CRITICA" if cv < 0.1 else "ALTA"
                self.registrar_alerta(
                    cursor,
                    "BEACONING",
                    src,
                    f"Posible beaconing C2: {src} → {dst} | {len(tiempos)} contactos/1h, intervalo ~{media:.0f}s, CV={cv:.2f}",
                    sev,
                )

    def detectar_doh(self, cursor) -> None:
        cutoff_10m = self.db.cutoff_str(minutes=10)
        rows = cursor.execute(
            """SELECT DISTINCT src_ip, dst_ip
               FROM lateral_connections
               WHERE fecha >= ? AND puerto_dst = '443'""",
            (cutoff_10m,),
        ).fetchall()
        for src, dst in rows:
            if dst in RESOLVERS_DOH:
                self.registrar_alerta(
                    cursor,
                    "DNS_OVER_HTTPS",
                    src,
                    f"{src} usa DNS over HTTPS hacia {dst}:443 — filtro Pi-hole evadido",
                    "ALTA",
                )

    def detectar_ja3(self, cursor) -> None:
        """Lee INCREMENTALMENTE tshark_ja3.csv (no relee el archivo completo cada 30s)."""
        self.ja3_db.refresh_if_stale()
        nuevas = self.ja3_reader.read_new_lines()
        for line in nuevas:
            line = line.strip()
            if not line or line.startswith("ip.src"):
                continue
            parts = line.split(",")
            if len(parts) < 4:
                continue
            src, dst, puerto, ja3 = parts[0], parts[1], parts[2], parts[3]
            herramienta = self.ja3_db.lookup(ja3)
            if herramienta:
                self.registrar_alerta(
                    cursor,
                    "JA3_C2",
                    src,
                    f"Huella TLS maliciosa ({herramienta}): {src} → {dst}:{puerto} | JA3={ja3}",
                    "CRITICA",
                )

    def detectar_suricata(self, cursor) -> None:
        nuevas = self.suricata_reader.read_new_lines()
        mapa_sev = {1: "CRITICA", 2: "ALTA", 3: "MEDIA"}
        for line in nuevas:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:
                continue
            if ev.get("event_type") != "alert":
                continue
            alerta = ev.get("alert", {})
            sig = alerta.get("signature", "")
            if any(fp in sig for fp in SURICATA_FALSE_POSITIVES):
                continue

            src_ip = ev.get("src_ip", "")
            dst_ip = ev.get("dest_ip", "")
            proto = ev.get("proto", "")
            dst_port = ev.get("dest_port", "")
            sev = mapa_sev.get(alerta.get("severity", 3), "MEDIA")

            mitre = ""
            meta = alerta.get("metadata", {})
            tecnica = meta.get("mitre_technique_name", [])
            if tecnica:
                mitre = f" | MITRE: {tecnica[0].replace('_', ' ')}"

            self.registrar_alerta(
                cursor,
                "SURICATA_IDS",
                src_ip,
                f"[Suricata] {sig} | {src_ip} → {dst_ip}:{dst_port} ({proto}){mitre}",
                sev,
            )

    def procesar_transiciones_watchdog(
        self, cursor, transitions: List[Dict[str, Any]]
    ) -> None:
        for tr in transitions:
            nombre = tr["nombre"]
            ip = tr["ip"]
            if tr["event"] == "DOWN":
                sev = "CRITICA" if tr.get("criticidad") == "CRITICO" else "ALTA"
                puerto_txt = f" (puerto {tr['puerto']})" if tr.get("puerto") else ""
                self.registrar_alerta(
                    cursor,
                    "ACTIVO_CAIDO",
                    ip,
                    f"Equipo crítico sin respuesta: {nombre} [{ip}]{puerto_txt}",
                    sev,
                    dedup_seconds=300,
                )
            elif tr["event"] == "UP":
                self.enviar_telegram(
                    f"🟢 <b>EQUIPO RECUPERADO</b>\n"
                    f"<b>Activo:</b> {html.escape(nombre)} ({html.escape(ip)})\n"
                    f"<b>Hora:</b> {html.escape(self.db.now_str())}"
                )
