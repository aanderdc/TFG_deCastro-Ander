# -*- coding: utf-8 -*-
"""Generación de Índice de Salud de la Tienda, CSV RFC-4180 e Informe Ejecutivo."""

import csv
import io
from typing import Any, Dict, List

from siem.config import SiemConfig
from siem.database import Database


def compute_shop_health(
    db: Database, conn, wan_online: bool = True
) -> Dict[str, Any]:
    """
    Calcula un índice de salud de 0 a 100 comprensible para el dueño de una librería/imprenta.
    """
    cutoff_24h = db.cutoff_str(hours=24)

    open_crit = conn.execute(
        "SELECT COUNT(*) FROM alertas WHERE estado='ABIERTA' AND severidad='CRITICA'"
    ).fetchone()[0]
    open_high = conn.execute(
        "SELECT COUNT(*) FROM alertas WHERE estado='ABIERTA' AND severidad='ALTA'"
    ).fetchone()[0]
    open_med = conn.execute(
        "SELECT COUNT(*) FROM alertas WHERE estado='ABIERTA' AND severidad='MEDIA'"
    ).fetchone()[0]

    crit_assets_total = conn.execute(
        "SELECT COUNT(*) FROM activos WHERE criticidad='CRITICO' AND monitorear_uptime=1"
    ).fetchone()[0]
    crit_assets_down = conn.execute(
        "SELECT COUNT(*) FROM activos WHERE criticidad='CRITICO' AND monitorear_uptime=1 AND estado_uptime='OFFLINE'"
    ).fetchone()[0]

    assets_total = conn.execute("SELECT COUNT(*) FROM activos").fetchone()[0]
    wan_uptime_row = conn.execute(
        "SELECT ROUND(100.0 * AVG(online), 1) FROM uptime_log WHERE ip='WAN' AND fecha >= ?",
        (cutoff_24h,),
    ).fetchone()
    wan_uptime_24h = wan_uptime_row[0] if wan_uptime_row and wan_uptime_row[0] is not None else 100.0

    score = 100
    reasons: List[str] = []

    if not wan_online:
        score -= 30
        reasons.append("Conexión a Internet (WAN) caída")
    if crit_assets_down > 0:
        score -= min(35, crit_assets_down * 20)
        reasons.append(f"{crit_assets_down} equipo(s) crítico(s) sin respuesta")
    if open_crit > 0:
        score -= min(40, open_crit * 15)
        reasons.append(f"{open_crit} alerta(s) crítica(s) sin resolver")
    if open_high > 0:
        score -= min(20, open_high * 5)
        reasons.append(f"{open_high} alerta(s) altas pendientes")
    if open_med > 3:
        score -= min(10, (open_med - 3) * 2)
        reasons.append(f"{open_med} avisos de severidad media acumulados")
    if assets_total == 0:
        score -= 5
        reasons.append("Aún no has registrado tus TPVs e impresoras en 'Mi Negocio'")

    score = max(0, min(100, score))
    if score >= 85:
        nivel, color, mensaje = "OPTIMO", "success", "Tienda protegida y operativa"
    elif score >= 60:
        nivel, color, mensaje = "ATENCION", "warning", "Requiere revisión preventiva"
    else:
        nivel, color, mensaje = "CRITICO", "danger", "Incidente activo — atención urgente"

    return {
        "score": score,
        "nivel": nivel,
        "color": color,
        "mensaje": mensaje,
        "razones": reasons,
        "wan_online": wan_online,
        "wan_uptime_24h": wan_uptime_24h,
        "alertas_abiertas": {
            "criticas": open_crit,
            "altas": open_high,
            "medias": open_med,
            "total": open_crit + open_high + open_med,
        },
        "activos_criticos": {
            "total": crit_assets_total,
            "caidos": crit_assets_down,
            "registrados": assets_total,
        },
    }


def export_alerts_csv(conn) -> str:
    """Exporta alertas en CSV estándar RFC-4180 con BOM UTF-8 para abrir directo en Excel."""
    rows = conn.execute(
        """SELECT id, fecha, severidad, estado, categoria, tipo, ip, descripcion, recomendacion
           FROM alertas ORDER BY id DESC"""
    ).fetchall()
    output = io.StringIO()
    output.write("\ufeff")  # BOM UTF-8 para tildes perfectas en Excel Windows
    writer = csv.writer(output, delimiter=",", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(
        [
            "ID",
            "Fecha",
            "Severidad",
            "Estado",
            "Categoria",
            "Tipo",
            "IP",
            "Descripcion",
            "Recomendacion",
        ]
    )
    for r in rows:
        writer.writerow(
            [
                r["id"],
                r["fecha"],
                r["severidad"],
                r["estado"],
                r["categoria"],
                r["tipo"],
                r["ip"],
                r["descripcion"],
                r["recomendacion"],
            ]
        )
    return output.getvalue()


def build_executive_report(
    db: Database, config: SiemConfig, conn, wan_online: bool = True, days: int = 7
) -> Dict[str, Any]:
    """Construye el informe ejecutivo imprimible/PDF para gerencia o soporte técnico."""
    cutoff = db.cutoff_str(days=days)
    business = db.get_business_config(conn)
    health = compute_shop_health(db, conn, wan_online=wan_online)
    assets = db.list_assets_with_uptime(conn, hours=days * 24)

    # Resumen de alertas en el periodo
    sev_counts = {
        r["severidad"]: r["n"]
        for r in conn.execute(
            """SELECT severidad, COUNT(*) AS n
               FROM alertas WHERE fecha >= ?
               GROUP BY severidad""",
            (cutoff,),
        ).fetchall()
    }
    top_alert_types = [
        dict(r)
        for r in conn.execute(
            """SELECT tipo, categoria, severidad, COUNT(*) AS total
               FROM alertas WHERE fecha >= ?
               GROUP BY tipo, categoria, severidad
               ORDER BY total DESC LIMIT 10""",
            (cutoff,),
        ).fetchall()
    ]
    recent_critical = [
        dict(r)
        for r in conn.execute(
            """SELECT fecha, tipo, ip, descripcion, severidad, estado, recomendacion
               FROM alertas
               WHERE fecha >= ? AND severidad IN ('CRITICA', 'ALTA')
               ORDER BY id DESC LIMIT 20""",
            (cutoff,),
        ).fetchall()
    ]

    # Resumen de tráfico real (delta) por dispositivo
    assets_by_ip = {a["ip"]: a["nombre"] for a in assets}
    top_devices = []
    for r in conn.execute(
        """SELECT ip,
                  ROUND(SUM(bytes_bajada), 2) AS bajada_mb,
                  ROUND(SUM(bytes_subida), 2) AS subida_mb
           FROM trafico_dispositivos
           WHERE fecha_hora >= ?
           GROUP BY ip
           ORDER BY bajada_mb DESC
           LIMIT 10""",
        (cutoff,),
    ).fetchall():
        top_devices.append(
            {
                "ip": r["ip"],
                "nombre": assets_by_ip.get(r["ip"], r["ip"]),
                "bajada_mb": r["bajada_mb"] or 0.0,
                "subida_mb": r["subida_mb"] or 0.0,
            }
        )

    # DNS último snapshot y promedio
    dns_latest = conn.execute(
        "SELECT total_queries, ads_blocked, fecha FROM estadisticas_dns ORDER BY id DESC LIMIT 1"
    ).fetchone()
    dns_summary = {
        "total_queries": dns_latest["total_queries"] if dns_latest else 0,
        "ads_blocked": dns_latest["ads_blocked"] if dns_latest else 0,
        "fecha": dns_latest["fecha"] if dns_latest else "Sin datos",
    }
    if dns_summary["total_queries"] > 0:
        dns_summary["percent"] = round(
            100.0 * dns_summary["ads_blocked"] / dns_summary["total_queries"], 1
        )
    else:
        dns_summary["percent"] = 0.0

    # Checklist de cumplimiento básico PYME / RGPD
    checklist = [
        {
            "item": "Inventario de equipos críticos (TPVs, impresoras/plotters, NAS)",
            "ok": len(assets) > 0,
            "detalle": f"{len(assets)} equipo(s) clasificado(s)" if assets else "Registra tus dispositivos en Mi Negocio",
        },
        {
            "item": "Monitorización de horario comercial activa",
            "ok": bool(business["alerta_fuera_horario"]),
            "detalle": f"{business['horario_apertura']} - {business['horario_cierre']}",
        },
        {
            "item": "Alertas instantáneas por Telegram",
            "ok": bool(config.telegram_token and config.telegram_chat_id),
            "detalle": "Configurado" if config.telegram_token else "Sin configurar en .env",
        },
        {
            "item": "Sin alertas críticas abiertas sin resolver",
            "ok": health["alertas_abiertas"]["criticas"] == 0,
            "detalle": f"{health['alertas_abiertas']['criticas']} abierta(s)",
        },
        {
            "item": "Disponibilidad de equipos críticos (Impresoras / TPV / NAS)",
            "ok": health["activos_criticos"]["caidos"] == 0,
            "detalle": f"{health['activos_criticos']['caidos']} caído(s)",
        },
    ]

    return {
        "generado_en": db.now_str(),
        "dias": days,
        "negocio": business,
        "health": health,
        "activos": assets,
        "sev_counts": {
            "CRITICA": sev_counts.get("CRITICA", 0),
            "ALTA": sev_counts.get("ALTA", 0),
            "MEDIA": sev_counts.get("MEDIA", 0),
        },
        "top_alert_types": top_alert_types,
        "recent_critical": recent_critical,
        "top_devices": top_devices,
        "dns": dns_summary,
        "checklist": checklist,
    }
