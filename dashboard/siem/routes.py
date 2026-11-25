# -*- coding: utf-8 -*-
"""Rutas HTML y API REST del SIEM PYME (Librerías e Imprentas)."""

import json
import logging
import os

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from siem.collectors import parse_tshark_line, tail_lines
from siem.config import (
    ASSET_CATEGORIES,
    CRITICAL_ADMIN_PORTS,
    PRINTER_PORTS,
)
from siem.detector import SURICATA_FALSE_POSITIVES
from siem.reports import (
    build_executive_report,
    compute_shop_health,
    export_alerts_csv,
)
from siem.security import (
    clamp_int,
    csrf_protect,
    csrf_required,
    ensure_csrf_token,
    login_required,
    validate_container_name,
    validate_hhmm,
    validate_ip,
    validate_mac,
    verify_credentials,
)

logger = logging.getLogger("siem.routes")
bp = Blueprint("siem", __name__)


def _svc():
    return current_app.extensions["siem_services"]


# ── HEALTHCHECK (Docker) ────────────────────────────────────────────────────────
@bp.route("/healthz")
def healthz():
    return jsonify({"status": "ok"}), 200


# ── AUTENTICACIÓN ───────────────────────────────────────────────────────────────
@bp.route("/login", methods=["GET", "POST"])
def login():
    svc = _svc()
    cfg = svc["config"]
    error = None

    if request.method == "GET":
        ensure_csrf_token()
        if not cfg.admin_pass:
            error = "Acceso bloqueado: define DASHBOARD_PASSWORD en el archivo .env y reinicia el contenedor."
        return render_template("login.html", error=error, csrf_token=session["csrf_token"])

    # Verificar CSRF en POST de login
    if csrf_protect() is not None:
        return (
            render_template(
                "login.html",
                error="Sesión expirada o token de seguridad inválido. Inténtalo de nuevo.",
                csrf_token=ensure_csrf_token(),
            ),
            403,
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not cfg.admin_pass:
        error = "Acceso bloqueado: falta configurar DASHBOARD_PASSWORD en .env"
    elif verify_credentials(username, password, cfg.admin_user, cfg.admin_pass):
        session.clear()
        session.permanent = True
        session["logged_in"] = True
        session["user"] = username
        ensure_csrf_token()
        return redirect(url_for("siem.index"))
    else:
        error = "Credenciales incorrectas"

    return render_template("login.html", error=error, csrf_token=ensure_csrf_token()), 401


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("siem.login"))


@bp.route("/api/csrf-token")
@login_required
def api_csrf_token():
    return jsonify({"token": ensure_csrf_token()})


# ── VISTAS PRINCIPALES ──────────────────────────────────────────────────────────
@bp.route("/")
@login_required
def index():
    svc = _svc()
    db = svc["db"]
    cfg = svc["config"]
    conn = db.get_conn()
    business = db.get_business_config(conn)
    return render_template(
        "index.html",
        raspberry_ip=cfg.raspberry_ip,
        pihole_port=cfg.pihole_web_port,
        net_interface=cfg.net_interface,
        negocio=business,
    )


@bp.route("/negocio")
@login_required
def negocio():
    svc = _svc()
    db = svc["db"]
    conn = db.get_conn()
    return render_template(
        "negocio.html",
        negocio=db.get_business_config(conn),
        categorias=ASSET_CATEGORIES,
    )


@bp.route("/reporte")
@login_required
def reporte():
    svc = _svc()
    db = svc["db"]
    cfg = svc["config"]
    days = clamp_int(request.args.get("dias", 7), 7, 1, 90)
    conn = db.get_conn()
    data = build_executive_report(
        db, cfg, conn, wan_online=svc["watchdog"].wan_online, days=days
    )
    return render_template("reporte.html", r=data)


@bp.route("/alertas")
@login_required
def alertas():
    svc = _svc()
    db = svc["db"]
    conn = db.get_conn()
    total = conn.execute("SELECT COUNT(*) FROM alertas").fetchone()[0]
    criticas = conn.execute(
        "SELECT COUNT(*) FROM alertas WHERE severidad='CRITICA' AND estado='ABIERTA'"
    ).fetchone()[0]
    altas = conn.execute(
        "SELECT COUNT(*) FROM alertas WHERE severidad='ALTA' AND estado='ABIERTA'"
    ).fetchone()[0]
    resueltas = conn.execute(
        "SELECT COUNT(*) FROM alertas WHERE estado IN ('RESUELTA', 'FALSO_POSITIVO')"
    ).fetchone()[0]
    return render_template(
        "alertas.html",
        total=total,
        criticas=criticas,
        altas=altas,
        resueltas=resueltas,
    )


@bp.route("/graficas")
@bp.route("/red")
@bp.route("/estadisticas")
@login_required
def estadisticas():
    svc = _svc()
    return render_template("estadisticas.html", net_interface=svc["config"].net_interface)


@bp.route("/lateral")
@login_required
def lateral():
    svc = _svc()
    db = svc["db"]
    conn = db.get_conn()
    cutoff_24h = db.cutoff_str(hours=24)
    total = conn.execute("SELECT COUNT(*) FROM lateral_connections").fetchone()[0]
    srcs = conn.execute(
        """SELECT src_ip, COUNT(DISTINCT dst_ip) AS destinos, COUNT(*) AS conexiones
           FROM lateral_connections
           WHERE fecha >= ?
           GROUP BY src_ip ORDER BY destinos DESC LIMIT 12""",
        (cutoff_24h,),
    ).fetchall()
    assets_map = db.get_assets_map(conn)
    return render_template(
        "lateral.html",
        total=total,
        srcs=srcs,
        assets_map=assets_map,
    )


@bp.route("/contenedores")
@login_required
def contenedores():
    return render_template("contenedores.html")


@bp.route("/sniffer")
@login_required
def sniffer():
    svc = _svc()
    cfg = svc["config"]
    n = clamp_int(request.args.get("n", 100), 100, 10, 1000)
    filtro = request.args.get("filtro", "").strip().lower()[:100]
    lineas = []
    error = None
    total_lineas = 0
    try:
        raw_lines, total_lineas = tail_lines(cfg.tshark_log_path, max_lines=5000)
        if filtro:
            raw_lines = [ln for ln in raw_lines if filtro in ln.lower()]
        lineas = [p for p in (parse_tshark_line(ln) for ln in raw_lines[-n:]) if p]
    except FileNotFoundError:
        error = f"Archivo de captura no encontrado: {cfg.tshark_log_path}"
    except Exception as e:
        error = str(e)
    return render_template(
        "sniffer.html",
        lineas=lineas,
        error=error,
        n=n,
        filtro=filtro,
        total=total_lineas,
        net_interface=cfg.net_interface,
        now=svc["db"].now_str(),
    )


# ── API: RESUMEN EJECUTIVO & SALUD TIENDA ───────────────────────────────────────
@bp.route("/api/resumen")
@login_required
def api_resumen():
    svc = _svc()
    db = svc["db"]
    conn = db.get_conn()
    health = compute_shop_health(db, conn, wan_online=svc["watchdog"].wan_online)
    assets = db.list_assets_with_uptime(conn, hours=24)
    business = db.get_business_config(conn)
    return jsonify(
        {
            "ok": True,
            "health": health,
            "negocio": business,
            "activos_criticos": [a for a in assets if a["criticidad"] == "CRITICO"],
            "wan_latency_ms": svc["watchdog"].wan_latency_ms,
        }
    )


# ── API: MI NEGOCIO — INVENTARIO DE ACTIVOS & HORARIO ───────────────────────────
@bp.route("/api/activos", methods=["GET", "POST"])
@login_required
def api_activos():
    svc = _svc()
    db = svc["db"]
    conn = db.get_conn()

    if request.method == "GET":
        return jsonify({"ok": True, "activos": db.list_assets_with_uptime(conn, hours=24)})

    err = csrf_protect()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    ip = validate_ip(data.get("ip", ""))
    nombre = str(data.get("nombre", "")).strip()[:80]
    if not ip or not nombre:
        return jsonify({"ok": False, "error": "IP válida y nombre del equipo son obligatorios"}), 400

    categoria = str(data.get("categoria", "OTRO")).upper()
    if categoria not in ASSET_CATEGORIES:
        categoria = "OTRO"

    criticidad = str(
        data.get("criticidad") or ASSET_CATEGORIES[categoria]["default_criticidad"]
    ).upper()
    if criticidad not in ("CRITICO", "NORMAL", "INVITADO"):
        criticidad = "NORMAL"

    mac = validate_mac(data.get("mac", ""))
    autorizado = 1 if data.get("autorizado", categoria != "WIFI_CLIENTES") else 0
    monitorear = 1 if data.get("monitorear_uptime", criticidad == "CRITICO") else 0
    default_port = int(ASSET_CATEGORIES[categoria]["default_port"])
    puerto_check = clamp_int(data.get("puerto_check", default_port), default_port, 0, 65535)
    notas = str(data.get("notas", "")).strip()[:200]

    try:
        conn.execute(
            """INSERT INTO activos
               (ip, mac, nombre, categoria, criticidad, autorizado,
                monitorear_uptime, puerto_check, notas, creado_en)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(ip) DO UPDATE SET
                 mac=excluded.mac,
                 nombre=excluded.nombre,
                 categoria=excluded.categoria,
                 criticidad=excluded.criticidad,
                 autorizado=excluded.autorizado,
                 monitorear_uptime=excluded.monitorear_uptime,
                 puerto_check=excluded.puerto_check,
                 notas=excluded.notas""",
            (
                ip,
                mac,
                nombre,
                categoria,
                criticidad,
                autorizado,
                monitorear,
                puerto_check,
                notas,
                db.now_str(),
            ),
        )
        conn.commit()
        return jsonify({"ok": True, "activos": db.list_assets_with_uptime(conn, hours=24)}), 201
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/api/activos/<int:asset_id>", methods=["DELETE"])
@login_required
@csrf_required
def api_activo_delete(asset_id: int):
    db = _svc()["db"]
    conn = db.get_conn()
    conn.execute("DELETE FROM activos WHERE id = ?", (asset_id,))
    conn.commit()
    return jsonify({"ok": True})


@bp.route("/api/activos/check-now", methods=["POST"])
@login_required
@csrf_required
def api_activos_check_now():
    svc = _svc()
    db = svc["db"]
    conn = db.get_conn()
    transitions = svc["watchdog"].run_checks(conn)
    if transitions:
        svc["engine"].procesar_transiciones_watchdog(conn.cursor(), transitions)
    conn.commit()
    return jsonify(
        {
            "ok": True,
            "wan_online": svc["watchdog"].wan_online,
            "wan_latency_ms": svc["watchdog"].wan_latency_ms,
            "activos": db.list_assets_with_uptime(conn, hours=24),
        }
    )


@bp.route("/api/negocio/config", methods=["GET", "POST"])
@login_required
def api_negocio_config():
    db = _svc()["db"]
    conn = db.get_conn()
    if request.method == "GET":
        return jsonify({"ok": True, "config": db.get_business_config(conn)})

    err = csrf_protect()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    apertura = str(data.get("horario_apertura", "08:30")).strip()
    cierre = str(data.get("horario_cierre", "21:00")).strip()
    if not validate_hhmm(apertura) or not validate_hhmm(cierre):
        return jsonify({"ok": False, "error": "Formato de horario inválido (usa HH:MM)"}), 400

    nombre = str(data.get("negocio_nombre", "Mi Negocio")).strip()[:80]
    tipo = str(data.get("negocio_tipo", "imprenta")).strip().lower()
    if tipo not in ("libreria", "imprenta", "copisteria", "mixto"):
        tipo = "imprenta"
    dias = ",".join(
        d.strip()
        for d in str(data.get("dias_apertura", "0,1,2,3,4,5")).split(",")
        if d.strip() in {"0", "1", "2", "3", "4", "5", "6"}
    )
    saved = db.save_business_config(
        {
            "negocio_nombre": nombre or "Mi Negocio",
            "negocio_tipo": tipo,
            "horario_apertura": apertura,
            "horario_cierre": cierre,
            "dias_apertura": dias or "0,1,2,3,4,5",
            "alerta_fuera_horario": bool(data.get("alerta_fuera_horario", True)),
        },
        conn=conn,
    )
    return jsonify({"ok": True, "config": saved})


# ── API: PI-HOLE STATS & BLOQUEO RÁPIDO DE DOMINIOS ─────────────────────────────
@bp.route("/api/data")
@login_required
def api_data():
    svc = _svc()
    data = svc["pihole"].get_summary(max_age=20)
    if not data:
        return jsonify({"ok": False, "error": "Pi-hole no disponible"}), 503
    total_q = int(data.get("queries", {}).get("total", 0) or 0)
    blocked_q = int(data.get("queries", {}).get("blocked", 0) or 0)
    percent = round((blocked_q / total_q) * 100, 1) if total_q > 0 else 0.0
    domains = int(data.get("gravity", {}).get("domains_being_blocked", 0) or 0)
    return jsonify(
        {
            "ok": True,
            "dns_queries_today": total_q,
            "ads_blocked_today": blocked_q,
            "ads_percentage_today": percent,
            "domains_being_blocked": domains,
            "last_update": svc["db"].now_str().split(" ")[1],
        }
    )


@bp.route("/api/pihole/blocklist", methods=["GET", "POST", "DELETE"])
@login_required
def api_pihole_blocklist():
    pihole = _svc()["pihole"]
    if request.method == "GET":
        return jsonify({"ok": True, "domains": pihole.list_blocked_domains()})

    err = csrf_protect()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    domain = str(data.get("domain", "")).strip()
    if request.method == "POST":
        comment = str(data.get("comment", "Bloqueado desde SIEM PYME")).strip()[:100]
        ok, msg = pihole.block_domain(domain, comment=comment)
        return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)

    ok, msg = pihole.unblock_domain(domain)
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


# ── API: ALERTAS ────────────────────────────────────────────────────────────────
@bp.route("/api/alertas")
@login_required
def api_alertas():
    db = _svc()["db"]
    n = clamp_int(request.args.get("n", 50), 50, 1, 500)
    sev_filter = request.args.get("severidad", "").strip().upper()
    estado_filter = request.args.get("estado", "").strip().upper()
    q = request.args.get("q", "").strip()[:80]

    clauses = []
    params = []
    if sev_filter in ("CRITICA", "ALTA", "MEDIA", "BAJA"):
        clauses.append("severidad = ?")
        params.append(sev_filter)
    if estado_filter in ("ABIERTA", "RESUELTA", "FALSO_POSITIVO"):
        clauses.append("estado = ?")
        params.append(estado_filter)
    if q:
        clauses.append("(ip LIKE ? OR tipo LIKE ? OR descripcion LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like])

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    conn = db.get_conn()
    rows = conn.execute(
        f"""SELECT id, fecha, tipo, ip, descripcion, severidad, estado, recomendacion, categoria
            FROM alertas {where}
            ORDER BY id DESC LIMIT ?""",
        (*params, n),
    ).fetchall()

    cutoff_5m = db.cutoff_str(minutes=5)
    no_leidas = conn.execute(
        "SELECT COUNT(*) FROM alertas WHERE estado='ABIERTA' AND fecha >= ?",
        (cutoff_5m,),
    ).fetchone()[0]
    abiertas_total = conn.execute(
        "SELECT COUNT(*) FROM alertas WHERE estado='ABIERTA'"
    ).fetchone()[0]

    return jsonify(
        {
            "ok": True,
            "alertas": [dict(r) for r in rows],
            "no_leidas": no_leidas,
            "abiertas_total": abiertas_total,
        }
    )


@bp.route("/api/alertas/<int:alerta_id>/estado", methods=["POST"])
@login_required
@csrf_required
def api_alerta_estado(alerta_id: int):
    data = request.get_json(silent=True) or {}
    estado = str(data.get("estado", "")).upper()
    if estado not in ("ABIERTA", "RESUELTA", "FALSO_POSITIVO"):
        return jsonify({"ok": False, "error": "Estado inválido"}), 400
    conn = _svc()["db"].get_conn()
    conn.execute("UPDATE alertas SET estado = ? WHERE id = ?", (estado, alerta_id))
    conn.commit()
    return jsonify({"ok": True, "id": alerta_id, "estado": estado})


@bp.route("/api/alertas/export/csv")
@login_required
def api_alertas_export_csv():
    conn = _svc()["db"].get_conn()
    csv_text = export_alerts_csv(conn)
    return Response(
        csv_text,
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=alertas_siem.csv"},
    )


@bp.route("/api/alertas/clear", methods=["POST"])
@login_required
@csrf_required
def api_alertas_clear():
    conn = _svc()["db"].get_conn()
    conn.execute("DELETE FROM alertas")
    conn.commit()
    return jsonify({"ok": True})


# ── API: GRÁFICAS HISTÓRICAS (CON FECHAS MADRID CONSISTENTES Y DELTAS REALES) ───
@bp.route("/api/graficas/trafico_total")
@login_required
def api_trafico_total():
    db = _svc()["db"]
    horas = clamp_int(request.args.get("horas", 24), 24, 1, 720)
    cutoff = db.cutoff_str(hours=horas)
    conn = db.get_conn()
    rows = conn.execute(
        """SELECT substr(fecha_hora, 1, 16) AS momento,
                  SUM(bytes_bajada) AS bajada,
                  SUM(bytes_subida) AS subida
           FROM trafico_dispositivos
           WHERE fecha_hora >= ?
           GROUP BY substr(fecha_hora, 1, 16)
           ORDER BY momento ASC""",
        (cutoff,),
    ).fetchall()
    return jsonify(
        {
            "labels": [r["momento"] for r in rows],
            "bajada": [round(float(r["bajada"] or 0), 3) for r in rows],
            "subida": [round(float(r["subida"] or 0), 3) for r in rows],
        }
    )


@bp.route("/api/graficas/trafico_dispositivos")
@login_required
def api_trafico_dispositivos():
    db = _svc()["db"]
    horas = clamp_int(request.args.get("horas", 24), 24, 1, 720)
    cutoff = db.cutoff_str(hours=horas)
    conn = db.get_conn()
    assets_map = db.get_assets_map(conn)
    rows = conn.execute(
        """SELECT ip,
                  SUM(bytes_bajada) AS total_bajada,
                  SUM(bytes_subida) AS total_subida
           FROM trafico_dispositivos
           WHERE fecha_hora >= ?
           GROUP BY ip
           ORDER BY total_bajada DESC
           LIMIT 10""",
        (cutoff,),
    ).fetchall()
    labels = [
        f"{assets_map[r['ip']]['nombre']} ({r['ip']})" if r["ip"] in assets_map else r["ip"]
        for r in rows
    ]
    return jsonify(
        {
            "labels": labels,
            "bajada": [round(float(r["total_bajada"] or 0), 3) for r in rows],
            "subida": [round(float(r["total_subida"] or 0), 3) for r in rows],
        }
    )


@bp.route("/api/graficas/dns")
@login_required
def api_graficas_dns():
    db = _svc()["db"]
    horas = clamp_int(request.args.get("horas", 24), 24, 1, 720)
    cutoff = db.cutoff_str(hours=horas)
    conn = db.get_conn()
    rows = conn.execute(
        """SELECT substr(fecha, 1, 16) AS momento,
                  MAX(total_queries) AS total_queries,
                  MAX(ads_blocked) AS ads_blocked
           FROM estadisticas_dns
           WHERE fecha >= ?
           GROUP BY substr(fecha, 1, 16)
           ORDER BY momento ASC""",
        (cutoff,),
    ).fetchall()
    return jsonify(
        {
            "labels": [r["momento"] for r in rows],
            "total": [int(r["total_queries"] or 0) for r in rows],
            "bloqueadas": [int(r["ads_blocked"] or 0) for r in rows],
        }
    )


@bp.route("/api/mac_vendors")
@login_required
def api_mac_vendors():
    conn = _svc()["db"].get_conn()
    rows = conn.execute(
        "SELECT mac, fabricante, fecha FROM mac_vendors ORDER BY fecha DESC"
    ).fetchall()
    return jsonify({"ok": True, "total": len(rows), "vendors": [dict(r) for r in rows]})


# ── API: HOSTS EN VIVO (ENRIQUECIDOS CON INVENTARIO DE NEGOCIO) ─────────────────
@bp.route("/api/hosts")
@login_required
def api_hosts():
    svc = _svc()
    hosts = svc["ntopng"].get_active_hosts(update_deltas=False)
    if hosts is None:
        return jsonify({"ok": False, "error": "No se pudo conectar con ntopng"}), 503
    assets_map = svc["db"].get_assets_map()
    for h in hosts:
        asset = assets_map.get(h["ip"])
        if asset:
            meta = ASSET_CATEGORIES.get(asset["categoria"], ASSET_CATEGORIES["OTRO"])
            h["alias"] = asset["nombre"]
            h["categoria"] = asset["categoria"]
            h["categoria_label"] = meta["label"]
            h["categoria_icon"] = meta["icon"]
            h["criticidad"] = asset["criticidad"]
            h["autorizado"] = bool(asset["autorizado"])
        else:
            h["alias"] = ""
            h["categoria"] = "NO_REGISTRADO"
            h["categoria_label"] = "Sin clasificar"
            h["categoria_icon"] = "❓"
            h["criticidad"] = "NORMAL"
            h["autorizado"] = False
    return jsonify({"ok": True, "hosts": hosts, "total": len(hosts)})


# ── API: TRÁFICO LATERAL (CON ARISTAS CRÍTICAS REALES) ──────────────────────────
@bp.route("/api/lateral")
@login_required
def api_lateral():
    db = _svc()["db"]
    horas = clamp_int(request.args.get("horas", 1), 1, 1, 168)
    cutoff = db.cutoff_str(hours=horas)
    conn = db.get_conn()
    assets_map = db.get_assets_map(conn)

    rows = conn.execute(
        """SELECT fecha, src_ip, dst_ip, protocolo, puerto_dst, info
           FROM lateral_connections
           WHERE fecha >= ?
           ORDER BY id DESC LIMIT 500""",
        (cutoff,),
    ).fetchall()

    critical_ports = set(CRITICAL_ADMIN_PORTS.keys()) | set(PRINTER_PORTS.keys())
    edges_map = {}
    grafo = {}
    conexiones = []

    for r in rows:
        src = r["src_ip"]
        dst = r["dst_ip"]
        puerto = r["puerto_dst"] or ""
        es_crit = puerto in critical_ports

        grafo.setdefault(src, [])
        if dst not in grafo[src]:
            grafo[src].append(dst)

        edge_key = (src, dst)
        prev_edge = edges_map.get(edge_key)
        if prev_edge is None:
            edges_map[edge_key] = {"src": src, "dst": dst, "critico": es_crit, "puerto": puerto}
        elif es_crit:
            prev_edge["critico"] = True
            prev_edge["puerto"] = puerto

        conexiones.append(
            {
                "fecha": r["fecha"],
                "src": src,
                "src_label": assets_map[src]["nombre"] if src in assets_map else src,
                "dst": dst,
                "dst_label": assets_map[dst]["nombre"] if dst in assets_map else dst,
                "proto": r["protocolo"] or "",
                "puerto": puerto,
                "info": r["info"] or "",
            }
        )

    aliases = {ip: a["nombre"] for ip, a in assets_map.items()}
    return jsonify(
        {
            "ok": True,
            "total": len(conexiones),
            "conexiones": conexiones,
            "grafo": grafo,
            "enlaces": list(edges_map.values()),
            "aliases": aliases,
        }
    )


@bp.route("/api/lateral/clear", methods=["POST"])
@login_required
@csrf_required
def api_lateral_clear():
    conn = _svc()["db"].get_conn()
    conn.execute("DELETE FROM lateral_connections")
    conn.commit()
    return jsonify({"ok": True})


# ── API: CONTENEDORES DOCKER (CON CSRF EN TODAS LAS ACCIONES) ───────────────────
@bp.route("/api/contenedores")
@login_required
def api_contenedores():
    try:
        items = _svc()["docker"].list_containers()
        return jsonify({"ok": True, "contenedores": items, "total": len(items)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/api/contenedores/<nombre>/<op>", methods=["POST"])
@login_required
@csrf_required
def api_contenedor_accion(nombre: str, op: str):
    if not validate_container_name(nombre) or op not in ("start", "stop", "restart"):
        return jsonify({"ok": False, "error": "Parámetros inválidos"}), 400
    try:
        estado = _svc()["docker"].action(nombre, op)
        return jsonify({"ok": True, "estado": estado})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/api/contenedores/<nombre>/logs")
@login_required
def api_contenedor_logs(nombre: str):
    if not validate_container_name(nombre):
        return jsonify({"ok": False, "error": "Nombre de contenedor inválido"}), 400
    try:
        logs = _svc()["docker"].logs(nombre, tail=80)
        return jsonify({"ok": True, "logs": logs})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── API: TSHARK & SNIFFER (SIN SHELL SUBPROCESS Y CON RESET DE OFFSET) ──────────
@bp.route("/api/tshark/status")
@login_required
def tshark_status():
    try:
        items = _svc()["docker"].list_containers()
        for c in items:
            if c["nombre"] == "tshark-sflow":
                return jsonify({"ok": True, "status": c["estado"]})
        return jsonify({"ok": False, "error": "Contenedor tshark-sflow no encontrado"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@bp.route("/api/tshark/start", methods=["POST"])
@login_required
@csrf_required
def tshark_start():
    try:
        return jsonify({"ok": True, "status": _svc()["docker"].action("tshark-sflow", "start")})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/api/tshark/stop", methods=["POST"])
@login_required
@csrf_required
def tshark_stop():
    try:
        return jsonify({"ok": True, "status": _svc()["docker"].action("tshark-sflow", "stop")})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/api/tshark/clear", methods=["POST"])
@login_required
@csrf_required
def tshark_clear():
    svc = _svc()
    try:
        with open(svc["config"].tshark_log_path, "w", encoding="utf-8"):
            pass
        # CORRIGE bug crítico del TFG original: resetear puntero al limpiar el archivo
        svc["tshark_reader"].reset()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@bp.route("/api/tshark/download")
@login_required
def tshark_download():
    path = _svc()["config"].tshark_log_path
    if not os.path.exists(path):
        return jsonify({"ok": False, "error": "Archivo no encontrado"}), 404
    return send_file(path, as_attachment=True, download_name="tshark_capture.txt")


@bp.route("/api/sniffer")
@login_required
def api_sniffer():
    cfg = _svc()["config"]
    n = clamp_int(request.args.get("n", 100), 100, 10, 1000)
    filtro = request.args.get("filtro", "").strip().lower()[:100]
    try:
        raw_lines, _ = tail_lines(cfg.tshark_log_path, max_lines=5000)
        if filtro:
            raw_lines = [ln for ln in raw_lines if filtro in ln.lower()]
        lineas = [p for p in (parse_tshark_line(ln) for ln in raw_lines[-n:]) if p]
        return jsonify(
            {"ok": True, "total": len(raw_lines), "mostrando": len(lineas), "lineas": lineas}
        )
    except FileNotFoundError:
        return jsonify({"ok": False, "error": "Archivo de captura no encontrado"}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ── API: MÉTRICAS HARDWARE, SURICATA (TAIL O(1) RAM) Y FAIL2BAN ─────────────────
@bp.route("/api/red/metrics")
@login_required
def api_red_metrics():
    try:
        return jsonify(_svc()["node_exporter"].fetch())
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 503


@bp.route("/api/red/pihole")
@login_required
def api_red_pihole():
    d = _svc()["pihole"].get_summary(max_age=10)
    if not d:
        return jsonify({"ok": False, "error": "Pi-hole no disponible"}), 503
    q = d.get("queries", {})
    c = d.get("clients", {})
    return jsonify(
        {
            "ok": True,
            "queries": q.get("total", 0),
            "blocked": q.get("blocked", 0),
            "percent": q.get("percent_blocked", 0),
            "clients": c.get("active", 0),
        }
    )


@bp.route("/api/suricata/alertas")
@login_required
def api_suricata_alertas():
    """Lee solo las últimas 1000 líneas de eve.json con tail_lines (evita OOM en Raspberry Pi)."""
    eve_path = _svc()["config"].suricata_eve_path
    alertas = []
    try:
        raw_lines, _ = tail_lines(eve_path, max_lines=1000)
        for line in raw_lines:
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
            alertas.append(
                {
                    "timestamp": ev.get("timestamp", "")[:19].replace("T", " "),
                    "signature": sig,
                    "src_ip": ev.get("src_ip", ""),
                    "dst_ip": ev.get("dest_ip", ""),
                    "dst_port": ev.get("dest_port", ""),
                    "categoria": alerta.get("category", ""),
                    "severidad_num": alerta.get("severity", 3),
                }
            )
    except FileNotFoundError:
        pass
    alertas = alertas[-50:]
    alertas.reverse()
    return jsonify({"ok": True, "alertas": alertas, "total": len(alertas)})


@bp.route("/api/fail2ban/bans")
@login_required
def api_fail2ban_bans():
    try:
        return jsonify(_svc()["docker"].fail2ban_status())
    except Exception as e:
        return jsonify(
            {"ok": False, "ips": [], "jails": [], "total_ips": 0, "error": str(e)}
        )
