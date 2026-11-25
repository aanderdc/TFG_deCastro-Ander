# -*- coding: utf-8 -*-
"""Suite de pruebas automatizadas del SIEM PYME (Librerías e Imprentas)."""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

import pytest
from werkzeug.security import generate_password_hash

# Añadir carpeta dashboard al path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from siem import create_app
from siem.collectors import (
    IncrementalFileReader,
    JA3Database,
    NodeExporterCollector,
    NtopngCollector,
    tail_lines,
)
from siem.config import SiemConfig
from siem.detector import is_outside_business_hours
from siem.security import validate_container_name, validate_domain, verify_credentials


@pytest.fixture()
def app_ctx(tmp_path):
    db_file = str(tmp_path / "test_siem.db")
    tshark_file = str(tmp_path / "tshark.txt")
    ja3_file = str(tmp_path / "ja3.csv")
    eve_file = str(tmp_path / "eve.json")

    app = create_app(
        config_override={
            "db_path": db_file,
            "tshark_log_path": tshark_file,
            "ja3_log_path": ja3_file,
            "suricata_eve_path": eve_file,
            "admin_user": "admin",
            "admin_pass": "SuperSegura2026!",
            "flask_secret_key": "a" * 64,
            "raspberry_ip": "192.168.1.100",
            "net_interface": "eth0",
            "testing": True,
        },
        start_background=False,
    )
    return app, tmp_path


def _login(client, username="admin", password="SuperSegura2026!"):
    resp = client.get("/login")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    marker = 'name="csrf_token" value="'
    start = html.index(marker) + len(marker)
    token = html[start : html.index('"', start)]
    res = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token},
        follow_redirects=False,
    )
    return res


def _get_csrf(client):
    r = client.get("/api/csrf-token")
    assert r.status_code == 200
    return r.get_json()["token"]


# ── 1. SEGURIDAD, AUTENTICACIÓN Y CSRF ──────────────────────────────────────────
def test_fail_closed_empty_password(tmp_path):
    app = create_app(
        config_override={
            "db_path": str(tmp_path / "empty.db"),
            "admin_user": "admin",
            "admin_pass": "",
            "flask_secret_key": "b" * 64,
            "testing": True,
        }
    )
    client = app.test_client()
    res = _login(client, "admin", "")
    assert res.status_code == 401
    assert client.get("/api/resumen").status_code == 401


def test_hashed_password_verification():
    hashed = generate_password_hash("Imprenta2026!")
    assert verify_credentials("admin", "Imprenta2026!", "admin", hashed) is True
    assert verify_credentials("admin", "wrong", "admin", hashed) is False
    assert verify_credentials("admin", "", "admin", "") is False


def test_login_and_universal_csrf(app_ctx):
    app, _ = app_ctx
    client = app.test_client()

    # Sin login redirige en vista HTML y devuelve 401 en API
    assert client.get("/").status_code == 302
    assert client.get("/api/alertas").status_code == 401

    res = _login(client)
    assert res.status_code == 302
    assert client.get("/healthz").status_code == 200
    assert client.get("/").status_code == 200
    assert client.get("/negocio").status_code == 200
    assert client.get("/reporte").status_code == 200

    # Todos los POST sensibles deben rechazar sin CSRF (403)
    for url in (
        "/api/alertas/clear",
        "/api/lateral/clear",
        "/api/contenedores/pihole/stop",
        "/api/contenedores/pihole/restart",
        "/api/tshark/clear",
        "/api/activos",
    ):
        assert client.post(url).status_code == 403, f"Faltó CSRF en {url}"


def test_input_validators():
    assert validate_container_name("pihole") is True
    assert validate_container_name("tshark-sflow") is True
    assert validate_container_name("../etc/passwd") is False
    assert validate_container_name("pihole;rm -rf /") is False

    assert validate_domain("https://TikTok.com/video") == "tiktok.com"
    assert validate_domain("bad domain!!") is None


# ── 2. RECOLECTORES Y CORRECCIONES DE BUGS CRÍTICOS ─────────────────────────────
def test_ntopng_delta_traffic_prevents_inflation(app_ctx):
    app, _ = app_ctx
    ntopng: NtopngCollector = app.extensions["siem_services"]["ntopng"]

    # Primera lectura: no suma tráfico acumulado histórico
    d1_rx, d1_tx = ntopng.compute_delta_mb("192.168.1.50", 100 * 1024 * 1024, 20 * 1024 * 1024)
    assert d1_rx == 0.0 and d1_tx == 0.0

    # Segunda lectura (+10 MB bajada, +2 MB subida)
    d2_rx, d2_tx = ntopng.compute_delta_mb("192.168.1.50", 110 * 1024 * 1024, 22 * 1024 * 1024)
    assert d2_rx == 10.0 and d2_tx == 2.0

    # Tercera lectura sin tráfico nuevo: delta 0 (antes volvía a sumar 110 MB!)
    d3_rx, d3_tx = ntopng.compute_delta_mb("192.168.1.50", 110 * 1024 * 1024, 22 * 1024 * 1024)
    assert d3_rx == 0.0 and d3_tx == 0.0


def test_incremental_reader_handles_clear_and_tail(tmp_path):
    p = tmp_path / "capture.txt"
    p.write_text("line1\nline2\n", encoding="utf-8")
    reader = IncrementalFileReader(str(p))

    assert reader.read_new_lines() == ["line1", "line2"]
    assert reader.read_new_lines() == []

    # Truncar archivo (como /api/tshark/clear o rotación)
    p.write_text("line3\n", encoding="utf-8")
    assert reader.read_new_lines() == ["line3"]

    lines, count = tail_lines(str(p), max_lines=10)
    assert lines == ["line3"] and count == 1


def test_ja3_parser_handles_both_dict_and_list():
    as_list = JA3Database.parse_payload(
        [{"md5": "AAA", "desc": "Cobalt Strike"}, {"ja3_md5": "BBB", "tool": "Sliver"}]
    )
    assert as_list == {"aaa": "Cobalt Strike", "bbb": "Sliver"}

    as_dict = JA3Database.parse_payload(
        {"CCC": {"desc": "Metasploit"}, "DDD": "CustomC2"}
    )
    assert as_dict == {"ccc": "Metasploit", "ddd": "CustomC2"}


def test_node_exporter_multi_core_and_eth0():
    sample = """
# HELP node_load1 1m load
node_load1 1.5
node_load5 1.0
node_cpu_seconds_total{cpu="0",mode="idle"} 100
node_cpu_seconds_total{cpu="1",mode="idle"} 100
node_cpu_seconds_total{cpu="2",mode="idle"} 100
node_cpu_seconds_total{cpu="3",mode="idle"} 100
node_memory_MemTotal_bytes 4000000000
node_memory_MemAvailable_bytes 2000000000
node_filesystem_size_bytes{mountpoint="/"} 32000000000
node_filesystem_avail_bytes{mountpoint="/"} 20000000000
node_network_receive_bytes_total{device="eth0"} 500000
node_network_transmit_bytes_total{device="eth0"} 100000
"""
    m = NodeExporterCollector.parse_metrics(sample, preferred_iface="eth0")
    assert m["cpu_cores"] == 4
    assert m["cpu_pct"] == 37.5
    assert m["active_interface"] == "eth0"
    assert m["net_rx"] == 500000.0
    assert m["disk_size"] == 32000000000.0


# ── 3. MOTOR DE ALERTAS + REGLAS DE LIBRERÍA E IMPRENTA ─────────────────────────
def test_detectar_alertas_hosts_no_crash_and_dns_spike(app_ctx):
    app, _ = app_ctx
    svc = app.extensions["siem_services"]
    db, engine = svc["db"], svc["engine"]
    conn = db.connect_new()
    try:
        cur = conn.cursor()
        ahora = db.now_str()
        # Insertar histórico previo para 192.168.1.20 (media 1 MB) y pico DNS (+80 bloqueadas)
        cur.execute(
            "INSERT INTO trafico_dispositivos (fecha_hora, dispositivo, ip, bytes_bajada, bytes_subida) VALUES (?, 'pc1', '192.168.1.20', 1.0, 0.2)",
            (ahora,),
        )
        cur.execute(
            "INSERT INTO estadisticas_dns (fecha, total_queries, ads_blocked) VALUES (?, 500, 100)",
            (ahora,),
        )
        cur.execute(
            "INSERT INTO estadisticas_dns (fecha, total_queries, ads_blocked) VALUES (?, 650, 180)",
            (ahora,),
        )
        conn.commit()

        # Hora de cierre (03:00 AM) para disparar también ACTIVIDAD_FUERA_HORARIO
        closed_dt = datetime(2026, 5, 11, 3, 0, 0)  # Lunes 03:00
        hosts = [
            {
                "ip": "192.168.1.20",
                "name": "pc1",
                "fabricante": "HP",
                "delta_rcvd_mb": 30.0,
                "delta_sent_mb": 2.0,
                "rcvd_mb": 30.0,
                "sent_mb": 2.0,
                "score": 150,
                "flows": 600,
            }
        ]
        engine.detectar_alertas_hosts(cur, hosts, now_dt=closed_dt)
        conn.commit()

        tipos = {r[0] for r in cur.execute("SELECT tipo FROM alertas").fetchall()}
        assert "DNS_BLOQUEADAS" in tipos
        assert "TRAFICO_ALTO" in tipos
        assert "SCORE_ALTO" in tipos
        assert "FLOOD_DETECTADO" in tipos
        assert "ACTIVIDAD_FUERA_HORARIO" in tipos
    finally:
        conn.close()


def test_bookstore_printshop_lateral_rules(app_ctx):
    app, tmp_path = app_ctx
    svc = app.extensions["siem_services"]
    db, engine = svc["db"], svc["engine"]
    conn = db.connect_new()
    try:
        cur = conn.cursor()
        ahora = db.now_str()
        # Registrar Plotter crítico (192.168.1.50), TPV (192.168.1.60) y Wi-Fi cliente (192.168.1.99)
        cur.execute(
            """INSERT INTO activos (ip, mac, nombre, categoria, criticidad, autorizado, monitorear_uptime, puerto_check, creado_en)
               VALUES ('192.168.1.50', '00:1E:8F:11:22:33', 'Plotter Canon', 'IMPRESORA_PLOTTER', 'CRITICO', 1, 1, 9100, ?)""",
            (ahora,),
        )
        cur.execute(
            """INSERT INTO activos (ip, mac, nombre, categoria, criticidad, autorizado, monitorear_uptime, puerto_check, creado_en)
               VALUES ('192.168.1.99', '', 'Movil Cliente', 'WIFI_CLIENTES', 'INVITADO', 0, 0, 0, ?)""",
            (ahora,),
        )
        conn.commit()

        # Simular captura tshark: móvil invitado imprime en Plotter (:9100) + propagación SMB (445) a 3 hosts
        tshark_data = "\n".join(
            [
                "1 0.100 192.168.1.99 → 192.168.1.50 TCP 74 51234 → 9100 [SYN]",
                "2 0.200 192.168.1.88 → 192.168.1.10 TCP 74 50001 → 445 [SYN]",
                "3 0.300 192.168.1.88 → 192.168.1.11 TCP 74 50002 → 445 [SYN]",
                "4 0.400 192.168.1.88 → 192.168.1.12 TCP 74 50003 → 445 [SYN]",
            ]
        )
        (tmp_path / "tshark.txt").write_text(tshark_data + "\n", encoding="utf-8")

        open_dt = datetime(2026, 5, 11, 11, 0, 0)  # Lunes 11:00 (horario abierto)
        engine.analizar_trafico_lateral(cur, now_dt=open_dt)
        conn.commit()

        rows = cur.execute("SELECT tipo, recomendacion FROM alertas").fetchall()
        tipos = {r[0] for r in rows}
        assert "ACCESO_ACTIVO_CRITICO" in tipos
        assert "IMPRESION_NO_AUTORIZADA" in tipos
        assert "RANSOMWARE_SOSPECHOSO" in tipos
        # Todas las alertas deben llevar recomendación clara para el dueño del negocio
        assert all(bool(r[1]) for r in rows)
    finally:
        conn.close()


def test_business_hours_logic():
    cfg = {
        "horario_apertura": "09:00",
        "horario_cierre": "20:30",
        "dias_apertura": "0,1,2,3,4,5",
        "alerta_fuera_horario": True,
    }
    assert is_outside_business_hours(cfg, datetime(2026, 5, 11, 12, 0)) is False  # Lun 12:00
    assert is_outside_business_hours(cfg, datetime(2026, 5, 11, 23, 30)) is True  # Lun 23:30
    assert is_outside_business_hours(cfg, datetime(2026, 5, 17, 12, 0)) is True   # Domingo


# ── 4. API DE NEGOCIO, INVENTARIO, RESOLUCIÓN DE ALERTAS Y CSV/REPORTE ──────────
def test_assets_crud_alerts_resolve_and_exports(app_ctx):
    app, tmp_path = app_ctx
    client = app.test_client()
    assert _login(client).status_code == 302
    csrf = _get_csrf(client)
    headers = {"X-CSRF-Token": csrf}

    # Crear activo crítico (Plotter)
    r = client.post(
        "/api/activos",
        json={
            "ip": "10.0.0.50",
            "mac": "00:1E:8F:AA:BB:CC",
            "nombre": "Plotter Roland VG3",
            "categoria": "IMPRESORA_PLOTTER",
            "criticidad": "CRITICO",
            "puerto_check": 9100,
        },
        headers=headers,
    )
    assert r.status_code == 201
    activos = r.get_json()["activos"]
    assert len(activos) == 1
    assert activos[0]["nombre"] == "Plotter Roland VG3"

    # Guardar configuración de horario
    r_cfg = client.post(
        "/api/negocio/config",
        json={
            "negocio_nombre": "Imprenta Gráfica Norte",
            "negocio_tipo": "imprenta",
            "horario_apertura": "08:00",
            "horario_cierre": "20:00",
            "dias_apertura": "0,1,2,3,4",
            "alerta_fuera_horario": True,
        },
        headers=headers,
    )
    assert r_cfg.status_code == 200
    assert r_cfg.get_json()["config"]["negocio_nombre"] == "Imprenta Gráfica Norte"

    # Insertar alerta vía JA3 incremental y resolverla por API
    (tmp_path / "ja3.csv").write_text(
        "ip.src,ip.dst,tcp.dstport,tls.handshake.ja3,tls.handshake.ja3s\n"
        "10.0.0.20,1.2.3.4,443,e54c6e2fd03f1e2b1c7f8f6e0aefb3a6,\n",
        encoding="utf-8",
    )
    svc = app.extensions["siem_services"]
    svc["ja3_db"]._ts = 9999999999.0  # evitar descarga externa en test
    conn = svc["db"].connect_new()
    try:
        svc["engine"].detectar_ja3(conn.cursor())
        conn.commit()
    finally:
        conn.close()

    r_al = client.get("/api/alertas?estado=ABIERTA")
    alertas = r_al.get_json()["alertas"]
    assert len(alertas) == 1
    assert alertas[0]["tipo"] == "JA3_C2"

    # Resolver alerta individual
    r_res = client.post(
        f"/api/alertas/{alertas[0]['id']}/estado",
        json={"estado": "RESUELTA"},
        headers=headers,
    )
    assert r_res.status_code == 200
    assert len(client.get("/api/alertas?estado=ABIERTA").get_json()["alertas"]) == 0

    # Exportar CSV real con UTF-8 BOM
    r_csv = client.get("/api/alertas/export/csv")
    assert r_csv.status_code == 200
    assert "text/csv" in r_csv.content_type
    assert r_csv.data.startswith(b"\xef\xbb\xbf")
    assert b"JA3_C2" in r_csv.data

    # Resumen de salud y reporte ejecutivo HTML
    r_sum = client.get("/api/resumen")
    assert r_sum.status_code == 200
    assert 0 <= r_sum.get_json()["health"]["score"] <= 100

    r_rep = client.get("/reporte?dias=30")
    assert r_rep.status_code == 200
    assert "Imprenta Gráfica Norte" in r_rep.get_data(as_text=True)


def test_suricata_incremental_and_watchdog_alerts(app_ctx):
    app, tmp_path = app_ctx
    svc = app.extensions["siem_services"]
    db, engine = svc["db"], svc["engine"]

    eve = tmp_path / "eve.json"
    eve.write_text(
        json.dumps(
            {
                "event_type": "alert",
                "timestamp": "2026-05-11T10:00:00",
                "src_ip": "192.168.1.77",
                "dest_ip": "192.168.1.50",
                "dest_port": 445,
                "proto": "TCP",
                "alert": {
                    "signature": "ET EXPLOIT SMB EternalBlue Attempt",
                    "category": "Attempted Administrator Privilege Gain",
                    "severity": 1,
                    "metadata": {"mitre_technique_name": ["Exploitation_of_Remote_Services"]},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    conn = db.connect_new()
    try:
        cur = conn.cursor()
        engine.detectar_suricata(cur)
        engine.procesar_transiciones_watchdog(
            cur,
            [
                {
                    "event": "DOWN",
                    "ip": "192.168.1.50",
                    "nombre": "Plotter Canon",
                    "categoria": "IMPRESORA_PLOTTER",
                    "criticidad": "CRITICO",
                    "puerto": 9100,
                }
            ],
        )
        conn.commit()
        tipos = {r[0] for r in cur.execute("SELECT tipo FROM alertas").fetchall()}
        assert "SURICATA_IDS" in tipos
        assert "ACTIVO_CAIDO" in tipos
    finally:
        conn.close()

    client = app.test_client()
    assert _login(client).status_code == 302
    r_sur = client.get("/api/suricata/alertas")
    assert r_sur.status_code == 200
    assert r_sur.get_json()["total"] == 1

