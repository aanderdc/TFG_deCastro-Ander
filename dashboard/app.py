import json
import re
# -*- coding: utf-8 -*-
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask, jsonify, render_template, request, redirect, url_for, session
from datetime import datetime
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
import time
from functools import wraps
import os
import secrets
import pytz

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app, default_limits=[])
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'cambia_esto_en_produccion')
from datetime import timedelta
app.permanent_session_lifetime = timedelta(hours=24)

# --- CONFIGURACIÓN (desde variables de entorno) ---
RASPBERRY_IP    = os.environ.get('RASPBERRY_IP', '127.0.0.1')
PIHOLE_BASE_URL = f"http://{RASPBERRY_IP}/api"
PASSWORD_PIHOLE = os.environ.get('PIHOLE_PASSWORD', '')

NTOPNG_BASE = "http://127.0.0.1:3001"
NTOPNG_USER = os.environ.get('NTOPNG_USER', 'admin')
NTOPNG_PASS = os.environ.get('NTOPNG_PASSWORD', '')

ntopng_session = requests.Session()
ntopng_authenticated = False

DB_PATH = 'data/historial_red.db'
ADMIN_USER = os.environ.get('DASHBOARD_USER', 'admin')
ADMIN_PASS = os.environ.get('DASHBOARD_PASSWORD', '')

TSHARK_LOG_PATH = '/tshark_logs/tshark_capture.txt'

# --- TELEGRAM ---
TELEGRAM_TOKEN   = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

current_sid = None
madrid_tz = pytz.timezone('Europe/Madrid')

# --- INICIALIZACIÓN DE DB ---
def init_db():
    if not os.path.exists('data'):
        os.makedirs('data')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS estadisticas_dns 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, fecha TEXT, total_queries INTEGER, ads_blocked INTEGER)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS trafico_dispositivos 
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, fecha_hora TEXT, dispositivo TEXT, 
                       ip TEXT, bytes_bajada REAL, bytes_subida REAL, protocolo_l7 TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS alertas
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       fecha TEXT,
                       tipo TEXT,
                       ip TEXT,
                       descripcion TEXT,
                       severidad TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS mac_vendors
                      (mac TEXT PRIMARY KEY,
                       fabricante TEXT,
                       fecha TEXT)''')
    # Tabla para conexiones laterales detectadas por tshark
    cursor.execute('''CREATE TABLE IF NOT EXISTS lateral_connections
                      (id INTEGER PRIMARY KEY AUTOINCREMENT,
                       fecha TEXT,
                       src_ip TEXT,
                       dst_ip TEXT,
                       protocolo TEXT,
                       puerto_dst TEXT,
                       info TEXT)''')
    # Índices para evitar full table scans con datos históricos
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_trafico_ip ON trafico_dispositivos(ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_trafico_fecha ON trafico_dispositivos(fecha_hora)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_lateral_src ON lateral_connections(src_ip, fecha)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_lateral_dst ON lateral_connections(dst_ip, fecha)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alertas_fecha ON alertas(fecha)')
    
    # WAL mode: mejora la concurrencia entre escrituras y lecturas
    conn.execute('PRAGMA journal_mode=WAL')
    conn.commit()
    conn.close()

def get_ahora_madrid():
    return datetime.now(madrid_tz).strftime("%Y-%m-%d %H:%M:%S")

def get_sid():
    global current_sid
    if current_sid: return current_sid
    try:
        r = requests.post(f"{PIHOLE_BASE_URL}/auth", json={"password": PASSWORD_PIHOLE}, timeout=5)
        if r.status_code == 200:
            current_sid = r.json().get("session", {}).get("sid")
            return current_sid
    except: return None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- PARSER TSHARK ---
def parse_tshark_line(line):
    line = line.strip()
    if not line:
        return None
    parts = line.split()
    try:
        return {
            "num":       parts[0] if len(parts) > 0 else "",
            "tiempo":    parts[1] if len(parts) > 1 else "",
            "src":       parts[2] if len(parts) > 2 else "",
            "dst":       parts[4] if len(parts) > 4 else "",
            "protocolo": parts[5] if len(parts) > 5 else "",
            "len":       parts[6] if len(parts) > 6 else "",
            "info":      " ".join(parts[7:]) if len(parts) > 7 else "",
        }
    except:
        return {"num": "", "tiempo": "", "src": "", "dst": "", "protocolo": "", "len": "", "info": line}

def get_fabricante(mac):
    """Consulta el fabricante de una MAC. Caché en memoria → SQLite → API externa."""
    if not mac or mac == '00:00:00:00:00:00':
        return "Desconocido"
    mac_upper = mac.upper()

    # 1. Caché en memoria (sin tocar BD ni red)
    if mac_upper in _mac_cache:
        return _mac_cache[mac_upper]

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # 2. Caché en SQLite
        cached = cursor.execute(
            'SELECT fabricante FROM mac_vendors WHERE mac=?', (mac_upper,)
        ).fetchone()
        if cached:
            conn.close()
            _mac_cache[mac_upper] = cached[0]
            return cached[0]

        # 3. Solo si no está en ningún caché → API externa
        try:
            r = requests.get(f"https://api.maclookup.app/v2/macs/{mac}", timeout=5)
            if r.status_code == 200:
                data = r.json()
                fabricante = data.get('company', '') or data.get('companyName', '') or 'Desconocido'
                if not fabricante or fabricante == 'n/a':
                    fabricante = 'Desconocido'
            else:
                fabricante = 'Desconocido'
        except:
            fabricante = 'Desconocido'

        cursor.execute(
            'INSERT OR REPLACE INTO mac_vendors (mac, fabricante, fecha) VALUES (?, ?, ?)',
            (mac_upper, fabricante, get_ahora_madrid())
        )
        conn.commit()
        conn.close()
        _mac_cache[mac_upper] = fabricante
        print(f"[MAC] {mac} → {fabricante}")
        return fabricante

    except Exception as e:
        print(f"[MAC] Error: {e}")
        return 'Desconocido'


def enviar_telegram(mensaje):
    """Envía una notificación a Telegram. Solo si están configurados token y chat_id."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": mensaje,
            "parse_mode": "HTML"
        }, timeout=5)
    except Exception as e:
        print(f"[Telegram] Error al enviar: {e}")

def registrar_alerta(cursor, tipo, ip, descripcion, severidad='MEDIA'):
    ahora = get_ahora_madrid()
    clave = f"{tipo}|{ip}"

    # Deduplicación en memoria (sin query a BD)
    ultima = _alertas_recientes.get(clave)
    if ultima:
        desde_ultima = (datetime.now(madrid_tz) - ultima).total_seconds()
        if desde_ultima < 600:  # 10 minutos
            return

    _alertas_recientes[clave] = datetime.now(madrid_tz)

    cursor.execute('''INSERT INTO alertas (fecha, tipo, ip, descripcion, severidad)
                      VALUES (?, ?, ?, ?, ?)''',
                   (ahora, tipo, ip, descripcion, severidad))

    # Notificación Telegram solo para CRITICA y ALTA
    if severidad in ('CRITICA', 'ALTA'):
        iconos = {'CRITICA': '🔴', 'ALTA': '🟠'}
        icono = iconos.get(severidad, '⚪')
        enviar_telegram(
            f"{icono} <b>ALERTA {severidad}</b>\n"
            f"<b>Tipo:</b> {tipo}\n"
            f"<b>IP:</b> {ip}\n"
            f"<b>Descripción:</b> {descripcion}\n"
            f"<b>Hora:</b> {ahora}"
        )
    print(f"[ALERTA] {severidad} — {tipo} — {ip} — {descripcion}")

def detectar_alertas(cursor, hosts, dns_data=None):
    ahora = get_ahora_madrid()

    # IPs conocidas (han aparecido antes en la BD)
    ips_conocidas = set(r[0] for r in cursor.execute(
        'SELECT DISTINCT ip FROM trafico_dispositivos WHERE ip LIKE "192.168.%"'
    ).fetchall())

    # Media de tráfico por IP en las últimas 24h
    medias = {}
    RASPY_IP = os.environ.get('RASPBERRY_IP', '192.168.1.147')
    rows = cursor.execute('''
        SELECT src_ip, dst_ip, fecha
        FROM lateral_connections
        WHERE fecha >= datetime(?, '-1 hour')
          AND dst_ip NOT LIKE '192.168.%'
          AND dst_ip NOT LIKE '10.%'
          AND dst_ip NOT LIKE '172.16.%'
          AND dst_ip NOT LIKE '172.17.%'
          AND dst_ip != '224.0.0.1'
          AND src_ip != ?
          AND src_ip != '192.168.1.1'
    ''', (ahora, RASPY_IP)).fetchall()
    for ip, media in rows:
        medias[ip] = media or 0

    # Última consulta de DNS bloqueadas
    ultimo_dns = cursor.execute('''
        SELECT ads_blocked FROM estadisticas_dns
        ORDER BY id DESC LIMIT 1
    ''').fetchone()
    penultimo_dns = cursor.execute('''
        SELECT ads_blocked FROM estadisticas_dns
        ORDER BY id DESC LIMIT 1 OFFSET 1
    ''').fetchone()

    for h in hosts:
        ip = h['ip']
        score = h.get('score', 0)
        bajada = h.get('rcvd_mb', 0)
        subida = h.get('sent_mb', 0)
        flows = h.get('flows', 0)

        # 1. Score alto
        if score > 100:
            severidad = 'CRITICA' if score > 500 else 'ALTA'
            registrar_alerta(cursor, 'SCORE_ALTO', ip,
                f'Score de amenaza: {score}', severidad)

        # 2. Dispositivo nuevo
        if ip not in ips_conocidas and ip != os.environ.get('RASPBERRY_IP', '127.0.0.1'):
            registrar_alerta(cursor, 'DISPOSITIVO_NUEVO', ip,
                f'Nueva IP detectada en la red: {ip}', 'MEDIA')

        # 3. Tráfico inusualmente alto (más de 5x la media)
        if ip in medias and medias[ip] > 0:
            if bajada > medias[ip] * 5 and bajada > 10:
                registrar_alerta(cursor, 'TRAFICO_ALTO', ip,
                    f'Tráfico {bajada:.1f}MB vs media {medias[ip]:.1f}MB', 'ALTA')

        # 5. Flood — demasiados flows activos
        UMBRAL_FLOWS_FLOOD = 500
        if flows > UMBRAL_FLOWS_FLOOD:
            severidad = 'CRITICA' if flows > 2000 else 'ALTA'
            registrar_alerta(cursor, 'FLOOD_DETECTADO', ip,
                f'Posible flood: {flows} flows activos desde {ip}', severidad)

        # 6. Ratio subida/bajada anómalo (exfiltración o amplificación UDP)
        if subida > 50 and bajada > 0 and subida / bajada > 10:
            registrar_alerta(cursor, 'RATIO_ANOMALO', ip,
                f'Ratio subida/bajada anómalo: ↑{subida:.1f}MB / ↓{bajada:.1f}MB', 'ALTA')

# --- BUGFIX: ntopng_login estaba erróneamente metido dentro de detectar_alertas ---
def ntopng_login():
    """Hace login en ntopng. Si el login está desactivado, lo marca como autenticado directamente."""
    global ntopng_authenticated
    try:
        # Primero intentamos acceder a la API directamente (login desactivado)
        r = ntopng_session.get(
            f"{NTOPNG_BASE}/lua/rest/v2/get/ntopng/interfaces.lua",
            allow_redirects=False,
            timeout=5
        )
        if r.status_code == 200:
            ntopng_authenticated = True
            print("[ntopng] Login desactivado — acceso directo OK")
            return True

        # Si redirige al login, intentamos autenticarnos
        r = ntopng_session.post(
            f"{NTOPNG_BASE}/authorize.html",
            data={"user": NTOPNG_USER, "password": NTOPNG_PASS},
            allow_redirects=False,
            timeout=5
        )
        location = r.headers.get('Location', '')
        if 'login' not in location:
            ntopng_authenticated = True
            print(f"[ntopng] Login correcto → {location}")
            return True
        print(f"[ntopng] Login fallido → {location}")
    except Exception as e:
        print(f"[ntopng] Error login: {e}")
    ntopng_authenticated = False
    return False

def get_ntopng_hosts():
    """Obtiene lista de hosts activos con su tráfico individual."""
    global ntopng_authenticated
    if not ntopng_authenticated:
        if not ntopng_login():
            return None
    try:
        r = ntopng_session.get(
            f"{NTOPNG_BASE}/lua/rest/v2/get/host/active.lua",
            params={"ifid": 0},
            allow_redirects=False,
            timeout=5
        )
        if r.status_code == 302:
            ntopng_authenticated = False
            if ntopng_login():
                r = ntopng_session.get(
                    f"{NTOPNG_BASE}/lua/rest/v2/get/host/active.lua",
                    params={"ifid": 0},
                    allow_redirects=False,
                    timeout=5
                )
            else:
                return None
        if r.status_code == 200:
            data = r.json()
            if data.get("rc") == 0:
                hosts = data.get("rsp", {}).get("data", [])
                resultado = []
                for h in hosts:
                    ip = h.get("ip", "")
                    # Filtrar IPs locales relevantes (192.168.x.x)
                    if not ip.startswith("192.168."):
                        continue
                    # Ignorar broadcast y multicast
                    if h.get("is_broadcast") or h.get("is_multicast"):
                        continue
                    name = h.get("name", ip)
                    if name.startswith("$") or name == ip:
                        name = ip
                    bytes_sent = h.get("bytes", {}).get("sent", 0)
                    bytes_rcvd = h.get("bytes", {}).get("recvd", 0)
                    mac = h.get("mac", "")
                    resultado.append({
                        "ip":         ip,
                        "name":       name,
                        "mac":        mac,
                        "fabricante": get_fabricante(mac),
                        "sent_mb":    round(bytes_sent / (1024 * 1024), 4),
                        "rcvd_mb":    round(bytes_rcvd / (1024 * 1024), 4),
                        "score":      h.get("score", {}).get("total", 0),
                        "flows":      h.get("num_flows", {}).get("total", 0),
                        "country":    h.get("country", ""),
                    })
                return resultado
        ntopng_authenticated = False
        return None
    except Exception as e:
        print(f"[ntopng] Error get_hosts: {e}")
        ntopng_authenticated = False
        return None

# --- DETECCIÓN DE TRÁFICO LATERAL ---

# Caché en memoria para fabricantes MAC (evita consultas repetidas a BD y API)
_mac_cache = {}
# Pool de conexiones SQLite por thread (evita crear conexión nueva en cada request)
_db_local = threading.local()

def get_db():
    if not hasattr(_db_local, 'conn') or _db_local.conn is None:
        _db_local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _db_local.conn.row_factory = sqlite3.Row
    return _db_local.conn

def close_db():
    if hasattr(_db_local, 'conn') and _db_local.conn:
        _db_local.conn.close()
        _db_local.conn = None
# Caché en memoria para deduplicación de alertas (evita query a BD por cada alerta)
# Formato: "tipo|ip" → timestamp última alerta
_alertas_recientes = {}
# Rastrea la última línea procesada para no reprocesar todo el log cada ciclo
_tshark_last_pos = 0
_tshark_lock = threading.Lock()
_suricata_last_pos = 0
_suricata_lock = threading.Lock()

def analizar_trafico_lateral(cursor):
    global _tshark_last_pos
    with _tshark_lock:
        try:
            with open(TSHARK_LOG_PATH, 'r', errors='replace') as f:
                f.seek(_tshark_last_pos)
                nuevas = f.readlines()
                _tshark_last_pos = f.tell()
        except FileNotFoundError:
            return

    ahora = get_ahora_madrid()
    # src_ip -> conjunto de dst_ip distintas contactadas en este ciclo
    contactos_por_src = {}

    for line in nuevas:
        p = parse_tshark_line(line)
        if not p:
            continue
        src = p.get('src', '')
        dst = p.get('dst', '')

        # Solo nos interesan conexiones donde el origen es interno
        # (incluye salientes al exterior para detección de beaconing)
        if not src.startswith('192.168.'):
            continue
        # Ignorar la propia Raspberry como origen (su tráfico ya lo vemos)
        # pero SÍ la queremos como destino para detectar escaneos hacia ella
        proto = p.get('protocolo', '')
        info  = p.get('info', '')

        # Extraer puerto destino de la info si es TCP/UDP
        puerto_dst = ''
        if '→' in info:
            partes = info.split('→')
            if len(partes) > 1:
                puerto_dst = partes[1].strip().split()[0] if partes[1].strip() else ''

        # Guardar en BD (deduplicar: misma pareja en el mismo minuto)
        existe = cursor.execute('''
            SELECT id FROM lateral_connections
            WHERE src_ip=? AND dst_ip=? AND protocolo=?
              AND fecha >= datetime(?, '-1 minute')
        ''', (src, dst, proto, ahora)).fetchone()

        if not existe:
            cursor.execute('''INSERT INTO lateral_connections
                              (fecha, src_ip, dst_ip, protocolo, puerto_dst, info)
                              VALUES (?, ?, ?, ?, ?, ?)''',
                           (ahora, src, dst, proto, puerto_dst, info[:120]))

        # Acumular contactos por src para detectar escaneo
        if src not in contactos_por_src:
            contactos_por_src[src] = set()
        contactos_por_src[src].add(dst)

    # Regla 5: Escaneo lateral — un dispositivo interno contacta >5 IPs internas distintas en 30s
    for src_ip, dsts in contactos_por_src.items():
        if len(dsts) >= 5:
            severidad = 'CRITICA' if len(dsts) >= 15 else 'ALTA'
            registrar_alerta(cursor, 'LATERAL_SCAN', src_ip,
                f'Posible escaneo interno: {src_ip} contactó {len(dsts)} IPs internas distintas en 30s',
                severidad)

    # Regla 6: Conexión lateral a puertos sensibles (RDP 3389, SMB 445, SSH 22)
    puertos_criticos = {'3389': 'RDP', '445': 'SMB', '22': 'SSH', '23': 'Telnet', '5900': 'VNC'}
    for src_ip, dsts in contactos_por_src.items():
        # Buscar en las nuevas líneas de este ciclo conexiones a esos puertos
        pass  # Ya se registra en lateral_connections; la alerta se genera en el insert

    # Alerta puntual por puerto crítico detectado en este ciclo
    rows_criticos = cursor.execute('''
        SELECT src_ip, dst_ip, puerto_dst FROM lateral_connections
        WHERE fecha >= datetime(?, '-1 minute')
          AND puerto_dst IN ('3389', '445', '22', '23', '5900')
    ''', (ahora,)).fetchall()

    for src_ip, dst_ip, puerto in rows_criticos:
        nombre_proto = puertos_criticos.get(puerto, puerto)
        registrar_alerta(cursor, 'LATERAL_PORT', src_ip,
            f'Conexión lateral a puerto crítico {nombre_proto} ({puerto}): {src_ip} → {dst_ip}',
            'CRITICA')

def detectar_beaconing(cursor):
    """
    Detecta beaconing C2: un host interno contacta la misma IP externa
    con intervalos muy regulares (coeficiente de variación < 0.3).
    Requiere al menos 5 contactos en la última hora.
    """
    import statistics as _stats
    from datetime import datetime as _dt

    ahora = get_ahora_madrid()

    rows = cursor.execute('''
        SELECT src_ip, dst_ip, fecha
        FROM lateral_connections
        WHERE fecha >= datetime(?, '-1 hour')
          AND dst_ip NOT LIKE '192.168.%'
          AND dst_ip NOT LIKE '10.%'
          AND dst_ip NOT LIKE '172.16.%'
          AND dst_ip NOT LIKE '172.17.%'
        ORDER BY src_ip, dst_ip, fecha
    ''', (ahora,)).fetchall()

    # Agrupar tiempos por par (src, dst)
    from collections import defaultdict
    grupos = defaultdict(list)
    for src, dst, fecha in rows:
        try:
            t = _dt.strptime(fecha, "%Y-%m-%d %H:%M:%S")
            grupos[(src, dst)].append(t)
        except Exception:
            pass

    for (src, dst), tiempos in grupos.items():
        if len(tiempos) < 5:
            continue

        tiempos.sort()
        intervalos = [
            (tiempos[i+1] - tiempos[i]).total_seconds()
            for i in range(len(tiempos) - 1)
        ]

        media = sum(intervalos) / len(intervalos)
        if media < 5:   # descarta ruido (conexiones casi simultáneas)
            continue

        stdev = _stats.stdev(intervalos) if len(intervalos) > 1 else 0
        cv = stdev / media  # coeficiente de variación

        if cv < 0.3:
            severidad = 'CRITICA' if cv < 0.1 else 'ALTA'
            registrar_alerta(
                cursor, 'BEACONING', src,
                f'Posible beaconing C2: {src} → {dst} | '
                f'{len(tiempos)} contactos en 1h, intervalo ~{media:.0f}s, CV={cv:.2f}',
                severidad
            )
def detectar_doh(cursor):
    """
    Detecta uso de DNS over HTTPS (DoH) que bypasea Pi-hole.
    Busca conexiones al puerto 443 hacia resolvers DoH conocidos.
    """
    RESOLVERS_DOH = {
        '8.8.8.8', '8.8.4.4',       # Google
        '1.1.1.1', '1.0.0.1',       # Cloudflare
        '9.9.9.9', '149.112.112.112' # Quad9
    }
    ahora = get_ahora_madrid()
    rows = cursor.execute('''
        SELECT src_ip, dst_ip, puerto_dst FROM lateral_connections
        WHERE fecha >= datetime(?, '-10 minutes')
          AND puerto_dst = '443'
    ''', (ahora,)).fetchall()

    for src, dst, puerto in rows:
        if dst in RESOLVERS_DOH:
            registrar_alerta(cursor, 'DNS_OVER_HTTPS', src,
                f'{src} usa DoH hacia {dst} — Pi-hole bypasado',
                'ALTA')
def detectar_ja3(cursor):
    """
    Detecta huellas TLS (JA3) asociadas a herramientas C2 conocidas.
    Lee el CSV generado por el contenedor tshark-ja3.
    """
    JA3_C2 = {
        # Cobalt Strike
        'e54c6e2fd03f1e2b1c7f8f6e0aefb3a6': 'Cobalt Strike',
        '72a589da586844d7f0818ce684948eea': 'Cobalt Strike',
        '6bca5d2a0b7d3d21e06a216c57b7bbfe': 'Cobalt Strike',
        # Metasploit
        'c27b06e79a31aff0839438dfff99f4a6': 'Metasploit',
        'd4d44f04a29f4e18bc49d48de3a88d55': 'Metasploit',
        # Sliver
        '5d41402abc4b2a76b9719d911017c592': 'Sliver C2',
        # Covenant
        'a0e9f5d64349fb13191bc781f81f42e1': 'Covenant C2',
    }

    JA3_PATH = '/app/tshark_logs/tshark_ja3.csv'
    try:
        with open(JA3_PATH, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('ip.src'):
                    continue
                parts = line.split(',')
                if len(parts) < 4:
                    continue
                src, dst, puerto, ja3 = parts[0], parts[1], parts[2], parts[3]
                ja3s = parts[4] if len(parts) > 4 else ''

                if ja3 and ja3 in JA3_C2:
                    herramienta = JA3_C2[ja3]
                    registrar_alerta(cursor, 'JA3_C2', src,
                        f'Huella TLS C2 detectada: {herramienta} | '
                        f'{src} → {dst}:{puerto} | JA3={ja3}',
                        'CRITICA')
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f'[JA3] Error: {e}')

def detectar_suricata(cursor):
    """
    Lee el eve.json de Suricata y registra alertas en el motor del dashboard.
    Solo procesa líneas nuevas desde la última posición leída.
    """
    global _suricata_last_pos
    EVE_PATH = '/tshark_logs/../suricata/logs/eve.json'
    # Ruta real montada en el contenedor
    EVE_PATHS = [
    '/suricata/logs/eve.json',
]
    eve_path = None
    for p in EVE_PATHS:
        if os.path.exists(p):
            eve_path = p
            break
    if not eve_path:
        return

    with _suricata_lock:
        try:
            with open(eve_path, 'r', errors='replace') as f:
                f.seek(_suricata_last_pos)
                nuevas = f.readlines()
                _suricata_last_pos = f.tell()
        except FileNotFoundError:
            return

    # Mapeo severidad Suricata (1=crítica, 2=alta, 3=media) → dashboard
    mapa_severidad = {1: 'CRITICA', 2: 'ALTA', 3: 'MEDIA'}

    # Firmas que ignoramos (falsos positivos conocidos)
    ignorar = {'duckdns', 'DYNAMIC_DNS', 'Spotify', 'Telegram'}

    for line in nuevas:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue

        if ev.get('event_type') != 'alert':
            continue

        alerta = ev.get('alert', {})
        signature = alerta.get('signature', '')

        # Ignorar falsos positivos conocidos
        if any(fp in signature for fp in ignorar):
            continue

        src_ip = ev.get('src_ip', '')
        dst_ip = ev.get('dest_ip', '')
        proto = ev.get('proto', '')
        dst_port = ev.get('dest_port', '')
        categoria = alerta.get('category', '')
        severidad_num = alerta.get('severity', 3)
        severidad = mapa_severidad.get(severidad_num, 'MEDIA')

        # Enriquecer con MITRE si está disponible
        mitre = ''
        metadata = alerta.get('metadata', {})
        tecnica = metadata.get('mitre_technique_name', [])
        tactica = metadata.get('mitre_tactic_name', [])
        if tecnica:
            mitre = f" | MITRE: {tecnica[0].replace('_', ' ')}"

        descripcion = (
            f"[Suricata] {signature} | "
            f"{src_ip} → {dst_ip}:{dst_port} ({proto}){mitre}"
        )

        registrar_alerta(cursor, 'SURICATA_IDS', src_ip, descripcion, severidad)

# --- LOGGER DE FONDO ---
def background_logger():
    ntopng_login()
    ciclos_sin_limpieza = 0          # cada 120 ciclos × 30s = 1 hora
    while True:
        try:
            ciclos_sin_limpieza += 1
            ahora = get_ahora_madrid()
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()

            # 1. Captura ntopng — por dispositivo
            hosts = get_ntopng_hosts()
            if hosts:
                for h in hosts:
                    cursor.execute('''INSERT INTO trafico_dispositivos 
                                      (fecha_hora, dispositivo, ip, bytes_bajada, bytes_subida, protocolo_l7)
                                      VALUES (?, ?, ?, ?, ?, ?)''',
                                   (ahora, h["name"], h["ip"],
                                    h["rcvd_mb"], h["sent_mb"],
                                    f"flows:{h['flows']} score:{h['score']}"))
                conn.commit()
                detectar_alertas(cursor, hosts)
                # Limpieza automatica de datos antiguos (retencion 30 dias)
                # Limpieza de datos antiguos — solo 1 vez por hora (cada 120 ciclos de 30s)
                if ciclos_sin_limpieza >= 120:
                    cursor.execute("DELETE FROM trafico_dispositivos WHERE fecha_hora < datetime('now', '-30 days')")
                    cursor.execute("DELETE FROM estadisticas_dns WHERE fecha < datetime('now', '-30 days')")
                    cursor.execute("DELETE FROM lateral_connections WHERE fecha < datetime('now', '-30 days')")
                    cursor.execute("DELETE FROM alertas WHERE fecha < datetime('now', '-90 days')")
                    ciclos_sin_limpieza = 0
                    print(f"[{ahora}] Limpieza de retención ejecutada")
                    # Limpiar caché de alertas en memoria
                    _alertas_recientes.clear()
                conn.commit()
                print(f"[{ahora}] ntopng OK — {len(hosts)} dispositivos guardados")
            else:
                print(f"[{ahora}] ntopng sin datos de hosts")

            # 2. Análisis de tráfico lateral (tshark) — siempre, independiente de ntopng
            analizar_trafico_lateral(cursor)
            detectar_beaconing(cursor)
            detectar_doh(cursor)
            detectar_ja3(cursor)
            detectar_suricata(cursor)
            conn.commit()


            # 3. Captura Pi-hole DNS (en paralelo con un thread)
            def capturar_pihole():
                sid = get_sid()
                if sid:
                    try:
                        headers = {"X-FTL-SID": sid}
                        r_pi = requests.get(f"{PIHOLE_BASE_URL}/stats/summary", headers=headers, timeout=5)
                        if r_pi.status_code == 200:
                            d = r_pi.json()
                            conn_ph = sqlite3.connect(DB_PATH)
                            conn_ph.execute("INSERT INTO estadisticas_dns (fecha, total_queries, ads_blocked) VALUES (?, ?, ?)",
                                           (ahora, d.get('queries', {}).get('total', 0), d.get('queries', {}).get('blocked', 0)))
                            conn_ph.commit()
                            conn_ph.close()
                    except: pass

            hilo_pihole = threading.Thread(target=capturar_pihole, daemon=True)
            hilo_pihole.start()

            conn.close()
            hilo_pihole.join(timeout=6)
        except Exception as e:
            print(f"Error crítico en logger: {e}")

        time.sleep(30)

# --- RUTAS DE FLASK ---


def csrf_protect():
    token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        return jsonify({"ok": False, "error": "CSRF token inválido"}), 403
    return None

@limiter.limit("10 per minute")
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] == ADMIN_USER and request.form['password'] == ADMIN_PASS:
            session.permanent = True
            session['logged_in'] = True
            session['csrf_token'] = secrets.token_hex(16)
            return redirect(url_for('index'))
        error = "Credenciales incorrectas"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    conn = get_db()
    cursor = conn.cursor()
    # ... código ...
    # (sin conn.close() — se reutiliza)
    cursor.execute("SELECT dispositivo, ip, bytes_bajada, protocolo_l7, fecha_hora FROM trafico_dispositivos ORDER BY id DESC LIMIT 15")
    flujos = cursor.fetchall()
    
    return render_template('index.html', flujos=flujos, raspberry_ip=RASPBERRY_IP)

@app.route('/api/data')
@login_required
def get_stats():
    sid = get_sid()
    if not sid: return jsonify({"error": "Auth failed"}), 401
    try:
        headers = {"X-FTL-SID": sid}
        r = requests.get(f"{PIHOLE_BASE_URL}/stats/summary", headers=headers, timeout=5)
        data = r.json()
        total_q = data.get('queries', {}).get('total', 0)
        blocked_q = data.get('queries', {}).get('blocked', 0)
        percent = round((blocked_q / total_q) * 100, 1) if total_q > 0 else 0.0
        domains = data.get('gravity', {}).get('domains_being_blocked', 0)
        return jsonify({
            "dns_queries_today": total_q,
            "ads_blocked_today": blocked_q,
            "ads_percentage_today": percent,
            "domains_being_blocked": domains,
            "last_update": get_ahora_madrid().split(" ")[1]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/alertas')
@login_required
def alertas():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''SELECT id, fecha, tipo, ip, descripcion, severidad 
                      FROM alertas ORDER BY id DESC LIMIT 100''')
    rows = cursor.fetchall()
    total = cursor.execute('SELECT COUNT(*) FROM alertas').fetchone()[0]
    criticas = cursor.execute("SELECT COUNT(*) FROM alertas WHERE severidad='CRITICA'").fetchone()[0]
    altas = cursor.execute("SELECT COUNT(*) FROM alertas WHERE severidad='ALTA'").fetchone()[0]
    # conn reutilizada por get_db()
    return render_template('alertas.html', alertas=rows, total=total, criticas=criticas, altas=altas)

@app.route('/api/alertas')
@login_required
def api_alertas():
    n = int(request.args.get('n', 20))
    conn = get_db()
    cursor = conn.cursor()
    rows = cursor.execute('''SELECT id, fecha, tipo, ip, descripcion, severidad 
                              FROM alertas ORDER BY id DESC LIMIT ?''', (n,)).fetchall()
    no_leidas = cursor.execute(
        "SELECT COUNT(*) FROM alertas WHERE fecha >= datetime('now', '-5 minutes', 'localtime')"
    ).fetchone()[0]
    # conn reutilizada por get_db()
    return jsonify({
        "ok": True,
        "alertas": [{"id": r[0], "fecha": r[1], "tipo": r[2], "ip": r[3],
                     "descripcion": r[4], "severidad": r[5]} for r in rows],
        "no_leidas": no_leidas
    })


@app.route('/api/alertas/export/csv')
@login_required
def api_alertas_export_csv():
    import csv, io
    from flask import Response
    conn = get_db()
    rows = conn.execute(
        'SELECT id, fecha, tipo, ip, descripcion, severidad FROM alertas ORDER BY id DESC'
    ).fetchall()
    # conn reutilizada por get_db()
    output = io.StringIO()
    writer = csv.writer(output, delimiter='\t')
    writer.writerow(['ID', 'Fecha', 'Tipo', 'IP', 'Descripcion', 'Severidad'])
    writer.writerows(rows)
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/plain',
        headers={"Content-Disposition": "attachment; filename=alertas_siem.txt"}
    )

@app.route('/api/csrf-token')
@login_required
def api_csrf_token():
    return jsonify({"token": session.get('csrf_token', '')})

@app.route('/api/alertas/clear', methods=['POST'])
@login_required
def api_alertas_clear():
    err = csrf_protect()
    if err: return err
    conn = get_db()
    conn.execute('DELETE FROM alertas')
    conn.commit()
    # conn reutilizada por get_db()
    return jsonify({"ok": True})

# --- BUGFIX: faltaba el decorador @app.route('/graficas') ---
@app.route("/graficas")
@app.route("/red")
@app.route("/estadisticas")
@login_required
def estadisticas():
    return render_template("estadisticas.html")






@app.route('/api/graficas/trafico_total')
@login_required
def api_trafico_total():
    horas = int(request.args.get('horas', 24))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            strftime('%Y-%m-%d %H:%M', fecha_hora, 'localtime') as momento,
            SUM(bytes_bajada) as bajada,
            SUM(bytes_subida) as subida
        FROM trafico_dispositivos
        WHERE fecha_hora >= datetime('now', ?, 'localtime')
        GROUP BY strftime('%Y-%m-%d %H:%M', fecha_hora)
        ORDER BY momento ASC
    ''', (f'-{horas} hours',))
    rows = cursor.fetchall()
    # conn reutilizada por get_db()
    return jsonify({
        "labels": [r[0] for r in rows],
        "bajada": [round(r[1], 3) for r in rows],
        "subida": [round(r[2], 3) for r in rows]
    })

@app.route('/api/graficas/trafico_dispositivos')
@login_required
def api_trafico_dispositivos():
    horas = int(request.args.get('horas', 24))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT ip, SUM(bytes_bajada) as total_bajada, SUM(bytes_subida) as total_subida
        FROM trafico_dispositivos
        WHERE fecha_hora >= datetime('now', ?, 'localtime')
          AND ip LIKE '192.168.%'
        GROUP BY ip
        ORDER BY total_bajada DESC
        LIMIT 10
    ''', (f'-{horas} hours',))
    rows = cursor.fetchall()
    # conn reutilizada por get_db()
    return jsonify({
        "labels": [r[0] for r in rows],
        "bajada": [round(r[1], 3) for r in rows],
        "subida": [round(r[2], 3) for r in rows]
    })

@app.route('/api/graficas/dns')
@login_required
def api_graficas_dns():
    horas = int(request.args.get('horas', 24))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            strftime('%Y-%m-%d %H:%M', fecha, 'localtime') as momento,
            total_queries,
            ads_blocked
        FROM estadisticas_dns
        WHERE fecha >= datetime('now', ?, 'localtime')
        ORDER BY momento ASC
    ''', (f'-{horas} hours',))
    rows = cursor.fetchall()
    # conn reutilizada por get_db()
    return jsonify({
        "labels": [r[0] for r in rows],
        "total": [r[1] for r in rows],
        "bloqueadas": [r[2] for r in rows]
    })

@app.route('/api/mac_vendors')
@login_required
def api_mac_vendors():
    conn = get_db()
    rows = conn.execute('SELECT mac, fabricante, fecha FROM mac_vendors ORDER BY fecha DESC').fetchall()
    # conn reutilizada por get_db()
    return jsonify({"ok": True, "total": len(rows),
                    "vendors": [{"mac": r[0], "fabricante": r[1], "fecha": r[2]} for r in rows]})

# --- BUGFIX: faltaba el decorador @app.route('/api/hosts') ---
@app.route('/api/hosts')
@login_required
def api_hosts():
    hosts = get_ntopng_hosts()
    if hosts is None:
        return jsonify({"ok": False, "error": "No se pudo conectar con ntopng"}), 500
    return jsonify({"ok": True, "hosts": hosts, "total": len(hosts)})


# --- RUTAS TRÁFICO LATERAL ---

@app.route('/lateral')
@login_required
def lateral():
    conn = get_db()
    cursor = conn.cursor()
    # Últimas 200 conexiones laterales
    rows = cursor.execute('''
        SELECT id, fecha, src_ip, dst_ip, protocolo, puerto_dst, info
        FROM lateral_connections ORDER BY id DESC LIMIT 200
    ''').fetchall()
    total = cursor.execute('SELECT COUNT(*) FROM lateral_connections').fetchone()[0]
    # IPs únicas que han generado tráfico lateral
    srcs_unicos = cursor.execute('''
        SELECT src_ip, COUNT(DISTINCT dst_ip) as destinos, COUNT(*) as conexiones
        FROM lateral_connections
        WHERE fecha >= datetime('now', '-24 hours', 'localtime')
        GROUP BY src_ip ORDER BY destinos DESC LIMIT 10
    ''').fetchall()
    # conn reutilizada por get_db()
    return render_template('lateral.html', conexiones=rows, total=total, srcs=srcs_unicos)

@app.route('/api/lateral')
@login_required
def api_lateral():
    horas = int(request.args.get('horas', 1))
    conn = get_db()
    cursor = conn.cursor()
    rows = cursor.execute('''
        SELECT fecha, src_ip, dst_ip, protocolo, puerto_dst, info
        FROM lateral_connections
        WHERE fecha >= datetime('now', ?, 'localtime')
        ORDER BY id DESC LIMIT 500
    ''', (f'-{horas} hours',)).fetchall()
    # Mapa src → lista de dst (para visualizar el grafo)
    grafo = {}
    for r in rows:
        src = r[1]
        dst = r[2]
        if src not in grafo:
            grafo[src] = []
        if dst not in grafo[src]:
            grafo[src].append(dst)
    # conn reutilizada por get_db()
    return jsonify({
        "ok": True,
        "total": len(rows),
        "conexiones": [{"fecha": r[0], "src": r[1], "dst": r[2],
                        "proto": r[3], "puerto": r[4], "info": r[5]} for r in rows],
        "grafo": grafo
    })

@app.route('/api/lateral/clear', methods=['POST'])
@login_required
def api_lateral_clear():
    err = csrf_protect()
    if err: return err
    conn = get_db()
    conn.execute('DELETE FROM lateral_connections')
    conn.commit()
    # conn reutilizada por get_db()
    return jsonify({"ok": True})



# --- RUTAS CONTENEDORES DOCKER ---

@app.route('/contenedores')
@login_required
def contenedores():
    return render_template('contenedores.html')

@app.route('/api/contenedores')
@login_required
def api_contenedores():
    try:
        client = docker_sdk.from_env()
        containers = client.containers.list(all=True)
        resultado = []
        for c in containers:
            # Calcular uptime legible
            uptime = "—"
            if c.status == "running":
                started = c.attrs.get("State", {}).get("StartedAt", "")
                if started:
                    try:
                        from datetime import timezone
                        dt = datetime.fromisoformat(started[:19])
                        dt = dt.replace(tzinfo=timezone.utc)
                        now_utc = datetime.now(timezone.utc)
                        diff = now_utc - dt
                        h, rem = divmod(int(diff.total_seconds()), 3600)
                        m = rem // 60
                        uptime = f"{h}h {m}m" if h > 0 else f"{m}m"
                    except:
                        uptime = "—"
            resultado.append({
                "id":     c.short_id,
                "nombre": c.name,
                "imagen": c.image.tags[0] if c.image.tags else c.image.short_id,
                "estado": c.status,
                "uptime": uptime,
            })
        # Ordenar: running primero, luego exited
        resultado.sort(key=lambda x: (0 if x["estado"] == "running" else 1, x["nombre"]))
        return jsonify({"ok": True, "contenedores": resultado, "total": len(resultado)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/contenedores/<nombre>/restart', methods=['POST'])
@login_required
def api_contenedor_restart(nombre):
    try:
        client = docker_sdk.from_env()
        c = client.containers.get(nombre)
        c.restart(timeout=10)
        return jsonify({"ok": True, "estado": "restarted"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/contenedores/<nombre>/stop', methods=['POST'])
@login_required
def api_contenedor_stop(nombre):
    err = csrf_protect()
    if err: return err
    try:
        client = docker_sdk.from_env()
        c = client.containers.get(nombre)
        c.stop(timeout=10)
        return jsonify({"ok": True, "estado": "stopped"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/contenedores/<nombre>/start', methods=['POST'])
@login_required
def api_contenedor_start(nombre):
    try:
        client = docker_sdk.from_env()
        c = client.containers.get(nombre)
        c.start()
        return jsonify({"ok": True, "estado": "started"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/api/contenedores/<nombre>/logs')
@login_required
def api_contenedor_logs(nombre):
    try:
        client = docker_sdk.from_env()
        c = client.containers.get(nombre)
        logs = c.logs(tail=50, timestamps=False).decode('utf-8', errors='replace')
        return jsonify({"ok": True, "logs": logs})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# --- RUTAS CONTROL TSHARK ---
import docker as docker_sdk

@app.route('/api/tshark/status')
@login_required
def tshark_status():
    try:
        client = docker_sdk.from_env()
        container = client.containers.get('tshark-sflow')
        return jsonify({"ok": True, "status": container.status})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route('/api/tshark/start', methods=['POST'])
@login_required
def tshark_start():
    try:
        client = docker_sdk.from_env()
        container = client.containers.get('tshark-sflow')
        container.start()
        return jsonify({"ok": True, "status": "started"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route('/api/tshark/stop', methods=['POST'])
@login_required
def tshark_stop():
    try:
        client = docker_sdk.from_env()
        container = client.containers.get('tshark-sflow')
        container.stop()
        return jsonify({"ok": True, "status": "stopped"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route('/api/tshark/clear', methods=['POST'])
@login_required
def tshark_clear():
    try:
        open(TSHARK_LOG_PATH, 'w').close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route('/api/tshark/download')
@login_required
def tshark_download():
    from flask import send_file
    try:
        return send_file(TSHARK_LOG_PATH, as_attachment=True, download_name='tshark_capture.txt')
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route('/sniffer')
@login_required
def sniffer():
    lineas = []
    error = None
    total_lineas = 0
    n = int(request.args.get('n', 100))
    filtro = request.args.get('filtro', '').lower()
    try:
        import subprocess
        # Leer solo las últimas líneas con tail (sin cargar todo en memoria)
        resultado = subprocess.run(
            ['tail', '-n', '5000', TSHARK_LOG_PATH],
            capture_output=True, text=True, errors='replace'
        )
        todas = resultado.stdout.splitlines(keepends=True)
        total_lineas = int(subprocess.run(
            ['wc', '-l', TSHARK_LOG_PATH],
            capture_output=True, text=True
        ).stdout.split()[0])
        if filtro:
            todas = [l for l in todas if filtro in l.lower()]
        ultimas = todas[-n:]
        lineas = [p for p in (parse_tshark_line(l) for l in ultimas) if p]
    except FileNotFoundError:
        error = f"Archivo no encontrado: {TSHARK_LOG_PATH}"
    except Exception as e:
        error = str(e)
    return render_template('sniffer.html', lineas=lineas, error=error, n=n, filtro=filtro, total=total_lineas)

@app.route('/api/sniffer')
@login_required
def api_sniffer():
    n = int(request.args.get('n', 100))
    filtro = request.args.get('filtro', '').lower()
    try:
        import subprocess
        resultado = subprocess.run(
            ['tail', '-n', '5000', TSHARK_LOG_PATH],
            capture_output=True, text=True, errors='replace'
        )
        todas = resultado.stdout.splitlines(keepends=True)
        if filtro:
            todas = [l for l in todas if filtro in l.lower()]
        ultimas = todas[-n:]
        lineas = [p for p in (parse_tshark_line(l) for l in ultimas) if p]
        return jsonify({"ok": True, "total": len(todas), "mostrando": len(lineas), "lineas": lineas})
    except FileNotFoundError:
        return jsonify({"ok": False, "error": "Archivo no encontrado"}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
# ─────────────────────────────────────────────
#  MONITOR DE RED — /red
# ─────────────────────────────────────────────
NODE_EXPORTER_URL = 'http://127.0.0.1:9100/metrics'




@app.route('/api/red/metrics')
@login_required
def api_red_metrics():
    try:
        resp = requests.get(NODE_EXPORTER_URL, timeout=3)

        # Parsear línea a línea una sola vez (en vez de 8 re.search/finditer separados)
        metrics = {}
        ifaces = {}
        for line in resp.text.splitlines():
            if line.startswith('#'):
                continue
            # Métricas simples clave=valor
            m = re.match(r'^(node_load1|node_load5|node_memory_MemTotal_bytes|node_memory_MemAvailable_bytes|node_thermal_zone_temp)\s+([\d.e+]+)', line)
            if m:
                metrics[m.group(1)] = float(m.group(2))
                continue
            # Filesystem
            m = re.match(r'^(node_filesystem_avail_bytes|node_filesystem_size_bytes)\{[^}]*mountpoint="/etc/hostname"[^}]*\}\s+([\d.e+]+)', line)
            if m:
                metrics[m.group(1)] = float(m.group(2))
                continue
            # Interfaces de red
            m = re.match(r'^node_network_(receive|transmit)_bytes_total\{device="([^"]+)"\}\s+([\d.e+]+)', line)
            if m:
                direction = 'rx' if m.group(1) == 'receive' else 'tx'
                ifaces.setdefault(m.group(2), {})[direction] = float(m.group(3))

        interfaces = [{'name': k, 'rx': v.get('rx', 0), 'tx': v.get('tx', 0)} for k, v in ifaces.items()]

        return jsonify({'ok': True,
                        'load1':      metrics.get('node_load1', 0.0),
                        'load5':      metrics.get('node_load5', 0.0),
                        'mem_total':  metrics.get('node_memory_MemTotal_bytes', 0),
                        'mem_avail':  metrics.get('node_memory_MemAvailable_bytes', 0),
                        'disk_avail': metrics.get('node_filesystem_avail_bytes'),
                        'disk_size':  metrics.get('node_filesystem_size_bytes'),
                        'temp':       metrics.get('node_thermal_zone_temp'),
                        'net_rx':     ifaces.get('wlan0', {}).get('rx'),
                        'net_tx':     ifaces.get('wlan0', {}).get('tx'),
                        'interfaces': interfaces})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/api/red/pihole')
@login_required
def api_red_pihole():
    try:
        r = requests.get(f"{PIHOLE_BASE_URL}/stats/summary", timeout=3,
                         headers={'X-FTL-SID': current_sid} if current_sid else {})
        d = r.json()
        return jsonify({'ok': True,
                        'queries': d.get('queries',{}).get('total') or d.get('dns_queries_today'),
                        'blocked': d.get('queries',{}).get('blocked') or d.get('ads_blocked_today'),
                        'percent': d.get('queries',{}).get('percent_blocked') or d.get('ads_percentage_today'),
                        'clients': d.get('clients',{}).get('active') or d.get('unique_clients')})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500

if __name__ == '__main__':
    init_db()
    threading.Thread(target=background_logger, daemon=True).start()
    app.run(host='0.0.0.0', port=5000, debug=False)

#ENDPOINT SURICATA
@app.route('/api/suricata/alertas')
@login_required
def api_suricata_alertas():
    EVE_PATH = '/suricata/logs/eve.json'
    ignorar = {'duckdns', 'DYNAMIC_DNS', 'Spotify', 'Telegram'}
    alertas = []
    try:
        with open(EVE_PATH, 'r', errors='replace') as f:
            for line in f:
                try:
                    ev = json.loads(line)
                    if ev.get('event_type') != 'alert':
                        continue
                    sig = ev.get('alert', {}).get('signature', '')
                    if any(fp in sig for fp in ignorar):
                        continue
                    alertas.append({
                        'timestamp': ev.get('timestamp', '')[:19].replace('T', ' '),
                        'signature': sig,
                        'src_ip': ev.get('src_ip', ''),
                        'dst_ip': ev.get('dest_ip', ''),
                        'dst_port': ev.get('dest_port', ''),
                        'categoria': ev.get('alert', {}).get('category', ''),
                        'severidad_num': ev.get('alert', {}).get('severity', 3),
                    })
                except:
                    continue
    except FileNotFoundError:
        pass
    alertas = alertas[-50:]
    alertas.reverse()
    return jsonify({'ok': True, 'alertas': alertas, 'total': len(alertas)})

#ENDPOINT PARA FAIL2BAN
@app.route('/api/fail2ban/bans')
@login_required
def api_fail2ban_bans():
    import subprocess
    try:
        result = subprocess.run(
            ['docker', 'exec', 'fail2ban', 'fail2ban-client', 'status'],
            capture_output=True, text=True, timeout=5
        )
        jails = []
        ips = []
        for line in result.stdout.splitlines():
            if 'Jail list:' in line:
                jails = [j.strip() for j in line.split(':')[1].split(',') if j.strip()]
        for jail in jails:
            r2 = subprocess.run(
                ['docker', 'exec', 'fail2ban', 'fail2ban-client', 'status', jail],
                capture_output=True, text=True, timeout=5
            )
            for line in r2.stdout.splitlines():
                if 'Banned IP list:' in line:
                    banned = line.split(':')[1].strip()
                    if banned:
                        ips.extend(banned.split())
        return jsonify({'ok': True, 'ips': ips, 'jails': jails, 'total_ips': len(ips)})
    except Exception as e:
        return jsonify({'ok': False, 'ips': [], 'jails': [], 'total_ips': 0, 'error': str(e)})
