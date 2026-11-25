# -*- coding: utf-8 -*-
"""Recolectores de red, sistema, DNS, activos críticos y contenedores."""

import json
import logging
import os
import re
import socket
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

import requests

from siem.config import SiemConfig
from siem.database import Database
from siem.security import validate_container_name, validate_domain

logger = logging.getLogger("siem.collectors")

# Prefijos OUI locales comunes en librerías e imprentas (funciona incluso sin internet)
LOCAL_OUI_HINTS: Dict[str, str] = {
    "00:1E:8F": "Canon (Impresora/Plotter)",
    "18:0C:AC": "Canon (Impresora/Plotter)",
    "F4:81:39": "Canon (Impresora/Plotter)",
    "00:26:AB": "Seiko Epson (Impresora/TPV)",
    "A4:D7:3C": "Seiko Epson (Impresora/TPV)",
    "00:00:48": "Seiko Epson (Impresora/TPV)",
    "3C:D9:2B": "Hewlett Packard (HP)",
    "00:1B:78": "Hewlett Packard (HP)",
    "9C:B6:54": "Hewlett Packard (HP)",
    "00:00:74": "Ricoh (Impresora Industrial)",
    "00:26:73": "Ricoh (Impresora Industrial)",
    "00:20:6B": "Konica Minolta (Imprenta)",
    "00:00:AA": "Xerox (Imprenta)",
    "00:80:77": "Brother Industries",
    "00:1B:A9": "Brother Industries",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "2C:CF:67": "Raspberry Pi Foundation",
    "00:11:32": "Synology (NAS)",
    "24:5E:BE": "QNAP Systems (NAS)",
}


def tail_lines(path: str, max_lines: int = 5000, chunk_size: int = 8192) -> Tuple[List[str], int]:
    """
    Lee las últimas `max_lines` líneas de un archivo grande en O(bytes finales) sin
    cargar todo el archivo en RAM ni lanzar subprocesos externos.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    file_size = os.path.getsize(path)
    if file_size == 0:
        return [], 0

    lines: List[bytes] = []
    with open(path, "rb") as f:
        pos = file_size
        remainder = b""
        while pos > 0 and len(lines) <= max_lines:
            read_size = min(chunk_size, pos)
            pos -= read_size
            f.seek(pos)
            chunk = f.read(read_size) + remainder
            parts = chunk.split(b"\n")
            remainder = parts[0]
            lines = parts[1:] + lines
        if remainder:
            lines.insert(0, remainder)

    decoded = [
        ln.decode("utf-8", errors="replace").rstrip("\r")
        for ln in lines[-max_lines:]
        if ln.strip()
    ]
    return decoded, len(decoded)


class IncrementalFileReader:
    """
    Lee solo las líneas nuevas de un log manejando truncado (clear) y rotación (inode).
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._offset = 0
        self._inode: Optional[int] = None

    def reset(self) -> None:
        with self._lock:
            self._offset = 0
            self._inode = None

    def read_new_lines(self, max_bytes: int = 4 * 1024 * 1024) -> List[str]:
        with self._lock:
            if not os.path.exists(self.path):
                return []
            try:
                st = os.stat(self.path)
            except OSError:
                return []

            # Si el archivo se rotó o truncó, reiniciamos el puntero
            if self._inode is not None and st.st_ino != self._inode:
                self._offset = 0
            if st.st_size < self._offset:
                self._offset = 0
            self._inode = st.st_ino

            if st.st_size == self._offset:
                return []

            with open(self.path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._offset)
                chunk = f.read(max_bytes)
                self._offset = f.tell()

            return chunk.splitlines()


def parse_tshark_line(line: str) -> Optional[Dict[str, str]]:
    line = (line or "").strip()
    if not line:
        return None
    parts = line.split()
    if len(parts) < 6:
        return None
    # Formato típico tshark: num time src → dst proto len info...
    arrow_idx = 3 if len(parts) > 3 and parts[3] in ("→", "->") else -1
    if arrow_idx == 3 and len(parts) >= 7:
        return {
            "num": parts[0],
            "tiempo": parts[1],
            "src": parts[2],
            "dst": parts[4],
            "protocolo": parts[5],
            "len": parts[6],
            "info": " ".join(parts[7:]) if len(parts) > 7 else "",
        }
    return {
        "num": parts[0],
        "tiempo": parts[1],
        "src": parts[2],
        "dst": parts[4] if len(parts) > 4 else "",
        "protocolo": parts[5] if len(parts) > 5 else "",
        "len": parts[6] if len(parts) > 6 else "",
        "info": " ".join(parts[7:]) if len(parts) > 7 else "",
    }


def extract_dst_port(info: str) -> str:
    """Extrae el puerto destino de la columna Info de tshark ('54321 → 445 ...')."""
    if not info:
        return ""
    sep = "→" if "→" in info else ("->" if "->" in info else None)
    if not sep:
        return ""
    right = info.split(sep, 1)[1].strip()
    if not right:
        return ""
    token = right.split()[0].rstrip(",:;")
    return token if token.isdigit() else ""


class MacVendorLookup:
    """Resolución OUI de fabricantes con caché acotada en RAM, hints locales y SQLite."""

    def __init__(self, db: Database, max_cache: int = 1024):
        self.db = db
        self._cache: "OrderedDict[str, str]" = OrderedDict()
        self._lock = threading.Lock()
        self._max_cache = max_cache

    def _put_cache(self, mac: str, vendor: str) -> None:
        with self._lock:
            self._cache[mac] = vendor
            self._cache.move_to_end(mac)
            while len(self._cache) > self._max_cache:
                self._cache.popitem(last=False)

    def lookup(self, mac: str, allow_external: bool = True) -> str:
        if not mac or mac == "00:00:00:00:00:00":
            return "Desconocido"
        mac_u = mac.strip().upper().replace("-", ":")

        with self._lock:
            if mac_u in self._cache:
                self._cache.move_to_end(mac_u)
                return self._cache[mac_u]

        # Hint rápido offline para impresoras/NAS/Raspberry
        oui = mac_u[:8]
        if oui in LOCAL_OUI_HINTS:
            vendor = LOCAL_OUI_HINTS[oui]
            self._put_cache(mac_u, vendor)
            return vendor

        conn = self.db.connect_new()
        try:
            row = conn.execute(
                "SELECT fabricante FROM mac_vendors WHERE mac = ?", (mac_u,)
            ).fetchone()
            if row:
                self._put_cache(mac_u, row["fabricante"])
                return row["fabricante"]

            vendor = "Desconocido"
            if allow_external:
                try:
                    r = requests.get(
                        f"https://api.maclookup.app/v2/macs/{mac_u}", timeout=3
                    )
                    if r.status_code == 200:
                        data = r.json()
                        cand = (
                            data.get("company")
                            or data.get("companyName")
                            or "Desconocido"
                        )
                        if cand and cand.lower() != "n/a":
                            vendor = cand
                except Exception:
                    vendor = "Desconocido"

            conn.execute(
                "INSERT OR REPLACE INTO mac_vendors (mac, fabricante, fecha) VALUES (?, ?, ?)",
                (mac_u, vendor, self.db.now_str()),
            )
            conn.commit()
            self._put_cache(mac_u, vendor)
            return vendor
        except Exception as e:
            logger.debug("Error consultando fabricante MAC %s: %s", mac_u, e)
            return "Desconocido"
        finally:
            conn.close()


class JA3Database:
    """Base de datos dinámica de hashes JA3 maliciosos con fallback local."""

    JA3_DB_URL = "https://raw.githubusercontent.com/trisulnsm/ja3era/master/ja3fingerprints.json"
    JA3_LOCAL: Dict[str, str] = {
        "e54c6e2fd03f1e2b1c7f8f6e0aefb3a6": "Cobalt Strike",
        "72a589da586844d7f0818ce684948eea": "Cobalt Strike",
        "6bca5d2a0b7d3d21e06a216c57b7bbfe": "Cobalt Strike",
        "c27b06e79a31aff0839438dfff99f4a6": "Metasploit",
        "d4d44f04a29f4e18bc49d48de3a88d55": "Metasploit",
        "5d41402abc4b2a76b9719d911017c592": "Sliver C2",
        "a0e9f5d64349fb13191bc781f81f42e1": "Covenant C2",
        "a0e9f5d64349fb13191bc781f81f42e2": "TrickBot / Malware TLS",
    }

    def __init__(self):
        self._db: Dict[str, str] = dict(self.JA3_LOCAL)
        self._ts: float = 0.0
        self._lock = threading.Lock()

    @staticmethod
    def parse_payload(data: Any) -> Dict[str, str]:
        """Parsea de forma segura tanto listas como diccionarios JSON de JA3."""
        parsed: Dict[str, str] = {}
        if isinstance(data, list):
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                h = entry.get("md5") or entry.get("ja3_md5") or entry.get("hash") or ""
                desc = (
                    entry.get("desc")
                    or entry.get("name")
                    or entry.get("tool")
                    or "Amenaza TLS conocida"
                )
                if h:
                    parsed[str(h).lower()] = str(desc)
        elif isinstance(data, dict):
            for h, v in data.items():
                if isinstance(v, dict):
                    desc = v.get("desc") or v.get("name") or "Amenaza TLS conocida"
                elif isinstance(v, str):
                    desc = v
                else:
                    desc = "Amenaza TLS conocida"
                parsed[str(h).lower()] = str(desc)
        return parsed

    def refresh_if_stale(self, ttl_seconds: int = 86400) -> None:
        if self._ts and (time.time() - self._ts) < ttl_seconds:
            return
        with self._lock:
            if self._ts and (time.time() - self._ts) < ttl_seconds:
                return
            try:
                r = requests.get(self.JA3_DB_URL, timeout=8)
                if r.status_code == 200:
                    remote = self.parse_payload(r.json())
                    if remote:
                        self._db = {**self.JA3_LOCAL, **remote}
                        self._ts = time.time()
                        logger.info("[JA3] Base actualizada: %d hashes", len(self._db))
                        return
            except Exception as e:
                logger.warning("[JA3] Error descargando lista remota (%s), usando local", e)
            self._db = dict(self.JA3_LOCAL)
            self._ts = time.time()

    def lookup(self, ja3_hash: str) -> Optional[str]:
        if not ja3_hash:
            return None
        return self._db.get(ja3_hash.strip().lower())


class NtopngCollector:
    """
    Cliente ntopng con cálculo REAL de tráfico delta por intervalo.
    Corrige el bug del TFG original donde se sumaban acumulados cada 30s (inflado ~120x/h).
    """

    def __init__(self, config: SiemConfig, mac_lookup: MacVendorLookup):
        self.config = config
        self.mac_lookup = mac_lookup
        self.session = requests.Session()
        self.authenticated = False
        self._lock = threading.Lock()
        # ip -> (bytes_rcvd_prev, bytes_sent_prev)
        self._prev_bytes: Dict[str, Tuple[int, int]] = {}

    def compute_delta_mb(
        self, ip: str, bytes_rcvd: int, bytes_sent: int
    ) -> Tuple[float, float]:
        """Calcula los MB transferidos desde el último muestreo para una IP."""
        prev = self._prev_bytes.get(ip)
        self._prev_bytes[ip] = (bytes_rcvd, bytes_sent)
        if prev is None:
            # Primera observación tras arranque: evitamos atribuir tráfico histórico al ciclo actual
            return 0.0, 0.0
        prev_rcvd, prev_sent = prev
        # Si ntopng reinició contadores (current < prev), usamos el nuevo valor como delta
        delta_rcvd = bytes_rcvd - prev_rcvd if bytes_rcvd >= prev_rcvd else bytes_rcvd
        delta_sent = bytes_sent - prev_sent if bytes_sent >= prev_sent else bytes_sent
        return (
            round(max(0, delta_rcvd) / (1024 * 1024), 4),
            round(max(0, delta_sent) / (1024 * 1024), 4),
        )

    def login(self) -> bool:
        try:
            r = self.session.get(
                f"{self.config.ntopng_base}/lua/rest/v2/get/ntopng/interfaces.lua",
                allow_redirects=False,
                timeout=4,
            )
            if r.status_code == 200:
                self.authenticated = True
                return True
            r = self.session.post(
                f"{self.config.ntopng_base}/authorize.html",
                data={"user": self.config.ntopng_user, "password": self.config.ntopng_pass},
                allow_redirects=False,
                timeout=4,
            )
            if "login" not in r.headers.get("Location", ""):
                self.authenticated = True
                return True
        except Exception as e:
            logger.debug("[ntopng] Error de conexión/login: %s", e)
        self.authenticated = False
        return False

    def get_active_hosts(self, update_deltas: bool = False) -> Optional[List[Dict[str, Any]]]:
        with self._lock:
            if not self.authenticated and not self.login():
                return None
            try:
                r = self.session.get(
                    f"{self.config.ntopng_base}/lua/rest/v2/get/host/active.lua",
                    params={"ifid": 0},
                    allow_redirects=False,
                    timeout=5,
                )
                if r.status_code == 302:
                    self.authenticated = False
                    if not self.login():
                        return None
                    r = self.session.get(
                        f"{self.config.ntopng_base}/lua/rest/v2/get/host/active.lua",
                        params={"ifid": 0},
                        allow_redirects=False,
                        timeout=5,
                    )
                if r.status_code != 200:
                    self.authenticated = False
                    return None
                data = r.json()
                if data.get("rc") != 0:
                    return None

                hosts = data.get("rsp", {}).get("data", [])
                resultado: List[Dict[str, Any]] = []
                for h in hosts:
                    ip = h.get("ip", "")
                    if not self.config.is_local_ip(ip):
                        continue
                    if h.get("is_broadcast") or h.get("is_multicast"):
                        continue

                    name = h.get("name", ip) or ip
                    if name.startswith("$"):
                        name = ip
                    bytes_sent = int(h.get("bytes", {}).get("sent", 0) or 0)
                    bytes_rcvd = int(h.get("bytes", {}).get("recvd", 0) or 0)
                    mac = (h.get("mac") or "").upper()

                    delta_rcvd_mb, delta_sent_mb = (
                        self.compute_delta_mb(ip, bytes_rcvd, bytes_sent)
                        if update_deltas
                        else (0.0, 0.0)
                    )

                    resultado.append(
                        {
                            "ip": ip,
                            "name": name,
                            "mac": mac,
                            "fabricante": self.mac_lookup.lookup(mac),
                            "sent_mb": round(bytes_sent / (1024 * 1024), 4),
                            "rcvd_mb": round(bytes_rcvd / (1024 * 1024), 4),
                            "delta_sent_mb": delta_sent_mb,
                            "delta_rcvd_mb": delta_rcvd_mb,
                            "score": int(h.get("score", {}).get("total", 0) or 0),
                            "flows": int(h.get("num_flows", {}).get("total", 0) or 0),
                            "country": h.get("country", ""),
                        }
                    )
                return resultado
            except Exception as e:
                logger.debug("[ntopng] Error get_active_hosts: %s", e)
                self.authenticated = False
                return None


class PiholeClient:
    """Cliente Pi-hole v6 con caché, auto-renovación de SID y bloqueo rápido de dominios."""

    def __init__(self, config: SiemConfig):
        self.config = config
        self._sid: Optional[str] = None
        self._lock = threading.Lock()
        self._summary_cache: Dict[str, Any] = {"data": None, "ts": 0.0}

    def _authenticate(self, force: bool = False) -> Optional[str]:
        with self._lock:
            if self._sid and not force:
                return self._sid
            try:
                r = requests.post(
                    f"{self.config.pihole_base_url}/auth",
                    json={"password": self.config.pihole_password},
                    timeout=5,
                )
                if r.status_code == 200:
                    self._sid = r.json().get("session", {}).get("sid")
                    return self._sid
            except Exception as e:
                logger.debug("[Pi-hole] Error auth: %s", e)
            self._sid = None
            return None

    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[requests.Response]:
        sid = self._authenticate()
        headers = kwargs.pop("headers", {})
        if sid:
            headers["X-FTL-SID"] = sid
        url = f"{self.config.pihole_base_url}{endpoint}"
        try:
            r = requests.request(method, url, headers=headers, timeout=5, **kwargs)
            if r.status_code == 401:
                sid = self._authenticate(force=True)
                if not sid:
                    return r
                headers["X-FTL-SID"] = sid
                r = requests.request(method, url, headers=headers, timeout=5, **kwargs)
            return r
        except Exception as e:
            logger.debug("[Pi-hole] Error %s %s: %s", method, endpoint, e)
            return None

    def get_summary(self, max_age: int = 15) -> Optional[Dict[str, Any]]:
        now = time.time()
        if (
            self._summary_cache["data"] is not None
            and now - self._summary_cache["ts"] < max_age
        ):
            return self._summary_cache["data"]
        r = self._request("GET", "/stats/summary")
        if r is None or r.status_code != 200:
            return None
        try:
            data = r.json()
            self._summary_cache = {"data": data, "ts": now}
            return data
        except Exception:
            return None

    def list_blocked_domains(self) -> List[Dict[str, Any]]:
        r = self._request("GET", "/domains/deny/exact")
        if r is None or r.status_code != 200:
            return []
        try:
            domains = r.json().get("domains", [])
            return [
                {
                    "domain": d.get("domain", ""),
                    "comment": d.get("comment", ""),
                    "enabled": d.get("enabled", True),
                }
                for d in domains
                if d.get("domain")
            ]
        except Exception:
            return []

    def block_domain(self, domain: str, comment: str = "Bloqueado desde SIEM") -> Tuple[bool, str]:
        clean = validate_domain(domain)
        if not clean:
            return False, "Dominio inválido"
        r = self._request(
            "POST",
            "/domains/deny/exact",
            json={"domain": clean, "comment": comment, "enabled": True},
        )
        if r is not None and r.status_code in (200, 201):
            return True, f"Dominio {clean} bloqueado"
        return False, "No se pudo contactar con Pi-hole para bloquear el dominio"

    def unblock_domain(self, domain: str) -> Tuple[bool, str]:
        clean = validate_domain(domain)
        if not clean:
            return False, "Dominio inválido"
        r = self._request("DELETE", f"/domains/deny/exact/{clean}")
        if r is not None and r.status_code in (200, 204):
            return True, f"Dominio {clean} desbloqueado"
        return False, "No se pudo eliminar el dominio de la lista negra"


class AssetWatchdog:
    """
    Comprueba proactivamente la disponibilidad de equipos críticos (Impresoras, Plotters,
    TPVs, NAS) e Internet WAN para librerías e imprentas.
    """

    def __init__(self, db: Database):
        self.db = db
        self.wan_online: bool = True
        self.wan_latency_ms: Optional[float] = None
        self.last_wan_check: Optional[str] = None

    @staticmethod
    def tcp_probe(host: str, port: int, timeout: float = 1.5) -> Tuple[bool, Optional[float]]:
        if not host or port <= 0:
            return False, None
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                ms = round((time.perf_counter() - t0) * 1000, 1)
                return True, ms
        except OSError:
            return False, None

    def check_wan(self) -> Tuple[bool, Optional[float]]:
        for host, port in (("1.1.1.1", 53), ("8.8.8.8", 53)):
            ok, ms = self.tcp_probe(host, port, timeout=2.0)
            if ok:
                self.wan_online = True
                self.wan_latency_ms = ms
                self.last_wan_check = self.db.now_str()
                return True, ms
        self.wan_online = False
        self.wan_latency_ms = None
        self.last_wan_check = self.db.now_str()
        return False, None

    def run_checks(self, conn) -> List[Dict[str, Any]]:
        """Ejecuta chequeos sobre todos los activos con monitorear_uptime=1 y WAN."""
        ahora = self.db.now_str()
        transitions: List[Dict[str, Any]] = []

        prev_wan = self.wan_online
        wan_ok, wan_ms = self.check_wan()
        conn.execute(
            """INSERT INTO uptime_log (fecha, activo_id, ip, nombre, online, latencia_ms)
               VALUES (?, NULL, 'WAN', 'Conexión a Internet (WAN)', ?, ?)""",
            (ahora, 1 if wan_ok else 0, wan_ms),
        )
        if prev_wan and not wan_ok:
            transitions.append(
                {
                    "event": "DOWN",
                    "ip": "WAN",
                    "nombre": "Conexión a Internet (WAN)",
                    "categoria": "RED_INFRA",
                    "criticidad": "CRITICO",
                }
            )
        elif not prev_wan and wan_ok:
            transitions.append(
                {
                    "event": "UP",
                    "ip": "WAN",
                    "nombre": "Conexión a Internet (WAN)",
                    "categoria": "RED_INFRA",
                    "criticidad": "CRITICO",
                }
            )

        rows = conn.execute(
            "SELECT * FROM activos WHERE monitorear_uptime = 1 AND puerto_check > 0"
        ).fetchall()
        for asset in rows:
            ok, ms = self.tcp_probe(asset["ip"], int(asset["puerto_check"]), timeout=1.5)
            new_state = "ONLINE" if ok else "OFFLINE"
            old_state = asset["estado_uptime"]

            conn.execute(
                """UPDATE activos
                   SET estado_uptime = ?, latencia_ms = ?, ultimo_check = ?
                   WHERE id = ?""",
                (new_state, ms, ahora, asset["id"]),
            )
            conn.execute(
                """INSERT INTO uptime_log (fecha, activo_id, ip, nombre, online, latencia_ms)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (ahora, asset["id"], asset["ip"], asset["nombre"], 1 if ok else 0, ms),
            )

            if old_state != "OFFLINE" and new_state == "OFFLINE":
                transitions.append(
                    {
                        "event": "DOWN",
                        "ip": asset["ip"],
                        "nombre": asset["nombre"],
                        "categoria": asset["categoria"],
                        "criticidad": asset["criticidad"],
                        "puerto": asset["puerto_check"],
                    }
                )
            elif old_state == "OFFLINE" and new_state == "ONLINE":
                transitions.append(
                    {
                        "event": "UP",
                        "ip": asset["ip"],
                        "nombre": asset["nombre"],
                        "categoria": asset["categoria"],
                        "criticidad": asset["criticidad"],
                        "puerto": asset["puerto_check"],
                    }
                )

        return transitions


class NodeExporterCollector:
    """Parsea métricas Prometheus de node-exporter en una sola pasada."""

    _SIMPLE_RE = re.compile(
        r"^(node_load1|node_load5|node_memory_MemTotal_bytes|node_memory_MemAvailable_bytes|node_thermal_zone_temp)(?:\{[^}]*\})?\s+([\d.eE+-]+)"
    )
    _FS_RE = re.compile(
        r'^(node_filesystem_avail_bytes|node_filesystem_size_bytes)\{[^}]*mountpoint="([^"]+)"[^}]*\}\s+([\d.eE+-]+)'
    )
    _NET_RE = re.compile(
        r'^node_network_(receive|transmit)_bytes_total\{device="([^"]+)"\}\s+([\d.eE+-]+)'
    )
    _CPU_RE = re.compile(r'^node_cpu_seconds_total\{cpu="(\d+)"')

    def __init__(self, config: SiemConfig):
        self.config = config

    def fetch(self) -> Dict[str, Any]:
        resp = requests.get(self.config.node_exporter_url, timeout=3)
        resp.raise_for_status()
        return self.parse_metrics(resp.text, self.config.net_interface)

    @classmethod
    def parse_metrics(cls, text: str, preferred_iface: str = "eth0") -> Dict[str, Any]:
        metrics: Dict[str, float] = {}
        ifaces: Dict[str, Dict[str, float]] = {}
        fs_candidates: Dict[str, Dict[str, float]] = {}
        cpus = set()

        for line in text.splitlines():
            if not line or line.startswith("#"):
                continue

            m_cpu = cls._CPU_RE.match(line)
            if m_cpu:
                cpus.add(m_cpu.group(1))
                continue

            m = cls._SIMPLE_RE.match(line)
            if m:
                key, val = m.group(1), float(m.group(2))
                if key not in metrics:
                    metrics[key] = val
                continue

            m_fs = cls._FS_RE.match(line)
            if m_fs:
                metric_name, mount, val = m_fs.group(1), m_fs.group(2), float(m_fs.group(3))
                if mount in ("/", "/etc/hostname", "/rootfs"):
                    fs_candidates.setdefault(mount, {})[metric_name] = val
                continue

            m_net = cls._NET_RE.match(line)
            if m_net:
                direction = "rx" if m_net.group(1) == "receive" else "tx"
                ifaces.setdefault(m_net.group(2), {})[direction] = float(m_net.group(3))

        # Elegir mejor punto de montaje de disco disponible
        disk_avail = None
        disk_size = None
        for mp in ("/", "/rootfs", "/etc/hostname"):
            if mp in fs_candidates and "node_filesystem_size_bytes" in fs_candidates[mp]:
                disk_avail = fs_candidates[mp].get("node_filesystem_avail_bytes")
                disk_size = fs_candidates[mp].get("node_filesystem_size_bytes")
                break

        # Elegir interfaz preferida o la más activa no-loopback
        active_iface = preferred_iface
        if active_iface not in ifaces:
            non_lo = [k for k in ifaces if k != "lo" and not k.startswith(("veth", "br-", "docker"))]
            if non_lo:
                active_iface = max(non_lo, key=lambda k: ifaces[k].get("rx", 0))

        interfaces = [
            {"name": k, "rx": v.get("rx", 0.0), "tx": v.get("tx", 0.0)}
            for k, v in sorted(ifaces.items())
        ]
        cpu_cores = max(len(cpus), 1)
        load1 = metrics.get("node_load1", 0.0)

        return {
            "ok": True,
            "load1": load1,
            "load5": metrics.get("node_load5", 0.0),
            "cpu_cores": cpu_cores,
            "cpu_pct": round(min((load1 / cpu_cores) * 100.0, 100.0), 1),
            "mem_total": metrics.get("node_memory_MemTotal_bytes", 0.0),
            "mem_avail": metrics.get("node_memory_MemAvailable_bytes", 0.0),
            "disk_avail": disk_avail,
            "disk_size": disk_size,
            "temp": metrics.get("node_thermal_zone_temp"),
            "active_interface": active_iface,
            "net_rx": ifaces.get(active_iface, {}).get("rx"),
            "net_tx": ifaces.get(active_iface, {}).get("tx"),
            "interfaces": interfaces,
        }


class DockerManager:
    """Envoltorio seguro para Docker API (restringida a 127.0.0.1:2375) y Fail2ban."""

    def __init__(self, config: SiemConfig):
        self.config = config

    def _api_base(self) -> str:
        return self.config.docker_host.replace("tcp://", "http://")

    def _client(self):
        import docker as docker_sdk

        return docker_sdk.DockerClient(base_url=self.config.docker_host, timeout=5)

    def list_containers(self) -> List[Dict[str, Any]]:
        from datetime import datetime, timezone

        client = self._client()
        containers = client.containers.list(all=True)
        resultado = []
        for c in containers:
            uptime = "—"
            if c.status == "running":
                started = c.attrs.get("State", {}).get("StartedAt", "")
                if started:
                    try:
                        dt = datetime.fromisoformat(started[:19]).replace(
                            tzinfo=timezone.utc
                        )
                        diff = datetime.now(timezone.utc) - dt
                        h, rem = divmod(max(0, int(diff.total_seconds())), 3600)
                        m = rem // 60
                        uptime = f"{h}h {m}m" if h > 0 else f"{m}m"
                    except Exception:
                        uptime = "—"
            resultado.append(
                {
                    "id": c.short_id,
                    "nombre": c.name,
                    "imagen": c.image.tags[0] if c.image.tags else c.image.short_id,
                    "estado": c.status,
                    "uptime": uptime,
                }
            )
        resultado.sort(key=lambda x: (0 if x["estado"] == "running" else 1, x["nombre"]))
        return resultado

    def action(self, name: str, op: str) -> str:
        if not validate_container_name(name):
            raise ValueError("Nombre de contenedor inválido")
        if op not in {"start", "stop", "restart"}:
            raise ValueError("Acción no permitida")
        client = self._client()
        c = client.containers.get(name)
        if op == "start":
            c.start()
            return "started"
        if op == "stop":
            c.stop(timeout=10)
            return "stopped"
        c.restart(timeout=10)
        return "restarted"

    def logs(self, name: str, tail: int = 80) -> str:
        if not validate_container_name(name):
            raise ValueError("Nombre de contenedor inválido")
        client = self._client()
        c = client.containers.get(name)
        return c.logs(tail=tail, timestamps=False).decode("utf-8", errors="replace")

    def fail2ban_status(self) -> Dict[str, Any]:
        api = self._api_base()
        r = requests.post(
            f"{api}/containers/fail2ban/exec",
            json={
                "AttachStdout": True,
                "AttachStderr": True,
                "Cmd": ["fail2ban-client", "status"],
            },
            timeout=5,
        )
        if r.status_code != 201:
            return {
                "ok": False,
                "error": f"Docker proxy devolvió HTTP {r.status_code} (verifica EXEC=1)",
                "ips": [],
                "jails": [],
                "total_ips": 0,
            }
        exec_id = r.json().get("Id")
        if not exec_id:
            return {"ok": False, "error": "No se pudo crear exec", "ips": [], "jails": [], "total_ips": 0}

        r2 = requests.post(
            f"{api}/exec/{exec_id}/start",
            json={"Detach": False, "Tty": False},
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        output = r2.content.decode("utf-8", errors="replace")

        jails: List[str] = []
        for line in output.splitlines():
            if "Jail list:" in line:
                jails = [j.strip() for j in line.split(":", 1)[1].split(",") if j.strip()]

        ips: List[str] = []
        for jail in jails:
            r3 = requests.post(
                f"{api}/containers/fail2ban/exec",
                json={
                    "AttachStdout": True,
                    "AttachStderr": True,
                    "Cmd": ["fail2ban-client", "status", jail],
                },
                timeout=5,
            )
            eid = r3.json().get("Id") if r3.status_code == 201 else None
            if eid:
                r4 = requests.post(
                    f"{api}/exec/{eid}/start",
                    json={"Detach": False, "Tty": False},
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                )
                for line in r4.content.decode("utf-8", errors="replace").splitlines():
                    if "Banned IP list:" in line:
                        banned = line.split(":", 1)[1].strip()
                        if banned:
                            ips.extend(banned.split())

        return {"ok": True, "ips": ips, "jails": jails, "total_ips": len(ips)}
