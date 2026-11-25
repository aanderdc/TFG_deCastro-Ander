# -*- coding: utf-8 -*-
"""Capa de persistencia SQLite (WAL) con migraciones seguras y consistencia horaria."""

import os
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from siem.config import ASSET_CATEGORIES, SiemConfig


class Database:
    """Gestor SQLite thread-safe con una conexión por hilo y modo WAL."""

    def __init__(self, config: SiemConfig):
        self.config = config
        self.db_path = config.db_path
        self._local = threading.local()

    def now_str(self) -> str:
        return datetime.now(self.config.tz).strftime("%Y-%m-%d %H:%M:%S")

    def cutoff_str(self, *, minutes: int = 0, hours: int = 0, days: int = 0) -> str:
        dt = datetime.now(self.config.tz) - timedelta(
            minutes=minutes, hours=hours, days=days
        )
        return dt.strftime("%Y-%m-%d %H:%M:%S")

    def connect_new(self) -> sqlite3.Connection:
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self.connect_new()
            self._local.conn = conn
        return conn

    def close_thread_conn(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def _ensure_column(
        self, cursor: sqlite3.Cursor, table: str, column: str, col_def: str
    ) -> None:
        cols = {
            row[1] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in cols:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")

    def init_schema(self) -> None:
        conn = self.connect_new()
        try:
            cur = conn.cursor()

            cur.execute(
                """CREATE TABLE IF NOT EXISTS estadisticas_dns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha TEXT NOT NULL,
                    total_queries INTEGER NOT NULL DEFAULT 0,
                    ads_blocked INTEGER NOT NULL DEFAULT 0
                )"""
            )

            cur.execute(
                """CREATE TABLE IF NOT EXISTS trafico_dispositivos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha_hora TEXT NOT NULL,
                    dispositivo TEXT,
                    ip TEXT NOT NULL,
                    bytes_bajada REAL NOT NULL DEFAULT 0,
                    bytes_subida REAL NOT NULL DEFAULT 0,
                    bajada_acumulada REAL NOT NULL DEFAULT 0,
                    subida_acumulada REAL NOT NULL DEFAULT 0,
                    protocolo_l7 TEXT
                )"""
            )

            cur.execute(
                """CREATE TABLE IF NOT EXISTS alertas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha TEXT NOT NULL,
                    tipo TEXT NOT NULL,
                    ip TEXT,
                    descripcion TEXT NOT NULL,
                    severidad TEXT NOT NULL DEFAULT 'MEDIA',
                    estado TEXT NOT NULL DEFAULT 'ABIERTA',
                    recomendacion TEXT DEFAULT '',
                    categoria TEXT DEFAULT 'SEGURIDAD'
                )"""
            )

            cur.execute(
                """CREATE TABLE IF NOT EXISTS mac_vendors (
                    mac TEXT PRIMARY KEY,
                    fabricante TEXT NOT NULL,
                    fecha TEXT NOT NULL
                )"""
            )

            cur.execute(
                """CREATE TABLE IF NOT EXISTS lateral_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    protocolo TEXT,
                    puerto_dst TEXT,
                    info TEXT
                )"""
            )

            # Inventario de activos orientado a librerías e imprentas
            cur.execute(
                """CREATE TABLE IF NOT EXISTS activos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL UNIQUE,
                    mac TEXT DEFAULT '',
                    nombre TEXT NOT NULL,
                    categoria TEXT NOT NULL DEFAULT 'OTRO',
                    criticidad TEXT NOT NULL DEFAULT 'NORMAL',
                    autorizado INTEGER NOT NULL DEFAULT 1,
                    monitorear_uptime INTEGER NOT NULL DEFAULT 0,
                    puerto_check INTEGER NOT NULL DEFAULT 0,
                    estado_uptime TEXT NOT NULL DEFAULT 'DESCONOCIDO',
                    latencia_ms REAL,
                    ultimo_check TEXT,
                    notas TEXT DEFAULT '',
                    creado_en TEXT NOT NULL
                )"""
            )

            # Histórico de disponibilidad de equipos críticos y WAN
            cur.execute(
                """CREATE TABLE IF NOT EXISTS uptime_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha TEXT NOT NULL,
                    activo_id INTEGER,
                    ip TEXT NOT NULL,
                    nombre TEXT NOT NULL,
                    online INTEGER NOT NULL,
                    latencia_ms REAL
                )"""
            )

            # Configuración persistente del negocio (editable desde la web)
            cur.execute(
                """CREATE TABLE IF NOT EXISTS configuracion_negocio (
                    clave TEXT PRIMARY KEY,
                    valor TEXT NOT NULL
                )"""
            )

            # Migraciones suaves para bases de datos anteriores del TFG
            self._ensure_column(
                cur, "trafico_dispositivos", "bajada_acumulada", "REAL NOT NULL DEFAULT 0"
            )
            self._ensure_column(
                cur, "trafico_dispositivos", "subida_acumulada", "REAL NOT NULL DEFAULT 0"
            )
            self._ensure_column(
                cur, "alertas", "estado", "TEXT NOT NULL DEFAULT 'ABIERTA'"
            )
            self._ensure_column(cur, "alertas", "recomendacion", "TEXT DEFAULT ''")
            self._ensure_column(
                cur, "alertas", "categoria", "TEXT DEFAULT 'SEGURIDAD'"
            )

            # Índices
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_trafico_ip_fecha ON trafico_dispositivos(ip, fecha_hora)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_trafico_fecha ON trafico_dispositivos(fecha_hora)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_dns_fecha ON estadisticas_dns(fecha)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_lateral_src_fecha ON lateral_connections(src_ip, fecha)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_lateral_dst_fecha ON lateral_connections(dst_ip, fecha)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_lateral_fecha ON lateral_connections(fecha)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_alertas_fecha ON alertas(fecha)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_alertas_estado ON alertas(estado, severidad)"
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_uptime_fecha ON uptime_log(fecha, ip)"
            )

            # Sembrar configuración inicial del negocio desde .env si no existe
            defaults = {
                "negocio_nombre": self.config.negocio_nombre,
                "negocio_tipo": self.config.negocio_tipo,
                "horario_apertura": self.config.horario_apertura,
                "horario_cierre": self.config.horario_cierre,
                "dias_apertura": self.config.dias_apertura,
                "alerta_fuera_horario": "true"
                if self.config.alerta_fuera_horario
                else "false",
            }
            for k, v in defaults.items():
                cur.execute(
                    "INSERT OR IGNORE INTO configuracion_negocio (clave, valor) VALUES (?, ?)",
                    (k, str(v)),
                )

            conn.commit()
        finally:
            conn.close()

    def get_business_config(self, conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
        c = conn or self.get_conn()
        rows = c.execute("SELECT clave, valor FROM configuracion_negocio").fetchall()
        cfg = {r["clave"]: r["valor"] for r in rows}
        return {
            "negocio_nombre": cfg.get("negocio_nombre", self.config.negocio_nombre),
            "negocio_tipo": cfg.get("negocio_tipo", self.config.negocio_tipo),
            "horario_apertura": cfg.get("horario_apertura", self.config.horario_apertura),
            "horario_cierre": cfg.get("horario_cierre", self.config.horario_cierre),
            "dias_apertura": cfg.get("dias_apertura", self.config.dias_apertura),
            "alerta_fuera_horario": cfg.get("alerta_fuera_horario", "true").lower()
            == "true",
        }

    def save_business_config(
        self, updates: Dict[str, Any], conn: Optional[sqlite3.Connection] = None
    ) -> Dict[str, Any]:
        c = conn or self.get_conn()
        allowed = {
            "negocio_nombre",
            "negocio_tipo",
            "horario_apertura",
            "horario_cierre",
            "dias_apertura",
            "alerta_fuera_horario",
        }
        for k, v in updates.items():
            if k in allowed:
                val = (
                    ("true" if v else "false")
                    if isinstance(v, bool)
                    else str(v).strip()
                )
                c.execute(
                    "INSERT OR REPLACE INTO configuracion_negocio (clave, valor) VALUES (?, ?)",
                    (k, val),
                )
        c.commit()
        return self.get_business_config(c)

    def get_assets_map(
        self, conn: Optional[sqlite3.Connection] = None
    ) -> Dict[str, Dict[str, Any]]:
        """Devuelve diccionario IP -> datos del activo registrado."""
        c = conn or self.get_conn()
        rows = c.execute("SELECT * FROM activos ORDER BY criticidad, nombre").fetchall()
        return {r["ip"]: dict(r) for r in rows}

    def list_assets_with_uptime(
        self, conn: Optional[sqlite3.Connection] = None, hours: int = 24
    ) -> List[Dict[str, Any]]:
        c = conn or self.get_conn()
        cutoff = self.cutoff_str(hours=hours)
        rows = c.execute(
            """SELECT a.*,
                      (SELECT ROUND(100.0 * AVG(u.online), 1)
                       FROM uptime_log u
                       WHERE u.ip = a.ip AND u.fecha >= ?) AS uptime_pct
               FROM activos a
               ORDER BY
                 CASE a.criticidad WHEN 'CRITICO' THEN 0 WHEN 'NORMAL' THEN 1 ELSE 2 END,
                 a.nombre ASC""",
            (cutoff,),
        ).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            meta = ASSET_CATEGORIES.get(item["categoria"], ASSET_CATEGORIES["OTRO"])
            item["categoria_label"] = meta["label"]
            item["categoria_icon"] = meta["icon"]
            out.append(item)
        return out

    def cleanup_old_records(self, conn: sqlite3.Connection) -> None:
        cutoff_30 = self.cutoff_str(days=30)
        cutoff_90 = self.cutoff_str(days=90)
        conn.execute(
            "DELETE FROM trafico_dispositivos WHERE fecha_hora < ?", (cutoff_30,)
        )
        conn.execute("DELETE FROM estadisticas_dns WHERE fecha < ?", (cutoff_30,))
        conn.execute("DELETE FROM lateral_connections WHERE fecha < ?", (cutoff_30,))
        conn.execute("DELETE FROM uptime_log WHERE fecha < ?", (cutoff_30,))
        conn.execute("DELETE FROM alertas WHERE fecha < ?", (cutoff_90,))
        conn.commit()
