# -*- coding: utf-8 -*-
"""Hilo recolector en segundo plano con aislamiento de fallos por módulo."""

import logging
import threading
import time

from siem.collectors import AssetWatchdog, NtopngCollector, PiholeClient
from siem.config import SiemConfig
from siem.database import Database
from siem.detector import AlertEngine

logger = logging.getLogger("siem.worker")


class BackgroundMonitor:
    """Ejecuta periódicamente los recolectores, watchdog y reglas de detección."""

    def __init__(
        self,
        config: SiemConfig,
        db: Database,
        ntopng: NtopngCollector,
        pihole: PiholeClient,
        watchdog: AssetWatchdog,
        engine: AlertEngine,
    ):
        self.config = config
        self.db = db
        self.ntopng = ntopng
        self.pihole = pihole
        self.watchdog = watchdog
        self.engine = engine
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._cycles = 0

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, name="siem-background-monitor", daemon=True
        )
        self._thread.start()
        logger.info("Hilo monitor SIEM iniciado (intervalo %ss)", self.config.logger_interval_seconds)

    def stop(self) -> None:
        self._stop_event.set()

    def run_once(self) -> None:
        """Ejecuta un ciclo completo aislando errores de cada recolector."""
        self._cycles += 1
        ahora = self.db.now_str()
        conn = self.db.connect_new()
        try:
            cur = conn.cursor()

            # 1. Recolección Pi-hole DNS (antes de detectar pico DNS)
            try:
                summary = self.pihole.get_summary(max_age=0)
                if summary:
                    q = summary.get("queries", {})
                    cur.execute(
                        "INSERT INTO estadisticas_dns (fecha, total_queries, ads_blocked) VALUES (?, ?, ?)",
                        (ahora, int(q.get("total", 0) or 0), int(q.get("blocked", 0) or 0)),
                    )
                    conn.commit()
            except Exception as e:
                logger.debug("[worker] Error Pi-hole: %s", e)

            # 2. Recolección ntopng con cálculo DELTA real + detección por host
            try:
                hosts = self.ntopng.get_active_hosts(update_deltas=True)
                if hosts:
                    for h in hosts:
                        cur.execute(
                            """INSERT INTO trafico_dispositivos
                               (fecha_hora, dispositivo, ip, bytes_bajada, bytes_subida,
                                bajada_acumulada, subida_acumulada, protocolo_l7)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                            (
                                ahora,
                                h["name"],
                                h["ip"],
                                h["delta_rcvd_mb"],
                                h["delta_sent_mb"],
                                h["rcvd_mb"],
                                h["sent_mb"],
                                f"flows:{h['flows']} score:{h['score']}",
                            ),
                        )
                    conn.commit()
                    self.engine.detectar_alertas_hosts(cur, hosts)
                    conn.commit()
            except Exception as e:
                logger.warning("[worker] Error ntopng/alertas host: %s", e)

            # 3. Análisis incremental de tráfico lateral, beaconing, DoH, JA3 y Suricata
            for name, fn in (
                ("lateral", self.engine.analizar_trafico_lateral),
                ("beaconing", self.engine.detectar_beaconing),
                ("doh", self.engine.detectar_doh),
                ("ja3", self.engine.detectar_ja3),
                ("suricata", self.engine.detectar_suricata),
            ):
                try:
                    fn(cur)
                except Exception as e:
                    logger.warning("[worker] Error detector %s: %s", name, e)
            conn.commit()

            # 4. Watchdog de equipos críticos (Impresoras, Plotters, TPV, NAS y WAN) cada 2 ciclos (~60s)
            if self._cycles == 1 or self._cycles % 2 == 0:
                try:
                    transitions = self.watchdog.run_checks(conn)
                    if transitions:
                        self.engine.procesar_transiciones_watchdog(cur, transitions)
                    conn.commit()
                except Exception as e:
                    logger.warning("[worker] Error watchdog activos: %s", e)

            # 5. Limpieza horaria de retención y caché de deduplicación
            if self._cycles % 120 == 0:
                try:
                    self.db.cleanup_old_records(conn)
                    self.engine.purge_dedup_cache()
                    logger.info("[%s] Limpieza de retención ejecutada", ahora)
                except Exception as e:
                    logger.warning("[worker] Error limpieza retención: %s", e)
        finally:
            conn.close()

    def _loop(self) -> None:
        self.ntopng.login()
        self.engine.ja3_db.refresh_if_stale()
        while not self._stop_event.is_set():
            try:
                self.run_once()
            except Exception as e:
                logger.exception("Error inesperado en ciclo monitor: %s", e)
            self._stop_event.wait(self.config.logger_interval_seconds)
