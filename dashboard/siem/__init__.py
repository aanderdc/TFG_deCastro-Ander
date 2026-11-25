# -*- coding: utf-8 -*-
"""Fábrica de aplicación Flask para el SIEM PYME."""

import logging
import os
from datetime import timedelta

from flask import Flask, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from siem.collectors import (
    AssetWatchdog,
    DockerManager,
    IncrementalFileReader,
    JA3Database,
    MacVendorLookup,
    NodeExporterCollector,
    NtopngCollector,
    PiholeClient,
)
from siem.config import SiemConfig
from siem.database import Database
from siem.detector import AlertEngine
from siem.routes import bp
from siem.security import ensure_csrf_token
from siem.worker import BackgroundMonitor


def create_app(
    config_override: dict | None = None, start_background: bool = False
) -> Flask:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    cfg = SiemConfig.from_env(config_override)
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(
        __name__,
        template_folder=os.path.join(root_dir, "templates"),
        static_folder=os.path.join(root_dir, "static"),
    )

    # Respetar X-Forwarded-For / X-Forwarded-Proto detrás de Nginx (clave para rate-limit real)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    app.secret_key = cfg.flask_secret_key
    app.config["TESTING"] = cfg.testing
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=24)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = cfg.session_cookie_secure

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=[],
        enabled=not cfg.testing,
    )

    db = Database(cfg)
    db.init_schema()

    mac_lookup = MacVendorLookup(db)
    ntopng = NtopngCollector(cfg, mac_lookup)
    pihole = PiholeClient(cfg)
    watchdog = AssetWatchdog(db)
    ja3_db = JA3Database()
    tshark_reader = IncrementalFileReader(cfg.tshark_log_path)
    ja3_reader = IncrementalFileReader(cfg.ja3_log_path)
    suricata_reader = IncrementalFileReader(cfg.suricata_eve_path)
    engine = AlertEngine(
        cfg, db, ja3_db, tshark_reader, ja3_reader, suricata_reader
    )
    node_exporter = NodeExporterCollector(cfg)
    docker_mgr = DockerManager(cfg)
    monitor = BackgroundMonitor(cfg, db, ntopng, pihole, watchdog, engine)

    app.extensions["siem_services"] = {
        "config": cfg,
        "db": db,
        "mac_lookup": mac_lookup,
        "ntopng": ntopng,
        "pihole": pihole,
        "watchdog": watchdog,
        "ja3_db": ja3_db,
        "tshark_reader": tshark_reader,
        "ja3_reader": ja3_reader,
        "suricata_reader": suricata_reader,
        "engine": engine,
        "node_exporter": node_exporter,
        "docker": docker_mgr,
        "monitor": monitor,
    }

    app.register_blueprint(bp)
    # Aplicar rate limiting específicamente a /login
    limiter.limit("10 per minute")(app.view_functions["siem.login"])

    @app.context_processor
    def inject_globals():
        csrf = session.get("csrf_token") or (ensure_csrf_token() if session.get("logged_in") else "")
        return {
            "csrf_token": csrf,
            "app_negocio_nombre": cfg.negocio_nombre,
        }

    @app.teardown_appcontext
    def teardown_db(_exc):
        db.close_thread_conn()

    if start_background:
        monitor.start()

    return app
