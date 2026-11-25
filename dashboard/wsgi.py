# -*- coding: utf-8 -*-
"""Punto de entrada WSGI de producción (Gunicorn)."""

from siem import create_app

application = create_app(start_background=True)
