# -*- coding: utf-8 -*-
"""Punto de entrada de desarrollo para el dashboard SIEM PYME."""

import os
from siem import create_app

app = create_app(start_background=True)

if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
