# -*- coding: utf-8 -*-
"""Utilidades de seguridad: autenticación constant-time, CSRF y validación de entradas."""

import hmac
import ipaddress
import re
import secrets
from functools import wraps

from flask import jsonify, redirect, request, session, url_for
from werkzeug.security import check_password_hash

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_CONTAINER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+$"
)
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def verify_credentials(
    username: str, password: str, expected_user: str, expected_pass: str
) -> bool:
    """
    Valida credenciales en tiempo constante (fail-closed si expected_pass está vacío).
    Soporta contraseñas hasheadas con Werkzeug (scrypt:/pbkdf2:) o texto plano del .env.
    """
    if not expected_user or not expected_pass:
        return False
    if not username or not password:
        return False

    user_ok = hmac.compare_digest(username.encode("utf-8"), expected_user.encode("utf-8"))
    if expected_pass.startswith(("scrypt:", "pbkdf2:")):
        pass_ok = check_password_hash(expected_pass, password)
    else:
        pass_ok = hmac.compare_digest(
            password.encode("utf-8"), expected_pass.encode("utf-8")
        )
    return bool(user_ok and pass_ok)


def ensure_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(24)
        session["csrf_token"] = token
    return token


def csrf_protect():
    """Verifica el token CSRF en cabecera X-CSRF-Token o formulario."""
    expected = session.get("csrf_token")
    provided = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    if (
        not expected
        or not provided
        or not hmac.compare_digest(str(provided), str(expected))
    ):
        return jsonify({"ok": False, "error": "CSRF token inválido o ausente"}), 403
    return None


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Sesión no iniciada"}), 401
            return redirect(url_for("siem.login"))
        return f(*args, **kwargs)

    return decorated


def csrf_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        err = csrf_protect()
        if err is not None:
            return err
        return f(*args, **kwargs)

    return decorated


def validate_ip(value: str) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def validate_mac(value: str) -> str:
    if not value:
        return ""
    cleaned = value.strip().upper().replace("-", ":")
    return cleaned if _MAC_RE.match(cleaned) else ""


def validate_container_name(name: str) -> bool:
    return bool(name and _CONTAINER_RE.match(name))


def validate_domain(domain: str) -> str | None:
    if not domain:
        return None
    d = domain.strip().lower()
    if d.startswith(("http://", "https://")):
        d = d.split("://", 1)[1].split("/", 1)[0]
    return d if _DOMAIN_RE.match(d) else None


def validate_hhmm(value: str) -> bool:
    return bool(value and _TIME_RE.match(value.strip()))


def clamp_int(raw, default: int, min_val: int, max_val: int) -> int:
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return default
    return max(min_val, min(max_val, val))
