# 🛡️ SIEM PYME — Monitorización y Ciberseguridad para Librerías e Imprentas

**Grado en Ingeniería en Tecnología de Telecomunicación — TFG**  
**Autor:** Ander de Castro · Despliegue sobre Raspberry Pi 4 (Docker) · Código abierto

---

## 🎯 ¿Qué problema resuelve?

Una librería, papelería o imprenta depende diariamente de **TPVs / cajas registradoras**, **impresoras industriales / plotters / servidores RIP**, **NAS con diseños de clientes** y conexión a Internet, a menudo conviviendo con **Wi-Fi para clientes o PCs de autoservicio** y sin departamento IT propio.

Este sistema convierte una **Raspberry Pi 4 (~100 €)** en un **SIEM + centro de control operativo** comprensible para el dueño del negocio y potente para soporte técnico:

### Funciones clave para Librerías e Imprentas
- **Índice de Salud del Negocio (0–100):** semáforo instantáneo del estado de TPVs, impresoras, Internet y alertas abiertas.
- **Inventario y Watchdog de Equipos Críticos (`/negocio`):** clasifica TPVs, Impresoras/Plotters (`:9100`, `:631`, `:515`), NAS de diseños (`:445`) y Wi-Fi clientes; comprueba disponibilidad/latencia cada minuto y avisa por Telegram si cae una impresora, el TPV o Internet (y cuando se recupera).
- **Reglas de Ciberseguridad Adaptadas al Negocio:**
  - `ACCESO_ACTIVO_CRITICO`: alerta crítica si un dispositivo no autorizado o de Wi-Fi clientes contacta con un TPV, plotter o NAS.
  - `IMPRESION_NO_AUTORIZADA`: detecta envíos a puertos de impresión (`9100/515/631`) desde equipos desconocidos (evita gasto de tinta/papel).
  - `RANSOMWARE_SOSPECHOSO`: alerta temprana ante propagación lateral SMB (`:445`) hacia múltiples equipos internos.
  - `ACTIVIDAD_FUERA_HORARIO`: detecta tráfico elevado, nuevos dispositivos o uso de impresoras/TPVs cuando la tienda está cerrada.
  - Reglas SIEM clásicas: Suricata IDS, huellas TLS `JA3_C2`, `BEACONING`, `DNS_OVER_HTTPS`, `LATERAL_SCAN`, `LATERAL_PORT`, `DNS_BLOQUEADAS`, `FLOOD_DETECTADO`, `RATIO_ANOMALO`.
- **Alertas Accionables en Lenguaje Claro:** cada alerta incluye *"¿Qué hacer?"*, gestión de estado (`ABIERTA` / `RESUELTA` / `FALSO_POSITIVO`), filtros y exportación **CSV UTF-8 (Excel)**.
- **Bloqueo Rápido de Dominios (Pi-hole):** bloquea o desbloquea sitios en toda la red en 1 clic desde el panel.
- **Informe Ejecutivo PDF (`/reporte`):** resumen imprimible/PDF de 7/30/90 días con SLA de equipos críticos, incidentes y checklist de seguridad PYME/RGPD.

---

## 🚀 Despliegue rápido (1 comando)

### Requisitos
- Raspberry Pi 4 (4 GB RAM recomendados) conectada **por cable Ethernet (`eth0`)** al router/switch
- MicroSD 32 GB+ y Docker (`curl -fsSL https://get.docker.com | sudo sh`)

```bash
git clone https://github.com/aanderdc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander
chmod +x scripts/setup.sh
./scripts/setup.sh
cd pihole
docker compose up -d --build
```

> El instalador detecta automáticamente tu interfaz (`eth0`/`wlan0`) e IP, genera contraseñas criptográficamente aleatorias, crea el certificado TLS con SAN y configura el horario de tu negocio.

### Acceso a servicios
| Servicio | URL | Notas |
|----------|-----|-------|
| **Dashboard SIEM** | `https://IP_RASPBERRY` | Redirección automática HTTP→HTTPS, TLS 1.2/1.3 |
| **Pi-hole Admin** | `http://IP_RASPBERRY:8080/admin` | Configura `IP_RASPBERRY` como DNS primario en el router |
| **ntopng** | `http://IP_RASPBERRY:3001` | Flujos L7 en tiempo real |
| **Grafana** *(opcional)* | `http://IP_RASPBERRY:3000` | Activar con `docker compose --profile opcional up -d` |
| **WireGuard VPN** *(opcional)* | `IP:51820/UDP` | Activar con `docker compose --profile vpn up -d` |

---

## 🏗️ Arquitectura modular

```text
TFG_deCastro-Ander/
├── scripts/setup.sh              # Instalador automático con generación de secretos y TLS
├── pihole/
│   ├── docker-compose.yml        # Orquestación endurecida con límites RAM y rotación de logs
│   ├── .env.example              # Plantilla de configuración de red y negocio
│   ├── nginx/siem.conf           # Proxy HTTPS TLS 1.2/1.3 + cabeceras de seguridad
│   ├── suricata/suricata.yaml    # IDS ajustado a memoria de Raspberry Pi 4
│   ├── tshark/                   # Imagen precompilada con rotación automática de capturas
│   └── prometheus.yml            # Scraping de métricas hardware y Pi-hole
└── dashboard/
    ├── Dockerfile                # Python 3.12-slim + Gunicorn + usuario no-root + HEALTHCHECK
    ├── requirements.txt          # Dependencias fijadas
    ├── wsgi.py / app.py          # Puntos de entrada producción / desarrollo
    ├── siem/
    │   ├── config.py             # Configuración validada (multi-subred RFC1918, interfaz dinámica)
    │   ├── database.py           # SQLite WAL, migraciones y timestamps consistentes
    │   ├── security.py           # Auth fail-closed constant-time, CSRF universal, validadores
    │   ├── collectors.py         # ntopng (cálculo delta real), tshark/Suricata/JA3 incrementales, Watchdog, Pi-hole
    │   ├── detector.py           # Motor de alertas SIEM + reglas librerías/imprentas + Telegram
    │   ├── reports.py            # Índice de salud, CSV RFC-4180 e informe ejecutivo
    │   ├── worker.py             # Hilo recolector con aislamiento de fallos por módulo
    │   └── routes.py             # Vistas HTML y API REST
    ├── templates/                # Plantillas Jinja2 con base común y protección anti-XSS
    └── tests/test_siem.py        # Suite automatizada pytest
```

---

## 🔒 Seguridad aplicada

| Capa | Medida |
|------|--------|
| **Autenticación** | Fail-closed si falta `DASHBOARD_PASSWORD`, comparación `hmac.compare_digest` (soporta hashes Werkzeug), rate-limiting con `ProxyFix` real |
| **Sesiones y CSRF** | Cookies `HttpOnly` + `SameSite=Lax`, CSRF obligatorio en login y en todos los endpoints `POST`/`DELETE` |
| **Prevención XSS** | Escape estricto (`esc()`) de todos los datos de red antes de renderizar en el DOM + cabecera CSP en Nginx |
| **Infraestructura Docker** | `docker-proxy` y `redis` restringidos a `127.0.0.1` (nunca expuestos en la LAN), contenedor dashboard sin `root`, límites RAM y rotación de logs |
| **Protección microSD** | Rotación automática de `tshark_capture.txt` y `tshark_ja3.csv` + retención SQLite (30/90 días) |

---

## 🧪 Ejecutar tests automatizados

```bash
cd dashboard
pip install -r requirements.txt
pytest -v
```
