# 🛡️ Sistema de Monitorización y Gestión de Red de Bajo Coste para PYME

**TFG — Grado en Ingeniería en Tecnología de Telecomunicación**  
**Autor:** Ander de Castro  
**Estado:** ✅ Completado y Documentado  
**Stack Principal:** Python 95.3% | HTML 4% | Otros 0.7%

---

## 📋 Inicio Rápido

### Requisitos Mínimos
- Raspberry Pi 4 (4 GB RAM recomendados) — ~60-70 €
- Tarjeta microSD 16+ GB
- Cable Ethernet + ordenador para configuración inicial
- Docker & Docker Compose preinstalados

### En 5 pasos (si tienes experiencia técnica)

```bash
# 1. Clonar y configurar
git clone https://github.com/aanderdc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander/pihole
cp .env.example .env && nano .env

# 2. Desplegar
docker compose up -d

# 3. Verificar
docker ps  # Deberías ver 12 contenedores activos

# 4. Configurar DNS en router
# Cambia DNS primario a IP_RASPBERRY

# 5. Acceder
# https://IP_RASPBERRY
```

---

## 📚 Tabla de Contenidos Completa

1. [Descripción del Proyecto](#-descripción-del-proyecto)
2. [Arquitectura del Sistema](#-arquitectura)
3. [Stack Tecnológico](#️-stack-tecnológico)
4. [Instalación Rápida](#-instalación-rápida)
5. [Guía de Usuario (sin experiencia)](#-guía-de-usuario)
6. [Matriz de Acceso](#-matriz-de-acceso-al-sistema)
7. [Funcionalidades](#-funcionalidades-del-dashboard)
8. [Notificaciones Telegram](#-configuración-de-notificaciones-telegram)
9. [Políticas de Seguridad](#-políticas-de-seguridad-dns-blocklists)
10. [Solución de Problemas](#-solución-de-problemas-frecuentes)
11. [Visibilidad de Red](#-visibilidad-de-red-limitaciones-y-soluciones)
12. [Acceso Externo (DuckDNS + Let's Encrypt)](#-acceso-externo-duckdns--lets-encrypt)
13. [Auditoría de Seguridad](#-auditoría-de-seguridad-y-hardening)
14. [Estructura del Repositorio](#-estructura-del-repositorio)
15. [Eficiencia Energética](#-eficiencia-energética)
16. [Buenas Prácticas](#-buenas-prácticas-aplicadas)

---

## 🎯 Descripción del Proyecto

Sistema de **monitorización y gestión de red** basado en **Raspberry Pi 4** y herramientas de código abierto, orientado a PYMES con presupuesto limitado.

### Funciones principales:
- ✅ Filtrado DNS preventivo de **dominios maliciosos**
- ✅ Análisis de flujos TCP/UDP en tiempo real
- ✅ Motor de alertas inteligente (6 reglas heurísticas)
- ✅ Dashboard unificado con gráficas históricas
- ✅ Detección de escaneos internos y movimiento lateral
- ✅ Panel de control de contenedores Docker
- ✅ Notificaciones automáticas por Telegram
- ✅ Acceso remoto seguro via VPN (WireGuard)
- ✅ Certificados TLS con Let's Encrypt

### Alineado con:
- 🎓 ODS 4 (Educación de Calidad)
- 🏭 ODS 9 (Industria, Innovación e Infraestructura)

---

## 🏗️ Arquitectura

```
INTERNET
│
▼
┌─────────────────────────┐
│      ROUTER PYME        │
│     192.168.1.1         │
└────────┬────────────────┘
         │
    ┌────┴─────────┐
    │              │
  LAN          WiFi
    │              │
    └────┬─────────┘
         ▼
┌──────────────────────────────┐
│    RASPBERRY PI 4 (Central)  │
│  - Pi-hole (DNS Filtering)   │
│  - ntopng (Análisis flujos)  │
│  - Tshark (Captura paquetes) │
│  - Dashboard Flask (SIEM)    │
│  - Grafana (Históricas)      │
│  - Prometheus (Métricas)     │
│  - WireGuard (VPN remota)    │
│  - Nginx (Proxy + TLS)       │
└──────────────────────────────┘
         │
    ┌────┴──────────────────┐
    ▼                       ▼
 Clientes              Acceso
  locales             externo
   (DNS)            (DuckDNS +
                    Let's Encrypt)
```

---

## 🛠️ Stack Tecnológico

| Servicio | Función | Puertos | Autenticación |
|----------|---------|---------|---------------|
| **Pi-hole** | Filtrado DNS preventivo | 53/UDP, 80/TCP | Contraseña |
| **ntopng** | Análisis flujos TCP/UDP en tiempo real | 3001/TCP | ✅ Login requerido |
| **Tshark** | Captura de paquetes | Interno | — |
| **Flask (Dashboard)** | Dashboard web + motor de alertas | 5000 (interno) | ✅ Autenticación |
| **Grafana** | Visualización históricas | 3000/TCP | ✅ Login requerido |
| **Prometheus** | Métricas de hardware (series temporales) | 9090 (localhost) | 🔒 Localhost only |
| **Node Exporter** | Telemetría SO (CPU, RAM, temp) | 9100 (localhost) | 🔒 Localhost only |
| **Redis** | Caché de flujos (autenticado) | 6379 (interno) | ✅ Contraseña |
| **Nginx** | Proxy inverso + TLS | 443/TCP, 80/TCP | ✅ TLS obligatorio |
| **WireGuard** | VPN remota | 51820/UDP | ✅ Criptografía ECC |
| **Docker Socket Proxy** | Acceso seguro a Docker API | 2375 (interno) | 🔒 Restringido |
| **SQLite** | Persistencia de alertas | Interno | 🔒 Archivo |

---

## ⚡ Instalación Rápida

### Requisitos Previos

Si ya tienes Docker instalado, salta este paso.

```bash
# Instalar Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Desconecta y vuelve a conectar SSH para aplicar cambios
```

### Despliegue Completo

```bash
# 1. Clonar repositorio
git clone https://github.com/aanderdc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander

# 2. Configurar credenciales
cp pihole/.env.example pihole/.env
nano pihole/.env
# 👉 Edita todos los valores marcados (contraseñas, IPs, etc.)

# 3. Iniciar servicios
cd pihole
docker compose up -d

# 4. Verificar que los 12 contenedores están UP
docker ps
# Esperado: dashboard, pi-hole, ntopng, grafana, prometheus, redis, nginx, wireguard, tshark, etc.

# 5. Acceder al dashboard
# Abre navegador: https://IP_DE_TU_RASPBERRY
# Usuario: El definido en DASHBOARD_USER
# Contraseña: El definido en DASHBOARD_PASSWORD
```

---

## 👥 Matriz de Acceso al Sistema

| Servicio | URL | Credenciales | Acceso | Encriptación |
|----------|-----|--------------|--------|--------------|
| **Dashboard (SIEM)** | `https://IP` | `DASHBOARD_USER` / `DASHBOARD_PASSWORD` | Red local + VPN | ✅ TLS |
| **Pi-hole** | `http://IP:80` | `PIHOLE_PASSWORD` | Red local | ❌ HTTP |
| **Grafana** | `http://IP:3000` | `admin` / `GRAFANA_PASSWORD` | Red local | ❌ HTTP |
| **ntopng** | `http://IP:3001` | `admin` / `NTOPNG_PASSWORD` | Red local | ❌ HTTP |
| **WireGuard** | IP pública:51820/UDP | Certificados | Acceso remoto | ✅ ECC |

> 🔒 **Prometheus, Node Exporter y pihole-exporter** están restringidos a `localhost` (inaccesibles desde la red local).

---

## 📲 Configuración de Notificaciones Telegram

El sistema envía alertas automáticas por Telegram para eventos de severidad **CRÍTICA** y **ALTA**.

### Paso 1: Crear el bot con BotFather

1. Abre Telegram y busca **@BotFather**
2. Envía `/newbot`
3. Elige un nombre y un username (ej: `TFG_Ander_bot`)
4. BotFather te dará un **token**. Ejemplo: `8990953884:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`
5. Guárdalo, lo necesitarás en el Paso 3

### Paso 2: Obtener tu Chat ID

1. Busca tu bot en Telegram y envíale cualquier mensaje
2. Ejecuta en la Raspberry:
```bash
curl "https://api.telegram.org/botTU_TOKEN/getUpdates"
```
3. En el resultado busca el campo `"id"` dentro de `"chat"`. Ese es tu **chat_id**.

### Paso 3: Configurar el .env

```bash
nano ~/TFG_deCastro-Ander/pihole/.env
```

Añade o edita estas dos líneas:
```env
TELEGRAM_TOKEN=tu_token_aqui
TELEGRAM_CHAT_ID=tu_chat_id_aqui
```

### Paso 4: Reiniciar el dashboard

```bash
cd ~/TFG_deCastro-Ander/pihole
docker compose restart dashboard
```

### Paso 5: Verificar

```bash
# Comprueba que las variables están cargadas
docker exec mi_dashboard env | grep TELEGRAM

# Test manual
curl -X POST "https://api.telegram.org/botTU_TOKEN/sendMessage" \
  -d chat_id=TU_CHAT_ID \
  -d text="✅ SIEM — Bot configurado correctamente"
```

### Alertas que generan notificación

| Regla | Severidad | Notifica |
|-------|-----------|----------|
| Threat Score > 500 | 🔴 CRÍTICA | ✅ |
| LATERAL_PORT (RDP/SMB/SSH) | 🔴 CRÍTICA | ✅ |
| Nueva IP detectada | 🟠 ALTA | ✅ |
| Pico de tráfico 5x | 🟠 ALTA | ✅ |
| LATERAL_SCAN ≥ 15 IPs | 🔴 CRÍTICA | ✅ |
| Bloqueos DNS > 50 en 30s | 🟡 MEDIA | ❌ |

> Las alertas de severidad MEDIA y BAJA solo se registran en el dashboard, no generan notificación Telegram.

---

## 👥 Guía de Usuario (Sin Experiencia Técnica)

### Paso 1: Flashear el Sistema Operativo

1. Descarga **[Raspberry Pi Imager](https://www.raspberrypi.com/software/)**
2. Inserta la microSD en tu ordenador
3. Selecciona:
   - Dispositivo: **Raspberry Pi 4**
   - SO: **Raspberry Pi OS (64-bit)**
   - Almacenamiento: **tu microSD**
4. Clic en **Escribir** y espera a que termine
5. Inserta la microSD en Raspberry Pi + cable Ethernet + enchufa

### Paso 2: Conexión Remota (SSH)

**Windows:** Abre PowerShell  
**Mac/Linux:** Abre Terminal

```bash
ssh pi@raspberrypi.local
# Contraseña: raspberry (cámbiala después)
```

> Si no funciona `raspberrypi.local`, usa la IP visible en tu router: `ssh pi@192.168.1.X`

### Paso 3: Instalar Docker

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

Desconecta y vuelve a conectar SSH.

### Paso 4: Clonar y Configurar

```bash
git clone https://github.com/aanderdc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander/pihole
cp .env.example .env
nano .env
# 👉 Edita los campos (contraseñas, IPs, etc.)
# Guardar: Ctrl+O → Enter → Ctrl+X
```

### Paso 5: Lanzar Servicios

```bash
docker compose up -d
docker ps  # Verifica que hay 12 contenedores UP
```

### Paso 6: Configurar DNS en el Router

1. Abre navegador → `192.168.1.1` (o dirección de tu router)
2. Inicia sesión
3. Busca **DHCP** o **DNS**
4. Cambia **DNS primario** a la IP de tu Raspberry (ej: `192.168.1.100`)
5. Guarda y reinicia router

### Paso 7: Accede al Dashboard

Abre: `https://IP_DE_TU_RASPBERRY`

Acepta el aviso de certificado y ¡listo!

---

## 🎨 Funcionalidades del Dashboard

### Vistas Principales

#### 1. 📊 Dashboard Principal (`index.html`)
- Métricas DNS en tiempo real
- Dispositivos activos en la red
- Consumo de ancho de banda por dispositivo
- Alertas recientes con severidad
- Estado de servicios críticos
- **Gráficas interactivas** con Chart.js
- **Diseño responsive** para móvil y escritorio

#### 2. 📡 Sniffer (`sniffer.html`) - Captura en vivo
- Análisis de paquetes HTTP/DNS en tiempo real
- Filtrado por texto (dominio, IP, puerto)
- Detalles de cada transacción (headers, payload)
- Exportación de capturas

#### 3. 📊 Estadísticas Avanzadas (`estadisticas.html`)
- Gráficas históricas de tráfico (6h, 24h, 48h, 7 días)
- Consultas DNS bloqueadas
- Tráfico por dispositivo
- Selectores de rango temporal
- Tendencias y picos de uso
- **Filtrado avanzado** por severidad y tipo

#### 4. 📈 Gráficas Históricas (`graficas.html`)
- Embedidas de Grafana
- Visualización de series temporales
- Dashboards personalizables

#### 5. ⚠️ Centro de Alertas (`alertas.html`)
- 6 reglas de detección automática
- Clasificación por severidad (Crítica, Alta, Media, Baja)
- Filtrado por tipo de alerta
- Exportación a CSV
- Notificaciones Telegram (CRÍTICA y ALTA)
- **CSRF protection** en formularios

#### 6. 🗺️ Red Interna (`lateral.html` + `red.html`)
- **lateral.html**: Mapa visual de conexiones entre dispositivos
- **red.html**: Vista de red mejorada con topología visual
- Detección de escaneos internos
- Identificación de puertos críticos
- Análisis de movimiento lateral
- **Análisis de tráfico por dispositivo**

#### 7. 🐳 Panel Docker (`contenedores.html`)
- Estado de los 12 contenedores (UP/DOWN)
- Logs en tiempo real de cada servicio
- Botones: Iniciar/Parar/Reiniciar
- Uptime y consumo de recursos (CPU, RAM)

#### 8. 🔐 Página de Login (`login.html`)
- Formulario seguro de autenticación
- **CSRF protection** integrada
- Sesiones cifradas

### 6 Reglas del Motor de Alertas

| Regla | Condición | Severidad |
|-------|-----------|-----------|
| **Threat Score** | ntopng > 100 (crítico > 500) | CRÍTICA |
| **Nueva IP** | Dispositivo no visto anteriormente | ALTA |
| **Pico de tráfico** | 5x la media 24h | ALTA |
| **Bloqueos DNS** | >50 dominios en 30s | MEDIA |
| **LATERAL_SCAN** | >5 IPs internas en 30s | ALTA / CRÍTICA |
| **LATERAL_PORT** | Conexión a RDP/SMB/SSH/Telnet/VNC | CRÍTICA |

---

## 🔐 Políticas de Seguridad (DNS Blocklists)

**Dos listas de bloqueo combinadas:**
- **Hagezi Multi Pro** — Telemetría, rastreadores, malware, Command & Control (C2)
- **StevenBlack/hosts** — Publicidad masiva y trackers

**Base activa:** 250,000+ dominios bloqueados

---

## ❌ Solución de Problemas Frecuentes

### Contenedor aparece "Exited"
```bash
docker logs nombre_contenedor
docker compose restart nombre_contenedor
```

### No puedo acceder al dashboard
- ¿Estás en la misma red que la Raspberry?
- ¿El navegador te muestra advertencia de certificado? (es normal, acepta)
- Verifica la IP: `docker inspect nombre_contenedor | grep IPAddress`

### Pi-hole no bloquea nada
Verifica que el DNS del router apunta a la IP correcta de la Raspberry.
```bash
nslookup google.com 192.168.1.X  # Reemplaza X con la IP de tu Raspberry
```

### Olvidé la contraseña del dashboard
```bash
nano .env  # Edita DASHBOARD_PASSWORD
docker compose restart dashboard
```

### "Credenciales incorrectas" aunque todo está bien
```bash
docker compose down
docker compose up -d --force-recreate
docker exec dashboard env | grep DASHBOARD
```

### Grafana no arranca — "permission denied"
```bash
sudo chown -R 472:472 ~/TFG_deCastro-Ander/pihole/grafana_data
docker compose restart grafana
```

### SSH no resuelve `raspberrypi.local`
Usa directamente la IP del router: `ssh pi@192.168.1.X`

### ntopng no conecta con Redis
La sintaxis debe ser: `127.0.0.1:6379:${REDIS_PASSWORD}@0`

### Docker Socket Proxy — error 403
Añade `IMAGES=1` a las variables de entorno del servicio `docker-proxy`.

### Contraseña Redis con caracteres especiales
⚠️ **Usa solo alfanuméricos.** Caracteres como `!` `@` `#` se interpretan mal. Ejemplo:
```env
REDIS_PASSWORD=MiContraseñaLargaSinSimbolos2024
```

### El dashboard envía alertas duplicadas
Borra el archivo de alertas y reinicia:
```bash
docker exec dashboard rm /app/alerts.db
docker compose restart dashboard
```

---

## 🌐 Visibilidad de Red: Limitaciones y Soluciones

### El Problema

ntopng y tshark capturan tráfico que **pasa por la Raspberry**. El tráfico lateral (PC ↔ Servidor interno) **no se ve**.

### Lo que SÍ detectamos
- ✅ Entradas maliciosas (bloqueadas por Pi-hole)
- ✅ Contacto con C2 (puntuación ntopng)
- ✅ Escaneos internos (regla `LATERAL_SCAN`)
- ✅ Conexiones a puertos críticos (regla `LATERAL_PORT`)

### Lo que NO vemos
- ❌ Movimiento lateral completo entre dispositivos internos

### Soluciones disponibles

| Opción | Coste | Dificultad | Visibilidad | Afecta red |
|--------|-------|-----------|-------------|-----------|
| **Port Mirroring (SPAN) en router** | 0 € | Baja | Total | No |
| **Raspberry como gateway** | ~25 € | Media | Total | Sí |
| **Switch gestionable (SPAN)** | ~30 € | Baja | Total | No |
| **Arquitectura actual** | 0 € | — | Parcial + detección | No |

### Switch recomendado (SPAN a bajo coste)
- TP-Link TL-SG105E (~25 €)
- Netgear GS305E (~30 €)
- TP-Link TL-SG108E (~35 €)

---

## 🌍 Acceso Externo: DuckDNS + Let's Encrypt

### 1. Crear dominio DuckDNS

```bash
# Ve a https://www.duckdns.org
# - Inicia sesión (con cuenta de GitHub/Google/Twitter)
# - Crea un subdominio (ej: misistema)
# - Nota el TOKEN
```

### 2. Script de actualización DNS

```bash
mkdir -p ~/duckdns
cat > ~/duckdns/duck.sh << 'EOF'
echo url="https://www.duckdns.org/update?domains=TU_DOMINIO&token=TU_TOKEN&ip=" | \
  curl -k -o ~/duckdns/duck.log -K -
EOF
chmod +x ~/duckdns/duck.sh

# Automatizar cada 5 minutos
crontab -e
# Añade: */5 * * * * ~/duckdns/duck.sh >/dev/null 2>&1
```

### 3. Obtener certificado Let's Encrypt

```bash
sudo apt update && sudo apt install certbot -y
cd ~/TFG_deCastro-Ander/pihole
docker compose stop nginx

sudo certbot certonly --standalone --preferred-challenges http \
  -d tunombre.duckdns.org --email tu@email.com --agree-tos --non-interactive
```

### 4. Configurar Nginx

```bash
sudo cp /etc/letsencrypt/live/tunombre.duckdns.org/fullchain.pem \
  ~/TFG_deCastro-Ander/pihole/nginx/certs/fullchain.pem
sudo cp /etc/letsencrypt/live/tunombre.duckdns.org/privkey.pem \
  ~/TFG_deCastro-Ander/pihole/nginx/certs/privkey.pem
sudo chmod 644 ~/TFG_deCastro-Ander/pihole/nginx/certs/*.pem
docker compose start nginx
```

### 5. Renovación automática

```bash
# Cron: Cada lunes a las 3:00
0 3 * * 1 sudo certbot renew --quiet && \
  sudo cp /etc/letsencrypt/live/tunombre.duckdns.org/fullchain.pem \
  ~/TFG_deCastro-Ander/pihole/nginx/certs/fullchain.pem && \
  docker restart nginx-siem
```

---

## 🔒 Auditoría de Seguridad y Hardening

### Vulnerabilidades Identificadas (Pre-hardening)

| ID | Componente | Severidad | Estado |
|----|-----------|-----------|--------|
| V1 | Prometheus expuesto en red sin auth | 🔴 Crítica | ✅ Corregida |
| V2 | Node Exporter expuesto | 🔴 Crítica | ✅ Corregida |
| V3 | pihole-exporter expuesto | 🔴 Crítica | ✅ Corregida |
| V4 | Redis sin contraseña | 🔴 Crítica | ✅ Corregida |
| V5 | ntopng con `--disable-login=1` | 🔴 Crítica | ✅ Corregida |
| V6 | Contraseña ntopng por defecto | 🔴 Crítica | ✅ Corregida |
| V7 | Docker socket sin proxy | 🟠 Alta | ✅ Corregida |
| V8 | Grafana con env_file innecesario | 🟡 Media | ✅ Corregida |

### Correcciones Aplicadas

- 🔒 **Prometheus, Node Exporter, pihole-exporter** restringidos a `localhost`
- 🔒 **Redis** con autenticación obligatoria y contraseña fuerte
  - Comando: `redis-server --requirepass ${REDIS_PASSWORD}`
  - Persistencia deshabilitada: `--save "" --appendonly no`
- 🔒 **ntopng** con login requerido (sintaxis Redis: `127.0.0.1:6379:${REDIS_PASSWORD}@0`)
- 🔒 **Docker Socket Proxy** implementado con restricciones (CONTAINERS, LOGS, INFO, POST, IMAGES)
- 🔒 **Dashboard** con carga de credenciales via `env_file` centralizado
- 🔒 **Tshark** con capabilities mejoradas (`NET_ADMIN`, `NET_RAW`)
- 🔒 **WireGuard** con 3 peers preconfigurados
- 🔒 **Sincronización de credenciales** pre-startup
- 🔒 **TLS obligatorio** en Nginx (HTTPS)
- 🔒 **CORS restringido** a orígenes locales

### Superficie de Ataque Residual (Post-hardening)

| Puerto | Servicio | Protección | Notas |
|--------|---------|-----------|-------|
| 443 | Dashboard Flask | Autenticación + TLS | Recomendado |
| 80 | Pi-hole admin | Autenticación + HTTP | Considerar HTTPS |
| 3000 | Grafana | Autenticación + HTTP | Local only |
| 3001 | ntopng | Autenticación + HTTP | Local only |
| 51820/UDP | WireGuard | Criptografía ECC | Muy seguro |

---

## 📁 Estructura del Repositorio

```
TFG_deCastro-Ander/
├── pihole/
│   ├── docker-compose.yml          # Orquestación 12 microservicios
│   │   ├── pihole                  # DNS filtering + admin panel
│   │   ├── redis                   # Cache autenticado (contraseña requerida)
│   │   ├── ntopng                  # Análisis flujos con login obligatorio
│   │   ├── tshark-sflow            # Captura paquetes (NET_ADMIN/NET_RAW)
│   │   ├── nginx                   # Proxy inverso + TLS
│   │   ├── docker-proxy            # Socket proxy con permisos específicos
│   │   ├── dashboard               # Flask + env_file centralizado
│   │   ├── wireguard               # VPN remota (3 peers preconfigurados)
│   │   ├── node-exporter           # Telemetría localhost (9100)
│   │   ├── prometheus              # Métricas localhost (9090)
│   │   ├── pihole-exporter         # Exportador localhost (9167)
│   │   ├── grafana                 # Visualización históricas
│   │   └── mitmproxy               # Servicio opcional (profiles)
│   ├── .env.example                # Plantilla credenciales
│   ├── prometheus.yml              # Scraping de métricas
│   ├── nginx/
│   │   ├── siem.conf              # Proxy inverso config
│   │   └── certs/                 # Certificados TLS (auto-generados)
│   └── grafana_data/              # Persistencia Grafana (volumen)
├── dashboard/
│   ├── app.py                      # Backend Flask (API + alertas)
│   ├── alerter.py                  # Motor de alertas (6 reglas)
│   ├── templates/
│   │   ├── index.html             # Dashboard principal (gráficas interactivas)
│   │   ├── sniffer.html           # Captura en vivo (filtrado avanzado)
│   │   ├── estadisticas.html      # Análisis avanzado con gráficas históricas
│   │   ├── graficas.html          # Embedidas de Grafana
│   │   ├── alertas.html           # Centro de alertas (6 reglas, exportación CSV)
│   │   ├── lateral.html           # Mapa red interna
│   │   ├── red.html               # Vista red mejorada (topología visual)
│   │   ├── contenedores.html      # Panel Docker (logs en vivo)
│   │   └── login.html             # Autenticación (CSRF protection)
│   ├── static/                     # CSS, JS, assets
│   │   ├── style.css              # Diseño responsive (móvil/escritorio)
│   │   ├── chart.js               # Gráficas interactivas
│   │   └── d3.js                  # Visualización avanzada
│   └── requirements.txt            # Dependencias Python
└── wireguard_config/               # Config WireGuard (excluida en .gitignore)
```

### Mejoras en Docker Compose (v1.0)

| Servicio | Actualización | Detalles |
|----------|--------------|---------|
| **redis** | ✅ Autenticación | Contraseña requerida + sin persistencia |
| **ntopng** | ✅ Login requerido | Sintaxis Redis con contraseña |
| **dashboard** | ✅ env_file | Carga centralizada de variables |
| **docker-proxy** | ✅ Permisos | IMAGES=1 agregado para compatibilidad |
| **exportadores** | ✅ Localhost | node-exporter (9100), prometheus (9090), pihole-exporter (9167) |
| **tshark** | ✅ Capabilities | NET_ADMIN y NET_RAW para captura |
| **wireguard** | ✅ Configuración | 3 peers preconfigurados |
| **mitmproxy** | ✅ Opcional | Disponible con profiles: ["opcional"] |

### Características del Dashboard (v1.0)

| Feature | Descripción | Archivos |
|---------|-------------|---------|
| 📊 **Gráficas Interactivas** | Chart.js + D3.js | index.html, estadisticas.html |
| 🔐 **CSRF Protection** | Seguridad en formularios | login.html, alertas.html |
| 📱 **Responsive Design** | Móvil y escritorio | static/style.css |
| 🌙 **Modo Oscuro** | Tema alternativo | static/style.css |
| 📥 **Exportación** | CSV, JSON | alertas.html |
| 🔔 **Notificaciones RT** | WebSocket | app.py |
| 🎯 **Filtrado Avanzado** | Por severidad/tipo | alertas.html, estadisticas.html |

---

## ⚡ Eficiencia Energética

| Condición | Consumo | Notas |
|-----------|---------|-------|
| Baja carga | ~3-5 W | Inactivo, pocos flujos |
| Carga sostenida | ~7-8 W | Dashboard + ntopng activos |
| **Coste anual (24/7)** | **< 20 €** | ~30 kWh/año (0.07€/kWh) |

**Estimado para PYME típica:**
- Equipos: 15-50 dispositivos
- Consumo diario: ~150-200 kWh
- Ahorros de red: 300-500 € vs soluciones comerciales

---

## 🛡️ Buenas Prácticas Aplicadas

- ✅ **Credenciales en `.env`** (nunca en repositorio)
- ✅ **Variables de entorno centralizadas** (fácil mantenimiento)
- ✅ **TLS obligatorio** (Nginx con certificados auto-generados)
- ✅ **Acceso remoto por VPN** (WireGuard, sin exponer puertos)
- ✅ **Historial Git limpio** (BFG Repo Cleaner, sin secretos)
- ✅ **Servicios internos en localhost** (Prometheus, Node Exporter, Redis)
- ✅ **Docker Socket Proxy** (acceso restrictivo a Docker API)
- ✅ **Autenticación en ntopng** (login requerido, no --disable-login)
- ✅ **Notificaciones opcionales** (Telegram, sin API keys en el repositorio)
- ✅ **Documentación completa** (español, paso a paso)
- ✅ **Servicios opcionales** (Grafana, Prometheus, Mitmproxy con profiles)
- ✅ **Persistencia securizada** (Redis sin datos, SQLite encriptado)

---

## 📄 Licencia

Proyecto académico — Trabajo de Fin de Grado.  
Libre para uso educativo y modificación.

---

## 🤝 Contacto y Soporte

Para preguntas o problemas:
1. Revisa la sección de [Solución de Problemas](#-solución-de-problemas-frecuentes)
2. Abre una **Issue** en GitHub con detalles del error y logs

**Última actualización:** 29 de Mayo de 2026  
**Versión:** 1.0 (Completado)
