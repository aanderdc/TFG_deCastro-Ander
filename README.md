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

### En 5 pasos

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

## 📚 Tabla de Contenidos

1. [Descripción del Proyecto](#-descripción-del-proyecto)
2. [Arquitectura](#-arquitectura)
3. [Stack Tecnológico](#️-stack-tecnológico)
4. [Instalación Rápida](#-instalación-rápida)
5. [Guía de Usuario](#-guía-de-usuario)
6. [Funcionalidades](#-funcionalidades-del-dashboard)
7. [Notificaciones Telegram](#-configuración-de-notificaciones-telegram)
8. [Solución de Problemas](#-solución-de-problemas-frecuentes)
9. [Acceso Externo](#-acceso-externo-duckdns--lets-encrypt)
10. [Auditoría de Seguridad](#-auditoría-de-seguridad-y-hardening)
11. [Estructura](#-estructura-del-repositorio)

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
| **ntopng** | Análisis flujos TCP/UDP | 3001/TCP | ✅ Login requerido |
| **Flask** | Dashboard web + alertas | 5000 (interno) | ✅ Autenticación |
| **Grafana** | Visualización históricas | 3000/TCP | ✅ Login requerido |
| **Prometheus** | Métricas hardware | 9090 (localhost) | 🔒 Localhost only |
| **Redis** | Caché de flujos | 6379 (interno) | ✅ Contraseña |
| **Nginx** | Proxy inverso + TLS | 443/TCP, 80/TCP | ✅ TLS obligatorio |
| **WireGuard** | VPN remota | 51820/UDP | ✅ Criptografía ECC |
| **Docker Proxy** | Acceso seguro Docker API | 2375 (interno) | 🔒 Restringido |

---

## ⚡ Instalación Rápida

### Requisitos Previos

```bash
# Instalar Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Desconecta y vuelve a conectar SSH
```

### Despliegue

```bash
# 1. Clonar repositorio
git clone https://github.com/aanderdc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander

# 2. Configurar credenciales
cp pihole/.env.example pihole/.env
nano pihole/.env
# 👉 Edita todos los valores marcados

# 3. Iniciar servicios
cd pihole
docker compose up -d

# 4. Verificar
docker ps

# 5. Acceder
# https://IP_DE_TU_RASPBERRY
```

---

## 👥 Matriz de Acceso

| Servicio | URL | Credenciales | Acceso | Encriptación |
|----------|-----|--------------|--------|--------------|
| **Dashboard** | `https://IP` | `DASHBOARD_USER` / `DASHBOARD_PASSWORD` | Red local + VPN | ✅ TLS |
| **Pi-hole** | `http://IP:80` | `PIHOLE_PASSWORD` | Red local | ❌ HTTP |
| **Grafana** | `http://IP:3000` | `admin` / `GRAFANA_PASSWORD` | Red local | ❌ HTTP |
| **ntopng** | `http://IP:3001` | `admin` / `NTOPNG_PASSWORD` | Red local | ❌ HTTP |
| **WireGuard** | IP pública:51820/UDP | Certificados | Acceso remoto | ✅ ECC |

---

## 📲 Configuración de Notificaciones Telegram

### Paso 1: Crear el bot

1. Abre Telegram y busca **@BotFather**
2. Envía `/newbot`
3. Elige un nombre y username
4. Guarda el **token** que te proporciona

### Paso 2: Obtener Chat ID

```bash
curl "https://api.telegram.org/botTU_TOKEN/getUpdates"
```

Busca el campo `"id"` dentro de `"chat"`.

### Paso 3: Configurar .env

```env
TELEGRAM_TOKEN=tu_token_aqui
TELEGRAM_CHAT_ID=tu_chat_id_aqui
```

### Paso 4: Reiniciar

```bash
cd ~/TFG_deCastro-Ander/pihole
docker compose restart dashboard
```

### Alertas que generan notificación

| Regla | Severidad | Notifica |
|-------|-----------|----------|
| Threat Score > 500 | 🔴 CRÍTICA | ✅ |
| LATERAL_PORT (RDP/SMB/SSH) | 🔴 CRÍTICA | ✅ |
| Nueva IP detectada | 🟠 ALTA | ✅ |
| Pico de tráfico 5x | 🟠 ALTA | ✅ |
| LATERAL_SCAN ≥ 15 IPs | 🔴 CRÍTICA | ✅ |

---

## 👥 Guía de Usuario

### Paso 1: Flashear SO

1. Descarga **[Raspberry Pi Imager](https://www.raspberrypi.com/software/)**
2. Inserta la microSD
3. Selecciona: **Raspberry Pi 4** + **Raspberry Pi OS (64-bit)**
4. Clic en **Escribir** y espera

### Paso 2: SSH

```bash
ssh pi@raspberrypi.local
# Contraseña: raspberry
```

### Paso 3: Docker

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
# Reconectar SSH
```

### Paso 4: Clonar y Configurar

```bash
git clone https://github.com/aanderdc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander/pihole
cp .env.example .env
nano .env
# Editar campos (Ctrl+O → Enter → Ctrl+X)
```

### Paso 5: Lanzar

```bash
docker compose up -d
docker ps  # Verificar 12 contenedores
```

### Paso 6: DNS en Router

1. Abre `192.168.1.1` en navegador
2. Inicia sesión
3. Busca **DHCP** o **DNS**
4. Cambia **DNS primario** a la IP de tu Raspberry
5. Guarda y reinicia

### Paso 7: Dashboard

Abre `https://IP_DE_TU_RASPBERRY` - Acepta el certificado

---

## 🎨 Funcionalidades del Dashboard

### Vistas Principales

#### 1. 📊 Dashboard Principal (`index.html`)
- Métricas DNS en tiempo real
- Dispositivos activos en la red
- Consumo de ancho de banda
- Alertas recientes con severidad
- Estado de servicios críticos

#### 2. 📡 Sniffer (`sniffer.html`)
- Análisis de paquetes HTTP/DNS en tiempo real
- Filtrado por dominio, IP, puerto
- Detalles de transacciones

#### 3. 📊 Estadísticas (`estadisticas.html`)
- Gráficas históricas (6h, 24h, 48h, 7 días)
- Consultas DNS bloqueadas
- Tráfico por dispositivo

#### 4. 📈 Gráficas (`graficas.html`)
- Embedidas de Grafana
- Series temporales

#### 5. ⚠️ Alertas (`alertas.html`)
- 6 reglas de detección automática
- Severidad: Crítica, Alta, Media, Baja
- Exportación a CSV

#### 6. 🗺️ Red (`lateral.html` + `red.html`)
- Mapa visual de conexiones
- Detección de escaneos internos
- Análisis de movimiento lateral

#### 7. 🐳 Docker (`contenedores.html`)
- Estado de los 12 contenedores
- Logs en tiempo real
- Botones: Iniciar/Parar/Reiniciar

### 6 Reglas del Motor de Alertas

| Regla | Condición | Severidad |
|-------|-----------|-----------|
| **Threat Score** | ntopng > 100 (crítico > 500) | CRÍTICA |
| **Nueva IP** | Dispositivo no visto | ALTA |
| **Pico tráfico** | 5x la media 24h | ALTA |
| **Bloqueos DNS** | >50 dominios en 30s | MEDIA |
| **LATERAL_SCAN** | >5 IPs internas en 30s | ALTA |
| **LATERAL_PORT** | Conexión RDP/SMB/SSH/Telnet/VNC | CRÍTICA |

---

## 🔐 Políticas de Seguridad

**DNS Blocklists:**
- **Hagezi Multi Pro** — Telemetría, rastreadores, malware, C2
- **StevenBlack/hosts** — Publicidad y trackers

**Base activa:** 250,000+ dominios bloqueados

---

## ❌ Solución de Problemas

### Contenedor aparece "Exited"
```bash
docker logs nombre_contenedor
docker compose restart nombre_contenedor
```

### No puedo acceder al dashboard
- ¿Estás en la misma red que la Raspberry?
- ¿El navegador muestra advertencia de certificado? (normal, acepta)

### Pi-hole no bloquea nada
```bash
nslookup google.com 192.168.1.X
```

### ntopng no conecta con Redis
La sintaxis debe ser: `127.0.0.1:6379:${REDIS_PASSWORD}@0`

### Docker Socket Proxy — error 403
Añade `IMAGES=1` a las variables de entorno del servicio `docker-proxy`.

### Contraseña Redis con caracteres especiales
⚠️ **Usa solo alfanuméricos.** Caracteres como `!` `@` `#` causan problemas.

---

## 🌐 Visibilidad de Red

### El Problema

ntopng y tshark capturan tráfico que **pasa por la Raspberry**. El tráfico lateral (PC ↔ Servidor) **no se ve**.

### Lo que SÍ detectamos
- ✅ Entradas maliciosas (bloqueadas por Pi-hole)
- ✅ Contacto con C2 (puntuación ntopng)
- ✅ Escaneos internos (LATERAL_SCAN)
- ✅ Conexiones a puertos críticos (LATERAL_PORT)

### Soluciones

| Opción | Coste | Dificultad | Visibilidad |
|--------|-------|-----------|-------------|
| **Port Mirroring (SPAN)** | 0 € | Baja | Total |
| **Raspberry como gateway** | ~25 € | Media | Total |
| **Switch gestionable** | ~30 € | Baja | Total |
| **Arquitectura actual** | 0 € | — | Parcial |

### Switches recomendados (SPAN)
- TP-Link TL-SG105E (~25 €)
- Netgear GS305E (~30 €)
- TP-Link TL-SG108E (~35 €)

---

## 🌍 Acceso Externo: DuckDNS + Let's Encrypt

### 1. Crear dominio DuckDNS

Ve a https://www.duckdns.org - Inicia sesión - Crea subdominio - Guarda TOKEN

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
# */5 * * * * ~/duckdns/duck.sh >/dev/null 2>&1
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
0 3 * * 1 sudo certbot renew --quiet && \
  sudo cp /etc/letsencrypt/live/tunombre.duckdns.org/fullchain.pem \
  ~/TFG_deCastro-Ander/pihole/nginx/certs/fullchain.pem && \
  docker restart nginx-siem
```

---

## 🔒 Auditoría de Seguridad y Hardening

### Vulnerabilidades Corregidas

| ID | Componente | Severidad | Estado |
|----|-----------|-----------|--------|
| V1 | Prometheus expuesto | 🔴 Crítica | ✅ Corregida |
| V2 | Node Exporter expuesto | 🔴 Crítica | ✅ Corregida |
| V3 | pihole-exporter expuesto | 🔴 Crítica | ✅ Corregida |
| V4 | Redis sin contraseña | 🔴 Crítica | ✅ Corregida |
| V5 | ntopng sin login | 🔴 Crítica | ✅ Corregida |
| V6 | Docker socket sin proxy | 🟠 Alta | ✅ Corregida |

### Correcciones Aplicadas

- 🔒 **Redis** - Autenticación obligatoria + sin persistencia
- 🔒 **ntopng** - Login requerido con sintaxis: `127.0.0.1:6379:${REDIS_PASSWORD}@0`
- 🔒 **Exportadores** - Restringidos a localhost (Prometheus 9090, Node Exporter 9100, pihole-exporter 9167)
- 🔒 **Docker Proxy** - Permisos específicos (CONTAINERS, LOGS, INFO, POST, IMAGES)
- 🔒 **Dashboard** - env_file centralizado
- 🔒 **Tshark** - Capabilities (NET_ADMIN, NET_RAW)
- 🔒 **WireGuard** - 3 peers preconfigurados
- 🔒 **Nginx** - TLS obligatorio

### Superficie de Ataque (Post-hardening)

| Puerto | Servicio | Protección |
|--------|---------|-----------|
| 443 | Dashboard | Autenticación + TLS |
| 80 | Pi-hole | Autenticación |
| 3000 | Grafana | Autenticación |
| 3001 | ntopng | Autenticación |
| 51820/UDP | WireGuard | Criptografía ECC |

---

## 📁 Estructura del Repositorio

```
TFG_deCastro-Ander/
├── pihole/
│   ├── docker-compose.yml          # 12 microservicios
│   │   ├── pihole                  # DNS + admin
│   │   ├── redis                   # Cache (autenticado)
│   │   ├── ntopng                  # Flujos (login requerido)
│   │   ├── tshark-sflow            # Captura paquetes
│   │   ├── nginx                   # Proxy + TLS
│   │   ├── docker-proxy            # Socket proxy
│   │   ├── dashboard               # Flask SIEM
│   │   ├── wireguard               # VPN (3 peers)
│   │   ├── node-exporter           # Telemetría
│   │   ├── prometheus              # Métricas
│   │   ├── pihole-exporter         # Exportador
│   │   ├── grafana                 # Visualización
│   │   └── mitmproxy               # Opcional
│   ├── .env.example                # Template credenciales
│   ├── prometheus.yml              # Scraping
│   ├── nginx/
│   │   ├── siem.conf              # Config proxy
│   │   └── certs/                 # Certificados TLS
│   └── grafana_data/              # Persistencia
├── dashboard/
│   ├── app.py                      # Backend Flask
│   ├── alerter.py                  # Motor alertas
│   ├── templates/
│   │   ├── index.html             # Dashboard principal
│   │   ├── sniffer.html           # Captura viva
│   │   ├── estadisticas.html      # Análisis avanzado
│   │   ├── graficas.html          # Grafana embed
│   │   ├── alertas.html           # Centro alertas
│   │   ├── lateral.html           # Red interna
│   │   ├── red.html               # Red mejorada
│   │   ├── contenedores.html      # Docker control
│   │   └── login.html             # Autenticación
│   ├── static/                     # CSS, JS, assets
│   └── requirements.txt            # Dependencias Python
└── wireguard_config/               # Config WireGuard
```

---

## ⚡ Eficiencia Energética

| Condición | Consumo | Notas |
|-----------|---------|-------|
| Baja carga | ~3-5 W | Inactivo |
| Carga sostenida | ~7-8 W | Dashboard + ntopng activos |
| **Coste anual** | **< 20 €** | ~30 kWh/año |

**Para PYME típica:**
- 15-50 dispositivos
- Ahorros: 300-500 € vs soluciones comerciales

---

## 🛡️ Buenas Prácticas

- ✅ Credenciales en `.env` (nunca en repositorio)
- ✅ Variables centralizadas (fácil mantenimiento)
- ✅ TLS obligatorio
- ✅ Acceso remoto por VPN
- ✅ Historial Git limpio
- ✅ Servicios internos en localhost
- ✅ Docker Socket Proxy
- ✅ Autenticación en ntopng
- ✅ Servicios opcionales con profiles
- ✅ Documentación completa

---

## 📄 Licencia

Proyecto académico — Trabajo de Fin de Grado.  
Libre para uso educativo y modificación.

---

## 🤝 Soporte

Para preguntas o problemas:
1. Revisa [Solución de Problemas](#-solución-de-problemas-frecuentes)
2. Abre una **Issue** en GitHub con detalles del error

**Última actualización:** 29 de Mayo de 2026  
**Versión:** 1.0
