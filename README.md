# 🛡️ Sistema de Monitorización y Gestión de Red de Bajo Coste para PYME

**TFG — Grado en Ingeniería en Tecnología de Telecomunicación**  
**Autor:** Ander de Castro

---

## 📋 Inicio Rápido

### Requisitos Mínimos
- Raspberry Pi 4 (4 GB RAM recomendados) — ~60-70 €
- Tarjeta microSD 16+ GB
- Cable Ethernet + ordenador para configuración inicial

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

1. [Descripción del Proyecto](#descripción-del-proyecto)
2. [Arquitectura del Sistema](#arquitectura)
3. [Stack Tecnológico](#stack-tecnológico)
4. [Instalación Rápida](#instalación-rápida)
5. [Guía de Usuario (sin experiencia)](#guía-de-usuario)
6. [Matriz de Acceso](#matriz-de-acceso)
7. [Funcionalidades](#funcionalidades)
8. [Políticas de Seguridad](#políticas-de-seguridad)
9. [Solución de Problemas](#solución-de-problemas)
10. [Visibilidad de Red](#visibilidad-de-red)
11. [Acceso Externo (DuckDNS + Let's Encrypt)](#acceso-externo)
12. [Auditoría de Seguridad](#auditoría-de-seguridad)
13. [Estructura del Repositorio](#estructura-del-repositorio)

---

## 🎯 Descripción del Proyecto

Sistema de **monitorización y gestión de red** basado en **Raspberry Pi 4** y herramientas de código abierto, orientado a PYMES con presupuesto limitado.

**Funciones principales:**
- ✅ Filtrado DNS preventivo de **600.000+ dominios maliciosos**
- ✅ Análisis de flujos TCP/UDP en tiempo real
- ✅ Motor de alertas inteligente (6 reglas heurísticas)
- ✅ Dashboard unificado con gráficas históricas
- ✅ Detección de escaneos internos y movimiento lateral
- ✅ Panel de control de contenedores Docker
- ✅ Notificaciones automáticas por Telegram

**Alineado con ODS 4 (Educación de Calidad) y ODS 9 (Industria, Innovación e Infraestructura)**

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

| Servicio | Función | Puertos |
|----------|---------|---------|
| **Pi-hole** | Filtrado DNS preventivo | 53/UDP, 80/TCP |
| **ntopng** | Análisis flujos TCP/UDP en tiempo real | 3001/TCP |
| **Tshark** | Captura de paquetes | Interno |
| **Flask** | Dashboard web + motor de alertas | 5000 (interno) |
| **Grafana** | Visualización históricas | 3000/TCP |
| **Prometheus** | Métricas de hardware (series temporales) | 9090 (localhost) |
| **Node Exporter** | Telemetría SO (CPU, RAM, temp) | 9100 (localhost) |
| **Redis** | Caché de flujos (autenticado) | 6379 (interno) |
| **Nginx** | Proxy inverso + TLS | 443/TCP, 80/TCP |
| **WireGuard** | VPN remota | 51820/UDP |
| **Docker Socket Proxy** | Acceso seguro a Docker API | 2375 (interno) |
| **SQLite** | Persistencia de alertas | Interno |

---

## ⚡ Instalación Rápida

### Requisitos Previos
```bash
# Solo si no tienes Docker instalado
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

### Despliegue
```bash
# 1. Clonar
git clone https://github.com/aanderdc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander

# 2. Configurar credenciales
cp pihole/.env.example pihole/.env
nano pihole/.env
# 👉 Edita todos los valores marcados

# 3. Iniciar servicios
cd pihole
docker compose up -d

# 4. Verificar que los 12 contenedores están UP
docker ps
```

---

## 👥 Matriz de Acceso al Sistema

| Servicio | URL | Credenciales | Acceso |
|----------|-----|--------------|--------|
| **Dashboard (SIEM)** | `https://IP` | `DASHBOARD_USER` / `DASHBOARD_PASSWORD` | Red local + VPN |
| **Pi-hole** | `http://IP:80` | `PIHOLE_PASSWORD` | Red local |
| **Grafana** | `http://IP:3000` | `admin` / `GRAFANA_PASSWORD` | Red local |
| **ntopng** | `http://IP:3001` | `admin` / `NTOPNG_PASSWORD` | Red local (autenticación requerida) |
| **WireGuard** | IP pública:51820/UDP | Certificados | Acceso remoto seguro |

> 🔒 **Prometheus, Node Exporter y pihole-exporter** están restringidos a `localhost` (inaccesibles desde la red local).

---

## 🎨 Funcionalidades del Dashboard

### Vistas Principales

1. **📊 Dashboard Principal**
   - Métricas DNS en tiempo real
   - Dispositivos activos
   - Consumo de ancho de banda
   - Alertas recientes

2. **📡 Sniffer (Captura en vivo)**
   - Análisis de paquetes HTTP/DNS
   - Filtrado por texto en tiempo real
   - Detalles de cada transacción

3. **📈 Gráficas Históricas**
   - Tráfico total (6h, 24h, 48h, 7 días)
   - Consultas DNS bloqueadas
   - Tráfico por dispositivo
   - Selectores de rango temporal

4. **⚠️ Centro de Alertas**
   - 6 reglas de detección automática
   - Clasificación por severidad (Crítica, Alta, Media, Baja)
   - Exportación a CSV
   - Notificaciones Telegram (CRÍTICA y ALTA)

5. **🗺️ Red Interna**
   - Mapa visual de conexiones
   - Detección de escaneos internos
   - Identificación de puertos críticos

6. **🐳 Panel Docker**
   - Estado de los 12 contenedores
   - Logs en tiempo real
   - Botones: Iniciar/Parar/Reiniciar
   - Uptime y consumo de recursos

---

### 6 Reglas del Motor de Alertas

| Regla | Condición | Severidad |
|-------|-----------|-----------|
| **Threat Score** | ntopng > 100 (crítico > 500) | CRÍTICA |
| **Nueva IP** | Dispositivo no visto anteriormente | ALTA |
| **Pico de tráfico** | 5x la media 24h | ALTA |
| **Bloqueos DNS** | >50 dominios en 30s | MEDIA |
| **`LATERAL_SCAN`** | >5 IPs internas en 30s | ALTA / CRÍTICA |
| **`LATERAL_PORT`** | Conexión a RDP/SMB/SSH/Telnet/VNC | CRÍTICA |

---

## 🔐 Políticas de Seguridad (DNS Blocklists)

**Dos listas de bloqueo combinadas:**
- **Hagezi Multi Pro** — Telemetría, rastreadores, malware, C2
- **StevenBlack/hosts** — Publicidad masiva

**Base activa:** 600.000+ dominios bloqueados

---

## 📖 Guía de Usuario (Sin Experiencia Técnica)

### Paso 1: Flashear el Sistema Operativo

1. Descarga **[Raspberry Pi Imager](https://www.raspberrypi.com/software/)**
2. Inserta la microSD
3. Selecciona:
   - Dispositivo: **Raspberry Pi 4**
   - SO: **Raspberry Pi OS (64-bit)**
   - Almacenamiento: **tu microSD**
4. Clic en **Escribir** y espera
5. Inserta en Raspberry Pi + cable Ethernet + enchufa

### Paso 2: Conexión Remota (SSH)

**Windows:** Abre PowerShell  
**Mac/Linux:** Abre Terminal

```bash
ssh pi@raspberrypi.local
# Contraseña: raspberry (cámbiala)
```

> Si no funciona `raspberrypi.local`, usa la IP visible en tu router: `ssh pi@192.168.1.X`

### Paso 3: Instalar Docker

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

Desconecta y vuelve a conectar.

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

## ❌ Solución de Problemas Frecuentes

### Contenedor aparece "Exited"
```bash
docker logs nombre_contenedor
```

### No puedo acceder al dashboard
- ¿Estás en la misma red que la Raspberry?
- ¿El navegador te muestra advertencia de certificado? (es normal, acepta)

### Pi-hole no bloquea nada
Verifica que el DNS del router apunta a la IP correcta de la Raspberry.

### Olvidé la contraseña del dashboard
```bash
nano .env  # Edita DASHBOARD_PASSWORD
docker compose restart mi_dashboard
```

### "Credenciales incorrectas" aunque todo está bien
```bash
docker compose down
docker compose up -d --force-recreate
docker exec mi_dashboard env | grep DASHBOARD
```

### Grafana no arranca — "permission denied"
```bash
sudo chown -R 472:472 ~/TFG_deCastro-Ander/pihole/grafana_data
docker compose restart grafana
```

### SSH no resuelve `raspberrypi.local`
Usa directamente la IP del router: `ssh ander@192.168.1.X`

### ntopng no conecta con Redis
La sintaxis debe ser: `127.0.0.1:6379:${REDIS_PASSWORD}@0`

### Docker Socket Proxy — error 403
Añade `IMAGES=1` a las variables de entorno del servicio `docker-proxy`.

### Contraseña Redis con caracteres especiales
⚠️ **Usa solo alfanuméricos.** Caracteres como `!` `@` `#` se interpretan mal. Ej:
```env
REDIS_PASSWORD=MiContraseñaLargaSinSimbolos2024
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

### Switch recomendado (SPAN a 0 €)
- TP-Link TL-SG105E (~25 €)
- Netgear GS305E (~30 €)
- TP-Link TL-SG108E (~35 €)

---

## 🌍 Acceso Externo: DuckDNS + Let's Encrypt

### 1. Crear dominio DuckDNS

```bash
# Ve a https://www.duckdns.org
# - Inicia sesión
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

- 🔒 Prometheus, Node Exporter, pihole-exporter restringidos a `localhost`
- 🔒 Redis con autenticación obligatoria
- 🔒 ntopng con login requerido
- 🔒 Docker Socket Proxy implementado
- 🔒 Sincronización de credenciales pre-startup

### Superficie de Ataque Residual (Post-hardening)

| Puerto | Servicio | Protección |
|--------|---------|-----------|
| 443 | Dashboard Flask | Autenticación + TLS |
| 80 | Pi-hole admin | Autenticación |
| 3000 | Grafana | Autenticación |
| 3001 | ntopng | Autenticación |
| 51820/UDP | WireGuard | Criptografía ECC |

---

## 📁 Estructura del Repositorio

```
TFG_deCastro-Ander/
├── pihole/
│   ├── docker-compose.yml          # Orquestación 12 microservicios
│   ├── .env.example                # Plantilla credenciales
│   ├── prometheus.yml              # Scraping de métricas
│   ├── nginx/
│   │   ├── siem.conf              # Proxy inverso config
│   │   └── certs/                 # Certificados TLS
│   └── grafana_data/              # Persistencia Grafana
├── dashboard/
│   ├── app.py                      # Backend Flask (API + alertas)
│   ├── templates/
│   │   ├── index.html             # Dashboard principal
│   │   ├── sniffer.html           # Captura en vivo
│   │   ├── graficas.html          # Históricas
│   │   ├── alertas.html           # Centro de alertas
│   │   ├── lateral.html           # Mapa red interna
│   │   └── contenedores.html      # Panel Docker
│   └── static/                     # CSS, JS, assets
└── wireguard_config/               # Config WireGuard (excluida)
```

---

## ⚡ Eficiencia Energética

| Condición | Consumo |
|-----------|---------|
| Baja carga | ~3-5 W |
| Carga sostenida | ~7-8 W |
| **Coste anual (24/7)** | **< 20 €** |

---

## 🛡️ Buenas Prácticas Aplicadas

- ✅ **Credenciales en `.env`** (nunca en repositorio)
- ✅ **Variables de entorno centralizadas**
- ✅ **TLS obligatorio** (Nginx)
- ✅ **Acceso remoto por VPN** (WireGuard)
- ✅ **Historial Git limpio** (BFG Repo Cleaner)
- ✅ **Servicios internos en localhost** (no expuestos)
- ✅ **Docker Socket Proxy** (acceso restrictivo)
- ✅ **Autenticación en ntopng** (login requerido)
- ✅ **Notificaciones opcionales** (Telegram)

---

## 📄 Licencia

Proyecto académico — Trabajo de Fin de Grado.
