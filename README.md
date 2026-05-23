# Sistema de Monitorización y Gestión de Red de Bajo Coste para entornos PYME
### TFG — Grado en Ingeniería en Tecnología de Telecomunicación
**Autor:** Ander de Castro

---

## Índice de Contenidos

- [1. Descripción del Proyecto](#1-descripción-del-proyecto)
  - [1.1. Alineación con los Objetivos de Desarrollo Sostenible (ODS)](#11-alineación-con-los-objetivos-de-desarrollo-sostenible-ods)
- [2. Arquitectura del Sistema](#2-arquitectura-del-sistema)
- [3. Stack Tecnológico](#3-stack-tecnológico)
- [4. Requisitos Previos del Sistema](#4-requisitos-previos-del-sistema)
  - [4.1. Instalación automatizada de Docker](#41-instalación-automatizada-de-docker)
- [5. Instalación y Despliegue](#5-instalación-y-despliegue)
  - [5.1. Clonar el repositorio](#51-clonar-el-repositorio)
  - [5.2. Configuración de Variables de Entorno](#52-configuración-de-variables-de-entorno)
  - [5.3. Inicialización del Entorno Multi-Contenedor](#53-inicialización-del-entorno-multi-contenedor)
  - [5.4. Verificación del Estado](#54-verificación-del-estado)
- [6. Matriz de Acceso al Sistema](#6-matriz-de-acceso-al-sistema)
- [7. Funcionalidades del Dashboard Core](#7-funcionalidades-del-dashboard-core)
  - [7.1. Reglas del Motor de Alertas (Heurística)](#71-reglas-del-motor-de-alertas-heurística)
- [8. Políticas de Seguridad de Red (DNS Blocklists)](#8-políticas-de-seguridad-de-red-dns-blocklists)
- [9. Estructura del Repositorio](#9-estructura-del-repositorio)
- [10. Buenas Prácticas de Ciberseguridad Aplicadas](#10-buenas-prácticas-de-ciberseguridad-aplicadas)
- [11. Eficiencia Energética y Costes de Operación](#11-eficiencia-energética-y-costes-de-operación)
- [12. Guía del Usuario (Despliegue sin Experiencia Técnica)](#12-guía-del-usuario-despliegue-sin-experiencia-técnica)
  - [12.1. Paso 1: Flashear el Sistema Operativo](#121-paso-1-flashear-el-sistema-operativo)
  - [12.2. Paso 2: Conexión Remota por Consola (SSH)](#122-paso-2-conexión-remota-por-consola-ssh)
  - [12.3. Paso 3: Instalación Automatizada del Motor Docker](#123-paso-3-instalación-automatizada-del-motor-docker)
  - [12.4. Paso 4: Descarga del Repositorio y Configuración del Entorno](#124-paso-4-descarga-del-repositorio-y-configuración-del-entorno)
  - [12.5. Paso 5: Lanzamiento de los Servicios](#125-paso-5-lanzamiento-de-los-servicios)
  - [12.6. Paso 6: Configurar el DNS en el Router Principal](#126-paso-6-configurar-el-dns-en-el-router-principal)
  - [12.7. Paso 7: Acceso al Cuadro de Mandos (SIEM)](#127-paso-7-acceso-al-cuadro-de-mandos-siem)
- [13. Resolución de Problemas Frecuentes (FAQ)](#13-resolución-de-problemas-frecuentes-faq)
- [14. Visibilidad de Red: Limitaciones y Ampliaciones](#14-visibilidad-de-red-limitaciones-y-ampliaciones)
  - [14.1. El problema: tráfico que el sistema no puede ver](#141-el-problema-tráfico-que-el-sistema-no-puede-ver)
  - [14.2. Detección de tráfico interno implementada](#142-detección-de-tráfico-interno-implementada)
  - [14.3. Soluciones para visibilidad total de red](#143-soluciones-para-visibilidad-total-de-red)
  - [14.4. Comparativa de opciones](#144-comparativa-de-opciones)
  - [14.5. Estado actual del proyecto](#145-estado-actual-del-proyecto)
- [15. Acceso Externo: DuckDNS y Let's Encrypt](#15-acceso-externo-duckdns-y-lets-encrypt)
  - [15.1. Crear dominio DuckDNS](#151-crear-dominio-duckdns)
  - [15.2. Instalar Certbot y obtener certificado](#152-instalar-certbot-y-obtener-certificado)
  - [15.3. Configurar Nginx con el certificado válido](#153-configurar-nginx-con-el-certificado-válido)
  - [15.4. Renovación automática](#154-renovación-automática)
- [16. Resolución de Incidencias del Despliegue Real](#16-resolución-de-incidencias-del-despliegue-real)
  - [16.1. Certificados TLS no encontrados](#161-certificados-tls-no-encontrados)
  - [16.2. Credenciales del dashboard incorrectas](#162-credenciales-del-dashboard-incorrectas)
  - [16.3. Grafana no arranca por permisos](#163-grafana-no-arranca-por-permisos)
  - [16.4. SSH — no resuelve raspberrypi.local](#164-ssh--no-resuelve-raspberrypilocal)
  - [16.5. ntopng no conecta con Redis tras añadir contraseña](#165-ntopng-no-conecta-con-redis-tras-añadir-contraseña)
  - [16.6. Docker socket proxy — error 403 en panel de contenedores](#166-docker-socket-proxy--error-403-en-panel-de-contenedores)
  - [16.7. Contraseña de Redis con caracteres especiales](#167-contraseña-de-redis-con-caracteres-especiales)
- [17. Auditoría de Seguridad y Hardening](#17-auditoría-de-seguridad-y-hardening)
  - [17.1. Metodología](#171-metodología)
  - [17.2. Vulnerabilidades identificadas](#172-vulnerabilidades-identificadas)
  - [17.3. Demostración del impacto](#173-demostración-del-impacto)
  - [17.4. Correcciones aplicadas](#174-correcciones-aplicadas)
  - [17.5. Verificación post-hardening](#175-verificación-post-hardening)
  - [17.6. Superficie de ataque residual](#176-superficie-de-ataque-residual)
- [18. Licencia](#18-licencia)

---

## 1. Descripción del Proyecto

Sistema de monitorización y gestión de red basado en **Raspberry Pi 4** y herramientas de código abierto, orientado a PYMES con presupuesto limitado. Integra filtrado DNS preventivo, análisis de flujos de tráfico en tiempo real, captura de paquetes, telemetría de hardware y un motor de alertas automático, todo accesible desde un dashboard web unificado desarrollado en Flask.

### 1.1. Alineación con los Objetivos de Desarrollo Sostenible (ODS)

**Alineado con los ODS 4 (Educación de Calidad) y ODS 9 (Industria, Innovación e Infraestructura).**

---

## 2. Arquitectura del Sistema

El sistema se organiza en tres niveles:

- **Nivel 1 — Dispositivos de usuario:** todos los equipos de la red local cuyo tráfico DNS pasa obligatoriamente por la Raspberry Pi.
- **Nivel 2 — Nodo central (Raspberry Pi 4):** núcleo del sistema con todos los microservicios dockerizados.
- **Nivel 3 — Capa de presentación:** dashboard web accesible desde cualquier navegador, protegido por autenticación y cifrado TLS.

---

## 3. Stack Tecnológico

| Servicio | Función |
|---|---|
| **Pi-hole** | Filtrado DNS preventivo (DNS sinkholing) |
| **ntopng** | Análisis de flujos TCP/UDP en tiempo real |
| **Tshark** | Captura de paquetes a nivel de trama |
| **Flask (Python)** | Dashboard web unificado y motor de alertas |
| **Prometheus** | Base de datos de series temporales (métricas de hardware) |
| **Node Exporter** | Telemetría del sistema operativo (CPU, RAM, temperatura) |
| **Grafana** | Visualización de métricas históricas |
| **Redis** | Caché de flujos para ntopng (autenticado) |
| **Nginx** | Proxy inverso con cifrado TLS |
| **WireGuard** | VPN para acceso remoto seguro |
| **Docker Socket Proxy** | Proxy restrictivo sobre el socket de Docker |
| **SQLite** | Persistencia histórica de eventos de red y alertas |

---

## 4. Requisitos Previos del Sistema

- Raspberry Pi 4 (recomendado 4 GB RAM o más)
- Raspberry Pi OS (64 bits)
- Docker y Docker Compose instalados
- Acceso a la red local con capacidad para configurar el DNS primario

### 4.1. Instalación automatizada de Docker

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

---

## 5. Instalación y Despliegue

### 5.1. Clonar el repositorio

```bash
git clone https://github.com/aanderdc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander
```

### 5.2. Configuración de Variables de Entorno

Copia el archivo de ejemplo y edítalo con tus propios valores:

```bash
cp pihole/.env.example pihole/.env
nano pihole/.env
```

Contenido del `.env`:

```env
RASPBERRY_IP=192.168.1.X
PIHOLE_PASSWORD=tu_contraseña_segura
GRAFANA_PASSWORD=tu_contraseña_segura
NTOPNG_USER=admin
NTOPNG_PASSWORD=tu_contraseña_segura
REDIS_PASSWORD=tu_contraseña_sin_caracteres_especiales
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=tu_contraseña_segura
FLASK_SECRET_KEY=cadena_larga_y_aleatoria
WIREGUARD_SERVERURL=tu_ip_publica
# Opcional — notificaciones Telegram
TELEGRAM_TOKEN=token_de_tu_bot
TELEGRAM_CHAT_ID=tu_chat_id
```

> Todas las credenciales se gestionan exclusivamente mediante variables de entorno. El archivo `.env` nunca se sube al repositorio.

> ⚠️ **Importante:** evita usar caracteres especiales como `!` en `REDIS_PASSWORD` — pueden causar problemas de interpretación en bash al pasarse como argumento al proceso de Redis dentro del contenedor.

> ⚠️ El servicio `mi_dashboard` lee las variables directamente del `.env` mediante `env_file`. Si añades variables nuevas al `.env`, reinicia el contenedor con `docker compose restart mi_dashboard` para que las cargue.

### 5.3. Inicialización del Entorno Multi-Contenedor

```bash
cd pihole
docker compose up -d
```

### 5.4. Verificación del Estado

```bash
docker ps
```

Deberías ver los siguientes **12 contenedores** en estado `Up`:
`pihole`, `ntopng`, `redis-ntopng`, `tshark-sflow`, `prometheus`, `node-exporter`, `pihole-exporter`, `grafana`, `nginx-siem`, `wireguard`, `docker-proxy`, `mi_dashboard`

---

## 6. Matriz de Acceso al Sistema

| Servicio | URL | Puerto | Acceso |
|---|---|---|---|
| Dashboard Flask (SIEM) | `https://IP_RASPBERRY` | 443 (via Nginx) | Red local + VPN |
| Pi-hole | `http://IP_RASPBERRY:80` | 80 | Red local |
| Grafana | `http://IP_RASPBERRY:3000` | 3000 | Red local |
| ntopng | `http://IP_RASPBERRY:3001` | 3001 | Red local (login requerido) |
| Prometheus | Solo interno | 127.0.0.1:9090 | Localhost únicamente |
| Node Exporter | Solo interno | 127.0.0.1:9100 | Localhost únicamente |
| pihole-exporter | Solo interno | 127.0.0.1:9167 | Localhost únicamente |
| WireGuard VPN | UDP | 51820 | Acceso remoto externo |

> Los servicios de telemetría (Prometheus, Node Exporter, pihole-exporter) están restringidos a localhost y no son accesibles desde la red local. Esto es intencional por seguridad — ver sección 17.

---

## 7. Funcionalidades del Dashboard Core

- **Dashboard principal:** métricas DNS en tiempo real (Pi-hole), dispositivos activos y consumo de ancho de banda.
- **Sniffer:** visualización en tiempo real de las capturas de Tshark con filtrado por texto.
- **Gráficas históricas:** tráfico total, consultas DNS y tráfico por dispositivo con selector de rango temporal (6h, 24h, 48h, 7 días).
- **Alertas de seguridad:** registro automático con clasificación por severidad (Crítica, Alta, Media, Baja) basado en seis reglas de detección. Incluye exportación a CSV para análisis externo.
- **Red Interna:** mapa visual de conexiones entre dispositivos de la red local, con detección de escaneos internos y conexiones a puertos críticos.
- **Contenedores:** panel de gestión de los microservicios Docker — estado, uptime, logs y botones de inicio/parada/reinicio por contenedor, con refresco automático cada 15 segundos.
- **Notificaciones Telegram:** el motor de alertas envía automáticamente un mensaje cuando detecta una alerta CRÍTICA 🔴 o ALTA 🟠, sin necesidad de tener el dashboard abierto.

### 7.1. Reglas del Motor de Alertas (Heurística)

1. Score de amenaza ntopng superior a 100 (crítico si supera 500)
2. Detección de dispositivos con IPs nuevas no vistas anteriormente
3. Tráfico de bajada superior a 5 veces la media histórica de las últimas 24h
4. Picos de más de 50 dominios bloqueados por Pi-hole en 30 segundos
5. **`LATERAL_SCAN`** — un dispositivo interno contacta más de 5 IPs internas distintas en 30 segundos (posible escaneo de red)
6. **`LATERAL_PORT`** — conexión interna a puerto crítico: RDP (3389), SMB (445), SSH (22), Telnet (23) o VNC (5900)

---

## 8. Políticas de Seguridad de Red (DNS Blocklists)

El sistema utiliza dos listas combinadas:

- **Hagezi Multi Pro** — telemetría, rastreadores, malware y dominios C2
- **StevenBlack/hosts** — publicidad masiva

Base de bloqueo activa: **más de 600.000 dominios**.

---

## 9. Estructura del Repositorio
```bash
TFG_deCastro-Ander/
├── pihole/                  # Configuración de todos los servicios Docker
│   ├── docker-compose.yml   # Orquestación de los 12 microservicios
│   ├── .env.example         # Plantilla de variables de entorno
│   ├── nginx/               # Configuración de Nginx y certificados TLS
│   └── prometheus.yml       # Configuración de scraping de Prometheus
├── dashboard/               # Código fuente del dashboard Flask
│   ├── app.py               # Backend principal (API, alertas, logging)
│   └── templates/           # Plantillas HTML (index, sniffer, graficas, alertas, lateral, contenedores)
└── wireguard_config/        # Configuración de WireGuard (claves excluidas)
```
---

## 10. Buenas Prácticas de Ciberseguridad Aplicadas

- Las credenciales **nunca se almacenan en el repositorio**. Se gestionan mediante variables de entorno en el archivo `.env` (excluido del control de versiones).
- Todas las variables sensibles están centralizadas en `.env`: contraseñas de Pi-hole, Grafana, ntopng, Redis, dashboard Flask y clave de sesión.
- El acceso al dashboard viaja siempre cifrado mediante TLS (Nginx).
- El acceso remoto se realiza exclusivamente a través de la VPN WireGuard.
- Las claves privadas de WireGuard y los certificados TLS están excluidos del repositorio mediante `.gitignore`.
- El historial de git ha sido limpiado con BFG Repo Cleaner para garantizar que ninguna credencial queda en commits anteriores.
- Los servicios de telemetría interna (Prometheus, Node Exporter, pihole-exporter, Redis) están restringidos a `localhost` y no son accesibles desde la red local.
- El socket de Docker está protegido mediante un proxy restrictivo (`tecnativa/docker-socket-proxy`) que limita las operaciones permitidas.
- ntopng requiere autenticación — el flag `--disable-login` está desactivado.
- Las notificaciones externas (Telegram) se configuran opcionalmente mediante variables de entorno; el sistema funciona sin ellas.

---

## 11. Eficiencia Energética y Costes de Operación

| Condición | Consumo |
|---|---|
| Baja carga | ~3-5 W |
| Carga sostenida | ~7-8 W |
| Coste energético anual (24/7) | < 20 € |

---

## 12. Guía del Usuario (Despliegue sin Experiencia Técnica)

Si nunca has usado una Raspberry Pi, Linux o Docker, esta sección es para ti. Sigue los pasos en orden y tendrás el sistema funcionando.

**¿Qué necesitas?**

- Una Raspberry Pi 4 (4 GB RAM recomendados) — precio aproximado: 60-70 €
- Una tarjeta microSD de al menos 16 GB
- Cable de red (Ethernet) para conectar la Raspberry Pi al router
- Un ordenador para los primeros pasos

### 12.1. Paso 1: Flashear el Sistema Operativo

1. Descarga **Raspberry Pi Imager** en tu ordenador: https://www.raspberrypi.com/software/
2. Inserta la tarjeta microSD en tu ordenador.
3. Abre Raspberry Pi Imager, selecciona:
   - **Dispositivo:** Raspberry Pi 4
   - **Sistema operativo:** Raspberry Pi OS (64-bit)
   - **Almacenamiento:** tu tarjeta microSD
4. Haz clic en **Escribir** y espera a que termine.
5. Inserta la microSD en la Raspberry Pi, conecta el cable de red y enchúfala.

### 12.2. Paso 2: Conexión Remota por Consola (SSH)

Desde tu ordenador, abre una terminal:
- **Windows:** busca "PowerShell" en el menú inicio
- **Mac/Linux:** abre "Terminal"

Escribe:
```bash
ssh pi@raspberrypi.local
```
La contraseña por defecto es `raspberry`. Cámbiala cuando te lo pida.

> Si no funciona, prueba con la IP de tu Raspberry Pi en lugar de `raspberrypi.local`.
> Puedes verla en la pantalla de tu router (suele ser algo como `192.168.1.X`).

### 12.3. Paso 3: Instalación Automatizada del Motor Docker

Copia y pega estos comandos uno a uno en la terminal:

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

Cierra la terminal y vuelve a conectarte para que los cambios surtan efecto.

### 12.4. Paso 4: Descarga del Repositorio y Configuración del Entorno

```bash
git clone https://github.com/aanderdc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander/pihole
cp .env.example .env
```

Ahora abre el archivo `.env` para poner tus contraseñas:

```bash
nano .env
```

Rellena todos los valores con tus credenciales. Para guardar: pulsa `Ctrl+O`, luego `Enter`, luego `Ctrl+X` para salir.

### 12.5. Paso 5: Lanzamiento de los Servicios

```bash
docker compose up -d
```

Espera 1-2 minutos y comprueba que todo funciona:

```bash
docker ps
```

Deberías ver 12 contenedores en estado **Up**. Si alguno aparece como **Exited**, consulta la sección [Resolución de problemas](#13-resolución-de-problemas-frecuentes-faq).

### 12.6. Paso 6: Configurar el DNS en el Router Principal

Este es el paso más importante: decirle a tu red que use la Raspberry Pi como servidor DNS.

1. Abre tu navegador y ve a la dirección de tu router (normalmente `192.168.1.1` o `192.168.0.1`).
2. Entra con tu usuario y contraseña (suelen estar en la pegatina del router).
3. Busca la sección **DHCP** o **DNS**.
4. Cambia el **DNS primario** por la IP de tu Raspberry Pi (ej: `192.168.1.100`).
5. Guarda los cambios y reinicia el router.

> A partir de este momento, todo el tráfico DNS de tu red pasará por Pi-hole.

### 12.7. Paso 7: Acceso al Cuadro de Mandos (SIEM)

Abre tu navegador y ve a: `https://IP_DE_TU_RASPBERRY`

Acepta el aviso de certificado (es autofirmado, es normal).
Verás el panel de control con métricas en tiempo real.

---

## 13. Resolución de Problemas Frecuentes (FAQ)

**Un contenedor aparece como Exited**
```bash
docker logs nombre_del_contenedor
```
Esto muestra el error. Los más comunes están documentados en las secciones 16 y 17 de este README.

**No puedo acceder al dashboard**
Comprueba que estás en la misma red Wi-Fi que la Raspberry Pi.

**Pi-hole no bloquea nada**
Verifica que el DNS de tu router apunta a la IP correcta de la Raspberry Pi (Paso 6).

**Olvidé la contraseña del dashboard**
Edita el archivo `.env`, cambia `DASHBOARD_PASSWORD` y reinicia con `docker compose restart mi_dashboard`.

**El dashboard muestra "Credenciales incorrectas" aunque el `.env` es correcto**
El contenedor puede haber arrancado antes de leer el `.env`. Fuerza una recreación completa:
```bash
docker compose down
docker compose up -d --force-recreate
```
Verifica que las variables llegaron al contenedor:
```bash
docker exec mi_dashboard env | grep DASHBOARD
```

**Grafana no arranca — error "permission denied" en `/var/lib/grafana`**
Los volúmenes de Grafana necesitan pertenecer al usuario interno de Grafana (UID 472):
```bash
sudo chown -R 472:472 ~/TFG_deCastro-Ander/pihole/grafana_data
docker compose restart grafana
```

---

## 14. Visibilidad de Red: Limitaciones y Ampliaciones

### 14.1. El problema: tráfico que el sistema no puede ver

En la arquitectura actual, ntopng y tshark escuchan sobre la interfaz `wlan0` de la Raspberry Pi. Esto significa que el sistema **solo captura el tráfico que pasa directamente por la Raspberry**, no el tráfico que circula entre otros dispositivos de la red.
```bash
INTERNET
│
▼
┌─────────────────┐
│     ROUTER      │
│   192.168.1.1   │
└────────┬────────┘
│
┌────┴────┐
│         │
LAN eth     WiFi
│         │
└────┬────┘
▼
┌─────────────────────────┐
│      RASPBERRY PI       │
│    ntopng · tshark      │
│  (solo ve su tráfico    │
│   y el WiFi de wlan0)   │
└─────────────────────────┘
┌──────────┐   ✗ NO visible   ┌──────────────────┐
│    PC    │ - - - - - - - -  │ Servidor interno  │
└──────────┘                  └──────────────────┘
↑
Este tráfico lateral no pasa
por la Raspberry → no se captura
```
- **Tráfico lateral (East-West):** comunicaciones entre dispositivos de la misma red.
- **Escaneo interno:** un dispositivo comprometido escaneando otros equipos.
- **Movimiento lateral de malware:** propagación de ransomware entre equipos internos.

**¿Por qué es relevante para una PYME?**
Fase 1 — Entrada via DNS malicioso   → ✅ Pi-hole lo bloquea
Fase 2 — Contacto con servidor C2    → ✅ ntopng detecta el score
Fase 3 — Movimiento lateral interno  → ⚠️  Detección parcial (ver sección 14.2)
Fase 4 — Cifrado de archivos         → ❌ Demasiado tarde

### 14.2. Detección de tráfico interno implementada

El módulo **Red Interna** analiza cada 30 segundos las tramas capturadas buscando comunicaciones entre IPs internas que pasen por la Raspberry.

- **Regla `LATERAL_SCAN`:** un dispositivo contacta más de 5 IPs internas distintas en 30 segundos → alerta ALTA. Más de 15 → alerta CRÍTICA.
- **Regla `LATERAL_PORT`:** conexión interna a puerto crítico (RDP 3389, SMB 445, SSH 22, Telnet 23, VNC 5900) → alerta CRÍTICA.

### 14.3. Soluciones para visibilidad total de red

#### Opción 1 — Port Mirroring en el router

**Coste:** 0 € | **Dificultad:** Baja | **Requisito:** Router con soporte SPAN/Port Mirror

#### Opción 2 — Raspberry Pi como gateway

**Coste:** ~25 € | **Dificultad:** Media | **Visibilidad:** Total

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo apt install iptables-persistent -y
sudo netfilter-persistent save
```

#### Opción 3 — Switch gestionable con SPAN port (recomendada)

**Coste:** ~25-35 € | **Dificultad:** Baja | **Visibilidad:** Total | **No altera la red**

| Modelo | Precio aprox. | Puertos |
|--------|--------------|---------|
| TP-Link TL-SG105E | ~25 € | 5x GbE |
| Netgear GS305E | ~30 € | 5x GbE |
| TP-Link TL-SG108E | ~35 € | 8x GbE |

### 14.4. Comparativa de opciones

| Opción | Coste | Dificultad | Visibilidad | Modifica la red |
|--------|-------|------------|-------------|-----------------|
| Port Mirror en router | 0 € | Baja | Total | No |
| Raspberry como gateway | ~25 € | Media | Total | Sí |
| Switch gestionable (SPAN) | ~30 € | Baja | Total | No |
| **Arquitectura actual** | **0 €** | **—** | **Parcial + detección activa** | **No** |

### 14.5. Estado actual del proyecto

- ✅ Filtrado DNS preventivo de más de 600.000 dominios maliciosos
- ✅ Detección de comunicaciones con servidores C2 conocidos
- ✅ Identificación de dispositivos por MAC y fabricante
- ✅ Motor de alertas con clasificación de severidad (6 reglas)
- ✅ Captura de paquetes HTTP/DNS en tiempo real
- ✅ Detección de escaneos internos (`LATERAL_SCAN`) y conexiones a puertos críticos (`LATERAL_PORT`)
- ✅ Mapa visual de conexiones internas en tiempo real
- ✅ Panel de gestión de contenedores Docker con logs y control de estado
- ✅ Notificaciones automáticas por Telegram para alertas CRÍTICA y ALTA
- ✅ Exportación de alertas a CSV para análisis forense externo
- ⚠️ Tráfico lateral entre dispositivos que no involucran a la Raspberry: requiere port mirroring (sección 14.3)

---

## 15. Acceso Externo: DuckDNS y Let's Encrypt

Por defecto el dashboard usa un certificado TLS autofirmado. Esta sección describe cómo obtener un certificado válido y gratuito mediante Let's Encrypt usando DuckDNS.

> **Resultado final:** acceso en `https://tunombre.duckdns.org` con candado verde.

### 15.1. Crear dominio DuckDNS

1. Ve a [duckdns.org](https://www.duckdns.org) e inicia sesión.
2. Crea un subdominio y apunta el token.
3. Crea el script de actualización:

```bash
mkdir -p ~/duckdns
cat > ~/duckdns/duck.sh << 'EOF'
echo url="https://www.duckdns.org/update?domains=TU_DOMINIO&token=TU_TOKEN&ip=" | curl -k -o ~/duckdns/duck.log -K -
EOF
chmod +x ~/duckdns/duck.sh
```

4. Automatiza con cron:
```bash
*/5 * * * * ~/duckdns/duck.sh >/dev/null 2>&1
```

### 15.2. Instalar Certbot y obtener certificado

```bash
sudo apt update && sudo apt install certbot -y
cd ~/TFG_deCastro-Ander/pihole
docker compose stop nginx
sudo certbot certonly --standalone --preferred-challenges http \
  -d tunombre.duckdns.org --email tu@email.com --agree-tos --non-interactive
```

### 15.3. Configurar Nginx con el certificado válido

```bash
sudo cp /etc/letsencrypt/live/tunombre.duckdns.org/fullchain.pem \
  ~/TFG_deCastro-Ander/pihole/nginx/certs/fullchain.pem
sudo cp /etc/letsencrypt/live/tunombre.duckdns.org/privkey.pem \
  ~/TFG_deCastro-Ander/pihole/nginx/certs/privkey.pem
sudo chmod 644 ~/TFG_deCastro-Ander/pihole/nginx/certs/*.pem
docker compose start nginx
```

Configuración `siem.conf`:
```nginx
server {
    listen 80;
    server_name tunombre.duckdns.org;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl;
    server_name tunombre.duckdns.org;
    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 15.4. Renovación automática

```bash
0 3 * * 1 sudo certbot renew --quiet && \
  sudo cp /etc/letsencrypt/live/tunombre.duckdns.org/fullchain.pem \
  ~/TFG_deCastro-Ander/pihole/nginx/certs/siem.crt && \
  sudo cp /etc/letsencrypt/live/tunombre.duckdns.org/privkey.pem \
  ~/TFG_deCastro-Ander/pihole/nginx/certs/siem.key && \
  docker restart nginx-siem
```

---

## 16. Resolución de Incidencias del Despliegue Real

### 16.1. Certificados TLS no encontrados

**Síntoma:** Nginx no arranca — `cannot load certificate key "/etc/nginx/certs/siem.key": No such file or directory`

**Causa:** Los certificados no están en el repositorio (excluidos por `.gitignore`).

**Solución — Generar certificados autofirmados nuevos:**
```bash
mkdir -p ~/TFG_deCastro-Ander/pihole/nginx/certs
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout ~/TFG_deCastro-Ander/pihole/nginx/certs/siem.key \
  -out ~/TFG_deCastro-Ander/pihole/nginx/certs/siem.crt \
  -subj "/CN=siem-dashboard/O=TFG/C=ES"
docker restart nginx-siem
```

### 16.2. Credenciales del dashboard incorrectas

**Síntoma:** "Credenciales incorrectas" aunque el `.env` es correcto.

**Causa:** El contenedor arrancó antes de leer el `.env`.

**Solución:**
```bash
docker compose down
docker compose up -d --force-recreate
docker exec mi_dashboard env | grep -E "DASHBOARD|FLASK"
```

### 16.3. Grafana no arranca por permisos

**Síntoma:** `failed to create directory "/var/lib/grafana/png": permission denied`

**Causa:** El directorio `grafana_data/` necesita pertenecer al UID 472 (usuario interno de Grafana).

**Solución:**
```bash
sudo chown -R 472:472 ~/TFG_deCastro-Ander/pihole/grafana_data
docker compose restart grafana
```

### 16.4. SSH — no resuelve raspberrypi.local

**Síntoma:** `ssh: Could not resolve hostname raspberrypi.local`

**Causa:** La resolución mDNS no funciona en redes WiFi Mesh o con ciertos routers.

**Solución:** Usa la IP directa visible en el panel de administración del router:
```bash
ssh ander@192.168.1.X
```

### 16.5. ntopng no conecta con Redis tras añadir contraseña

**Síntoma:** ntopng muestra `ERROR: NOAUTH Authentication required` en bucle y no arranca.

**Causa:** La sintaxis del parámetro `-r` de ntopng para incluir contraseña no es obvia. El formato correcto es `host:port:password@db`.

**Solución:** Verificar la sintaxis exacta de tu versión:
```bash
docker exec ntopng ntopng --help 2>&1 | grep -A3 "\-r "
```
El comando correcto para conectar con Redis autenticado es:
```yaml
command: ntopng -i wlan0 -w 3001 --community -r 127.0.0.1:6379:${REDIS_PASSWORD}@0
```

### 16.6. Docker socket proxy — error 403 en panel de contenedores

**Síntoma:** La pestaña Contenedores del dashboard devuelve error 500. Los logs del proxy muestran `403` en peticiones a `/images`.

**Causa:** El proxy `tecnativa/docker-socket-proxy` bloquea el endpoint `/images` por defecto, pero el dashboard lo necesita para mostrar información de los contenedores.

**Solución:** Añadir `IMAGES=1` a las variables de entorno del servicio `docker-proxy` en el `docker-compose.yml`:
```yaml
environment:
  - CONTAINERS=1
  - IMAGES=1
  - START=1
  - STOP=1
  - RESTART=1
  - LOGS=1
  - INFO=1
  - POST=1
```

### 16.7. Contraseña de Redis con caracteres especiales

**Síntoma:** ntopng no conecta con Redis aunque la contraseña parece correcta. Al inspeccionar el contenedor con `docker inspect`, la contraseña aparece truncada o malformada.

**Causa:** Caracteres especiales como `!`, `@`, `#` en la variable `REDIS_PASSWORD` se interpretan de forma especial por bash al expandirse dentro del `command` del `docker-compose.yml`.

**Solución:** Usar únicamente caracteres alfanuméricos en `REDIS_PASSWORD`. Una contraseña larga sin símbolos especiales es igual de segura:
```env
REDIS_PASSWORD=MiContraseñaLargaSinSimbolos2024
```

---

## 17. Auditoría de Seguridad y Hardening

### 17.1. Metodología

Como parte del proceso de validación del sistema, se realizó una auditoría de seguridad ofensiva sobre el despliegue real, simulando el escenario de un atacante con acceso a la red local. El objetivo fue identificar vulnerabilidades antes de la entrega y aplicar las correcciones correspondientes.

### 17.2. Vulnerabilidades identificadas

| ID | Componente | Vulnerabilidad | Severidad |
|----|-----------|---------------|-----------|
| V1 | Prometheus | Puerto 9090 expuesto en red sin autenticación | Crítica |
| V2 | Node Exporter | Puerto 9100 expuesto en red sin autenticación | Crítica |
| V3 | pihole-exporter | Puerto 9167 expuesto en red sin autenticación | Crítica |
| V4 | Redis | Sin contraseña — acceso libre a todos los datos de ntopng | Crítica |
| V5 | ntopng | Flag `--disable-login=1` deshabilitaba toda autenticación | Crítica |
| V6 | ntopng | Contraseña admin por defecto sin cambiar (hash MD5) | Crítica |
| V7 | Dashboard Flask | Docker socket montado directamente sin restricciones | Alta |
| V8 | Grafana | `env_file` completo innecesariamente cargado | Media |

### 17.3. Demostración del impacto

Sin ninguna credencial, un atacante en la red local habría podido:

1. **Reconocimiento** — Obtener sistema operativo, kernel y arquitectura del nodo vía Prometheus sin autenticación.
2. **Extracción de credenciales** — Leer el hash de la contraseña admin de ntopng directamente desde Redis sin contraseña:
```bash
redis-cli get "ntopng.user.admin.password"
→ [hash MD5 de la contraseña por defecto de ntopng]
```
3. **Acceso a tráfico de red** — Acceder a ntopng sin credenciales y visualizar todos los flujos TCP/UDP de la red en tiempo real.
4. **Mapeo de la red** — Obtener las IPs de todos los dispositivos conectados desde la caché DNS de Redis.

### 17.4. Correcciones aplicadas

**V1, V2 y V3 — Restricción de puertos a localhost**

Prometheus, Node Exporter y pihole-exporter modificados para escuchar únicamente en `127.0.0.1`:

```yaml
ports:
  - "127.0.0.1:9090:9090"
  - "127.0.0.1:9100:9100"
  - "127.0.0.1:9167:9167"
```

**V4 — Autenticación en Redis**

```yaml
command: redis-server --requirepass ${REDIS_PASSWORD} --save "" --appendonly no
```

**V5 — Activación del login en ntopng**

Eliminado `--disable-login=1`. Sintaxis correcta para Redis autenticado:

```yaml
command: ntopng -i wlan0 -w 3001 --community -r 127.0.0.1:6379:${REDIS_PASSWORD}@0
```

**V6 — Cambio de contraseña por defecto de ntopng**

```bash
docker exec -it redis-ntopng redis-cli -a ${REDIS_PASSWORD} \
  set "ntopng.user.admin.password" $(echo -n "NuevaPassword" | md5sum | cut -d' ' -f1)
```

**V7 — Docker Socket Proxy**

Sustituido el montaje directo del socket por `tecnativa/docker-socket-proxy`:

```yaml
docker-proxy:
  image: tecnativa/docker-socket-proxy
  environment:
    - CONTAINERS=1
    - IMAGES=1
    - START=1
    - STOP=1
    - RESTART=1
    - LOGS=1
    - INFO=1
    - POST=1
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock:ro
```

El dashboard se conecta al proxy en lugar del socket directamente:
```yaml
environment:
  - DOCKER_HOST=tcp://127.0.0.1:2375
```

**V8 — Limpieza de Grafana**

Eliminado `env_file` innecesario del servicio Grafana.

### 17.5. Verificación post-hardening

Comprobación desde un equipo externo en la misma red local:
```bash
curl http://IP_RASPBERRY:9090/-/healthy  → 000 (inaccesible) ✅
curl http://IP_RASPBERRY:9100/metrics    → 000 (inaccesible) ✅
curl http://IP_RASPBERRY:9167/metrics    → 000 (inaccesible) ✅
curl http://IP_RASPBERRY:3001/           → 302 (login requerido) ✅
redis-cli -h IP_RASPBERRY ping           → NOAUTH required ✅
```

### 17.6. Superficie de ataque residual

Tras el hardening, los únicos servicios accesibles desde la red local son:

| Puerto | Servicio | Protección |
|--------|---------|-----------|
| 443 | Dashboard Flask (Nginx + TLS) | Autenticación + cifrado |
| 80 | Pi-hole admin | Autenticación |
| 3000 | Grafana | Autenticación |
| 3001 | ntopng | Autenticación |
| 51820/UDP | WireGuard VPN | Criptografía de clave pública |

Todos los servicios de telemetría interna quedaron inaccesibles desde la red tras el hardening.

---

## 18. Licencia

Proyecto académico desarrollado como Trabajo de Fin de Grado.
