# Sistema de Monitorización y Gestión de Red de Bajo Coste
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
- [15. Licencia](#15-licencia)

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
| **Redis** | Caché de flujos para ntopng |
| **Nginx** | Proxy inverso con cifrado TLS |
| **WireGuard** | VPN para acceso remoto seguro |
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
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=tu_contraseña_segura
FLASK_SECRET_KEY=cadena_larga_y_aleatoria
WIREGUARD_SERVERURL=tu_ip_publica
```

> Todas las credenciales se gestionan exclusivamente mediante variables de entorno. El archivo `.env` nunca se sube al repositorio.

### 5.3. Inicialización del Entorno Multi-Contenedor

```bash
cd pihole
docker compose up -d
```

### 5.4. Verificación del Estado

```bash
docker ps
```

Deberías ver los siguientes contenedores en estado `Up`:
`pihole`, `ntopng`, `redis-ntopng`, `tshark-sflow`, `prometheus`, `node-exporter`, `pihole-exporter`, `grafana`, `nginx-siem`, `wireguard`, `mi_dashboard`

---

## 6. Matriz de Acceso al Sistema

| Servicio | URL | Puerto |
|---|---|---|
| Dashboard Flask (SIEM) | `https://IP_RASPBERRY` | 443 (via Nginx) |
| Pi-hole | `http://IP_RASPBERRY:80` | 80 |
| Grafana | `http://IP_RASPBERRY:3000` | 3000 |
| ntopng | `http://IP_RASPBERRY:3001` | 3001 |
| Prometheus | `http://IP_RASPBERRY:9090` | 9090 |

> El dashboard principal es accesible también desde fuera de la red local mediante la VPN WireGuard en el puerto UDP 51820.

---

## 7. Funcionalidades del Dashboard Core

- **Dashboard principal:** métricas DNS en tiempo real (Pi-hole), dispositivos activos y consumo de ancho de banda.
- **Sniffer:** visualización en tiempo real de las capturas de Tshark con filtrado por texto.
- **Gráficas históricas:** tráfico total, consultas DNS y tráfico por dispositivo con selector de rango temporal (6h, 24h, 48h, 7 días).
- **Alertas de seguridad:** registro automático con clasificación por severidad (Crítica, Alta, Media, Baja) basado en seis reglas de detección.
- **Red Interna:** mapa visual de conexiones entre dispositivos de la red local, con detección de escaneos internos y conexiones a puertos críticos.

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

```
TFG_deCastro-Ander/
├── pihole/                  # Configuración de todos los servicios Docker
│   ├── docker-compose.yml   # Orquestación de los 11 microservicios
│   ├── .env.example         # Plantilla de variables de entorno
│   ├── nginx/               # Configuración de Nginx y certificados TLS
│   └── ...
├── dashboard/               # Código fuente del dashboard Flask
│   ├── app.py               # Backend principal (API, alertas, logging)
│   └── templates/           # Plantillas HTML (index, sniffer, graficas, alertas, lateral)
└── wireguard_config/        # Configuración de WireGuard (claves excluidas)
```

---

## 10. Buenas Prácticas de Ciberseguridad Aplicadas

- Las credenciales **nunca se almacenan en el repositorio**. Se gestionan mediante variables de entorno en el archivo `.env` (excluido del control de versiones).
- Todas las variables sensibles están centralizadas en `.env`: contraseñas de Pi-hole, Grafana, ntopng, dashboard Flask y clave de sesión.
- El acceso al dashboard viaja siempre cifrado mediante TLS (Nginx).
- El acceso remoto se realiza exclusivamente a través de la VPN WireGuard.
- Las claves privadas de WireGuard y los certificados TLS están excluidos del repositorio mediante `.gitignore`.
- El historial de git ha sido limpiado con BFG Repo Cleaner para garantizar que ninguna credencial queda en commits anteriores.

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

Deberías ver 11 contenedores en estado **Up**. Si alguno aparece como **Exited**, consulta la sección [Resolución de problemas](#13-resolución-de-problemas-frecuentes-faq).

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
Esto muestra el error. Los más comunes están documentados en el Anexo III de la memoria del TFG.

**No puedo acceder al dashboard**  
Comprueba que estás en la misma red Wi-Fi que la Raspberry Pi.

**Pi-hole no bloquea nada**  
Verifica que el DNS de tu router apunta a la IP correcta de la Raspberry Pi (Paso 6).

**Olvidé la contraseña del dashboard**  
Edita el archivo `.env`, cambia `DASHBOARD_PASSWORD` y reinicia con `docker compose restart`.

---

## 14. Visibilidad de Red: Limitaciones y Ampliaciones

### 14.1. El problema: tráfico que el sistema no puede ver

En la arquitectura actual, ntopng y tshark escuchan sobre la interfaz `wlan0` de la Raspberry Pi. Esto significa que el sistema **solo captura el tráfico que pasa directamente por la Raspberry**, no el tráfico que circula entre otros dispositivos de la red.

```
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

- **Tráfico lateral (East-West):** comunicaciones entre dispositivos de la misma red (PC ↔ servidor, móvil ↔ impresora).
- **Escaneo interno:** un dispositivo comprometido escaneando otros equipos de la red en busca de vulnerabilidades.
- **Movimiento lateral de malware:** propagación de ransomware entre equipos internos.
- **Transferencias entre dispositivos:** archivos enviados de un equipo a otro sin salir a internet.

**¿Por qué es relevante para una PYME?**

El movimiento lateral es la fase más crítica de un ataque de ransomware:

```
Fase 1 — Entrada via DNS malicioso   → ✅ Pi-hole lo bloquea
Fase 2 — Contacto con servidor C2    → ✅ ntopng detecta el score
Fase 3 — Movimiento lateral interno  → ⚠️  Detección parcial (ver sección 14.2)
Fase 4 — Cifrado de archivos         → ❌ Demasiado tarde
```

---

### 14.2. Detección de tráfico interno implementada

El sistema incorpora una capa de detección de tráfico lateral basada en el análisis de las capturas de Tshark. Aunque sin port mirroring no se ve todo el tráfico East-West, el módulo **Red Interna** analiza cada 30 segundos las tramas capturadas buscando comunicaciones entre IPs internas (`192.168.x.x → 192.168.x.x`) que sí pasen por la Raspberry.

**Qué detecta:**

- Pares de dispositivos internos que se comunican entre sí
- Mapa visual de conexiones internas actualizado en tiempo real
- **Regla `LATERAL_SCAN`:** un dispositivo contacta más de 5 IPs internas distintas en 30 segundos → alerta ALTA. Más de 15 → alerta CRÍTICA. Patrón típico de ransomware en fase de reconocimiento.
- **Regla `LATERAL_PORT`:** conexión interna a puerto crítico (RDP 3389, SMB 445, SSH 22, Telnet 23, VNC 5900) → alerta CRÍTICA. Estos protocolos son los vectores más habituales de movimiento lateral.

**Dónde verlo:**

Accede a la sección **Red Interna** del dashboard. Muestra el mapa de conexiones, el ranking de dispositivos por número de destinos contactados y el histórico de conexiones con filtro temporal (1h, 6h, 24h).

**Limitación que persiste:**

Esta detección solo cubre el tráfico que pasa físicamente por la Raspberry Pi. Las comunicaciones entre dos dispositivos que no involucren a la Raspberry siguen siendo invisibles sin las soluciones descritas en la sección 14.3.

---

### 14.3. Soluciones para visibilidad total de red

#### Opción 1 — Port Mirroring en el router

Si tu router lo soporta, puedes configurarlo para que clone todo el tráfico y lo envíe a la Raspberry, sin modificar nada de la arquitectura de red.

**Coste:** 0 € (sin hardware adicional)  
**Dificultad:** Baja  
**Requisito:** Que el router soporte port mirroring (la mayoría de routers domésticos no lo tienen)

**Cómo comprobarlo:**
1. Entra a la configuración de tu router: `http://192.168.1.1`
2. Busca las opciones `Port Mirror`, `SPAN Port` o `Traffic Mirror`
3. Si aparece, configura el puerto de destino como la IP de la Raspberry Pi

---

#### Opción 2 — Raspberry Pi como gateway (visibilidad total)

Se coloca la Raspberry Pi **entre el router y el resto de la red**. Todo el tráfico pasa físicamente por ella, lo que permite capturarlo completamente.

```
INTERNET → ROUTER → RASPBERRY PI → SWITCH → Dispositivos
                        eth0    eth1
                      (hacia   (hacia
                      router)   LAN)
                          ↑
                   Todo el tráfico
                    pasa por aquí
```

**Coste:** ~25 € (adaptador USB-Ethernet + switch básico)  
**Dificultad:** Media  
**Visibilidad:** Total — todo el tráfico de la red, incluyendo el lateral

**Hardware necesario:**
- **Adaptador USB-Ethernet** (~10 €): para tener una segunda interfaz de red en la Raspberry Pi.
- **Switch básico** (~15 €): para conectar todos los dispositivos a la segunda interfaz.

**Configuración paso a paso:**

```bash
# 1. Identificar interfaces
ip link show
# eth0 → router (WAN) | eth1 → adaptador USB (LAN)

# 2. Activar reenvío de paquetes
echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 3. Configurar NAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo apt install iptables-persistent -y
sudo netfilter-persistent save

# 4. Forzar DNS al Pi-hole
sudo iptables -t nat -A PREROUTING -i eth1 -p udp --dport 53 -j DNAT --to-destination 192.168.1.X:53
sudo iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 53 -j DNAT --to-destination 192.168.1.X:53
```

Modificar `docker-compose.yml` para escuchar en ambas interfaces:
```yaml
ntopng:
  command: ntopng -i eth1 -i wlan0 -w 3001 --community --disable-login=1 -r 127.0.0.1

tshark-sflow:
  command: >
    bash -c "apt-get update -qq && apt-get install -y -qq tshark &&
    touch /logs/tshark_capture.txt && chmod 666 /logs/tshark_capture.txt &&
    tshark -i eth1 -s 1600 -l >> /logs/tshark_capture.txt 2>&1"
```

---

#### Opción 3 — Switch gestionable con SPAN port (recomendada)

Se añade un switch gestionable entre el router y los dispositivos. El switch clona todo el tráfico y lo envía a la Raspberry a través de un puerto espejo, sin modificar la arquitectura existente.

```
INTERNET → ROUTER → SWITCH GESTIONABLE → Dispositivos
                          │
                          │ Puerto espejo (SPAN)
                          ▼
                     RASPBERRY PI
                   ntopng · tshark
                  ven todo el tráfico
```

**Coste:** ~25-35 €  
**Dificultad:** Baja — solo configuración web  
**Visibilidad:** Total  
**Ventaja:** No altera la topología de red

**Switches compatibles recomendados:**

| Modelo | Precio aprox. | Puertos |
|--------|--------------|---------|
| TP-Link TL-SG105E | ~25 € | 5x GbE |
| Netgear GS305E | ~30 € | 5x GbE |
| TP-Link TL-SG108E | ~35 € | 8x GbE |

**Configuración en TP-Link TL-SG105E:**
1. Conecta el switch entre el router y los dispositivos.
2. Conecta la Raspberry Pi al puerto 5 del switch.
3. Accede a la interfaz web del switch.
4. Ve a **Switching → Port Mirror** y configura:
   - **Mirror Port (destino):** Puerto 5
   - **Mirrored Ports (origen):** Puertos 1, 2, 3, 4
   - **Mode:** Ingress + Egress
5. Guarda. Desde ese momento ntopng y tshark ven todo el tráfico.

```yaml
# Ajuste en docker-compose.yml si el tráfico llega por eth0:
ntopng:
  command: ntopng -i eth0 -i wlan0 -w 3001 --community --disable-login=1 -r 127.0.0.1
```

---

### 14.4. Comparativa de opciones

| Opción | Coste | Dificultad | Visibilidad | Modifica la red |
|--------|-------|------------|-------------|-----------------|
| Port Mirror en router | 0 € | Baja | Total | No |
| Raspberry como gateway | ~25 € | Media | Total | Sí |
| Switch gestionable (SPAN) | ~30 € | Baja | Total | No |
| **Arquitectura actual** | **0 €** | **—** | **Parcial + detección activa** | **No** |

---

### 14.5. Estado actual del proyecto

La arquitectura actual captura el tráfico que atraviesa la Raspberry Pi e incorpora detección activa de patrones de movimiento lateral sobre ese tráfico:

- ✅ Filtrado DNS preventivo de más de 600.000 dominios maliciosos
- ✅ Detección de comunicaciones con servidores C2 conocidos
- ✅ Identificación de dispositivos por MAC y fabricante
- ✅ Motor de alertas con clasificación de severidad (6 reglas)
- ✅ Captura de paquetes HTTP/DNS en tiempo real
- ✅ Detección de escaneos internos (`LATERAL_SCAN`) y conexiones a puertos críticos (`LATERAL_PORT`)
- ✅ Mapa visual de conexiones internas en tiempo real (sección **Red Interna**)
- ⚠️ Tráfico lateral entre dispositivos que no involucran a la Raspberry: requiere port mirroring (sección 14.3)

La implementación de cualquiera de las opciones de la sección 14.3 eliminaría la limitación restante y convertiría el sistema en una solución de visibilidad total de red.

---

## 15. Licencia

Proyecto académico desarrollado como Trabajo de Fin de Grado.
