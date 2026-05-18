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
- [14. Licencia](#14-licencia)

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
git clone https://github.com/a***REMOVED***dc/TFG_deCastro-Ander.git
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
PIHOLE_PASSWORD=tu_contraseña_segura
GRAFANA_PASSWORD=tu_contraseña_segura
WIREGUARD_SERVERURL=tu_ip_local
```

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
- **Alertas de seguridad:** registro automático con clasificación por severidad (Crítica, Alta, Media, Baja) basado en cuatro reglas de detección.

### 7.1. Reglas del Motor de Alertas (Heurística)

1. Score de amenaza ntopng superior a 100 (crítico si supera 500)
2. Detección de dispositivos con IPs nuevas no vistas anteriormente
3. Tráfico de bajada superior a 5 veces la media histórica de las últimas 24h
4. Picos de más de 50 dominios bloqueados por Pi-hole en 30 segundos

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
│   └── templates/           # Plantillas HTML (index, sniffer, graficas, alertas)
└── wireguard_config/        # Configuración de WireGuard (claves excluidas)
```

---

## 10. Buenas Prácticas de Ciberseguridad Aplicadas

- Las credenciales **nunca se almacenan en el repositorio**. Se gestionan mediante variables de entorno en el archivo `.env` (excluido del control de versiones).
- El acceso al dashboard viaja siempre cifrado mediante TLS (Nginx).
- El acceso remoto se realiza exclusivamente a través de la VPN WireGuard.
- Las claves privadas de WireGuard y los certificados TLS están excluidos del repositorio mediante `.gitignore`.

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
git clone https://github.com/a***REMOVED***dc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander/pihole
cp .env.example .env
```

Ahora abre el archivo `.env` para poner tus contraseñas:

```bash
nano .env
```

Verás algo así:

- `PIHOLE_PASSWORD=tu_contraseña_segura`
- `GRAFANA_PASSWORD=tu_contraseña_segura`
- `WIREGUARD_SERVERURL=tu_ip_local`

Sustituye `tu_contraseña_segura` por una contraseña de tu elección y `tu_ip_local` por la IP de tu Raspberry Pi (ej: `192.168.1.100`).

Para guardar: pulsa `Ctrl+O`, luego `Enter`, luego `Ctrl+X` para salir.

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
Edita el archivo `.env`, cambia `PIHOLE_PASSWORD` y reinicia con `docker compose restart`.

---

## 14. Licencia

Proyecto académico desarrollado como Trabajo de Fin de Grado.
