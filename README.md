# Sistema de Monitorización y Gestión de Red de Bajo Coste
### TFG — Grado en Ingeniería en Tecnología de Telecomunicación
**Autor:** Ander de Castro  

---

## Descripción

Sistema de monitorización y gestión de red basado en **Raspberry Pi 4** y herramientas de código abierto, orientado a PYMES con presupuesto limitado. Integra filtrado DNS preventivo, análisis de flujos de tráfico en tiempo real, captura de paquetes, telemetría de hardware y un motor de alertas automático, todo accesible desde un dashboard web unificado desarrollado en Flask.

**Alineado con los ODS 4 (Educación de Calidad) y ODS 9 (Industria, Innovación e Infraestructura).**

---

## Arquitectura

El sistema se organiza en tres niveles:

- **Nivel 1 — Dispositivos de usuario:** todos los equipos de la red local cuyo tráfico DNS pasa obligatoriamente por la Raspberry Pi.
- **Nivel 2 — Nodo central (Raspberry Pi 4):** núcleo del sistema con todos los microservicios dockerizados.
- **Nivel 3 — Capa de presentación:** dashboard web accesible desde cualquier navegador, protegido por autenticación y cifrado TLS.

---

## Stack tecnológico

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

## Requisitos previos

- Raspberry Pi 4 (recomendado 4 GB RAM o más)
- Raspberry Pi OS (64 bits)
- Docker y Docker Compose instalados
- Acceso a la red local con capacidad para configurar el DNS primario

### Instalación de Docker en Raspberry Pi OS

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

---

## Instalación y despliegue

### 1. Clonar el repositorio

```bash
git clone https://github.com/a***REMOVED***dc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander
```

### 2. Configurar las credenciales

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

### 3. Arrancar los servicios

```bash
cd pihole
docker compose up -d
```

### 4. Verificar que todos los contenedores están activos

```bash
docker ps
```

Deberías ver los siguientes contenedores en estado `Up`:
`pihole`, `ntopng`, `redis-ntopng`, `tshark-sflow`, `prometheus`, `node-exporter`, `pihole-exporter`, `grafana`, `nginx-siem`, `wireguard`, `mi_dashboard`

---

## Acceso al sistema

| Servicio | URL | Puerto |
|---|---|---|
| Dashboard Flask (SIEM) | `https://IP_RASPBERRY` | 443 (via Nginx) |
| Pi-hole | `http://IP_RASPBERRY:80` | 80 |
| Grafana | `http://IP_RASPBERRY:3000` | 3000 |
| ntopng | `http://IP_RASPBERRY:3001` | 3001 |
| Prometheus | `http://IP_RASPBERRY:9090` | 9090 |

> El dashboard principal es accesible también desde fuera de la red local mediante la VPN WireGuard en el puerto UDP 51820.

---

## Funcionalidades del dashboard

- **Dashboard principal:** métricas DNS en tiempo real (Pi-hole), dispositivos activos y consumo de ancho de banda.
- **Sniffer:** visualización en tiempo real de las capturas de Tshark con filtrado por texto.
- **Gráficas históricas:** tráfico total, consultas DNS y tráfico por dispositivo con selector de rango temporal (6h, 24h, 48h, 7 días).
- **Alertas de seguridad:** registro automático con clasificación por severidad (Crítica, Alta, Media, Baja) basado en cuatro reglas de detección.

### Reglas de detección de alertas

1. Score de amenaza ntopng superior a 100 (crítico si supera 500)
2. Detección de dispositivos con IPs nuevas no vistas anteriormente
3. Tráfico de bajada superior a 5 veces la media histórica de las últimas 24h
4. Picos de más de 50 dominios bloqueados por Pi-hole en 30 segundos

---

## Listas de bloqueo DNS

El sistema utiliza dos listas combinadas:

- **Hagezi Multi Pro** — telemetría, rastreadores, malware y dominios C2
- **StevenBlack/hosts** — publicidad masiva

Base de bloqueo activa: **más de 600.000 dominios**.

---

## Estructura del repositorio

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

## Seguridad

- Las credenciales **nunca se almacenan en el repositorio**. Se gestionan mediante variables de entorno en el archivo `.env` (excluido del control de versiones).
- El acceso al dashboard viaja siempre cifrado mediante TLS (Nginx).
- El acceso remoto se realiza exclusivamente a través de la VPN WireGuard.
- Las claves privadas de WireGuard y los certificados TLS están excluidos del repositorio mediante `.gitignore`.

---

## Consumo energético

| Condición | Consumo |
|---|---|
| Baja carga | ~3-5 W |
| Carga sostenida | ~7-8 W |
| Coste energético anual (24/7) | < 20 € |

---

## Licencia

Proyecto académico desarrollado como Trabajo de Fin de Grado.  

