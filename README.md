# 🛡️ Sistema de Monitorización y Gestión de Red de bajo coste para entorno PYME— TFG

**Grado en Ingeniería en Tecnología de Telecomunicación**  
**Autor:** Ander de Castro · Raspberry Pi 4 · Código abierto

---

## ¿Qué es esto?

Sistema de monitorización de red de bajo coste para entornos PYMES, desplegado sobre una Raspberry Pi 4. Integra filtrado DNS, análisis de tráfico, detección de amenazas y un dashboard web propio.

**Funciones principales:**
- Filtrado DNS preventivo con bloqueo de dominios maliciosos
- Análisis de flujos TCP/UDP en tiempo real (ntopng)
- Captura de paquetes y detección de tráfico lateral (Tshark)
- Motor de alertas con reglas heurísticas
- Dashboard web unificado con gráficas históricas
- Notificaciones automáticas por Telegram
- Acceso remoto seguro por VPN (WireGuard)

---

## 🚀 Despliegue rápido

### Requisitos
- Raspberry Pi 4 (4 GB RAM recomendados)
- Tarjeta microSD 16+ GB o disco duro
- Docker instalado

```bash
# Instalar Docker si no lo tienes
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
```

### Instalación

```bash
git clone https://github.com/aanderdc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander/pihole
cp .env.example .env
nano .env        # Edita contraseñas e IPs
docker compose up -d
docker ps        # Verifica que los contenedores están UP
```

### Configurar DNS en el router
Cambia el **DNS primario** de tu router a la IP de la Raspberry (ej: `192.168.1.100`).

### Acceder al dashboard
Abre `https://IP_DE_TU_RASPBERRY` en el navegador. Acepta el aviso de certificado.

---

## 🗂️ Acceso a los servicios

| Servicio | URL | Credenciales |
|----------|-----|--------------|
| **Dashboard (SIEM)** | `https://IP` | `DASHBOARD_USER` / `DASHBOARD_PASSWORD` |
| **Pi-hole** | `http://IP:80` | `PIHOLE_PASSWORD` |
| **Grafana** | `http://IP:3000` | `admin` / `GRAFANA_PASSWORD` |
| **ntopng** | `http://IP:3001` | `admin` / `NTOPNG_PASSWORD` |
| **WireGuard** | `IP:51820/UDP` | Certificados de cliente |

> Prometheus, Node Exporter y pihole-exporter están restringidos a `localhost`.

---

## 📲 Configurar notificaciones Telegram

### 1. Crear el bot
1. Abre Telegram y busca **@BotFather**
2. Envía `/newbot` y sigue las instrucciones
3. Guarda el **token** que te dará BotFather

### 2. Obtener tu Chat ID
Envía cualquier mensaje a tu bot y ejecuta:
```bash
curl "https://api.telegram.org/botTU_TOKEN/getUpdates"
```
Busca el campo `"id"` dentro de `"chat"`.

### 3. Configurar el .env
```bash
nano ~/TFG_deCastro-Ander/pihole/.env
```
```env
TELEGRAM_TOKEN=tu_token_aqui
TELEGRAM_CHAT_ID=tu_chat_id_aqui
```

### 4. Reiniciar el dashboard
```bash
cd ~/TFG_deCastro-Ander/pihole
docker compose restart dashboard
docker exec mi_dashboard env | grep TELEGRAM  # Verificar
```

---

## ⚠️ Motor de alertas

| Regla | Condición | Severidad | Telegram |
|-------|-----------|-----------|----------|
| `SCORE_ALTO` | ntopng score > 100 (crítico > 500) | CRÍTICA/ALTA | 
| `DISPOSITIVO_NUEVO` | IP no vista anteriormente | MEDIA | 
| `TRAFICO_ALTO` | Bajada > 5x media 24h y > 10MB | ALTA | 
| `DNS_BLOQUEADAS` | > 50 dominios bloqueados en 30s | ALTA | 
| `FLOOD_DETECTADO` | > 500 flows activos desde una IP | CRÍTICA/ALTA | 
| `RATIO_ANOMALO` | Subida/bajada > 10x y subida > 50MB | ALTA | 
| `LATERAL_SCAN` | > 5 IPs internas contactadas en 30s | CRÍTICA/ALTA | 
| `LATERAL_PORT` | Conexión a RDP/SMB/SSH/Telnet/VNC | CRÍTICA | 
| `BEACONING` | Contacto regular a IP externa (CV < 0.3) | CRÍTICA/ALTA | 
| `DNS_OVER_HTTPS` | Conexión a resolver DoH conocido (puerto 443) | ALTA | 
| `JA3_C2` | Huella TLS asociada a Cobalt Strike/Metasploit/Sliver | CRÍTICA | 
Puede que se añadan más en siguientes versiones.
---

## 🏗️ Arquitectura

```
INTERNET
    │
    ▼
┌─────────────┐
│   ROUTER    │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────┐
│       RASPBERRY PI 4            │
│                                 │
│  Pi-hole      → Filtrado DNS    │
│  ntopng       → Flujos L7       │
│  Tshark       → Captura paquetes│
│  Flask SIEM   → Dashboard web   │
│  Prometheus   → Métricas HW     │
│  Grafana      → Visualización   │
│  WireGuard    → VPN remota      │
│  Nginx        → Proxy TLS       |
|  Más contenedores.....          │
└─────────────────────────────────┘
```

## 🛠️ Stack completo

| Servicio | Imagen | Función |
|----------|--------|---------|
| Pi-hole | `pihole/pihole:latest` | Filtrado DNS |
| ntopng | `ntop/ntopng_arm64.dev:latest` | Análisis flujos |
| Tshark | `ubuntu:22.04` | Captura paquetes |
| Tshark-JA3 | `ubuntu:22.04` | Huellas TLS |
| Flask | `python:3.9-slim` | Dashboard + alertas |
| Grafana | `grafana/grafana-oss:latest` | Gráficas históricas |
| Prometheus | `prom/prometheus:latest` | Series temporales |
| Node Exporter | `prom/node-exporter:latest` | Métricas SO |
| pihole-exporter | `ekofr/pihole-exporter:latest` | Bridge Pi-hole→Prometheus |
| Redis | `redis:alpine` | Caché ntopng |
| Nginx | `nginx:alpine` | Proxy inverso TLS |
| WireGuard | `linuxserver/wireguard:latest` | VPN |
| Docker Proxy | `tecnativa/docker-socket-proxy` | Acceso seguro Docker API |

> Los servicios `prometheus`, `pihole-exporter`, `grafana` y `mitmproxy` son opcionales (`profiles: ["opcional"]`), consumen recursos excesivos, pero se pueden encender desde el dashboard.

---

## 🌐 Visibilidad de red

ntopng y Tshark capturan el tráfico que **pasa por la Raspberry**. El tráfico lateral entre dispositivos no es visible por defecto.

**Soluciones para visibilidad total:**

| Opción | Coste | Dificultad |
|--------|-------|-----------|
| Port Mirroring en router | 0 € | Baja |
| Switch gestionable (SPAN) | desde 30 € | Baja |
| Raspberry como gateway (ej: con adaptador USB-Ethernet) | ~20 € | Media |

**Switches baratos:** TP-Link TL-SG105E (~25€), Netgear GS305E (~30€)
---
 
## 🔗 Acceso externo rápido: ngrok
 
ngrok permite exponer el dashboard a internet en segundos, sin necesidad de configurar DNS ni abrir puertos en el router. Útil para pruebas o acceso puntual.
 
> ⚠️ **Advertencia:** ngrok expone el dashboard públicamente. Asegúrate de tener configuradas contraseñas fuertes en el `.env` antes de activarlo.
 
### 1. Crear cuenta y obtener token
 
1. Regístrate en [https://dashboard.ngrok.com](https://dashboard.ngrok.com)
2. Ve a **Your Authtoken** y copia el token
### 2. Configurar el .env
 
```bash
nano ~/TFG_deCastro-Ander/pihole/.env
```
```env
NGROK_AUTHTOKEN=tu_token_aqui
```
 
### 3. Arrancar ngrok
 
ngrok está configurado como servicio opcional. Para activarlo:
 
```bash
cd ~/TFG_deCastro-Ander/pihole
docker compose --profile opcional up -d ngrok
```
 
### 4. Obtener la URL pública
 
```bash
docker logs ngrok 2>&1 | grep "url="
# O accede a http://127.0.0.1:4040 desde la Raspberry para ver el panel de ngrok
```
 
La URL tendrá el formato `https://xxxx-xx-xx-xxx-xx.ngrok-free.app`.
 
### 5. Parar ngrok cuando no lo necesites
 
```bash
docker compose stop ngrok
```
 
> Para acceso externo permanente se recomienda usar **DuckDNS + Let's Encrypt** (sección siguiente), que no depende de terceros y no expone el servicio públicamente.
 
---

## 🌍 Acceso externo: DuckDNS + Let's Encrypt

```bash
# 1. Crear dominio en https://www.duckdns.org

# 2. Script de actualización DNS automática
mkdir -p ~/duckdns
cat > ~/duckdns/duck.sh << 'EOF'
echo url="https://www.duckdns.org/update?domains=TU_DOMINIO&token=TU_TOKEN&ip=" | curl -k -o ~/duckdns/duck.log -K -
EOF
chmod +x ~/duckdns/duck.sh
# Añadir a crontab: */5 * * * * ~/duckdns/duck.sh >/dev/null 2>&1

# 3. Certificado Let's Encrypt
sudo apt install certbot -y
docker compose stop nginx
sudo certbot certonly --standalone -d tunombre.duckdns.org --email tu@email.com --agree-tos --non-interactive

# 4. Copiar certificados
sudo cp /etc/letsencrypt/live/tunombre.duckdns.org/fullchain.pem pihole/nginx/certs/
sudo cp /etc/letsencrypt/live/tunombre.duckdns.org/privkey.pem pihole/nginx/certs/
docker compose start nginx
```

---

## 🔒 Seguridad aplicada

| Componente | Medida |
|------------|--------|
| Credenciales | Variables de entorno (`.env`) |
| Acceso web | TLS obligatorio (Nginx) |
| Acceso remoto | VPN WireGuard |
| Docker API | Socket Proxy (acceso restringido) |
| Métricas | Restringidas a `localhost` |
| Redis | Autenticación obligatoria |
| Login dashboard | Rate limiting + CSRF token |
| Sesiones | Expiración 24h |

---

## ❌ Solución de problemas

**Contenedor en "Exited":**
```bash
docker logs nombre_contenedor
```

**Dashboard no accesible:**
- Verifica que estás en la misma red que la Raspberry
- El aviso de certificado es normal, acéptalo

**Pi-hole no bloquea:**
```bash
# Verifica que el DNS del router apunta a la Raspberry
nslookup google.com IP_RASPBERRY
```

**Variables de entorno no cargadas:**
```bash
docker exec mi_dashboard env | grep DASHBOARD
# Si están vacías:
docker compose up -d --force-recreate dashboard
```

**Grafana sin permisos:**
```bash
sudo chown -R 472:472 ~/TFG_deCastro-Ander/pihole/grafana_data
docker compose restart grafana
```

**Redis con caracteres especiales en contraseña:**
Usa solo caracteres alfanuméricos en `REDIS_PASSWORD`.

---

## 📁 Estructura del repositorio

```
TFG_deCastro-Ander/
├── pihole/
│   ├── docker-compose.yml     # Orquestación de servicios
│   ├── .env.example           # Plantilla de credenciales
│   ├── prometheus.yml         # Configuración de métricas
│   └── nginx/                 # Proxy inverso + certificados TLS
├── dashboard/
│   ├── app.py                 # Backend Flask + motor de alertas
│   └── templates/             # Vistas HTML del dashboard
└── wireguard_config/          # Configuración VPN (excluida del repo)
```

---

## 📄 Licencia

Proyecto académico — Trabajo de Fin de Grado.  
Alineado con ODS 4 (Educación de Calidad) y ODS 9 (Industria, Innovación e Infraestructura).
