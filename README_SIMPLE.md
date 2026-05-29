# 🛡️ Sistema de Control y Seguridad de Red para Pequeñas Empresas

**Lo que necesitas saber en 30 segundos:**
Este sistema vigila y protege toda tu red Wi-Fi de la empresa con una pequeña caja llamada Raspberry Pi. Te avisa si algo sospechoso sucede (intrusos, accesos raros, etc.) 24/7. Cuesta ~100€ en hardware y casi nada en electricidad.

---

### 📊 Comparación: Con vs Sin este sistema

| Característica | Sin el sistema | Con el sistema |
|---|---|---|
| **¿Bloquea virus?** | Tu antivirus solo (débil) | ✅ **Bloquea ANTES de descargar** |
| **¿Ves qué se descarga?** | No tienes ni idea | ✅ **Gráficos en tiempo real** |
| **¿Sabes si alguien entra?** | No | ✅ **Alerta instantánea al móvil** |
| **¿Cuesta mucho?** | Software caro ($$$) | ✅ **~70€ una sola vez** |
| **¿Consume electricidad?** | N/A | ✅ **Menos de 1€ al mes** |

---

## ¿QUÉ NECESITO?

### 🛠️ Hardware (Lo que tienes que comprar)

**Lista de compra:**

1. **Raspberry Pi 4** — 70€
   - Es como un ordenador del tamaño de una tarjeta de crédito
   - Recomendado: 4GB RAM mínimo

2. **Tarjeta microSD 32GB** — 15€
   - Para guardar el sistema operativo
   - Marca recomendada: SanDisk, Kingston

3. **Cable Ethernet** — 3€
   - Para conectar a tu router
   - ¡IMPORTANTE: cable físico, no Wi-Fi!

4. **Cable USB-C + Adaptador** — 10€
   - Para enchufar a la corriente
   - Poder: 5V/3A mínimo

5. **Opcional: Caja de protección** — 5€
   - Para que no se raye

**TOTAL: ~100€ (único gasto)**

### 🖥️ Software (Gratis)
- ✅ Sistema operativo Raspberry Pi OS (gratis)
- ✅ Docker (gratis)
- ✅ Todas las herramientas (gratis)

### 📡 Requisitos de red
- ✅ Conexión a Internet
- ✅ Acceso a tu router (para cambiar configuración DNS)
- ✅ Estar en la misma red que los ordenadores que quieras vigilar

---

## GUÍA PASO A PASO

### ✅ Paso 1: Preparar la tarjeta microSD (10 minutos)

**¿Qué vamos a hacer?** 
Instalar un sistema operativo en la tarjeta (como Windows en tu ordenador).

**Necesitas:**
- La tarjeta microSD
- Un adaptador para insertarla en tu ordenador
- Descargar un programa: [Raspberry Pi Imager](https://www.raspberrypi.com/software/)

**Instrucciones:**

1. Abre **Raspberry Pi Imager**
2. Selecciona:
   - **Dispositivo:** Raspberry Pi 4
   - **Sistema Operativo:** Raspberry Pi OS (64-bit)
   - **Almacenamiento:** Tu tarjeta microSD
3. Haz clic en **ESCRIBIR** ⏳ (espera 5-10 minutos)
4. Cuando termine, expulsa la tarjeta con seguridad

**Resultado:** Tarjeta lista para instalar ✅

---

### ✅ Paso 2: Conectar la Raspberry Pi (2 minutos)

**¿Qué vamos a hacer?** 
Insertar la tarjeta y encender el dispositivo.

1. Apaga el router (paciencia 30 segundos)
2. Inserta la tarjeta microSD en la Raspberry Pi (por debajo, hacia el lado)
3. **Conecta con cable Ethernet** (¡esto es CRUCIAL!) a tu router
4. Enchufa el cable USB-C a la corriente

**¡La Raspberry Pi se enciende automáticamente!** ✨

La luz roja indica que está encendida. La luz verde parpadea = está funcionando.

---

### ✅ Paso 3: Acceder a la Raspberry desde tu ordenador (5 minutos)

**¿Qué vamos a hacer?** 
Conectarnos remotamente para enviar comandos.

#### En Windows:
1. Abre **PowerShell** (escribe "PowerShell" en el buscador)
2. Copia y pega esto:
   ```
   ssh pi@raspberrypi.local
   ```
3. Presiona Enter
4. Contesta `yes` cuando pida confirmación
5. Contraseña: `raspberry` (escribirá invisible)

#### En Mac/Linux:
1. Abre **Terminal**
2. Lo mismo que arriba

**Si no funciona:** Prueba con la IP que ves en tu router (como `192.168.1.100`)

**Resultado:** Ves un texto que empieza con `pi@raspberrypi` ✅

---

### ✅ Paso 4: Instalar Docker (3 minutos)

**¿Qué es Docker?** 
Es un "empaquetador" que permite ejecutar múltiples programas en la Raspberry Pi sin que interfieran.

En la terminal, copia y pega estos 3 comandos (uno a la vez):

```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

Cada comando tardará un poco. Espera a que vuelva el símbolo `pi@...`.

Luego cierra la terminal y vuelve a conectarte:
```bash
ssh pi@raspberrypi.local
```

**Resultado:** Docker instalado ✅

---

### ✅ Paso 5: Descargar el sistema de vigilancia (3 minutos)

En la terminal:

```bash
git clone https://github.com/aanderdc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander/pihole
cp .env.example .env
```

**Resultado:** Archivos descargados ✅

---

### ✅ Paso 6: Configurar contraseñas (5 minutos)

**¿Qué es .env?** 
Un archivo de contraseñas y configuración (como guardar el PIN en el móvil).

En la terminal:
```bash
nano .env
```

Verás un editor de texto. Cambia esto:

| Línea | Valor actual | Cambia a... | Ejemplo |
|---|---|---|---|
| `PIHOLE_PASSWORD` | `tu_contraseña_segura` | Una contraseña tuya | `Mi2024Segura!` |
| `RASPBERRY_IP` | `192.168.1.X` | Tu IP Raspberry | `192.168.1.100` |
| `GRAFANA_PASSWORD` | `tu_contraseña_segura` | Otra contraseña | `Grafana2024!` |
| `DASHBOARD_PASSWORD` | `tu_contraseña_segura` | Otra contraseña | `Dashboard2024!` |
| Las demás | `tu_...` | Rellena todas igual | La misma que PIHOLE |

**¿Cómo sé mi IP Raspberry?** 
- Accede a tu router (normalmente 192.168.1.1)
- Busca "dispositivos conectados"
- Encuentra "raspberrypi" → esa es tu IP

Para guardar:
1. Presiona `Ctrl + O` (la O mayúscula)
2. Presiona `Enter`
3. Presiona `Ctrl + X` para salir

**Resultado:** Contraseñas guardadas ✅

---

### ✅ Paso 7: Encender el sistema (5 minutos)

En la terminal:

```bash
docker compose up -d
```

Espera 1-2 minutos a que termine. Luego verifica:

```bash
docker ps
```

Deberías ver algo así:

```
CONTAINER ID   STATUS
abcd1234       Up 2 minutes   pihole
efgh5678       Up 2 minutes   ntopng
ijkl9012       Up 2 minutes   grafana
... (más contenedores)
```

Si todos dicen **"Up"** = ¡funciona! ✅

---

### ✅ Paso 8: Configurar tu router (3 minutos)

**¿QUÉ SIGNIFICA ESTO?** 
Le decimos al router "oye, usa la Raspberry Pi como guardaespaldas de internet".

1. Abre tu navegador y ve a: `192.168.1.1` (o la IP de tu router)
2. Entra con usuario/contraseña (suelen estar en una pegatina en el router)
3. Busca: **DHCP** → **Servidor DNS** o similar
4. Cambia el **DNS primario** a: Tu IP Raspberry (ej: `192.168.1.100`)
5. Guarda y reinicia el router

**Después de esto:** Todos los ordenadores/móviles de tu red estarán protegidos 🛡️

---

### ✅ Paso 9: Acceso al panel de control (2 minutos)

Abre tu navegador y ve a:
```
https://192.168.1.100
```

(Reemplaza con tu IP Raspberry)

**⚠️ Verás una advertencia sobre certificado** — es normal, es seguro. Haz clic en "Continuar" o similar.

**Usuario:** `admin` (el que configuraste en .env)  
**Contraseña:** `tu_contraseña_segura`

**¡Ya está! ¡Puedes ver tus gráficos! 📊**

---

## ALGO NO FUNCIONA

### 🔴 "No puedo conectar con SSH"

**Posibles causas y soluciones:**

- **La Raspberry no aparece en la red:**
  - Verifica que el cable Ethernet está bien conectado
  - Espera 2 minutos después de encender
  - Reinicia el router

- **Solución rápida:**
  ```bash
  ping raspberrypi.local
  ```
  Si no funciona, usa la IP directa: `ssh pi@192.168.1.100` (busca tu IP en el router)

### 🔴 "Docker dice error 403"

**Solución:**
```bash
sudo usermod -aG docker $USER
exit  # Cierra y reconecta
ssh pi@raspberrypi.local
docker ps  # Intenta de nuevo
```

### 🔴 "No puedo acceder al panel web"

Comprueba en orden:
- ☐ ¿Está la Raspberry Pi conectada al cable Ethernet?
- ☐ ¿Todos los contenedores dicen "Up"? (`docker ps`)
- ☐ ¿Es la IP correcta? (Mira tu router)
- ☐ ¿Usaste HTTPS (con "s")? Sí, `https://...`

Si nada funciona:
```bash
docker logs mi_dashboard
```

Busca líneas en rojo (errores).

### 🔴 "No puedo acceder con mis credenciales"

**Solución:**
```bash
docker compose down
docker compose up -d --force-recreate
```

Espera 1 minuto y vuelve a intentar.

### 🔴 "¿Dónde están mis gráficos de datos?"

El sistema necesita **24-48 horas** para recopilar datos. Paciencia, luego verás:
- ✅ Dispositivos en la red
- ✅ Ancho de banda usado
- ✅ Bloques de DNS maliciosos
- ✅ Alertas de seguridad

### 🔴 "¿Cómo cambio una contraseña?"

```bash
nano .env
# Edita la contraseña que quieras
docker compose restart mi_dashboard
```

### 🔴 "Un contenedor aparece como 'Exited'"

```bash
docker logs nombre_del_contenedor
```

Esto muestra el error. Ejemplos comunes:

| Error | Solución |
|---|---|
| `permission denied` | `sudo chown -R 472:472 ~/TFG_deCastro-Ander/pihole/grafana_data` |
| `NOAUTH` | Verifica que `REDIS_PASSWORD` no tiene caracteres especiales |
| `certificate not found` | Ejecuta: `mkdir -p nginx/certs && openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout nginx/certs/siem.key -out nginx/certs/siem.crt -subj "/CN=siem"` |

---

## 🚨 ALERTAS: QUÉ SIGNIFICAN

El sistema te avisará cuando vea algo raro:

| Alerta | Significado | ¿Es grave? | Qué hacer |
|---|---|---|---|
| 🟢 **Dispositivo nuevo** | Se conectó un móvil/ordenador que no habíamos visto | ℹ️ Informativo | Nada, es normal |
| 🟠 **Tráfico inusual** | Se descarga MUCHO más de lo normal | ⚠️ Aviso | Revisa qué dispositivo |
| 🔴 **DNS bloqueado masivo** | Muchas URLs maliciosas en poco tiempo | 🚨 CRÍTICO | Revisa ese ordenador |
| 🔴 **Acceso a puerto crítico** | Algo intenta conectar con funciones administrativas | 🚨 CRÍTICO | Aísla el dispositivo |

---

## 💡 TRUCOS Y CONSEJOS

### 📱 Recibir alertas en tu móvil

Puedes configurar notificaciones de Telegram (es gratis):

1. Ve a [@BotFather](https://t.me/botfather) en Telegram
2. Escribe `/newbot` y sigue los pasos
3. Te dará un **TOKEN**
4. Crea un grupo privado y añade tu bot
5. Obtén tu **CHAT_ID** 
6. Edita `.env` y añade:
   ```
   TELEGRAM_TOKEN=tu_token
   TELEGRAM_CHAT_ID=tu_id
   ```
7. Reinicia: `docker compose restart mi_dashboard`

Ahora recibirás alertas **CRÍTICAS** en tu móvil automáticamente 📲

### 🔄 Ver gráficos históricos

En la sección **Gráficas**:
- Desliza los botones para elegir rango (6h, 24h, 7 días)
- Puedes exportar los datos a Excel si quieres

### 💾 Guardar alertas

En **Alertas** hay un botón "Descargar CSV" → puedes abrir en Excel para análisis

### 🔐 Cambiar la clave secreta (avanzado)

Si quieres mayor seguridad de sesión:
```bash
nano .env
# Cambia FLASK_SECRET_KEY a algo largo y aleatorio
docker compose restart mi_dashboard
```

---

## 🔧 MANTENIMIENTO BÁSICO

### Cada semana
- ✅ Revisar alertas (1 minuto)
- ✅ Nota si hay dispositivos nuevos sospechosos

### Cada mes
- ✅ Reiniciar sistema: `docker compose restart`
- ✅ Revisar el ancho de banda consumido

### Cada 6 meses
- ✅ Actualizar todo: 
  ```bash
  docker compose pull
  docker compose up -d
  ```

---

## 📞 PREGUNTAS FRECUENTES

### ❓ "¿Necesito conocimientos de Linux?"
No, esta guía es paso a paso. Solo necesitas copiar y pegar comandos.

### ❓ "¿Se puede perder la red?"
No, si algo falla, los ordenadores seguirán conectados (solo sin protección). Es muy seguro.

### ❓ "¿Puedo añadir más dispositivos después?"
Sí, se detectan automáticamente. No hay que tocar nada más.

### ❓ "¿Qué pasa si apago la Raspberry?"
Todo sigue funcionando, solo sin protección DNS. Se reinicia automáticamente si vuelves a enchufar.

### ❓ "¿Es fácil de mover a otro lugar?"
Sí, solo apaga, transporta y enchufa en otro sitio. Funciona automáticamente.

### ❓ "¿Cuántos dispositivos puede vigilar?"
Hasta 200-300 dispositivos sin problema. Más que eso requiere hardware mejor.

### ❓ "¿Puede hackearse?"
Es muy difícil. Está protegido con autenticación y cifrado. Más seguro que un router normal.

### ❓ "¿Qué pasa con mi privacidad?"
Los datos se guardan SOLO en tu Raspberry Pi. No se envía nada a internet (salvo si configuras Telegram).

