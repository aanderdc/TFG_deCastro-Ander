# 🛡️ Guía Práctica de Instalación para Librerías e Imprentas

Esta guía explica cómo poner en marcha tu sistema de protección de red en **menos de 20 minutos** sin necesidad de ser informático.

---

## 1. ¿Qué necesitas? (~100 € pago único)
1. **Raspberry Pi 4 (4 GB RAM)** con fuente USB-C 5V/3A.
2. **Tarjeta microSD de 32 GB** (SanDisk o Kingston).
3. **Cable de red Ethernet** para conectarla directamente al router de la tienda (**siempre por cable**, nunca solo por Wi-Fi).

---

## 2. Preparar la Raspberry Pi
1. Instala **Raspberry Pi OS (64-bit)** en la microSD usando [Raspberry Pi Imager](https://www.raspberrypi.com/software/) y activa **SSH** en sus ajustes avanzados (crea tu usuario y una contraseña fuerte).
2. Conecta la Raspberry al router con el **cable Ethernet** y enciéndela.
3. Accede desde tu PC (PowerShell en Windows o Terminal en Mac/Linux):
   ```bash
   ssh tu_usuario@raspberrypi.local
   ```
4. Instala Docker:
   ```bash
   curl -fsSL https://get.docker.com -o get-docker.sh
   sudo sh get-docker.sh
   sudo usermod -aG docker $USER
   ```
   Cierra sesión (`exit`) y vuelve a entrar por SSH.

---

## 3. Instalar el SIEM en 1 paso
```bash
git clone https://github.com/aanderdc/TFG_deCastro-Ander.git
cd TFG_deCastro-Ander
chmod +x scripts/setup.sh
./scripts/setup.sh
```
El asistente te pedirá:
- El **nombre de tu librería o imprenta**.
- Tu **horario comercial** (para avisarte si alguien usa la red o las impresoras de madrugada).
- Confirmará tu cable de red (`eth0`) y generará todas las contraseñas y certificados HTTPS automáticamente.

Después arranca el sistema:
```bash
cd pihole
docker compose up -d --build
```

---

## 4. Activar la protección en toda la tienda
1. Entra en tu router (normalmente `http://192.168.1.1`) y cambia el **DNS primario** en DHCP a la IP de la Raspberry Pi.
2. Abre en tu navegador `https://IP_DE_TU_RASPBERRY` (acepta el aviso inicial del certificado local) e inicia sesión con el usuario y contraseña que mostró `setup.sh`.

---

## 5. Primeros 5 minutos dentro del panel (MUY IMPORTANTE)
1. Ve a **🏪 Mi Negocio** y registra tus equipos clave pulsando los botones rápidos:
   - **🖨️ Plotters e impresoras de red** (puerto `9100` o `631`) → te avisará si se caen o si un móvil de cliente intenta imprimir sin permiso.
   - **💳 TPV / Caja registradora** → te avisará si algún dispositivo desconocido intenta acceder a ella.
   - **🗄️ NAS / Servidor de diseños** (puerto `445`) → vigilancia reforzada frente a ransomware y exfiltración.
2. *(Opcional recomendado)* Configura **Telegram** en `pihole/.env` (`TELEGRAM_TOKEN` y `TELEGRAM_CHAT_ID`) y reinicia con `docker compose restart dashboard` para recibir avisos críticos al instante en tu móvil.
3. Cada mes pulsa **📄 Informe PDF** arriba a la derecha para guardar una copia del estado de seguridad y disponibilidad de tu negocio.
