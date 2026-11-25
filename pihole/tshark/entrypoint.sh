#!/bin/bash
set -euo pipefail

MODE="${TSHARK_MODE:-sflow}"
IFACE="${NET_INTERFACE:-eth0}"
MAX_BYTES="${TSHARK_MAX_LOG_BYTES:-20971520}"  # 20 MB por defecto (protege la microSD)

# Auto-fallback si la interfaz configurada no existe
if ! ip link show "$IFACE" >/dev/null 2>&1; then
    FALLBACK=$(ip -o -4 route show to default | awk '{print $5}' | head -n1 || true)
    if [ -n "$FALLBACK" ]; then
        echo "[tshark] Interfaz '$IFACE' no encontrada; usando interfaz por defecto '$FALLBACK'"
        IFACE="$FALLBACK"
    fi
fi

mkdir -p /logs

# Rotación automática en segundo plano para evitar llenar la tarjeta microSD
rotate_loop() {
    local target="$1"
    local header="${2:-}"
    while true; do
        sleep 60
        if [ -f "$target" ]; then
            local size
            size=$(stat -c%s "$target" 2>/dev/null || echo 0)
            if [ "$size" -gt "$MAX_BYTES" ]; then
                echo "[tshark] Rotando $target ($size bytes > $MAX_BYTES)"
                cp "$target" "${target}.old" 2>/dev/null || true
                if [ -n "$header" ]; then
                    printf '%s\n' "$header" > "$target"
                else
                    : > "$target"
                fi
            fi
        fi
    done
}

if [ "$MODE" = "ja3" ]; then
    LOG_FILE="/logs/tshark_ja3.csv"
    HEADER="ip.src,ip.dst,tcp.dstport,tls.handshake.ja3,tls.handshake.ja3s"
    if [ ! -s "$LOG_FILE" ]; then
        printf '%s\n' "$HEADER" > "$LOG_FILE"
    fi
    rotate_loop "$LOG_FILE" "$HEADER" &
    exec tshark -i "$IFACE" -s 1600 -l \
        -Y 'tls.handshake.type == 1 or tls.handshake.type == 2' \
        -T fields -e ip.src -e ip.dst -e tcp.dstport \
        -e tls.handshake.ja3 -e tls.handshake.ja3s \
        -E separator=, -E header=n >> "$LOG_FILE" 2>&1
else
    LOG_FILE="/logs/tshark_capture.txt"
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
    rotate_loop "$LOG_FILE" &
    exec tshark -i "$IFACE" -s 1600 -l >> "$LOG_FILE" 2>&1
fi
