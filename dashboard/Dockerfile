FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Europe/Madrid

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends tzdata curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --create-home --shell /bin/bash siem && \
    mkdir -p /app/data && \
    chown -R siem:siem /app

USER siem

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:5000/healthz || exit 1

# Un solo proceso worker con múltiples hilos para evitar duplicar el hilo recolector en segundo plano
CMD ["gunicorn", "--bind", "127.0.0.1:5000", "--workers", "1", "--threads", "4", "--timeout", "60", "--access-logfile", "-", "wsgi:application"]
