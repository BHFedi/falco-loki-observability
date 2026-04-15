FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    curl \
    iputils-ping \
    # needed by update-feeds.sh
    bash \
    grep \
    coreutils \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY . .

# Create the analyser user FIRST
RUN useradd -m -r analyser \
 && mkdir -p /app/cache /app/threatintel/feeds /app/threatintel/rules.d \
 && chown -R analyser:analyser /app

# Make threat intel scripts executable (now as root, before switching user)
RUN chmod +x /app/threatintel/update-feeds.sh /app/threatintel/lookup-ip.sh

USER analyser

# Threat intel feeds directory — override with THREATINTEL_FEEDS_DIR env var
ENV THREATINTEL_FEEDS_DIR=/app/threatintel/feeds

EXPOSE 5000

CMD ["gunicorn","--bind","0.0.0.0:5000","--workers","2","--timeout","120","api:app"]
