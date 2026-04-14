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

# Make threat intel scripts executable and create the feeds directory so the
# container starts cleanly even before update-feeds.sh has been run.
RUN chmod +x /app/threatintel/update-feeds.sh /app/threatintel/lookup-ip.sh \
 && mkdir -p /app/threatintel/feeds

RUN useradd -m -r analyser \
 && mkdir -p /app/cache \
 && chown -R analyser:analyser /app

USER analyser

# Threat intel feeds directory — override with THREATINTEL_FEEDS_DIR env var
# if you prefer to mount feeds from outside the container.
ENV THREATINTEL_FEEDS_DIR=/app/threatintel/feeds

EXPOSE 5000

CMD ["gunicorn","--bind","0.0.0.0:5000","--workers","2","--timeout","120","api:app"]
