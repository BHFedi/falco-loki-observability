FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    curl \
    iputils-ping \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -r analyser \
 && mkdir -p /app/cache \
 && chown -R analyser:analyser /app

USER analyser

EXPOSE 5000

CMD ["gunicorn","--bind","0.0.0.0:5000","--workers","2","--timeout","120","api:app"]
