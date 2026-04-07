FROM python:3.12-slim

WORKDIR /app

# Install dependencies from requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy analysis module
COPY *.py ./

# Create non-root user and cache directory
RUN useradd -m -r analyser && \
    mkdir -p /app/cache && \
    chown -R analyser:analyser /app
USER analyser

EXPOSE 5000

# Use gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "api:app"]
