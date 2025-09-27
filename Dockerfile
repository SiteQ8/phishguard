# filename: Dockerfile
# Production-ready Dockerfile for PhishGuard
# - Uses Python slim base image
# - Installs deps with pip (no root user used for app)
# - Runs via Gunicorn + eventlet to support SocketIO/WebSockets

FROM python:3.11-slim

# Set non-root user for better security
ARG USER=appuser
ARG UID=10001
ARG GID=10001

# Install system deps required by common Python packages and DNS/WHOIS utils if used
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    git \
    # optional: whois + dnsutils if domain_analyzer uses them at runtime
    whois \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy only requirements first for layer caching
COPY requirements.txt /app/requirements.txt

# Install OpenSquat and its dependencies
RUN git clone https://github.com/atenreiro/opensquat.git /opt/opensquat && \
    cd /opt/opensquat && \
    pip install --no-cache-dir -r requirements.txt

# Upgrade pip and install PhishGuard dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt && \
    # Install gunicorn + eventlet explicitly in case not included
    pip install --no-cache-dir gunicorn eventlet

# Create a non-root user and switch
RUN groupadd -g ${GID} ${USER} && useradd -m -u ${UID} -g ${GID} ${USER}
USER ${USER}

# Copy application code
COPY . /app/

# Environment defaults (can be overridden)
ENV FLASK_ENV=production \
    LOG_LEVEL=INFO \
    SECRET_KEY=change-me-in-env \
    CERTSTREAM_URL=wss://certstream.calidog.io/ \
    OPENSQUAT_SCAN_INTERVAL=1800 \
    OPENSQUAT_PATH=/opt/opensquat/opensquat.py \
    CRITICAL_RISK_THRESHOLD=90 \
    HIGH_RISK_THRESHOLD=70 \
    MEDIUM_RISK_THRESHOLD=50

# Expose the app port
EXPOSE 5000

# Healthcheck (basic) — adjust to a real endpoint if available
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD curl -f http://127.0.0.1:5000/ || exit 1

# Run with Gunicorn + eventlet (SocketIO friendly)
# If app.py defines `app = Flask(__name__)`, the entry point is `app:app`
CMD ["gunicorn", "--worker-class", "eventlet", "-w", "1", "--bind", "0.0.0.0:5000", "app:app"]

