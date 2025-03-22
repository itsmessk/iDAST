# Use a specific version of Python for better reproducibility
FROM python:3.9-slim-bullseye

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="$PATH:/root/go/bin:/usr/local/go/bin:/usr/bin" \
    DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PORT=3000

WORKDIR /app
COPY . /app

# Create a non-root user for security
RUN groupadd -r secpro && useradd -r -g secpro -s /sbin/nologin -d /app secpro

# Set up virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies first (for better layer caching)
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Install system dependencies in a single layer to reduce image size
RUN apt-get update && apt-get install -y --no-install-recommends \
    apt-transport-https \
    nmap \
    curl \
    wget \
    git \
    unzip \
    build-essential \
    gnupg \
    chromium-driver \
    libnss3 \
    libxss1 \
    libappindicator1 \
    libgconf-2-4 \
    libpango1.0-0 \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Install Chrome
RUN wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb && \
    apt-get update && \
    apt-get install -y --no-install-recommends ./google-chrome-stable_current_amd64.deb && \
    rm google-chrome-stable_current_amd64.deb && \
    rm -rf /var/lib/apt/lists/*

# Install Node.js and npm
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get update && \
    apt-get install -y --no-install-recommends nodejs && \
    npm install -g retire && \
    rm -rf /var/lib/apt/lists/*

# Install Go and Go tools
RUN wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && \
    rm go1.21.0.linux-amd64.tar.gz && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/hahwul/dalfox/v2@latest

# Install security tools from GitHub
RUN git clone https://github.com/devanshbatham/ParamSpider /opt/paramspider && \
    cd /opt/paramspider && \
    pip install --no-cache-dir . && \
    git clone https://github.com/0xInfection/XSRFProbe.git /opt/xsrfprobe && \
    cd /opt/xsrfprobe && \
    pip install --no-cache-dir . && \
    git clone https://github.com/ryandamour/ssrfuzz.git /opt/ssrfuzz && \
    cd /opt/ssrfuzz && \
    go mod init ssrfuzz && \
    go mod tidy && \
    go build && \
    mv ssrfuzz /usr/local/bin/ssrfuzz

# Install SQLMap
RUN pip install --no-cache-dir sqlmap

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs /app/results /app/tests/scan_results && \
    chown -R secpro:secpro /app

# Switch to non-root user
USER secpro

# Expose port - use PORT env variable
EXPOSE ${PORT}

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Start the application with gunicorn for production
CMD gunicorn --bind 0.0.0.0:${PORT} --workers 4 --threads 2 --timeout 120 "app:app"