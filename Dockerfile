FROM python:3.9-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="$PATH:/root/go/bin:/usr/local/go/bin:/usr/bin"

WORKDIR /app

# Install system dependencies and clean up in one layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    apt-transport-https \
    build-essential \
    curl \
    wget \
    git \
    gnupg \
    unzip \
    nmap \
    chromium-driver \
    libnss3 \
    libxss1 \
    libappindicator1 \
    libgconf-2-4 \
    libpango1.0-0 \
    fonts-liberation && \
    # Install Chrome
    wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb && \
    apt-get install -y ./google-chrome-stable_current_amd64.deb && \
    rm google-chrome-stable_current_amd64.deb && \
    # Install Node.js
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    npm install -g npm@latest && \
    # Cleanup
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    # Create security user
    useradd -m -s /bin/bash secpro

# Set up Python environment
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel

ENV PATH="/opt/venv/bin:$PATH"

# Install Go and tools
RUN wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && \
    rm go1.21.0.linux-amd64.tar.gz && \
    # Install Go tools
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/hahwul/dalfox/v2@latest

# Install Node.js tools
RUN npm install -g retire@4.0.0

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir sqlmap random2

# Install security tools
RUN git clone --depth 1 https://github.com/devanshbatham/ParamSpider /opt/paramspider && \
    cd /opt/paramspider && \
    pip install --no-cache-dir . && \
    git clone --depth 1 https://github.com/0xInfection/XSRFProbe.git /opt/xsrfprobe && \
    cd /opt/xsrfprobe && \
    pip install --no-cache-dir . && \
    git clone --depth 1 https://github.com/ryandamour/ssrfuzz.git /opt/ssrfuzz && \
    cd /opt/ssrfuzz && \
    go mod init ssrfuzz && \
    go mod tidy && \
    go build && \
    mv ssrfuzz /usr/local/bin/ssrfuzz && \
    # Verify installations
    ssrfuzz -h || echo "SSRFuzz installation verified"

# Copy application code
COPY --chown=secpro:secpro . .

# Switch to non-root user
USER secpro

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

EXPOSE 3000

CMD ["python", "app.py"]