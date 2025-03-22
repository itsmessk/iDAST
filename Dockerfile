FROM python:3.9

ENV PYTHONUNBUFFERED=1
ENV PATH="$PATH:/root/go/bin:/usr/local/go/bin:/usr/bin"

WORKDIR /app
COPY . /app

# Test
RUN echo "Step -1: Testing Dockerfile."
RUN echo "Testing pip" && pip --version
RUN echo "Testing python" && python --version
RUN echo "List Files" && ls -la
RUN echo "Testing pip random package" && pip install random2 
RUN echo "Testing pip requests package" && pip install requests

# Step 0: Set up virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Step 1: Install setuptools (to avoid errors with setup.py)
RUN echo "Step 1: Installing setuptools." && pip install --upgrade pip setuptools

# Step 2: Install Python dependencies
RUN echo "Step 2.1: Installing Python dependencies." && pip install -v -r ./requirements.txt

# Step 17: Install Paramspider from GitHub
RUN echo "Step 2.2: Installing Paramspider from GitHub." && \
    git clone https://github.com/devanshbatham/ParamSpider /opt/paramspider && \
    cd /opt/paramspider && \
    set PYTHONUTF8=1 && \
    pip install .


RUN echo "Step 2.3: Installing SQLMap and XSRFProbe." && \
    pip install sqlmap && \
    git clone https://github.com/0xInfection/XSRFProbe.git /opt/xsrfprobe && \
    cd /opt/xsrfprobe && \
    pip install .

# Step 3: Update package lists
RUN echo "Step 3: Updating package lists." && apt-get update && apt-get install -y --no-install-recommends apt-transport-https
RUN echo "Step 3.1: Installing nmap." && apt-get install -y nmap

# Step 4: Install curl
RUN echo "Step 4: Installing curl." && apt-get install -y --no-install-recommends curl

# Step 5: Install wget
RUN echo "Step 5: Installing wget." && apt-get install -y --no-install-recommends wget

# Step 6: Install git
RUN echo "Step 6: Installing git." && apt-get install -y --no-install-recommends git

# Step 7: Install unzip
RUN echo "Step 7: Installing unzip." && apt-get install -y --no-install-recommends unzip

# Step 8: Install build-essential
RUN echo "Step 8: Installing build-essential." && apt-get install -y --no-install-recommends build-essential

# Step 9: Install gnupg
RUN echo "Step 9: Installing gnupg." && apt-get install -y --no-install-recommends gnupg

# Step 10: Install Chromium Driver
RUN echo "Step 10: Installing Chromium Driver." && apt-get install -y --no-install-recommends chromium-driver

# Step 11: Install Chrome via direct download
RUN echo "Step 11: Installing Chrome." && wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb && \
    apt-get install -y ./google-chrome-stable_current_amd64.deb && \
    rm google-chrome-stable_current_amd64.deb

# Step 12: Install additional Chrome libraries
RUN echo "Step 12: Installing Chrome dependencies." && apt-get install -f -y --no-install-recommends \
    libnss3 libxss1 libappindicator1 libgconf-2-4 libpango1.0-0 fonts-liberation

# Step 13: Clean up
RUN echo "Step 13: Cleaning up apt cache." && apt-get clean && rm -rf /var/lib/apt/lists/*

# Step 14: Install Node.js and npm
RUN echo "Step 14: Installing Node.js and npm." && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs

# Step 15: Install Go
RUN echo "Step 15: Installing Go." && wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && \
    rm go1.21.0.linux-amd64.tar.gz

# Step 16: Install Go tools
RUN echo "Step 16.1: Installing assetfinder." && go install github.com/tomnomnom/assetfinder@latest
RUN echo "Step 16.2: Installing subfinder." && go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN echo "Step 16.3: Installing httpx." && go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN echo "Step 16.4: Installing waybackurls." && go install github.com/tomnomnom/waybackurls@latest
RUN echo "Step 16.5: Installing dalfox." && go install github.com/hahwul/dalfox/v2@latest


# Step 17: Install Node.js tool
RUN echo "Step 17: Installing retire." && npm install -g retire


# Step 11: Install SSRFuzz
RUN echo "Step 18: Installing SSRFuzz." && \
    git clone https://github.com/ryandamour/ssrfuzz.git /opt/ssrfuzz && \
    cd /opt/ssrfuzz && \
    go mod init ssrfuzz && \
    go mod tidy && \
    go build && \
    mv ssrfuzz /usr/local/bin/ssrfuzz

# Step 12: Verify SSRFuzz installation
RUN echo "Step 19: Testing SSRFuzz installation." && ssrfuzz -h || echo "SSRFuzz installation failed"

# Finally
EXPOSE 3000
CMD echo "Step 20: Starting Flask app." && python app.py
