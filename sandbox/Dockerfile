# ============================================
# VulnScan Sandbox Service Dockerfile
# ============================================
FROM python:3.11-slim

LABEL maintainer="vulnscan-team"
LABEL description="Independent sandbox service for PoC execution and vulnerability verification"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV SANDBOX_HOME=/opt/sandbox
ENV PATH="/usr/local/go/bin:/usr/local/node/bin:${PATH}"

# ============================================
# 1. System Dependencies & Security Tools
# ============================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    gcc \
    g++ \
    make \
    cmake \
    # Docker CLI (for container-in-container)
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    # Security tools
    libseccomp2 \
    seccomp \
    apparmor \
    apparmor-utils \
    libapparmor1 \
    # Utilities
    wget \
    git \
    unzip \
    procps \
    jq \
    # Network tools for healthchecks
    iputils-ping \
    net-tools \
    # Cleanup
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI (not daemon - uses host socket)
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-buildx-plugin docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

# ============================================
# 2. Multi-language Runtimes
# ============================================

# --- Node.js (LTS) ---
ENV NODE_VERSION=20.11.1
RUN curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" | tar -xJf - -C /usr/local \
    && mv /usr/local/node-v${NODE_VERSION}-linux-x64 /usr/local/node \
    && ln -s /usr/local/node/bin/node /usr/local/bin/node \
    && ln -s /usr/local/node/bin/npm /usr/local/bin/npm \
    && ln -s /usr/local/node/bin/npx /usr/local/bin/npx \
    && node --version \
    && npm --version

# --- OpenJDK 17 ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk \
    && rm -rf /var/lib/apt/lists/* \
    && java -version

# --- Go 1.22 ---
ENV GO_VERSION=1.22.0
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xzf - \
    && ln -s /usr/local/go/bin/go /usr/local/bin/go \
    && ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt \
    && go version

# --- Python already included in base image ---
RUN python3 --version && pip3 --version

# ============================================
# 3. Python Dependencies
# ============================================
WORKDIR ${SANDBOX_HOME}

COPY requirements.txt ${SANDBOX_HOME}/
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ============================================
# 4. Application Setup
# ============================================
COPY sandbox_api.py ${SANDBOX_HOME}/
COPY seccomp-profile.json ${SANDBOX_HOME}/
COPY entrypoint.sh ${SANDBOX_HOME}/
RUN chmod +x ${SANDBOX_HOME}/entrypoint.sh

# Create sandbox working directories
RUN mkdir -p /tmp/sandbox/jobs /tmp/sandbox/containers /tmp/sandbox/logs \
    && chmod 755 /tmp/sandbox

# ============================================
# 5. Security Hardening
# ============================================
# Create non-root user for sandbox execution
RUN groupadd -r sandbox -g 1000 \
    && useradd -r -g sandbox -u 1000 -d ${SANDBOX_HOME} -s /sbin/nologin sandbox \
    && chown -R sandbox:sandbox ${SANDBOX_HOME} /tmp/sandbox

# Restrict permissions
RUN chmod 700 /tmp/sandbox/jobs /tmp/sandbox/containers

# ============================================
# 6. Runtime Configuration
# ============================================
EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

USER root

ENTRYPOINT ["./entrypoint.sh"]
CMD ["uvicorn", "sandbox_api:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "2"]
