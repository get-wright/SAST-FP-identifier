FROM python:3.14-slim AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends git curl && \
    rm -rf /var/lib/apt/lists/*

# Install gkg (GitLab Knowledge Graph)
RUN curl -fsSL https://gitlab.com/api/v4/projects/69095239/releases/permalink/latest/downloads/gkg-linux-$(uname -m).tar.gz \
    -o /tmp/gkg.tar.gz && \
    tar -xzf /tmp/gkg.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/gkg && \
    rm /tmp/gkg.tar.gz

# Install SBOM tools
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm && \
    npm install -g @cyclonedx/cdxgen && \
    rm -rf /var/lib/apt/lists/*
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app

# Install dependencies (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ src/
COPY frontend/ frontend/
COPY run.py .

# Persistent volumes for cloned repos and analysis cache
VOLUME ["/app/repos_cache", "/app/cache"]

EXPOSE 8000

CMD ["python", "run.py"]
