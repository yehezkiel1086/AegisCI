# ==============================================================================
# AegisCI Runner Image
# Pre-packaged with Go runtime, Semgrep SAST, Gitleaks Secrets Detection, and AegisCI CLI
# ==============================================================================

# Stage 1: Build AegisCI binary
FROM golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /aegisci ./cmd/aegisci

# Stage 2: Final runtime container
FROM python:3.11-slim

LABEL maintainer="AegisCI Team"
LABEL description="All-in-One DevSecOps Security Orchestrator"

# Install system dependencies, git, and gitleaks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    tar \
    && GITLEAKS_VERSION="8.18.4" \
    && curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep
RUN pip install --no-cache-dir --upgrade semgrep

# Copy AegisCI orchestrator binary
COPY --from=builder /aegisci /usr/local/bin/aegisci
RUN chmod +x /usr/local/bin/aegisci

WORKDIR /workspace

ENTRYPOINT ["aegisci"]
CMD ["--target", "/workspace"]
