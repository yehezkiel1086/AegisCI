# ==============================================================================
# AegisCI Runner Image (v3.0)
# Pre-packaged with:
# - Go Runtime & AegisCI CLI Orchestrator
# - Semgrep (SAST)
# - Gitleaks (Secrets Detection)
# - Trivy (SCA & SBOM Generation)
# - Checkov (IaC & Container Auditing)
# - Zizmor (CI Workflow Hardening)
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
LABEL description="All-in-One DevSecOps Security Orchestrator (v3.0)"

# Install system dependencies, git, curl, tar
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    ca-certificates \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Install Gitleaks
RUN GITLEAKS_VERSION="8.18.4" \
    && curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# Install Trivy
RUN TRIVY_VERSION="0.51.0" \
    && curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | tar -xz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy

# Install Semgrep, Checkov, and Zizmor via pip
RUN pip install --no-cache-dir --upgrade semgrep checkov zizmor

# Copy AegisCI orchestrator binary
COPY --from=builder /aegisci /usr/local/bin/aegisci
RUN chmod +x /usr/local/bin/aegisci

WORKDIR /workspace

ENTRYPOINT ["aegisci"]
CMD ["--target", "/workspace"]
