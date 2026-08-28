# 📖 AegisCI — Complete "How to Use" Guide

> **All-in-One DevSecOps Scanner, Policy-as-Code Engine & Security Orchestrator for GitHub Actions and Local CI/CD.**

---

## 📑 Table of Contents

1. [Overview](#1-overview)
2. [Quickstart in GitHub Actions](#2-quickstart-in-github-actions)
3. [Local CLI Installation & Usage](#3-local-cli-installation--usage)
4. [Docker Container Usage](#4-docker-container-usage)
5. [Pipeline Modes (`auto`, `pr-check`, `deep-scan`)](#5-pipeline-modes)
6. [Security Pillars Configuration](#6-security-pillars-configuration)
   - [Secrets Detection (Gitleaks)](#secrets-detection-gitleaks)
   - [Static Application Security Testing (Semgrep)](#sast-semgrep)
   - [Software Composition Analysis & SBOM (Trivy)](#sca--sbom-trivy)
   - [Infrastructure-as-Code (Checkov)](#iac--container-auditing-checkov)
   - [Dynamic Application Security Testing (OWASP ZAP)](#dast-runtime-testing-owasp-zap)
   - [CI Workflow Hardening (Zizmor)](#ci-workflow-hardening-zizmor)
7. [Policy-as-Code Configuration (`.aegisci.yml`)](#7-policy-as-code-configuration-aegisciyml)
8. [Enterprise Features (v4.0)](#8-enterprise-features-v40)
   - [Writing Custom Plugins (`.aegisci/plugins/`)](#custom-plugins-sdk)
   - [AI Remediation & Patch Generation](#ai-remediation--patch-generation)
   - [Enterprise Dashboard Telemetry Streamer](#enterprise-dashboard-telemetry)
   - [Vortex Threat Intelligence Integration](#vortex-threat-intelligence)
9. [Complete GitHub Actions Workflow Examples](#9-complete-github-actions-workflow-examples)
10. [CLI Flags & Parameter Reference](#10-cli-flags--parameter-reference)
11. [Troubleshooting & FAQ](#11-troubleshooting--faq)

---

## 1. Overview

AegisCI replaces fragmented security scanning workflows by consolidating **6 security pillars** into a single high-performance orchestrator:
- **Secrets Detection**: Gitleaks
- **SAST**: Semgrep
- **SCA & SBOM**: Trivy (CycloneDX / SPDX)
- **IaC & Containers**: Checkov
- **DAST**: OWASP ZAP (Baseline / API Scan) with endpoint health check
- **CI Workflow Hardening**: Zizmor
- **Enterprise Extensibility**: Custom Plugins, AI Patch Generator, and Telemetry Webhooks

All findings are deduplicated and merged into a **single unified SARIF v2.1.0 report** that renders directly in the GitHub **Security → Code scanning alerts** dashboard and as inline diff annotations on Pull Requests.

---

## 2. Quickstart in GitHub Actions

Add AegisCI to your repository in `.github/workflows/security.yml`:

```yaml
name: AegisCI Security Audit

on:
  push:
    branches: [ "main", "develop" ]
  pull_request:
    branches: [ "main" ]

jobs:
  security-audit:
    name: AegisCI Full-Spectrum Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # Required for GitHub Code Scanning tab upload
      pull-requests: write   # Optional: For PR annotations and comments

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Full history ensures optimal secret detection

      - name: Run AegisCI
        uses: yehezkiel1086/AegisCI@v1
        with:
          mode: 'auto'               # Runs 'pr-check' on PRs, 'deep-scan' on main branch
          fail-on-severity: 'HIGH'   # Blocks pipeline if HIGH or CRITICAL issues exist
          upload-sarif: 'true'       # Uploads results.sarif to GitHub Security Tab
```

---

## 3. Local CLI Installation & Usage

### Building from Source

Ensure you have **Go 1.22+** installed:

```bash
# Clone the repository
git clone https://github.com/yehezkiel1086/AegisCI.git
cd AegisCI

# Build the aegisci executable
go build -o bin/aegisci ./cmd/aegisci
```

### Running Scans Locally

```bash
# Basic scan against current directory
./bin/aegisci --target .

# Run fast PR-Check mode
./bin/aegisci --target . --mode pr-check

# Run full deep scan with SBOM generation
./bin/aegisci --target . --mode deep-scan --sbom --sbom-format cyclonedx-json --sbom-output sbom.cdx.json

# Fail only on CRITICAL findings
./bin/aegisci --target . --fail-on-severity CRITICAL

# Target a live staging environment with DAST
./bin/aegisci --target . --dast --dast-target-url https://staging.example.com
```

---

## 4. Docker Container Usage

AegisCI comes with a multi-stage `Dockerfile` containing pre-installed scanning engines (`gitleaks`, `semgrep`, `trivy`, `checkov`, `zizmor`):

```bash
# Build the Docker image
docker build -t aegisci:latest .

# Run against a local repository mounted to /workspace
docker run --rm -v $(pwd):/workspace aegisci:latest \
  --target /workspace \
  --output /workspace/results.sarif \
  --mode auto
```

---

## 5. Pipeline Modes

AegisCI dynamically routes scan execution to optimize developer velocity without compromising release security:

| Mode | Target Runtime | Scanner Execution Profile |
| :--- | :--- | :--- |
| **`auto`** *(Default)* | Dynamic | Automatically detects CI triggers: uses **`pr-check`** on PR events, and **`deep-scan`** on main/release branch merges. |
| **`pr-check`** | < 3 minutes | Parallel fast scans: **Secrets + SAST + SCA lockfiles + Workflow linters**. Skips slow recursive IaC and deep scans. |
| **`deep-scan`** | Comprehensive | Full security suite: **Secrets + SAST + SCA + IaC + Container auditing + DAST + SBOM generation**. |

---

## 6. Security Pillars Configuration

Each security scanner can be individually toggled via CLI flags or GitHub Action inputs:

### Secrets Detection (Gitleaks)
- **Flag**: `--secrets` (default: `true`)
- **What it scans**: Git history and codebase for API keys, AWS credentials, private keys, database passwords.

### SAST (Semgrep)
- **Flag**: `--sast` (default: `true`)
- **What it scans**: Source code vulnerabilities, SQL injections, XSS, insecure cryptography, and anti-patterns.

### SCA & SBOM (Trivy)
- **Flags**: `--sca` (default: `true`), `--sbom` (default: `false`), `--sbom-format` (`cyclonedx-json` or `spdx-json`), `--sbom-output`
- **What it scans**: Vulnerabilities across dependencies (`go.mod`, `package-lock.json`, `requirements.txt`, `Cargo.lock`, `pom.xml`, etc.).
- **SBOM Generation**:
  ```bash
  ./aegisci --sbom --sbom-format cyclonedx-json --sbom-output sbom.json
  ```

### IaC & Container Auditing (Checkov)
- **Flag**: `--iac` (default: `true`)
- **What it scans**: Terraform (`.tf`), Dockerfiles, Kubernetes manifests, Helm charts, and CloudFormation templates.

### DAST Runtime Testing (OWASP ZAP)
- **Flags**: `--dast` (default: `false`), `--dast-target-url`, `--dast-mode` (`baseline`, `api`, `full`)
- **Automated Health Probing**: Automatically pings the target URL before scanning. If the endpoint is down or unreachable, it reports a clear diagnostic message instead of hanging.
- **Example**:
  ```bash
  ./aegisci --dast --dast-target-url http://localhost:8080 --dast-mode baseline
  ```

### CI Workflow Hardening (Zizmor)
- **Flag**: `--workflow-audit` (default: `true`)
- **What it scans**: `.github/workflows/*.yml` files for unpinned action tags (`@v4`), script injection risks (`${{ github.event.* }}` in `run:` blocks), and token privilege escalations.

---

## 7. Policy-as-Code Configuration (`.aegisci.yml`)

Add a `.aegisci.yml` file to the root of your repository to manage exemptions, tolerances, and compliance rules:

```yaml
version: "4.0"

# Global tolerances and quality gate settings
settings:
  fail_on_unpatched_cves: false # Don't block builds if no upstream vendor fix exists
  max_critical: 0               # Zero tolerance for critical vulnerabilities
  max_high: 2                   # Allow up to 2 high findings before failing gate
  max_medium: 10                # Allow up to 10 medium findings

# Suppressions and exception rules
ignore:
  - id: "G401"
    path: "pkg/legacy/hash.go"
    reason: "Non-cryptographic hash used for caching"
    expires: "2026-12-31"       # Rule expires and is re-evaluated after this date

  - id: "generic-api-key"
    path: "test/fixtures/**"    # Recursive glob matching supported
    reason: "Synthetic dummy tokens in unit test fixtures"
    expires: "2027-01-01"

  - id: "CKV_DOCKER_2"
    path: "Dockerfile*"
    reason: "HEALTHCHECK instruction not needed on temporary job runner images"

# DAST scan exclusions
dast:
  exclude_paths:
    - "/logout"
    - "/admin/reset-db"
    - "/api/v1/billing/charge"

# Open-source license compliance policies
license_policy:
  banned:
    - "GPL-3.0"
    - "AGPL-3.0"
    - "SSPL"
  allowed:
    - "MIT"
    - "Apache-2.0"
    - "BSD-2-Clause"
    - "BSD-3-Clause"
    - "ISC"
```

---

## 8. Enterprise Features (v4.0)

### Custom Plugins SDK
Place custom scripts or binaries in `.aegisci/plugins/` (or specify `--plugins-dir`):
- Any executable file (`.sh`, `.py`, `.exe`, `.bin`, `.wasm`) that accepts `--target <dir> --output <path> --format sarif` will be auto-discovered and executed concurrently with built-in scanners.
- Findings are automatically ingested into the master SARIF report.

### AI Remediation & Patch Generation
AegisCI can automatically analyze vulnerabilities and generate git patch files:
- **Flags**: `--ai-remediation`, `--ai-provider=gemini|openai|custom`, `--ai-api-key=<KEY>`, `--patches-dir=patches`
- **Output**: Generates `.patch` files (e.g. `patches/patch-01-sql-injection.patch`) and a markdown guide in `patches/remediations.md`.

```bash
./aegisci --ai-remediation --ai-provider gemini --ai-api-key $GEMINI_API_KEY
```

### Enterprise Dashboard Telemetry
Stream scan metrics to your internal security dashboard or SIEM webhook:
- **Flags**: `--dashboard-url=https://dashboard.corp.internal/api/telemetry`, `--dashboard-token=$TOKEN`
- Dispatches structured JSON payload containing repository, commit SHA, branch, duration, engine breakdown, and gate pass/fail status.

### Vortex Threat Intelligence
Query Vortex Threat Feeds during scan execution:
- **Flags**: `--vortex`, `--vortex-api-url`, `--vortex-api-key`

---

## 9. Complete GitHub Actions Workflow Examples

### Example 1: Full Security Pipeline with PR Gate & AI Remediation

```yaml
name: Security Pipeline

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  aegisci-scan:
    name: AegisCI Security Gate
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run AegisCI
        uses: yehezkiel1086/AegisCI@v1
        with:
          mode: 'auto'
          fail-on-severity: 'HIGH'
          sbom: 'true'
          ai-remediation: 'true'
          ai-provider: 'gemini'
          ai-api-key: ${{ secrets.GEMINI_API_KEY }}

      - name: Upload SBOM Artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sbom-cyclonedx
          path: sbom.cdx.json

      - name: Upload AI Patches
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: ai-patches
          path: patches/
```

### Example 2: Scheduled Nightly Deep Scan with DAST & Dashboard Reporting

```yaml
name: Nightly Deep Security Audit

on:
  schedule:
    - cron: '0 2 * * *' # Every night at 2:00 AM UTC
  workflow_dispatch:

jobs:
  deep-scan:
    name: Deep Scan & DAST
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Start Staging Service
        run: docker compose up -d

      - name: Run AegisCI Deep Scan
        uses: yehezkiel1086/AegisCI@v1
        with:
          mode: 'deep-scan'
          fail-on-severity: 'CRITICAL'
          dast: 'true'
          dast-target-url: 'http://localhost:8080'
          dast-mode: 'baseline'
          dashboard-url: ${{ secrets.ENTERPRISE_DASHBOARD_URL }}
          dashboard-token: ${{ secrets.ENTERPRISE_DASHBOARD_TOKEN }}
```

---

## 10. CLI Flags & Parameter Reference

| Flag / Input | Default | Allowed Values | Description |
| :--- | :--- | :--- | :--- |
| `-t, --target` | `.` | Directory Path | Target directory or repository root to scan |
| `-o, --output` | `results.sarif` | File Path | Destination path for unified SARIF report |
| `-m, --mode` | `auto` | `auto`, `pr-check`, `deep-scan` | Pipeline depth mode |
| `-f, --fail-on-severity` | `HIGH` | `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Severity threshold to fail the build |
| `--sast` | `true` | `true`, `false` | Enable/Disable Semgrep SAST engine |
| `--secrets` | `true` | `true`, `false` | Enable/Disable Gitleaks Secrets engine |
| `--sca` | `true` | `true`, `false` | Enable/Disable Trivy SCA engine |
| `--iac` | `true` | `true`, `false` | Enable/Disable Checkov IaC engine |
| `--workflow-audit` | `true` | `true`, `false` | Enable/Disable Zizmor workflow linter |
| `--dast` | `false` | `true`, `false` | Enable/Disable OWASP ZAP DAST engine |
| `--dast-target-url` | `""` | URL (`http://...`) | Web endpoint for DAST scanning |
| `--dast-mode` | `baseline` | `baseline`, `api`, `full` | DAST scan depth profile |
| `--annotations` | `true` | `true`, `false` | Emit inline GitHub Actions PR annotations |
| `--sbom` | `false` | `true`, `false` | Generate Software Bill of Materials (SBOM) |
| `--sbom-format` | `cyclonedx-json` | `cyclonedx-json`, `spdx-json` | Format for SBOM export |
| `--sbom-output` | `sbom.cdx.json` | File Path | Output destination for SBOM file |
| `--ai-remediation` | `false` | `true`, `false` | Generate AI-powered code fix patches |
| `--ai-provider` | `gemini` | `gemini`, `openai`, `custom` | AI Remediation LLM provider |
| `--ai-api-key` | `""` | String | API key for AI provider |
| `--patches-dir` | `patches` | Directory Path | Directory for generated `.patch` files |
| `--plugins-dir` | `.aegisci/plugins` | Directory Path | Directory for custom scanner plugins |
| `--dashboard-url` | `""` | Webhook URL | Enterprise dashboard telemetry endpoint |
| `--dashboard-token`| `""` | String | Bearer authentication token for dashboard |
| `--policy-file` | `.aegisci.yml` | File Path | Path to policy-as-code YAML file |
| `-v, --verbose` | `false` | `true`, `false` | Enable verbose terminal output |

---

## 11. Troubleshooting & FAQ

### Q: Why did the SARIF upload step fail in GitHub Actions?
**A:** Ensure your GitHub workflow job contains the permission `security-events: write`. Without this permission, GitHub will reject the SARIF upload.

```yaml
permissions:
  contents: read
  security-events: write
```

### Q: How do I ignore false positives without changing workflow YAMLs?
**A:** Add the rule ID and file path to `.aegisci.yml` under the `ignore:` section. You can set an `expires:` date so the exception is periodically re-audited.

### Q: What happens if a tool like Gitleaks or Checkov is not installed locally?
**A:** AegisCI gracefully checks for binary availability. Missing local tools are reported with a yellow notice `[!] NOT INSTALLED in PATH`, allowing other available engines to run uninterrupted. In GitHub Actions and Docker containers, all engines are pre-packaged.

### Q: Can I run DAST against a service running inside Docker?
**A:** Yes! Start your service in the previous workflow step (e.g. `docker compose up -d`), then provide `dast-target-url: "http://localhost:8080"`. AegisCI will probe the endpoint health before launching OWASP ZAP.

---

*For issues, feature requests, or contributions, please visit the [AegisCI GitHub Repository](https://github.com/yehezkiel1086/AegisCI).*
