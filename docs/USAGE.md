# AegisCI — Complete Guide

> All-in-One DevSecOps Scanner, Policy-as-Code Engine & Security Orchestrator for GitHub Actions and Standalone Terminals.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Installation Guide](#2-installation-guide)
   - [macOS & Linux via Homebrew](#macos--linux-via-homebrew)
   - [Debian / Ubuntu via APT / .deb](#debian--ubuntu-deb)
   - [Fedora / RHEL / CentOS via RPM](#fedora--rhel--centos-rpm)
   - [Go Developers via `go install`](#go-developers-go-install)
   - [Direct Standalone Binary Downloads](#direct-binary-download)
3. [Quickstart in GitHub Actions](#3-quickstart-in-github-actions)
4. [CLI Commands & Subcommands](#4-cli-commands--subcommands)
   - [`aegisci scan`](#aegisci-scan)
   - [`aegisci version`](#aegisci-version)
5. [Docker Container Usage](#5-docker-container-usage)
6. [Pipeline Modes (`auto`, `pr-check`, `deep-scan`)](#6-pipeline-modes)
7. [Security Pillars Configuration](#7-security-pillars-configuration)
   - [Secrets Detection (Gitleaks)](#secrets-detection-gitleaks)
   - [Static Application Security Testing (Semgrep)](#sast-semgrep)
   - [Software Composition Analysis & SBOM (Trivy)](#sca--sbom-trivy)
   - [Infrastructure-as-Code (Checkov)](#iac--container-auditing-checkov)
   - [Dynamic Application Security Testing (OWASP ZAP)](#dast-runtime-testing-owasp-zap)
   - [CI Workflow Hardening (Zizmor)](#ci-workflow-hardening-zizmor)
8. [Policy-as-Code Configuration (`.aegisci.yml`)](#8-policy-as-code-configuration-aegisciyml)
9. [Enterprise Features](#9-enterprise-features)
   - [Writing Custom Plugins (`.aegisci/plugins/`)](#custom-plugins-sdk)
   - [AI Remediation & Patch Generation](#ai-remediation--patch-generation)
   - [Enterprise Dashboard Telemetry Streamer](#enterprise-dashboard-telemetry)
   - [Vortex Threat Intelligence Integration](#vortex-threat-intelligence)
10. [Complete GitHub Actions Workflow Recipes](#10-complete-github-actions-workflow-recipes)
11. [CLI Flags & Parameter Reference](#11-cli-flags--parameter-reference)
12. [Troubleshooting & FAQ](#12-troubleshooting--faq)

---

## 1. Overview

AegisCI consolidates 6 security pillars into a single high-performance standalone terminal binary and GitHub Action:
- Secrets Detection: Gitleaks
- SAST: Semgrep
- SCA & SBOM: Trivy (CycloneDX / SPDX)
- IaC & Containers: Checkov
- DAST: OWASP ZAP (Baseline / API Scan) with endpoint health check
- CI Workflow Hardening: Zizmor
- Enterprise Extensibility: Custom Plugins, AI Patch Generator, and Telemetry Webhooks

All findings are deduplicated and merged into a single unified SARIF v2.1.0 report that renders directly in the GitHub Security (Code scanning alerts) dashboard and as inline diff annotations on Pull Requests.

---

## 2. Installation Guide

`aegisci` is cross-compiled across Linux (x86_64, ARM64), macOS (Apple Silicon, Intel), and Windows.

### macOS & Linux (via Homebrew)
```bash
brew tap yehezkiel1086/tap
brew install aegisci

# verify installation
aegisci version
```

### Debian / Ubuntu (.deb)
```bash
curl -sLO https://github.com/yehezkiel1086/AegisCI/releases/latest/download/aegisci_linux_amd64.deb
sudo dpkg -i aegisci_linux_amd64.deb
```

### Fedora / RHEL / CentOS (.rpm)
```bash
sudo rpm -ivh https://github.com/yehezkiel1086/AegisCI/releases/latest/download/aegisci_linux_amd64.rpm
```

### Go Developers (go install)
```bash
go install github.com/yehezkiel1086/AegisCI/cmd/aegisci@latest
```

### Direct Binary Download
Download pre-built standalone binaries from the [GitHub Releases Page](https://github.com/yehezkiel1086/AegisCI/releases):
- Linux (x86_64 / ARM64): `aegisci_<version>_linux_amd64.tar.gz`
- macOS (Apple Silicon / Intel): `aegisci_<version>_darwin_arm64.tar.gz`
- Windows (x86_64): `aegisci_<version>_windows_amd64.zip`

---

## 3. Quickstart in GitHub Actions

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
      security-events: write
      pull-requests: write

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run AegisCI
        uses: yehezkiel1086/AegisCI@v1
        with:
          mode: 'auto'
          fail-on-severity: 'HIGH'
          upload-sarif: 'true'
```

---

## 4. CLI Commands & Subcommands

### `aegisci scan`
The primary command to execute security scans:

```bash
# basic scan against current directory
aegisci scan --target .

# fast PR-check mode
aegisci scan --target . --mode pr-check

# full deep scan with SBOM generation
aegisci scan --target . --mode deep-scan --sbom --sbom-format cyclonedx-json --sbom-output sbom.cdx.json

# fail only on CRITICAL findings
aegisci scan --target . --fail-on CRITICAL

# target a live staging environment with DAST
aegisci scan --target . --dast --dast-target-url https://staging.example.com
```

### `aegisci version`
Prints version number, git commit SHA, build timestamp, and runtime architecture:

```bash
$ aegisci version
aegisci version 4.0.0
  commit:     e5f8a92
  built at:   2026-08-28T12:00:00Z
  built by:   goreleaser
  os/arch:    linux/amd64
  go version: go1.26.0
```

---

## 5. Docker Container Usage

```bash
# build the Docker image
docker build -t aegisci:latest .

# run against a local repository mounted to /workspace
docker run --rm -v $(pwd):/workspace aegisci:latest scan \
  --target /workspace \
  --output /workspace/results.sarif \
  --mode auto
```

---

## 6. Pipeline Modes

AegisCI dynamically routes scan execution:

| Mode | Target Runtime | Scanner Execution Profile |
| :--- | :--- | :--- |
| `auto` (Default) | Dynamic | Automatically detects CI triggers: uses `pr-check` on PR events, and `deep-scan` on main/release branch merges. |
| `pr-check` | < 3 minutes | Parallel fast scans: Secrets + SAST + SCA lockfiles + Workflow linters. Skips slow recursive scans. |
| `deep-scan` | Comprehensive | Full security suite: Secrets + SAST + SCA + IaC + Container auditing + DAST + SBOM generation. |

---

## 7. Security Pillars Configuration

### Secrets Detection (Gitleaks)
- Flag: `--secrets` (default: `true`)
- Scans: Git history and codebase for API keys, private keys, database credentials.

### SAST (Semgrep)
- Flag: `--sast` (default: `true`)
- Scans: Source code vulnerabilities, SQL injections, XSS, insecure cryptography.

### SCA & SBOM (Trivy)
- Flags: `--sca` (default: `true`), `--sbom` (default: `false`), `--sbom-format` (`cyclonedx-json` or `spdx-json`), `--sbom-output`
- Scans: Vulnerabilities across lockfiles (`go.mod`, `package-lock.json`, `requirements.txt`, etc.).

### IaC & Container Auditing (Checkov)
- Flag: `--iac` (default: `true`)
- Scans: Terraform (.tf), Dockerfiles, Kubernetes manifests, Helm charts.

### DAST Runtime Testing (OWASP ZAP)
- Flags: `--dast` (default: `false`), `--dast-target-url`, `--dast-mode` (`baseline`, `api`, `full`)
- Automated Health Probing: Automatically pings the target URL before scanning.

### CI Workflow Hardening (Zizmor)
- Flag: `--workflow-audit` (default: `true`)
- Scans: `.github/workflows/*.yml` files for unpinned action tags, script injection risks, and token privilege escalations.

---

## 8. Policy-as-Code Configuration (`.aegisci.yml`)

```yaml
version: "4.0"

settings:
  fail_on_unpatched_cves: false
  max_critical: 0
  max_high: 2
  max_medium: 10

ignore:
  - id: "G401"
    path: "pkg/legacy/hash.go"
    reason: "Non-cryptographic hash used for caching"
    expires: "2026-12-31"

  - id: "generic-api-key"
    path: "test/fixtures/**"
    reason: "Synthetic dummy tokens in unit test fixtures"
    expires: "2027-01-01"

  - id: "CKV_DOCKER_2"
    path: "Dockerfile*"
    reason: "HEALTHCHECK instruction not needed on temporary job runner images"

dast:
  exclude_paths:
    - "/logout"
    - "/admin/reset-db"

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

## 9. Enterprise Features

### Custom Plugins SDK
Place custom scripts or binaries in `.aegisci/plugins/` (or specify `--plugins-dir`):
- Any executable file (`.sh`, `.py`, `.exe`, `.bin`, `.wasm`) that accepts `--target <dir> --output <path> --format sarif` will be auto-discovered and executed concurrently with built-in scanners.

### AI Remediation & Patch Generation
- Flags: `--ai-remediation`, `--ai-provider=gemini|openai|custom`, `--ai-api-key=<KEY>`, `--patches-dir=patches`
- Output: Generates `.patch` files (e.g. `patches/patch-01-sql-injection.patch`) and markdown recommendations in `patches/remediations.md`.

### Enterprise Dashboard Telemetry
- Flags: `--dashboard-url=https://dashboard.corp.internal/api/telemetry`, `--dashboard-token=$TOKEN`
- Dispatches structured JSON payload containing repository, commit SHA, branch, duration, engine breakdown, and gate pass/fail status.

---

## 10. Complete GitHub Actions Workflow Recipes

### Recipe 1: Standard Security Pipeline

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
```

---

## 11. CLI Flags & Parameter Reference

| Flag | Short | Default | Allowed Values | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--target` | `-t` | `.` | Directory Path | Target directory or repository root to scan |
| `--output` | `-o` | `results.sarif` | File Path | Destination path for unified SARIF report |
| `--mode` | `-m` | `auto` | `auto`, `pr-check`, `deep-scan` | Pipeline depth mode |
| `--fail-on` / `--fail-on-severity` | `-f` | `HIGH` | `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Severity threshold to fail the build |
| `--config` / `--policy-file` | `-c` | `.aegisci.yml` | File Path | Path to policy-as-code YAML file |
| `--sast` | | `true` | `true`, `false` | Enable/Disable Semgrep SAST engine |
| `--secrets` | | `true` | `true`, `false` | Enable/Disable Gitleaks Secrets engine |
| `--sca` | | `true` | `true`, `false` | Enable/Disable Trivy SCA engine |
| `--iac` | | `true` | `true`, `false` | Enable/Disable Checkov IaC engine |
| `--workflow-audit` | | `true` | `true`, `false` | Enable/Disable Zizmor workflow linter |
| `--dast` | | `false` | `true`, `false` | Enable/Disable OWASP ZAP DAST engine |
| `--dast-target-url` | | `""` | URL (`http://...`) | Web endpoint for DAST scanning |
| `--dast-mode` | | `baseline` | `baseline`, `api`, `full` | DAST scan depth profile |
| `--annotations` | | `true` | `true`, `false` | Emit inline GitHub Actions PR annotations |
| `--sbom` | | `false` | `true`, `false` | Generate Software Bill of Materials (SBOM) |
| `--sbom-format` | | `cyclonedx-json` | `cyclonedx-json`, `spdx-json` | Format for SBOM export |
| `--sbom-output` | | `sbom.cdx.json` | File Path | Output destination for SBOM file |
| `--ai-remediation` | | `false` | `true`, `false` | Generate AI-powered code fix patches |
| `--ai-provider` | | `gemini` | `gemini`, `openai`, `custom` | AI Remediation LLM provider |
| `--ai-api-key` | | `""` | String | API key for AI provider |
| `--patches-dir` | | `patches` | Directory Path | Directory for generated `.patch` files |
| `--plugins-dir` | | `.aegisci/plugins` | Directory Path | Directory for custom scanner plugins |
| `--dashboard-url` | | `""` | Webhook URL | Enterprise dashboard telemetry endpoint |
| `--dashboard-token` | | `""` | String | Bearer authentication token for dashboard |
| `--verbose` | `-v` | `false` | `true`, `false` | Enable verbose terminal output |

---

## 12. Troubleshooting & FAQ

### Why did the SARIF upload step fail in GitHub Actions?
Ensure your GitHub workflow job contains the permission `security-events: write`.

### How do I ignore false positives?
Add the rule ID and file path to `.aegisci.yml` under the `ignore:` section with an optional `expires:` date.
