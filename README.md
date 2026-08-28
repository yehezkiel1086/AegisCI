# AegisCI

> All-in-One DevSecOps Scanner, Policy-as-Code Engine & Enterprise Security Orchestrator for GitHub Actions and Standalone Terminals.  
> Consolidates SAST, DAST, Secrets Detection, SCA, IaC Auditing, CI Workflow Linters, and AI Remediation into a single Go binary with native GitHub Security Tab integration.

[![GitHub Release](https://img.shields.io/github/v/release/yehezkiel1086/AegisCI?style=flat-square&color=blue)](https://github.com/yehezkiel1086/AegisCI/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-AegisCI-purple?style=flat-square&logo=github)](https://github.com/marketplace/actions/aegisci)
[![Documentation: How to Use](https://img.shields.io/badge/Docs-How%20to%20Use-blue.svg?style=flat-square)](docs/USAGE.md)

---

## Installation

`aegisci` is cross-compiled as a single standalone terminal binary for Linux (x86_64/ARM64), macOS (Apple Silicon/Intel), and Windows.

### macOS & Linux (via Homebrew)
```bash
brew tap yehezkiel1086/tap
brew install aegisci
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
Download pre-built standalone binaries from the [Releases Page](https://github.com/yehezkiel1086/AegisCI/releases):
- Linux (x86_64 / ARM64): `aegisci_<version>_linux_amd64.tar.gz`
- macOS (Apple Silicon / Intel): `aegisci_<version>_darwin_arm64.tar.gz`
- Windows (x86_64): `aegisci_<version>_windows_amd64.zip`

---

## Overview

AegisCI provides a single Go-powered orchestrator for your entire DevSecOps pipeline:
1. Multi-Engine Concurrency: Runs Semgrep, Gitleaks, Trivy, Checkov, Zizmor, OWASP ZAP, and custom plugins concurrently in parallel goroutines.
2. Unified SARIF v2.1.0: Deduplicates and aggregates all findings into a single SARIF document rendered directly in Security → Code scanning alerts.
3. Inline PR Annotations: Emits native GitHub Workflow Commands to display security issues directly on pull request code diffs.
4. Smart Pipeline Modes: Dynamically routes execution between fast `pr-check` (< 3 mins) and comprehensive `deep-scan`.
5. Policy-as-Code (`.aegisci.yml`): Manage suppressions with expiration dates, glob matching, tolerance limits, and license compliance rules.
6. AI Remediation Engine: Automatically generates unified Git diff patch files (`.patch`) for detected vulnerabilities using LLMs.
7. Enterprise Extensibility: Supports custom WASM/executable plugins and centralized dashboard telemetry streaming.

---

## Security Pillars

| Security Pillar | Engine | Description |
| :--- | :--- | :--- |
| Secrets Detection | Gitleaks | Leaked API tokens, private keys, database credentials, AWS keys |
| SAST | Semgrep | Source code vulnerabilities, SQL injections, XSS, insecure crypto |
| SCA & SBOM | Trivy | Vulnerable open-source packages across lockfiles; CycloneDX/SPDX SBOMs |
| IaC & Containers | Checkov | Misconfigured Terraform (.tf), Dockerfiles, Kubernetes manifests, Helm |
| DAST | OWASP ZAP | Web app & API runtime vulnerabilities with automated URL health check |
| CI Meta-Security | Zizmor | Unpinned GitHub Actions (@v4), script injection risks in workflows |
| AI Remediation | LLM Engine | Automated code fix patch generation (patches/*.patch) |
| Custom Plugins | Plugin SDK | Custom corporate compliance rules (WASM, Python, Bash, Go) |

---

## Quickstart

Add AegisCI to `.github/workflows/security.yml` in your repository:

```yaml
name: AegisCI Security Audit

on:
  push:
    branches: [ "main", "develop" ]
  pull_request:
    branches: [ "main" ]

jobs:
  security-scan:
    name: AegisCI Full-Spectrum Audit
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run AegisCI Security Suite
        uses: yehezkiel1086/AegisCI@v1
        with:
          mode: 'auto'
          fail-on-severity: 'HIGH'
          sbom: 'true'
```

---

## Architecture & Flow

```
┌────────────────────────────────────────────────────────────────────────┐
│                      AegisCI Enterprise Orchestrator                   │
│                                                                        │
│   1. Stack Auto-Detection & Smart Mode Router (pr-check / deep-scan)   │
│   2. Concurrent Engine Execution (Parallel Goroutines)                 │
│      ├── Semgrep (SAST)           ├── Trivy (SCA & SBOM)               │
│      ├── Gitleaks (Secrets)       ├── Checkov (IaC)                    │
│      ├── Zizmor (CI Workflows)    ├── OWASP ZAP (DAST Runtime)         │
│      └── Custom Plugins Engine (WASM / Executable Plugin SDK)          │
│                                                                        │
│   3. SARIF Aggregator, Deduplicator & Policy-as-Code Engine            │
│   4. AI Remediation Engine (Automated Patch Diffs)                     │
│   5. Unified Dispatcher:                                               │
│      ├── GitHub Inline PR Annotations (::error file=...,line=...)      │
│      ├── Unified results.sarif -> GitHub Code Scanning Tab             │
│      └── Enterprise Dashboard Webhook Telemetry Streamer               │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Policy-as-Code (`.aegisci.yml`)

Configure exemptions and tolerance limits by adding `.aegisci.yml` to your repository root:

```yaml
version: "4.0"

settings:
  fail_on_unpatched_cves: false
  max_critical: 0
  max_high: 2

ignore:
  - id: "G401"
    path: "pkg/legacy/hash.go"
    reason: "Non-cryptographic hash used for caching"
    expires: "2026-12-31"

  - id: "generic-api-key"
    path: "test/fixtures/**"
    reason: "Synthetic test fixture with dummy token"

license_policy:
  banned:
    - "GPL-3.0"
    - "AGPL-3.0"
  allowed:
    - "MIT"
    - "Apache-2.0"
    - "BSD-3-Clause"

dast:
  exclude_paths:
    - "/logout"
    - "/admin/reset-db"
```

---

## CLI Usage

```bash
# basic scan against current directory
aegisci scan --target .

# fast PR-check mode
aegisci scan --target . --mode pr-check

# deep scan with SBOM and AI Remediation
aegisci scan --target . --mode deep-scan --sbom --ai-remediation --ai-provider gemini --ai-api-key $GEMINI_API_KEY

# run DAST against staging endpoint
aegisci scan --dast --dast-target-url https://staging.example.com --fail-on CRITICAL

# inspect version and build metadata
aegisci version
```

---

## Documentation

For full guides, detailed configuration options, CLI reference, and recipe workflows, please see:
[Complete Guide (`docs/USAGE.md`)](docs/USAGE.md)

---

## License

Distributed under the MIT License. See [`LICENSE`](LICENSE) for details.