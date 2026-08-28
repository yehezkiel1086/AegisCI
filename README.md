# 🛡️ AegisCI

> **All-in-One DevSecOps Scanner & Security Orchestrator for GitHub Actions.**  
> Consolidate SAST, DAST, Secrets Detection, SCA, and IaC Auditing into a single Go-powered action with native GitHub Security Tab integration.

[![GitHub Release](https://img.shields.io/github/v/release/your-org/aegisci?style=flat-square&color=blue)](https://github.com/your-org/aegisci/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-AegisCI-purple?style=flat-square&logo=github)](https://github.com/marketplace/actions/aegisci)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

---

## 🚀 Why AegisCI?

Security tool sprawl kills pipeline performance and frustrates engineering teams. Maintaining separate workflow configurations for static code analysis, dependency audits, container scanning, secret detection, and dynamic API testing leads to fragmented reports and alert fatigue.

**AegisCI** brings end-to-end security automation into a single GitHub Action. It auto-detects your repository stack, runs light or deep security suites based on pipeline triggers, and merges all findings into a **single unified SARIF report** uploaded straight to your GitHub Security tab.

---

## ✨ Key Features

| Security Pillar | Engines / Capabilities | What It Secures |
| :--- | :--- | :--- |
| **SAST** | SonarScanner, Semgrep | Source code vulnerabilities, anti-patterns, OWASP Top 10 |
| **DAST** | OWASP ZAP (Baseline & Full API) | Runtime endpoints, header misconfigurations, exposure |
| **SCA & SBOM** | Trivy, Syft | Vulnerable open-source packages (`npm`, `pip`, `go.mod`), SPDX/CycloneDX SBOMs |
| **Secrets Detection** | Gitleaks | Leaked API keys, private certificates, cloud tokens with optional live checks |
| **IaC & Containers** | Checkov, KICS | Misconfigured Terraform, Dockerfiles, Kubernetes manifests |
| **Workflow Hardening**| Zizmor | Unpinned GitHub Actions, script injections inside `.github/workflows/` |

---

## 📦 Quickstart

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
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write # Required for GitHub Security Tab upload

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run AegisCI Security Suite
        uses: your-org/aegisci@v1
        with:
          mode: "auto" # Runs lightweight 'pr-check' on PRs, full scan on merge
          fail-on-severity: "HIGH"

```

---

## ⚡ PR-Check vs. Deep-Scan Modes

AegisCI automatically scales its scan depth depending on the workflow context to protect pipeline speeds:

* **PR-Check (Fast)**: Optimized for fast developer feedback (< 3 mins). Runs SAST, secret checks, dependency auditing, and a light OWASP ZAP Baseline scan.
* **Deep-Scan (Comprehensive)**: Triggered on main branch pushes or releases (~10-15 mins). Executes full active DAST crawls, full container layer auditing, and deep IaC compliance policies.

```yaml
- name: AegisCI PR Gate
  uses: your-org/aegisci@v1
  with:
    mode: "pr-check"
    sast: true
    dast: true
    dast-target-url: "http://localhost:8080"

```

---

## 🛠️ Inputs & Configuration

| Input | Description | Default | Required |
| --- | --- | --- | --- |
| `mode` | Execution mode: `auto`, `pr-check`, or `deep-scan`. | `auto` | No |
| `fail-on-severity` | Fail pipeline on findings: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. | `HIGH` | No |
| `sast` | Enable Static Application Security Testing. | `true` | No |
| `dast` | Enable Dynamic Application Security Testing (OWASP ZAP). | `false` | No |
| `dast-target-url` | Web app URL or local HTTP endpoint for DAST scanning. | `""` | Optional |
| `secrets` | Enable secret scanning via Gitleaks engine. | `true` | No |
| `sca` | Enable Software Composition Analysis & SBOM generation. | `true` | No |
| `iac` | Enable Infrastructure-as-Code & Container scanning. | `true` | No |
| `upload-sarif` | Automatically upload unified SARIF to GitHub Code Scanning. | `true` | No |
| `policy-file` | Path to custom `.aegisci.yml` policy rules. | `.aegisci.yml` | No |

---

## 🎯 Unified SARIF & GitHub Code Scanning

AegisCI aggregates output across all scanning engines into a single valid `results.sarif` file. Vulnerabilities appear directly inline on Pull Request diffs and inside **Security → Code scanning alerts**.

```
┌────────────────────────────────────────────────────────┐
│                    AegisCI Engine                      │
│                                                        │
│  [SAST Engine]   [DAST Engine]   [Secrets]   [SCA Engine] │
│        │                │            │           │     │
│        └──────────┬─────┴────────────┴───────────┘     │
│                   ▼                                    │
│        Unified SARIF Aggregator                        │
└───────────────────┬────────────────────────────────────┘
                    │
                    ▼
   GitHub Code Scanning (Security Tab)

```

> [!TIP]
> Ensure your workflow job includes the permission `security-events: write` so AegisCI can post security findings to the repository's Security dashboard.

---

## 📄 Policy-as-Code (`.aegisci.yml`)

Fine-tune rules, bypass false positives, and set grace periods by adding a `.aegisci.yml` file to your repository root:

```yaml
version: "1.0"

settings:
  fail_on_unpatched_cves: false # Don't block builds if no vendor fix exists

exceptions:
  - id: "CVE-2023-XXXXX"
    reason: "Internal microservice not exposed to public network"
    expires: "2026-12-31"

  - id: "G304" # Semgrep file path provided as taint input
    path: "src/utils/fileReader.ts"
    reason: "Path validated by internal sanitizer routine"

dast:
  exclude_paths:
    - "/logout"
    - "/admin/reset-db"

```

---

## 🤝 Contributing

Contributions are warmly welcome! Whether you want to add a new security engine, optimize SARIF parsing logic, or improve documentation:

1. Fork the project repository.
2. Create your feature branch (`git checkout -b feat/new-engine`).
3. Commit changes (`git commit -m 'feat: add custom SAST rule module'`).
4. Push to the branch (`git push origin feat/new-engine`).
5. Open a Pull Request.

Please see our [CONTRIBUTING.md](https://www.google.com/search?q=CONTRIBUTING.md) guide for build instructions and local testing setups.

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](https://www.google.com/search?q=LICENSE) for details.

```

<ElicitationsGroup message="What component of AegisCI would you like to construct next?">
  <Elicitation label="Draft the action.yml metadata manifest" query="Draft the action.yml file for the AegisCI composite GitHub Action using the new input parameter schema."/>
  <Elicitation label="Write the Go code for the .aegisci.yml policy evaluator" query="Write the Go package for parsing .aegisci.yml policy files and filtering SARIF results based on exception rules."/>
</ElicitationsGroup>

```