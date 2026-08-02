---
title: "Npm-Monitor: Package Security Pipeline"
---

**A Kubernetes-native pipeline for detecting malicious packages in npm and PyPI in real time via static heuristics and dynamic sandboxing.**

This system design details the architecture of **Npm-Monitor**, an open-source, automated pipeline designed to mitigate supply-chain attacks. It is based on the implementation in the [ManuMW/Npm-Monitor](https://github.com/ManuMW/Npm-Monitor) repository.

---

## The Problem

Supply-chain attacks against package registries (npm typosquatting, dependency confusion, compromised developer accounts) are typically discovered *after* packages are integrated into builds. The window between a malicious package being published and its public disclosure is when the damage occurs. 

**Npm-Monitor** closes this window by watching registry publish feeds in real time, downloading new packages (including pre-releases) into network-restricted sandbox environments, and scanning them with a dual static/dynamic analysis pipeline before they can infect developer environments or CI/CD pipelines.

---

## Design Goals

1. **Dual-Layer Analysis**: Combine static parsing and active execution monitoring to catch obfuscated malware.
2. **Defensive Isolation**: Execute untrusted code exclusively in disposable, kernel-isolated sandboxes (`gVisor`).
3. **Decoupled Architecture**: Structure ingestion, storage, scanning, and indexing using message queues and object stores to scale parts of the pipeline independently.
4. **Comprehensive Ingestion**: Listen to all published registry releases, specifically targeting pre-release versions (`alpha`, `beta`, `rc`) which are frequently used as delivery channels for early stage implants.

---

## System Architecture

The pipeline processes new packages sequentially through three trust boundaries (`ingestion`, `scanning`, and `results`). Shared plumbing runs in the `infra` boundary:

```text
                        Public Registries (npm / PyPI)
                                       │
                                       │ HTTP Polling (inc. pre-releases)
                                       ▼
                       ┌──────────────────────────────┐
                       │   feed-listener (Pod)        │   namespace: ingestion
                       └──────────────┬───────────────┘
                                      │ Publish {name, version, registry}
                                      ▼
                       ┌──────────────────────────────┐
                       │   Redis Stream (packages:new)│   namespace: infra
                       └──────────────┬───────────────┘
                                      │
                         ┌────────────┴────────────┐
                         │  Job Dispatcher / KEDA  │
                         └────────────┬────────────┘
                                      │ Spawns Ephemeral Jobs
                                      ▼
 ┌──────────────────────────────────────────────────────────────────────────────────┐
 │ scanning namespace (Hardened Pod Sandboxes / gVisor)                             │
 │                                                                                  │
 │  ┌─────────────────────────┐  ┌─────────────────────────┐  ┌───────────────────┐ │
 │  │    downloader (Job)     │  │  scanner (Static Job)   │  │  dynamic-scanner  │ │
 │  │ ├─ GET archive          │  │ ├─ GuardDog Scan        │  │  │ (gVisor Job)   │ │
 │  │ └─ SafeExtract Guard    │  │ └─ JS/TS AST Heuristics │  │ ├─ 30s Timeout    │ │
 │  └───────────┬─────────────┘  └───────────┬─────────────┘  │ ├─ require() Exec │ │
 └──────────────┼────────────────────────────┼────────────────│ └─ Proc/Net Monitor│ │
                │                            │                └─────────┬─────────┘ │
                │                            │                          │           │
                ▼ Store Archives             ▼ Index Verdicts           ▼ Index Telemetry
 ┌────────────────────────────┐  ┌────────────────────────────┐                     │
 │   Object Storage (MinIO)   │  │ Elasticsearch / Kibana     │◄────────────────────┘
 └────────────────────────────┘  └───────────┬────────────────┘   namespace: results
                                             │ Trigger Alerts
                                             ▼
                                       Slack Webhook
```

---

## Trust Boundaries & Hardened Execution

The system isolates components according to their level of exposure to untrusted data:

| Namespace | What Runs There | Exposure to Untrusted Data | Security Controls |
| :--- | :--- | :--- | :--- |
| **`ingestion`** | Feed listener | None. Only processes metadata. | Default-deny network policies; egress restricted to Redis and public registries. |
| **`scanning`** | Downloader, Static Scanner, Dynamic Scanner | **Full**. Interacts directly with unverified code. | Runs inside `gVisor` (`runsc`) container runtime. Pods run as non-root with dropped capabilities (`capabilities.drop: [ALL]`), read-only root filesystems, and strict egress tracking. |
| **`results`** | Elasticsearch, Kibana, alerting | None. Only stores structured JSON alerts. | Accessible only within internal networks; no access to scanning namespace. |

---

## Core Components & Capabilities

### 1. Pre-Release Feed Ingestion
Malware authors often publish packages under pre-release tags (`beta`, `rc`, `alpha`) or non-`latest` tags to test their implants or avoid mainstream scanning. The `feed-listener` monitors registries by querying version history metadata directly:
* **npm**: Ingests CouchDB `_changes` feeds, parsing the full document version histories to capture release tags like `@joyfill/layouts@0.1.2-2773.beta.0`.
* **PyPI**: Polls the PyPI RSS/JSON feeds to extract and queue new publish releases.

---

### 2. Defensive Decompression (`safe_extract.py`)
Package archives (e.g., `.tgz`, `.whl`) are parsed by the downloader using strict defensive boundaries to prevent exploitation during extraction:
* **Path Traversal Guard**: Explicitly rejects files containing directory traversal tokens (like `../`), preventing malware from writing files outside the target directory (e.g., overwriting `~/.bashrc` or `/etc/passwd`).
* **Decompression Bomb Guard**: Enforces a strict limit (default `100MB`) on uncompressed sizes to neutralize zip-bomb attacks that seek to crash the host node.
* **Symlink Escape Guard**: Validates that all symlinks extracted point strictly within the destination directory root, rejecting links pointing to host paths.

---

### 3. Dual-Layer Scanning Pipeline

#### A. Static Analysis
The static scanner combines community rulesets with custom abstract syntax tree (AST) matching to find high-signal indicators of malicious intent:
* **GuardDog Integration**: Identifies structural patterns such as unexpected package metadata, missing repositories, and basic exfiltration heuristics.
* **Custom JS/TS AST Heuristics**: Analyzes JavaScript source code structures without executing them:
  * Detects advanced obfuscation (dense string arrays, encoding, hex formatting).
  * Flags execution hooks embedded in lifecycle scripts (e.g., npm `preinstall` or `postinstall`).
  * Identifies multi-blockchain C2 resolvers that fetch C2 destinations from Tron, Aptos, or BSC smart contract transactions.
  * Spots sandbox evasion checks targeting virtualization variables (e.g., detecting `github-runner`, `microsoft-standard-WSL2`, or common docker paths).

#### B. Dynamic Sandbox Analysis
Static analysis is often bypassed by obfuscated or dynamic payload loaders. The dynamic scanner resolves this by running the code inside a highly secured container environment:
* **Isolation runtime**: Containers run on the `gVisor` (`runsc`) sandbox runtime to restrict system call access to the host Linux kernel.
* **30-Second hard timeout**: Blunts endless loops and stalls.
* **Import-time execution**: Simulates how a developer imports the module by running package entry points (e.g., executing `require('malicious-module')` or importing Python modules).
* **System Call & Process Auditing**: Monitors process creations (e.g., spawning shell instances like `powershell`, `cmd.exe`, `xclip`, or `pbpaste`).
* **Network Egress Guard**: Audits and drops network calls to capture exfiltration strings and record active C2 IP addresses.

---

## Data Decoupling & Queue Management

The pipeline uses message queues and object stores to decouple stages and prevent bottlenecks:
* **Redis Streams**: The `feed-listener` publishes raw metadata into the `packages:new` stream. Consumer groups allow workers to claim and process tasks. If a worker pod crashes mid-scan, `XCLAIM` retries ensure the package is re-scanned.
* **KEDA (Kubernetes Event-driven Autoscaling)**: KEDA monitors Redis stream lag. When registries experience large bursts of publishes, KEDA spins up ephemeral `ScaledJobs` in Kubernetes. Pods scale to zero when the stream is empty to save resources.
* **Object Storage**: Extracted files and raw tarballs are persisted in MinIO/S3 using the key format `{registry}/{name}/{version}/`. This allows the static and dynamic scanners to fetch source structures independently without re-downloading files from public registries.

---

## Tech Stack & Architecture Choices

| Component | Choice | Rationale |
| :--- | :--- | :--- |
| **Broker** | Redis Streams | Provides persistent queuing, consumer groups, and retry state with low operational overhead. |
| **Object Store** | MinIO | S3-compatible object storage that can be self-hosted locally and scales to real AWS S3 easily. |
| **Autoscaler** | KEDA | Handles event-driven scaling of Kubernetes Jobs directly from Redis queue depth. |
| **Sandbox Runtime** | gVisor (`runsc`) | Provides kernel-level virtualization for running untrusted container payloads safely. |
| **Database** | Elasticsearch | Indexes nested, semi-structured JSON verdicts containing AST and dynamic trace metadata. |
| **Heuristic Engines** | GuardDog & `safe_extract` | Lightweight, purpose-built engines for identifying supply-chain threats without complex dependencies. |

---

## Getting Started & Repository Reference

To explore the pipeline implementation, configure local stacks, or run the test suite, reference the official repository:

* **Repository**: [github.com/ManuMW/Npm-Monitor](https://github.com/ManuMW/Npm-Monitor)

### Run Automated Tests Locally
To verify the path-traversal prevention, decompression guards, ingestion processes, and analysis components, run the pytest suite:
```bash
python3 -m pytest
```

### Seeding Packages to Pipeline
You can test ingestion by seeding mock packages:
```bash
# Seed a package with pre-release tags and blockchain C2 resolvers
python3 scripts/seed-test-package.py --name @joyfill/layouts --version 0.1.2-2773.beta.0 --registry npm
```
