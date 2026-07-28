---
title: "Package Scanner — System Design"
---

**A Kubernetes-native pipeline for detecting malicious packages in npm and PyPI at publish time.**

## Problem

Supply-chain attacks against open-source registries (typosquats, dependency
confusion, compromised maintainer accounts) are usually discovered *after*
they've already been pulled into production builds. The window between
publish and detection is where the damage happens. This project closes that
window by watching registry publish feeds in real time, pulling every new
package into an isolated environment, and running it through static
malware-detection heuristics — without ever executing the package's code.

## Design goals

1. **Never execute untrusted code.** The entire pipeline only fetches and
   statically inspects packages — no `npm install`, no `pip install`, no
   running install-time scripts.
2. **Contain the blast radius.** Every stage that touches a real package
   archive is disposable, sandboxed, and network-restricted, so a
   sufficiently hostile package can't affect anything beyond its own
   short-lived job.
3. **Run unattended, indefinitely, on modest infrastructure.** This is built
   for a single operator, not a SOC team — every technology choice favors
   low operational overhead over horizontal scale.

## Architecture

```
                    ┌─────────────────────┐
  npm _changes  ──▶ │   Feed Listener      │   namespace: ingestion
  PyPI JSON feed──▶ │  (long-running pod)  │   metadata only, no package
                    └──────────┬───────────┘   contents ever touched
                               │  {name, version, registry}
                               ▼
                    ┌─────────────────────┐
                    │   Redis Stream       │   namespace: infra
                    │   packages:new       │   consumer groups + XCLAIM retry
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Downloader Job      │   namespace: scanning
                    │  fetch + safe-extract│   non-root, read-only rootfs,
                    │  (one-shot, dies)    │   capabilities dropped, sandboxed
                    └──────────┬───────────┘   runtime (gVisor)
                               │  raw + extracted source
                               ▼
                    ┌─────────────────────┐
                    │   Object Storage     │   namespace: infra
                    │   (MinIO / S3)       │   keyed by name@version
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   Scanner Job        │   namespace: scanning
                    │   GuardDog (static   │   same hardening as downloader
                    │   analysis only)     │   egress locked to registry API
                    └──────────┬───────────┘
                               │  verdict + indicators
                               ▼
                    ┌─────────────────────┐
                    │   Elasticsearch      │   namespace: results
                    │   + Kibana           │   dashboards, alerting rules
                    └──────────┬───────────┘
                               │  high severity
                               ▼
                        Slack webhook
```

## Trust boundaries

The system is split into three Kubernetes namespaces, each representing a
different level of exposure to adversarial input:

| Namespace   | What runs there                     | Exposure to untrusted data                     |
|-------------|--------------------------------------|-------------------------------------------------|
| `ingestion` | Feed listener                        | None — only sees JSON metadata (name/version)   |
| `scanning`  | Downloader Job, Scanner Job           | Full — extracts and inspects raw package archives |
| `results`   | Elasticsearch, Kibana, alerting       | None — only sees structured verdict documents   |

`infra` (Redis, MinIO) sits outside the three trust-boundary namespaces since
it's shared plumbing, not a compute stage.

Each namespace has a **default-deny NetworkPolicy** with explicit allows only
for what that stage actually needs — the scanning namespace, for example, can
reach the npm/PyPI registry APIs and object storage, but nothing else.

## Why packages are never executed

This is the load-bearing security property of the whole design. Most package
malware triggers via install-time hooks — npm's `postinstall` script, or
Python's `setup.py` running arbitrary code on `pip install`. By only ever
downloading and extracting an archive — never installing it — the pipeline
sidesteps the primary way these packages actually cause harm. GuardDog then
performs *static* analysis: pattern-matching on source code, flagging
suspicious install hooks and obfuscation, checking for typosquatting — all
without needing to run anything.

## Why Kubernetes Jobs, not long-lived containers

An earlier version of this design considered a pair of long-lived containers
(one for the scanner tooling, one for pulling/scanning packages), reset
periodically to avoid cross-contamination between packages. The final design
goes further: the downloader and scanner are **Kubernetes Jobs** — one-shot
workloads that run to completion and terminate. There is no "reset" step
because there's no persistent process to reset; every package gets a fresh
pod, and `ttlSecondsAfterFinished` cleans up completed Jobs automatically.
This removes an entire class of bugs where state from one package's
extraction could leak into the next.

## Sandbox hardening (downloader + scanner pods)

- `runAsNonRoot: true`
- `readOnlyRootFilesystem: true`
- All Linux capabilities dropped
- `emptyDir` extraction volume with a hard size limit (blunts decompression /
  zip-bomb attacks)
- Archive extraction guards against path traversal (`../` entries) and
  symlink escapes
- Sandboxed container runtime (gVisor) for kernel-level isolation on the
  component handling the most adversarial input — the downloader
- `automountServiceAccountToken: false` — no Kubernetes API access needed
  from inside these pods

## Data flow decoupling

Rather than wiring stages directly together, every handoff goes through
shared infrastructure so each stage can fail, retry, or scale independently:

- **Feed listener → downloader**: Redis Stream (`packages:new`), consumer
  groups with `XPENDING`/`XCLAIM` so a crashed downloader doesn't lose work.
- **Downloader → scanner**: object storage (MinIO), keyed by
  `{registry}/{name}/{version}/` — also gives free deduplication and an
  audit trail of every artifact ever pulled.
- **Scanner → alerting**: Elasticsearch document write, with Kibana alerting
  rules firing a Slack webhook on high-severity verdicts.

**Idempotency key** throughout: `{registry}:{name}@{version}`. Any stage can
check whether a package has already been processed and skip it.

## Tech stack and why

| Component        | Choice                | Why |
|-------------------|------------------------|-----|
| Queue             | Redis Streams          | Simple to operate solo; persistence via AOF/RDB; consumer groups give retry semantics without a heavier broker |
| Object storage    | MinIO                  | S3-compatible, trivial to self-host, swappable for real S3 later |
| Static scanner    | GuardDog                | Purpose-built for package supply-chain heuristics; never executes package code |
| Results store     | Elasticsearch           | Scan output is semi-structured (varying indicators, nested metadata) — a better fit than a rigid relational schema |
| Dashboard/alerting | Kibana                | Comes free with Elasticsearch; built-in alerting rules cover Slack webhooks without a separate service |
| Autoscaling        | KEDA                   | Scales downloader/scanner Jobs based on Redis stream lag — idle most of the time, scales up during publish bursts |
| Isolation runtime  | gVisor                 | Kernel-level sandboxing for the pods handling raw, untrusted archives |

## What this demonstrates

- Threat modeling a data pipeline by trust boundary, not just by service
- Defense in depth: no single control (non-root, read-only fs, network
  policy, sandboxed runtime, static-only analysis) is load-bearing alone
- Event-driven, horizontally scalable design that still runs affordably for
  a single operator
- Understanding of the actual mechanism of npm/PyPI supply-chain attacks
  (install-time script execution) and designing specifically against it

## Status / roadmap

- [ ] Feed listener (npm + PyPI)
- [ ] Downloader with safe-extract guards
- [ ] Scanner with GuardDog integration
- [ ] Kubernetes manifests + NetworkPolicies
- [ ] KEDA autoscaling
- [ ] Kibana alerting → Slack
