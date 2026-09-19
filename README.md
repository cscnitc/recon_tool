# Automated Recon Platform

> **Engineering Execution Plan - 5-Developer Team**

A fast, structured reconnaissance orchestrator designed to parallelize asset mapping and deliver a single actionable report:

**Domains -> Subdomains -> IPs -> Ports -> Services -> Technologies -> URLs -> APIs -> JS Endpoints -> Paths**

## Operational Modes

### Mode 1: THM / HTB / CTF

- Aggressive + comprehensive active scanning
- Maximized parallel execution for fast turnaround
- Port sweeping, service detection (Nmap/Naabu)
- Full active directory brute-forcing (ffuf/feroxbuster)
- Deep JS asset extraction & live endpoint analysis

### Mode 2: Real Web Scan

- Non-aggressive, safe scanning posture
- Prioritizes passive OSINT & public APIs
- Zero direct directory brute-forcing
- Passive port/service mapping (Shodan/Censys)
- Basic HTTP/TLS health verification

## Work Allocation Matrix

| Developer | Primary Domain | Core Tools & Tech | Key Deliverables |
|---|---|---|---|
| **Dev 1 (Lead)** | Architecture, State & Concurrency | Go / Python, Redis, Docker | Main orchestration engine, worker queue, module loader, CLI/API config, mode enforcement |
| **Dev 2** | Passive Discovery & OSINT | Subfinder, Amass, Crt.sh, Shodan | Subdomain discovery, CT log parser, passive IP lookup, centralized API key manager |
| **Dev 3** | Active Scanning & Probing | Nmap, Masscan, Httpx, Ffuf | Active port scanner, HTTP probing wrapper, mode-switch controls, content fuzzer |
| **Dev 4** | JS & API Analysis | Katana, LinkFinder, SecretFinder | Historical URL fetcher, JS static analysis engine, path/parameter extractor, secret scanner |
| **Dev 5** | Data Pipeline & Reporting | PostgreSQL, SQLite, Jinja2 | Unified JSON schema validator, graph/tree data aggregator, JSON export & HTML dashboard |

## Core Platform Architecture

The platform follows this execution flow:

```text
Target IP/Domain
      |
      v
[ Dev 1 Engine ]
      |
      v
[ Dev 2 Passive + Dev 3 Active + Dev 4 JS Analysis ]
      |
      v
[ Dev 5 Aggregator ]
      |
      v
Attack Surface Map
```

## Sprint Breakdown & Task Delegation

### Developer 1: Core Engine & Orchestration

**Primary domain:** Core Platform & Architecture

- **Architecture & Pipeline:** Build the core execution engine utilizing an asynchronous task queue or event-driven worker pool.
- **Mode Controller:** Enforce strict runtime execution based on operational mode:
  - **CTF Mode:** Maximum thread pool, active port sweeps, and directory fuzzing enabled.
  - **Passive Mode:** Rate-limiting enforced, brute-force disabled, IP queries routed to passive APIs.
- **Module Lifecycle:** Create abstract interfaces and plugin loaders so Devs 2, 3, and 4 can register modules dynamically.

### Developer 2: Passive Reconnaissance Engine

**Primary domain:** OSINT & Passive Discovery

- **Subdomain Enumeration:** Wrap and integrate subfinder, amass, and chaos with dynamic deduplication.
- **Certificate Transparency:** Query crt.sh and certspotter APIs to discover Subject Alternative Names (SANs).
- **Passive Asset Profiling:** Query Shodan and Censys REST APIs for open ports and banners when in safe mode.
- **Secrets Config Manager:** Build central credential management for passive service API keys.

### Developer 3: Active Scanning & Probing Engine

**Primary domain:** Active Recon & Content Discovery

- **Port Scanning (CTF Mode):** Integrate naabu or masscan for fast port discovery, piping live ports to nmap for service identification (`-sV`).
- **HTTP Probing & Tech Stacks:** Implement httpx wrapper to check host status, titles, and map technology signatures (Wappalyzer).
- **Content Discovery (CTF Mode):** Wrap ffuf or feroxbuster with context-aware wordlists and pipe findings to Dev 5.

### Developer 4: JS & API Analysis Engine

**Primary domain:** Endpoint & Parameter Extraction

- **Historical & Crawled URLs:** Aggregate legacy URLs using waybackurls, gau, and crawling with katana.
- **JS Static Analysis:** Extract JavaScript files and pass them through LinkFinder and JSFinder to discover hidden API paths.
- **Secret Identification:** Implement regex analysis via SecretFinder to highlight potential API keys and unlinked endpoints.

### Developer 5: Data Pipeline, Aggregation & Reporting

**Primary domain:** Data Normalization & Dashboards

- **Data Aggregation Engine:** Ingest concurrent data feeds from Devs 2, 3, and 4 into a unified node graph.
- **Data Validation & Schema:** Enforce strict JSON schema validation for all intermediate tool outputs.
- **Reporting Suite:** Generate structured JSON outputs and an interactive HTML attack-surface dashboard.

## Deliverable

The final system is intended to consolidate parallel reconnaissance results into a unified, actionable **attack surface map**, with structured JSON output and an interactive HTML dashboard.
