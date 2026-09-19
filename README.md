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
| **Dev 1 (Lead)** | Architecture, State & Concurrency | Python, Docker (lite v1, no Redis) | Runner with shared flags, scope check, mode enforcement, log per run |
| **Dev 2** | Passive Discovery & OSINT | Subfinder, Amass, Crt.sh, Shodan | Subdomain discovery, CT log parser, passive IP lookup, centralized API key manager |
| **Dev 3** | Active Scanning & Probing | Naabu, Nmap, Httpx, Ffuf | Naabu to Nmap service scan, httpx tech probe, mode-gated ffuf fuzzer |
| **Dev 4** | JS & API Analysis | Katana, LinkFinder, SecretFinder | Historical URL fetcher, JS static analysis engine, path/parameter extractor, secret scanner |
| **Dev 5** | Data Pipeline & Reporting | Python, SQLite, JSON/Markdown (lite v1) | Schema check, merge to report.json/md, run metadata (DB and HTML dashboard in v2) |

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

v1 is a lite Python runner (see `dev1` branch). No Redis, no database. The full queue can replace it later without changing module flags.
- **Architecture & Pipeline:** Call dev2, then dev3, then dev4 with the same four flags (`--in --mode --scope --out`).
- **Mode Controller:** Enforce strict runtime execution based on operational mode:
  - **CTF Mode:** High threads, active port sweeps, and directory fuzzing enabled.
  - **Audit Mode:** Low rate (`nmap -T2`, top 100 ports), fuzzing off, `scope.txt` required. Anything outside scope stops the run.
- **Module Lifecycle:** Each module exposes `run(targets, mode, scope_file)` and writes JSON. The runner logs user, time, mode, and exit code per module.

### Developer 2: Passive Reconnaissance Engine

**Primary domain:** OSINT & Passive Discovery

- **Subdomain Enumeration:** Wrap and integrate subfinder, amass, and chaos with dynamic deduplication.
- **Certificate Transparency:** Query crt.sh and certspotter APIs to discover Subject Alternative Names (SANs).
- **Passive Asset Profiling:** Query Shodan and Censys REST APIs for open ports and banners when in safe mode.
- **Secrets Config Manager:** Build central credential management for passive service API keys.

### Developer 3: Active Scanning & Probing Engine

**Primary domain:** Active Recon & Content Discovery

Stack is Python with naabu, nmap, httpx, and ffuf in Docker (see `dev3` branch). No masscan, no paid services.
- **Port Scanning (CTF Mode):** Run naabu for fast discovery, pipe live ports to nmap for service identification (`-sV -sC`). In audit mode limit to top 100 ports at `--rate 20` with `-T2`.
- **HTTP Probing & Tech Stacks:** Use the httpx wrapper with tech detect and TLS probe to record status, title, and tech. No separate Wappalyzer step.
- **Content Discovery (CTF Mode):** Use ffuf with raft wordlists. It stays off in audit mode unless IT approved a window and the target is in scope. Findings go to Dev 5 as `dev3.json`.

### Developer 4: JS & API Analysis Engine

**Primary domain:** Endpoint & Parameter Extraction

- **Historical & Crawled URLs:** Aggregate legacy URLs using waybackurls, gau, and crawling with katana.
- **JS Static Analysis:** Extract JavaScript files and pass them through LinkFinder and JSFinder to discover hidden API paths.
- **Secret Identification:** Implement regex analysis via SecretFinder to highlight potential API keys and unlinked endpoints.

### Developer 5: Data Pipeline, Aggregation & Reporting

**Primary domain:** Data Normalization & Dashboards

v1 is a lite Python merge (see `dev5` branch). No Postgres, no hosted dashboard. Those move to v2 and will read the same `report.json`.
- **Data Aggregation Engine:** Read `dev2.json`, `dev3.json`, and `dev4.json` from one folder and join on host or IP.
- **Data Validation & Schema:** Check required keys and types. Skip bad records with file and line noted, allow extra keys.
- **Reporting Suite:** Write `report.json`, `report.md`, and `run-meta.json`. The markdown fits a CTF writeup or a short note to IT.

## Module outputs

`dev*.json` means the three files Dev 5 merges: `dev2.json` holds subdomains and IPs, `dev3.json` holds ports, services, and HTTP results, `dev4.json` holds URLs and JS endpoints. Phase 2 starts when all three exist and pass key checks.

## Branches

- main holds this overview.
- dev1 holds the lite runner and shared flags.
- dev3 holds the active scanner (naabu, nmap, httpx, ffuf).
- dev5 holds the lite merge to `report.json` and `report.md`.
- dev2 and dev4 are owned by their teams and stay untouched here.

## Deliverable

The final system is intended to consolidate parallel reconnaissance results into a unified, actionable **attack surface map**, with structured JSON output and an interactive HTML dashboard.
