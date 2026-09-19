# Automated Recon Platform

> **Engineering Execution Plan - 5-Developer Team**

A fast, structured reconnaissance orchestrator designed to parallelize asset mapping and deliver a single actionable report:

**Domains -> Subdomains -> IPs -> Ports -> Services -> Technologies -> URLs -> APIs -> JS Endpoints -> Paths**

## Aims

v1 exists for two uses: fast recon in CTF labs, and quiet checkups on college infra in scope. Same tools, different loudness, picked by `--mode`.

Success means one command per module with the same flags, three json files that join on host without manual cleanup, and a report the team or IT can read without asking what a column means.

Out of scope for v1: exploitation, credential testing, paid services, hosted servers, and scans outside `scope.txt` in audit mode. Those stay out even if a tool offers them. v2 (queue, database, dashboard) starts only after v1 has run one CTF and one college checkup off these files.

Targets are arbitrary. Examples use college names as placeholders. Any domain, IP, or CIDR works. The scope file decides what is allowed, not the format of the name.

## Operational Modes

### Mode 1: THM / HTB / CTF

- Aggressive active scanning with high defaults for fast turnaround
- Naabu to Nmap service scan (`-sV -sC`), defaults per mode, overridable within bounds and logged
- ffuf only in ctf mode, off in audit mode
- Deep JS asset extraction and live endpoint analysis

### Mode 2: Real Web Scan

- Quiet scanning posture with low defaults
- Passive OSINT and free public sources first
- Zero directory brute-forcing
- Free sources only (crt.sh, chaos free, Shodan or Censys only if the user plugs in their own free key, otherwise fallback to crt.sh)
- HTTP and TLS health check only

## Work Allocation Matrix

| Developer | Primary Domain | Core Tools & Tech | Key Deliverables |
|---|---|---|---|
| **Dev 1 (Lead)** | Architecture, State & Concurrency | Python, Docker (lite v1, no Redis) | Runner with shared flags, scope check, mode enforcement, log per run |
| **Dev 2** | Passive Discovery & OSINT | Python, Subfinder, Chaos free, Crt.sh, Dnsx (BYO-key optional, amass only on --extended) | Subdomain find, resolve, and dedupe to dev2.json with the same 4 flags |
| **Dev 3** | Active Scanning & Probing | Naabu, Nmap, Httpx, Ffuf (masscan or ferox only as ctf opt-in) | Naabu to Nmap service scan, httpx tech probe, mode-gated ffuf fuzzer |
| **Dev 4** | JS & API Analysis | Python, Gau, Waybackurls, Katana, LinkFinder, SecretFinder | Archive plus crawl to dev4.json with the same 4 flags, shallow only in audit |
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

Stack is Python with subfinder, chaos free, crt.sh and certspotter, plus dnsx for resolving, all in Docker. Same four flags as every module. Output is `dev2.json` with required `host` and `ips` (see `schemas/`).
- **Subdomain Enumeration:** Run subfinder and chaos, pull crt.sh and certspotter for SANs, resolve with dnsx, then dedupe. Amass runs only when `--extended` is passed, since it is slow and mostly duplicates subfinder for v1.
- **Rate and Keys:** Passive sources need no rate flags. API keys are BYO and optional: each member creates their own free account and fills their own `keys.env` (see `keys.example.env`). With no key the module falls back to crt.sh only and logs `enrichment skipped, no key` in notes. Required keys never change either way.
- **Audit Limits:** Passive only in audit mode. No DNS brute force. Every target is checked against scope before any lookup batch starts.

### Developer 3: Active Scanning & Probing Engine

**Primary domain:** Active Recon & Content Discovery

Stack is Python with naabu, nmap, httpx, and ffuf in Docker (see `dev3` branch). Same four flags plus optional `--rate` and `--threads`. Output is `dev3.json`, one record per port (see `schemas/`).
- **Port Scanning:** Run naabu for fast discovery, pipe live ports to nmap for service identification (`-sV -sC`). Defaults are audit `rate 20, threads 10` and ctf `rate 1000, threads 100`. Audit allows `10-50` and `5-20` freely, above that needs `--override reason-text` which is written to the log and report notes. Ctf allows `100-5000` and `10-200`. Masscan is a ctf-only opt-in via `--scanner masscan` when the binary exists, same output shape.
- **HTTP Probing & Tech Stacks:** Use the httpx wrapper with tech detect and TLS probe to record status, title, and tech. No separate Wappalyzer step.
- **Content Discovery:** Use ffuf with raft wordlists in ctf mode. It stays off in audit mode. Feroxbuster is a ctf-only opt-in via `--fuzzer ferox` when the binary exists. Findings go to Dev 5 as `dev3.json`.

### Developer 4: JS & API Analysis Engine

**Primary domain:** Endpoint & Parameter Extraction

Stack is Python with gau, waybackurls, katana, LinkFinder, and SecretFinder in Docker. Same four flags as every module. Input is the dev2 list plus dev3 live hosts. Output is `dev4.json` with required `host` and `urls` (see `schemas/`).
- **Historical & Crawled URLs:** Pull gau and waybackurls first, then crawl with katana. Audit mode uses archives plus katana depth 2 at most. Ctf mode may crawl deeper.
- **JS Static Analysis:** Extract JavaScript files and pass them through LinkFinder to find hidden API paths. JSFinder is dropped as overlap. Params are collected by the parser, not a separate tool.
- **Secret Identification:** Run SecretFinder regex and store matches as hints for the team. Hints stay in `dev4.json` and `report.json` but are redacted from the IT-facing `report.md`.

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
- dev2 finds subdomains and IPs to dev2.json (see Dev 2 section above for flags and keys).
- dev4 finds URLs and JS endpoints to dev4.json (see Dev 4 section above for flags and limits).

## Deliverable

v1 delivers a unified attack surface map as `report.json` plus a readable `report.md`, built from flat files with no servers. The interactive HTML dashboard and database-backed history are v2 and will read the same `report.json`.
