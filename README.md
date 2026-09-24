# Dev4: JS & API Analysis Engine

Dev4 extracts JavaScript endpoints, API parameters, and secrets from crawled URLs and historical archives. It takes the subdomain list from Dev2 and live hosts from Dev3, then performs deep JS static analysis to find hidden APIs, paths, and potential secrets.

## What it does

- **Historical URL aggregation**: Pulls URLs via `gau` and `waybackurls` from archives
- **Crawling**: Uses `katana` to discover additional endpoints (depth gated by mode)
- **JS static analysis**: Extracts JavaScript files and runs them through `LinkFinder` to find hidden API paths and parameters
- **Secret identification**: Runs `SecretFinder` regex to highlight potential API keys, tokens, and unlinked endpoints
- **Output**: `dev4.json` with host, URLs, JS endpoints, and discovered params/secrets

## Input and output

Input is usually the subdomain list from Dev2 or live hosts from Dev3.

```
portal.college.edu
app.college.edu
```

Output is `dev4.json`, one record per host:

```json
{
  "host": "portal.college.edu",
  "urls": ["/api/v1/login", "/dashboard", "https://portal.college.edu/js/app.js"],
  "js_endpoints": ["/api/v1/login", "/api/v2/users"],
  "params": [{"key": "token", "value": "secret123"}, {"key": "api_key", "value": "AKIA..."}],
  "secrets": [{"type": "api_key", "value": "AKIA...", "location": "/js/app.js"}],
  "source_tool": "gau+waybackurls+katana+LinkFinder+SecretFinder"
}
```

If no JS files are found or crawl is disabled (audit mode), `js_endpoints`, `params`, and `secrets` stay empty.

## Modes

The `--mode` flag picks defaults, while `--rate` and `--threads` let the person running it adjust within bounds. Omit them to take mode defaults.

### CTF mode

- Full crawling depth with katana
- ffuf-style content discovery not included (handled by Dev3), but JS crawling runs deep
- LinkFinder and SecretFinder run on all extracted JS files
- Deep parameter extraction and secret scanning

### Audit mode

- Katana limited to depth 2 at most
- SecretFinder runs but results are noted as "shallow analysis" in output
- No aggressive parameter harvesting
- Fewer requests, safer for college infrastructure

## Scope check

`--scope` points to a file with one allowed host, domain, or CIDR per line. Targets are arbitrary, examples are placeholders. A subdomain of a listed domain counts as in scope. For CIDR entries, network and broadcast addresses are skipped. IPv6 is out for v1. The runner checks each target against it before starting any module. Anything outside scope ends the run with an error.

## Shared flags

Every module uses the same four flags plus two optional rate flags so the runner stays simple.

```
--in targets.txt --mode ctf|audit --scope scope.txt --out out.json [--rate N] [--threads N]
```

## Layout

```
dev4/
  dev4.py
  scope.py
  parsers.py
  wordlists/
  Dockerfile
```

- `dev4.py` handles flags and calls each step
- `scope.py` holds the scope check
- `parsers.py` converts gau, waybackurls, katana, LinkFinder, and SecretFinder output into the JSON above
- `Dockerfile` for club laptops

## How to run

```bash
python dev4.py --in subdomains.txt --mode ctf --scope scope.txt --out dev4.json
python dev4.py --in subdomains.txt --mode audit --scope scope.txt --out dev4.json
```

Docker build for club laptops:

```bash
docker build -t csc-recon:dev4 .
docker run --rm -v $(pwd)/out:/out csc-recon:dev4 \
  --in /out/subdomains.txt --mode audit --scope /out/scope.txt --out /out/dev4.json
```

Gau and waybackurls need no privileges. Katana and LinkFinder need root only if they make external requests; otherwise they work fine without root.

## For Dev2, Dev3, Dev4

Build your script so it works alone first:

```bash
python ../dev4/dev4.py --in targets.txt --mode ctf --scope scope.txt --out dev4.json
```

If it runs alone with these four flags, the runner can pick it up with no changes.
