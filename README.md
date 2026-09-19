# Dev1: core engine and orchestration

This branch holds the runner that ties the recon modules together. Dev2 finds subdomains, Dev3 probes ports and web hosts, Dev4 pulls URLs from JS and archives. Dev1 calls them in order and passes the same flags to each.

This is a lite version. No Redis, no database, no API server. The full engine can replace it later without changing how Dev2, Dev3, or Dev4 are called.

## What lives here

- `contracts.md` records the shared flags and JSON keys.
- `schemas/` holds one example output per module.
- `runner.py` runs dev2, then dev3, then dev4.
- `logs/` stores one log file per run.

## Shared flags

Every module uses the same four flags plus two optional rate flags so the runner stays simple.

```
--in targets.txt --mode ctf|audit --scope scope.txt --out out.json [--rate N] [--threads N]
```

`--mode` controls how aggressive the run is. `--scope` points to a text file with one host, domain, or CIDR per line. Targets are arbitrary, examples are placeholders. In audit mode the runner stops if a target is outside scope. Omit `--rate` and `--threads` to take mode defaults: audit `rate 20, threads 10`, ctf `rate 1000, threads 100`. Audit allows up to `rate 50, threads 20` freely, above that needs `--override reason-text` which is logged.

## Module contract

Each module is a Python script with a `run` function:

```python
def run(targets: list[str], mode: str, scope_file: str) -> dict
```

It reads the target list, writes JSON to the path given by `--out`, and returns 0 on success. It prints errors to stderr and never asks for input mid-run.

## Modes

ctf mode is for THM, HTB, and other lab targets. Threads are high, port sweeps and fuzzing are allowed.

audit mode is for college infra. Defaults are low rate and low threads. Port sweeps are limited to the top 100 ports with `nmap -T2`. Fuzzing is off. API keys are BYO via `keys.env`, fallback is keyless sources with a note logged.

## Scope and logging

scope.txt is required in audit mode. A subdomain of a listed domain counts as in scope. For CIDR entries, network and broadcast addresses are skipped. IPv6 is out for v1. The runner checks each target against it before starting any module. Anything outside scope ends the run with an error.

Each run writes to `logs/run-<date>.log` with the user, time, mode, effective rate and threads, override reason if used, scope file hash, and exit code of each module. Keep these logs. IT may ask what was scanned and when.

## Layout

```
dev1/
  runner.py
  contracts.md
  schemas/
    dev2.json
    dev3.json
    dev4.json
  logs/
```

## How to run

```bash
python runner.py --in targets.txt --mode audit --scope scope.txt --out-dir ./out
python runner.py --in targets.txt --mode ctf --scope scope.txt --out-dir ./out
```

Output lands in `./out/dev2.json`, `./out/dev3.json`, `./out/dev4.json`. Dev5 merges them later.

## For Dev2, Dev3, Dev4

Build your script so it works alone first:

```bash
python ../dev3/dev3.py --in targets.txt --mode ctf --scope scope.txt --out dev3.json
```

If it runs alone with these four flags, the runner can pick it up with no changes.
