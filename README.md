# Dev1: core engine and orchestration

This branch holds the runner that ties the recon modules together. Dev2 finds subdomains, Dev3 probes ports and web hosts, Dev4 pulls URLs from JS and archives. Dev1 calls them in order and passes the same flags to each.

This is a lite version. No Redis, no database, no API server. The full engine can replace it later without changing how Dev2, Dev3, or Dev4 are called.

## What lives here

- `contracts.md` records the shared flags and JSON keys.
- `schemas/` holds one example output per module.
- `runner.py` runs dev2, then dev3, then dev4.
- `logs/` stores one log file per run.

## Shared flags

Every module uses the same four flags so the runner stays simple.

```
--in targets.txt --mode ctf|audit --scope scope.txt --out out.json
```

`--mode` controls how aggressive the run is. `--scope` points to a text file with one host, domain, or CIDR per line. In audit mode the runner stops if a target is outside scope.

## Module contract

Each module is a Python script with a `run` function:

```python
def run(targets: list[str], mode: str, scope_file: str) -> dict
```

It reads the target list, writes JSON to the path given by `--out`, and returns 0 on success. It prints errors to stderr and never asks for input mid-run.

## Modes

ctf mode is for THM, HTB, and other lab targets. Threads are high, port sweeps and fuzzing are allowed.

audit mode is for college infra. The runner forces low threads and a low rate. Port sweeps are limited to the top 100 ports with `nmap -T2`. Fuzzing is off unless IT approved a window and the target is listed in scope.

## Scope and logging

scope.txt is required in audit mode. The runner checks each target against it before starting any module. Anything outside scope ends the run with an error.

Each run writes to `logs/run-<date>.log` with the user, time, mode, scope file hash, and exit code of each module. Keep these logs. IT may ask what was scanned and when.

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
