# Contracts

Shared flags and keys for dev2, dev3, and dev4. The runner and the merge script rely on these, so keep them stable.

## Flags

Every module takes the same four flags:

```
--in targets.txt --mode ctf|audit --scope scope.txt --out out.json
```

`--in` is a text file with one host per line. `--mode` is either ctf or audit. `--scope` points to a file with one allowed host, domain, or CIDR per line. `--out` is where the module writes JSON.

In audit mode the scope check runs first. A target outside scope stops the run before any packet is sent. The real scope file stays local and never goes into git. Only `scope.example.txt` is tracked.

## Function shape

Each module exposes this function and works alone from the command line:

```python
def run(targets: list[str], mode: str, scope_file: str) -> dict
```

It returns 0 on success, writes JSON to `--out`, and prints errors to stderr. It never asks for input mid-run.

## Required keys

dev2.json, one record per host. Required: `host, ips`.

dev3.json, one record per port. Required: `host, ip, port, service`. `http` is null when no HTTP answers. `dirs` stays empty in audit mode.

dev4.json, one record per host. Required: `host, urls`.

report.json is built by dev5 by joining the three files on `host`. run-meta.json records mode, time, scope hash, input hashes, and counts.

## Extra keys

A module may add a new key without breaking the merge. The merge checks required keys and types, skips bad records with file and line noted, and keeps the rest.

## Test

```bash
python dev3.py --in schemas/dev2.json --mode audit --scope scope.example.txt --out out.json
python merge.py --in ./out --out ./report
```
