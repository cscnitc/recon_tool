# Contracts

Shared flags and keys for dev2, dev3, and dev4. The runner and the merge script rely on these, so keep them stable.

## Flags

Every module takes the same four flags, plus two optional rate flags:

```
--in targets.txt --mode ctf|audit --scope scope.txt --out out.json [--rate N] [--threads N]
```

`--in` is a text file with one host per line. Targets are arbitrary: any domain, IP, or CIDR works, examples are placeholders. `--mode` is either ctf or audit. `--scope` points to a file with one allowed host, domain, or CIDR per line. A subdomain of a listed domain counts as in scope. For CIDR entries, network and broadcast addresses are skipped. IPv6 is out for v1. `--out` is where the module writes JSON.

In audit mode the scope check runs first. A target outside scope stops the run before any packet is sent. The real scope file stays local and never goes into git. Only `scope.example.txt` is tracked.

## Rates

Omit `--rate` and `--threads` to take mode defaults. Audit defaults to `rate 20, threads 10`. Ctf defaults to `rate 1000, threads 100`.

Bounds are enforced in code. Audit allows `rate 10-50` and `threads 5-20` freely. Above that needs `--override reason-text`, which is written to the run log and report notes. Ctf allows `rate 100-5000` and `threads 10-200`. Every run logs the effective rate, threads, and whether override was used.

## Keys

API keys are BYO and optional. Copy `keys.example.env` to `keys.env` (gitignored) and fill your own free keys. With no key the module falls back to keyless sources and logs `enrichment skipped, no key` in notes. Required JSON keys never change either way. Devs never share keys.

BYO tools follow the same rule and never change required keys. `--scanner masscan` and `--fuzzer ferox` work only in ctf mode when the binary exists, otherwise the run continues on defaults with a note. `--extended` enables amass for dev2 in ctf mode.

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

report.json is built by dev5 by joining the three files on `host`. run-meta.json records mode, time, scope hash, input hashes, effective rate and threads, and counts. Secret hints from dev4 are redacted from `report.md` and kept only in `report.json` for the team.

## Extra keys

A module may add a new key without breaking the merge. The merge checks required keys and types, skips bad records with file and line noted, and keeps the rest.

## Test

```bash
python dev3.py --in schemas/dev2.json --mode audit --scope scope.example.txt --out out.json
python merge.py --in ./out --out ./report
```
