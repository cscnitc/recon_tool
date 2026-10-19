# Contracts

Shared flags and keys for dev2, dev3, and dev4. The runner and the merge script rely on these, so keep them stable.
`main` is the authority. `dev1/dev2/dev4/dev5` branches are untouched by this edit; they adopt `main` on next pull.

## Flags

Every module takes the same four flags, plus two optional rate flags:

```
--in targets.txt --mode ctf|audit --scope scope.txt --out out.json [--rate N] [--threads N] [--override reason-text] [--scanner masscan] [--fuzzer ferox] [--extended]
```

Flag ownership (no branch edit needed, main only documents what branches already do):

- Base `--in --mode --scope --out + --rate --threads`: accepted by every module (dev2/dev4 accept-but-ignore rate; archives don't rate-limit).
- `--override reason-text`: audit-only, all modules. Written to run log and report notes.
- `--scanner masscan`: dev3, ctf-only opt-in.
- `--fuzzer ferox`: dev3, ctf-only opt-in.
- `--extended`: dev2, ctf-only (enables amass).

`--in` is a text file with one host per line. Targets are arbitrary: any domain, IP, or CIDR works, examples are placeholders. `--mode` is either ctf or audit. `--scope` points to a file with one allowed host, domain, or CIDR per line. A subdomain of a listed domain counts as in scope. For CIDR entries, network and broadcast addresses are skipped. IPv6 is out for v1. `--out` is a single JSON file where the module writes its records. Exception: the dev1 runner takes `--out-dir dir/` and dev5 merge takes `--in dir --out dir` (see Test below).

In audit mode the scope check runs first. A target outside scope stops the run before any packet is sent. In ctf mode the `--scope` flag is still required for call-shape stability, but the check is lenient (warn-and-continue) since lab IPs are ephemeral. The real scope file stays local and never goes into git. Only `scope.example.txt` is tracked.

## Rates

Omit `--rate` and `--threads` to take mode defaults. Audit defaults to `rate 20, threads 10`. Ctf defaults to `rate 1000, threads 100`.

Bounds are enforced in code. Audit allows `rate 10-50` and `threads 5-20` freely. Above audit max needs `--override reason-text`, which is written to the run log and report notes. Ctf allows `rate 100-5000` and `threads 10-200` with a hard reject above max (no override in ctf). Every run logs the effective rate, threads, and whether override was used.

## Keys

API keys are BYO and optional. Copy `keys.example.env` to `keys.env` (gitignored) and fill your own free keys. Key fallback (`crt.sh`-only plus `enrichment skipped, no key` in notes) is dev2-only; dev3/dev4 run keyless and ignore `keys.env`. Required JSON keys never change either way. Devs never share keys.

BYO tools follow the same rule and never change required keys. `--scanner masscan` and `--fuzzer ferox` work only in ctf mode when the binary exists, otherwise the run continues on defaults with a note. `--extended` enables amass for dev2 in ctf mode.

## Function shape

Each module exposes this function and works alone from the command line.
Normative (supersedes the old `-> dict` typo; no branch code exists yet, so no branch edit needed):

```python
def run(targets: list[str], mode: str, scope_file: str, out: str, **opts) -> int
```

It returns 0 on success, writes JSON to the path given by `--out`, and prints errors to stderr. It never asks for input mid-run. The CLI `--out` is authoritative.

## Required keys

dev2.json, one record per host. Required: `host: str, ips: list[str] (non-empty)`. Optional: `source_tool: str`.

dev3.json, one record per port. Required: `host, ip, port, service`. `http` is an object or null when no HTTP answers (null forces `dirs: []`). `dirs: list[str]` stays empty in audit mode. Optional: `banner, source_tool`.

dev4.json, one record per host. Required: `host, urls`. Optional typed as strings (authoritative over the old dev4 README object example): `js_endpoints: list[str]`, `params: list[str]`, `secrets_hint: list[str]`.

report.json is built by dev5 by joining the three files on `host` (primary) with `ip` fallback for IP-only dev3 records (noted as `joined on ip` in notes). run-meta.json records mode, time, scope hash, input hashes, effective rate and threads, override usage, and counts. Secret hints from dev4 are redacted from `report.md` and kept only in `report.json` for the team.

## Logging

Each run writes `logs/run-<ISO-date>.log` with: user, started/finished, mode, effective rate/threads, override reason (or null), scope file sha256, and per-module exit code. Module stderr also goes to the log. Dev1 owns the file; dev2/3/4 emit the same fields so the runner can merge them.

## Extra keys

A module may add a new key without breaking the merge. The merge checks required keys and types, skips bad records with file and line noted, and keeps the rest.

## Test

```bash
python dev3.py --in targets.txt --mode audit --scope scope.example.txt --out out.json
python merge.py --in ./out --out ./report
```

`targets.txt` is one host per line (not a JSON file). `merge.py --in` takes a directory holding `dev2.json/dev3.json/dev4.json`, while module `--out` takes a single JSON file.
