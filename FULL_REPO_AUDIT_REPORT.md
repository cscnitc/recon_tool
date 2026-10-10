# Full-Repo Security & Correctness Audit Report

**Scope:** `main` authority files + `dev2` + `dev3` + `dev4` + integration contract
**Date:** 2026-10-10 · **Mode:** read-only evidence, `/tmp`-only probes, no live targets, no commits
**Protocol:** swarm-orchestrator (workers → independent validator → hostile testers → security oracles → orchestrator re-run)
**Branch state at audit:** `dev3` at `fcb4638` (3 ahead of `origin/dev3`); `origin/dev1`, `origin/dev5` README-only; `origin/dev2` partial; `origin/dev4` skeleton

---

## 1. Executive Summary

| Metric | Value |
|---|---|
| Phase verdicts | P1 PROVEN · P2 PROVEN (findings confirmed) · P3 PROVEN (findings confirmed) · P4 PROVEN · P5 PROVEN (sim only) |
| Validator re-derivation | 12/12 PROVEN, REJECTED COUNT: 0 |
| Oracles (orchestrator re-run) | `scan-sinks.sh` exit 0 · `scan-secrets.sh` exit 0 |
| Blockers | 4 (F1–F4, all in dev2/dev4 — none in dev3) |
| Majors | 11 · Minors | 5 |
| Module grades | dev3 **A** (integration-ready) · main docs **A-** · dev2 **C** · dev4 **D** · dev1/dev5 **N/A** (no code) |
| Overall | **C+** — one stable integration target (dev3), siblings not contract-conformant, E2E un-runnable |

**Key finding:** dev3 is the only module that honors its contract. dev2 breaks the contract in four load-bearing places (wrong `run()` shape, empty `ips`, no ctf scope gate, ctf override accepted) plus a CIDR-expansion DoS. dev4 is a skeleton with the wrong secret key name, no `run()`, and fail-closed ctf behavior. dev1/dev5 have no code, so the pipeline cannot run end-to-end. Nothing here blocks dev3; everything here blocks the siblings.

---

## 2. Per-Phase Verdicts

### P1 — main authority (worker PROVEN, validator V1–V3 PROVEN)
- All 5 `schemas/*.json` parse; required keys/types match contracts (dev2 `ips` non-empty, dev3 `http`-null⇒`dirs==[]`, dev4 `secrets_hint: list[str]`, report join shape, run-meta fields).
- `contracts.md` internally consistent (flags, ownership, function shape, logging, extra-keys). One stale wording: “four flags, plus two optional rate flags” header above a 10-flag line — cosmetic.
- `scope.example.txt` / `keys.example.env` placeholders-only, no secrets. `.gitignore` covers all 7 patterns. Secret grep over all 10 main files: clean.
- **H11 CONFIRMED:** `origin/dev1:README.md:29` documents `run(targets, mode, scope_file) -> dict` vs normative `run(targets, mode, scope_file, out, **opts) -> int` (`main:contracts.md:41-47`).
- **H12 CONFIRMED as by-design:** no `merge.py`/`runner.py` on main; references are dev5-branch-scoped.

### P2 — dev2 (worker PROVEN, validator V4–V6 PROVEN)
- **H1 CONFIRMED:** `run(targets, mode, scope_file) -> dict`, returns `{"results": [...]}` — Dev1 cannot call it per contract.
- **H2 CONFIRMED:** subfinder-path records emit `"ips": []` (schema demands non-empty) — starves Dev5 join.
- **H3 CONFIRMED:** `setup_logging()` writes `logs/dev2.log` relative to cwd — log-ownership violation (writes only on `main()`, not import; still wrong owner).
- **H4 CONFIRMED:** ctf mode performs **zero** scope checking; audit enforces.
- **H5 CONFIRMED:** `validate_rate_threads` accepts above-max **with** `--override` in ctf — contract demands hard reject.
- **H6 CONFIRMED:** `--extended` parsed/logged only; amass/chaos/crt.sh/dnsx absent (grep: amass 1, chaos 0, crt 0, dnsx 0).
- **H7 CONFIRMED:** `--out` unsanitized; `parent.mkdir(parents=True)`; traversal accepted (sandbox demo).
- EXTRA battery green except quirk: exact-IP scope entry (`1.2.3.4` vs `1.2.3.4`) returns **False** — parsed as /32 then skipped as network address. `run_subfinder` is list-form, no shell (static; never executed).

### P3 — dev4 (worker PROVEN, validator V7–V9 PROVEN)
- **H8 CONFIRMED:** no `def run(`; output key is `"secrets"`, contract demands `"secrets_hint"`.
- **H9 CONFIRMED:** ctf out-of-scope exits 2 (no leniency); rate bounds are flat 1–500/1–50 ignoring modes; mode defaults diverge (ctf rate 150 vs contract 1000).
- **H10 PARTLY CLEARED:** `::1` exits 1 cleanly, no traceback on Python 3.14 (`in` returns False on v4/v6 mismatch) — but version-dependent; older Pythons raise `TypeError` past the `except ValueError`. CIDR-as-target **collapses** (`_host('10.10.5.0/24')` → `'10.10.5.0'`, exit 0) — silent wrong-scope scan surface.
- Exit codes 0/1/2 internally consistent; missing-scope=2, missing-targets=1. Garbage scope lines tolerated. No sinks (no subprocess at all).

### P4 — dev3 spot-check (worker PROVEN, validator V10 PROVEN)
- `run()` returns int 0 on direct call; signature is explicit kwargs `(rate, threads, override, scanner, fuzzer)` — no `**opts`, no `->int` annotation (runtime-conformant, textually divergent; cosmetic).
- `build_record` sample matches schema shape; `http=None` forces `dirs==[]`.
- Traversal guard exits 2 on all three flags; clean absolute `/tmp` + `/var/tmp` exit 0.
- Image `User=dev3`, HEALTHCHECK present, no rebuild needed.
- Diff vs `origin/dev3`: exactly `Dockerfile, README.md, dev3.py, DEV3_SECURITY_AUDIT_REPORT.md` — no contracts/schemas/tests/runners/SQLite/logs.

### P5 — integration simulation (worker PROVEN, validator V11–V12 PROVEN)
- Join sim on `/tmp` fixtures: host-primary aggregates multi-port; ip-fallback fires exactly once with `joined on ip` note; bad record skipped with file+line; extra key preserved; orphan surfaced (not dropped); empty-`ip` never joins on ip (guard `rec["ip"] != ""`).
- `ip=""` convention verified end-to-end against `main:README.md:99`.
- Ownership checklist: Dev1 owns log file; modules emit fields; `run-meta.json` fields enumerated.
- **E2E un-runnable as fact:** `origin/dev1` and `origin/dev5` are README-only; `merge.py`/`runner.py`/`validate.py` exist nowhere.

---

## 3. Detailed Findings

### Blockers
| ID | Location | Finding | Evidence | Remediation |
|---|---|---|---|---|
| F1 | `origin/dev2:dev2.py:337` `expand_targets` | CIDR expansion **materializes every address**: `/16`→65,534 strings, `/8`→16.7M, `/0`→4.2B — OOM/DoS on hostile or fat-finger input | Hostile repro `expand_targets(['10.0.0.0/16'])` → 65534; orchestrator `num_addresses` counts | Cap prefix length (reject below /24 or cap host count with exit 2 + note) |
| F2 | `origin/dev2:dev2.py:475-492` | Subfinder records emit `"ips": []` — violates schema non-empty, starves Dev5 ip-fallback join | Validator V5 record print; schema `ips (non-empty)` | Resolve via dnsx before emit, or drop unresolvable hosts with note |
| F3 | `origin/dev2:dev2.py:425-429` | `run()` shape `(targets, mode, scope_file)->dict` vs contract `(..., out, **opts)->int` — Dev1 cannot call it; returns dict, never writes `--out` | Orchestrator `inspect.signature` print | Adopt normative shape; write `--out` inside `run()` |
| F4 | `origin/dev4:dev4.py:165-174` + missing `run()` | No `run()` at all (Dev1 cannot import/call); emits `"secrets"` not `"secrets_hint"` — merge drops or misfiles secrets | Validator V7 `has run: False`, keys print | Add `run()`; rename key to `secrets_hint` |

### Majors
| ID | Location | Finding |
|---|---|---|
| F5 | dev2.py:439-446 | ctf mode skips scope check entirely (not even lenient) |
| F6 | dev2.py:257-278 | ctf above-max accepted with `--override` (contract: hard reject) |
| F7 | dev2.py:269 | blank/whitespace `--override` (`'   '`) bypasses bounds; `threads=10**9` passes with any override |
| F8 | dev2.py:12-13,20-21,570-572 | writes `logs/dev2.log` — Dev1 owns logs; modules emit to stderr |
| F9 | dev2.py:533-536,704-709 | `--out` traversal accepted + `mkdir(parents=True)` (CLAIM-8 sibling) |
| F10 | dev4.py:148-150 | ctf out-of-scope fail-closed exit 2 — no contract leniency |
| F11 | dev4.py:16-17,43-50 | flat 1–500/1–50 bounds ignore modes; ctf default rate 150 vs contract 1000 |
| F12 | dev4.py:23-28,75,120 | CIDR-as-target silently collapses to bare host IP, exit 0 |
| F13 | dev4.py:23-28 | `_host()` passes NUL/space/newline through (`'\x00evil.com'`, `'evil.cominjected'`) + NUL reaches scope-abort log line |
| F14 | dev3 `parsers.py:158` | `build_record` accepts port `-1`/`99999`/`'443'`, `host None`, `http` str/list with dirs — clamp port 1–65535, require host str, require http dict-or-None |
| F15 | dev2.py:138 | `host_in_scope(None)` → uncaught `AttributeError` (programmatic callers crash) |
| F16 | dev2 scope quirk | exact-IP entry `1.2.3.4` vs scope `1.2.3.4` returns False (/32 treated as network address and skipped) |

### Minors
- F17 dev1 README stale `run()->dict` (doc-sync, same class as prior main:README fix).
- F18 contracts Test references root `merge.py` (cosmetic; dev5-scoped in practice).
- F19 dev4 exit scheme 1-vs-2 is internally consistent; contract only pins 0-on-success — note, not break.
- F20 dev4 IPv6 `in` semantics are version-dependent (3.14 False vs older TypeError) — pin behavior explicitly.
- F21 HEALTHCHECK body always exits 0 (vacuous liveness on a one-shot container) — accepted, non-blocking.

### Accepted residuals (not bugs)
- dev3 `_validate_path` permits absolute/symlink/programmatic-`run()` paths — operator-controlled CLI boundary per policy.
- dev5 shared-IP fan-out semantics unspecified — dev5 must define (host-key vs ip-key) when it lands.
- Supply-chain CVEs in Go binaries out of scope; `sudo docker :latest` in dev2 noted under F4/H4.

---

## 4. Remediation Plan

**Immediate (blocks integration):** F1 cap CIDR expansion · F2 non-empty `ips` · F3 dev2 `run()` shape · F4 dev4 `run()` + `secrets_hint`.
**Short-term:** F5 ctf scope gate (lenient) · F6 ctf hard-reject · F7 strip+require override · F8 stderr-only logging · F9 traversal guard · F10 ctf leniency · F11 mode-aligned bounds · F12 reject-or-expand CIDR targets · F13 sanitize `_host` · F14 validate `build_record` · F15/F16 input guards · F17 dev1 README sync.
**Long-term:** dev1 runner + dev5 merge/validate code per contract; full E2E battery; Docker packaging for dev2/dev4 mirroring dev3 (nonroot + pinned bases).

---

## 5. Standards Mapping

| Finding | OWASP | CWE |
|---|---|---|
| F1 CIDR DoS | A04 Insecure Design | CWE-400 Uncontrolled Resource Consumption |
| F9/F13 traversal & sanitization | A01 Broken Access Control / A03 Injection | CWE-22, CWE-20 |
| F5/F10 scope gates | A01 Broken Access Control | CWE-284 |
| F8 log ownership | A09 Logging Failures | CWE-778 |
| Rest (contract breaks) | A04 Insecure Design | CWE-703, CWE-754 |

---

## 6. Methodology & Estimates

Static review + `/tmp`-only fixture probes; subfinder/docker/network never executed; every load-bearing claim re-derived by an independent validator (12/12 PROVEN, 0 rejected); oracles re-run by orchestrator (both exit 0); hostile battery (10 probes, 8 HOLEs adjudicated above, 2 ROBUST). False-positive estimate <3% (F20 version-dependence and F19 scheme notes are the soft edges). False-negative risk concentrates in unexecuted surfaces: real subfinder/amass/chaos/crt.sh/dnsx/gau/katana behavior and the nonexistent runner/merge.

**Receipts:** worker envelopes P1–P5, validator 12-verdict pass, hostile 10-probe pass, orchestrator oracle + spot-gate outputs — all reproduced in-session, none trusted on claim alone. No commits, no pushes, no repo writes; all fixtures under `/tmp`.
