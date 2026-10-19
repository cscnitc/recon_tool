# Structure Audit & Monorepo Adoption Report — `dev3`

**Scope:** `cscnitc/recon_tool`, branch `dev3` working tree (pre-restructure tip `1aaacd1`)
**Date:** 2026-10-18
**Method:** fresh read-only probes of local git objects; offline verification battery with stub tools under `/tmp` (**zero network packets**); cross-model re-validation by `opencode/mimo-v2.6-flash-free`. All changes left **uncommitted**; no other branch touched.

---

## 1. Executive summary

The team lead's remark is **confirmed** at the project-structure level: the repo used branches as module containers while its own documented design is a single monorepo tree with per-module directories and a pipeline the modules attach to. `dev3` pre-restructure had a correct, contract-conforming module but none of the whole-project skeleton (hub files, slots, cross-branch sync). This branch now carries the adopted layout, offline-verified.

| Lead's statement | Verdict (pre-restructure) | Key evidence |
|---|---|---|
| "proper file structure of entire project" | **CONFIRMED — missing** | Every branch keeps its module flat at branch root; no `devN/` dirs anywhere (§3) |
| "dev2, dev5 could fork urs and add their part" | **CONFIRMED — broken** | Forking `dev3` shipped no `contracts.md`, `schemas/`, `keys.example.env`, `scope.example.txt`; no slot dirs (§4.2) |
| "If all will do individually there will be no sync / separate parts" | **CONFIRMED** | Star topology: `dev3` 17–18 commits ahead; siblings 1–7 divergent commits; authority files duplicated per branch (§4.3) |
| "proper pipeline / how the input is parsed" | **CONFIRMED — missing** | `runner.py`, `merge.py`, `validate.py` exist on no branch; pipeline is docs-only (§4.4) |
| "others attach at the specific point where the function is needed" | **PARTIAL** — contract existed, physical attach structure did not | `contracts.md` defines `run(targets, mode, scope_file, out, **opts) -> int`; no slot dirs to attach into (§4.5) |

Restructure applied on `dev3` only (uncommitted): monorepo layout with hub files at root, `dev3/` module directory, pointer slots `dev1/ dev2/ dev4/ dev5/`, plus one real defect found and fixed (CWD-relative wordlist path, §5.2, proof in §6.4).

---

## 2. Evidence base

### 2.1 Branch availability (no clone needed)

`git ls-remote --heads origin` vs `git rev-parse origin/<branch>` — all six refs present locally and identical:

| Branch | SHA (7) | Full SHA |
|---|---|---|
| main | `eadf234` | `eadf2343cc3a01c907d14c4ecb306851ddf6ee44` |
| dev1 | `bb1a700` | `bb1a7006d8b5e9ab470514593047554fa4b29bec` |
| dev2 | `6d3f589` | `6d3f589cdc7b6910f5d1040ea110566c147431f6` |
| dev3 | `1aaacd1` | `1aaacd125e1a75a0238d5d25caebcfa6cd342f7f` (pre-restructure) |
| dev4 | `2649359` | `2649359266c45f399912134f985519230e70737d` |
| dev5 | `a11b397` | `a11b3978b83413e105bc18d246eadf7dc2289684` |

### 2.2 Cross-model validation

An independent verifier session (`opencode/mimo-v2.6-flash-free`) re-ran all 19 probe commands itself — **REJECTED COUNT: 0** — and returned **TRUE on all 7 load-bearing claims**: branch parity, flat trees, dev3 hub-file absence, absent pipeline files, divergence counts (17/18 vs 1–7), dangling `contracts.md` reference. Its three refinements are folded into this report: projected-vs-current collision framing (§4.5), `run()` call-shape wording (§4.5), dangling-reference reconciliation (§4.6).

### 2.3 Evidence protocol (no false positives)

- Every claim below is backed by a fresh command output or `file:line`; nothing is trusted on assertion.
- Untestable surfaces are listed explicitly and **excluded from verdicts** (§7).
- The offline battery replaces all four external tools with shell stubs (`/tmp/recon-verify/bin/`); the ffuf stub **checks that its `-w` wordlist file exists**, which makes §6.4 falsifiable in both directions.

---

## 3. Per-branch trees (pre-restructure)

`git ls-tree -r --name-only origin/<branch>`:

| Branch | Tracked files |
|---|---|
| main | `README.md`, `contracts.md`, `keys.example.env`, `schemas/{dev2,dev3,dev4,report,run-meta}.json`, `scope.example.txt`, `.gitignore` |
| dev1 | `README.md` (only — declares `dev1/runner.py`, no code) |
| dev2 | `README.md`, `contracts.md`, `dev2.py`, `keys.example.env`, `roadmap`, `schemas/*.json`, `scope.example.txt` |
| dev3 | `.gitignore`, `DEV3_SECURITY_AUDIT_REPORT.md`, `Dockerfile`, `FULL_REPO_AUDIT_REPORT.md`, `README.md`, `dev3.py`, `parsers.py`, `scope.py`, `wordlists/raft-small.txt` |
| dev4 | `README.md`, `dev4.py` (skeleton) |
| dev5 | `README.md` (only — declares `dev5/merge.py`, no code) |

No branch contains a `devN/` directory. All modules sit flat at branch root.

---

## 4. Findings

### 4.1 F1 — No whole-project structure (lead claim 1)

The documented target (`main` README "File structures", `dev1`/`dev4`/`dev5` READMEs: `python ../dev3/dev3.py`, `dev5/merge.py`) is a monorepo tree with per-module directories and root hub files. Reality: module-per-branch, flat root. No single checkout could ever hold the full v1 project.

### 4.2 F2 — dev3 was not a fork base (lead claim 2)

Pre-restructure, forking `dev3` shipped only its own module + local `README.md`/`.gitignore`. Absent: `contracts.md`, `schemas/`, `keys.example.env`, `scope.example.txt` — while `dev3.py:4` itself cites "per contracts.md". Dev2's branch had already copied the hub files from main; dev3 had not. No slot directories existed for siblings to drop modules into.

### 4.3 F3 — Branch isolation ⇒ "separate parts" (lead claim 3)

`git rev-list --count` pairs (verified by the mimo validator):

| Pair | Direction: ahead/behind |
|---|---|
| dev3 ↔ dev1 | +17 / −2 |
| dev3 ↔ dev2 | +17 / −7 |
| dev3 ↔ dev4 | +18 / −2 |
| dev3 ↔ dev5 | +17 / −1 |
| dev3 ↔ main | +17 / −7 |

Authority files were duplicated with no sync mechanism: `README.md` on all 6 branches (already drifted — dev1 README documents a stale `run()->dict` signature vs normative `contracts.md:41-47`), `contracts.md` on main+dev2 only, `schemas/` on main+dev2. Merging the branches would require manual reconciliation per file.

### 4.4 F4 — Pipeline exists only in docs (lead claim 4)

`runner.py` (dev1), `merge.py`/`validate.py` (dev5) appear in **none** of the six branch trees (ls-tree over all branches). The "input parsed → dev2 → dev3 → dev4 → dev5 merge" flow is documented in `main` README / `contracts.md` but physically absent; E2E is un-runnable. (Sibling-branch deliverables — outside dev3's edit scope.)

### 4.5 F5 — Attach contract existed; attach *structure* did not (lead claim 5)

- Contract norm (`main:contracts.md`): `def run(targets: list[str], mode: str, scope_file: str, out: str, **opts) -> int`.
- dev3 dev3.py:228 implements `run(targets, mode, scope_file, out, rate=None, threads=None, override=None, scanner=None, fuzzer=None)` — explicit kwargs; runtime-equivalent, textually divergent (**cosmetic**, matches prior audit P4).
- Prior audit (2026-10-10) found dev2 returns `dict` with wrong shape and dev4 has no `run()` at all — re-derivation on demand; both are sibling-branch ownership.
- What was missing on dev3: the physical structure (slot dirs) that tells each dev *where* their `run()` lands.

**Collision nuance (projected, not current):** per the documented trees, `scope.py` is a per-module copy, `parsers.py` is per-module, and dev2/dev3/dev4 each ship a `Dockerfile` — impossible in one flat root. Today only dev3 ships `Dockerfile`/`scope.py`/`parsers.py` (single owner, no collision *yet*); the collision materializes as siblings land their documented copies. Directory slots are the fix by construction.

### 4.6 F6 — Dangling cross-references

| Reference | Where | Target shipped? (pre) |
|---|---|---|
| "per contracts.md" | `dev3.py:4` (docstring) | No — absent from dev3 branch |
| `runner.py` path `/logs` | `dev1:README.md` | No code anywhere |
| `merge.py --in ./out` | `contracts.md` Test section | No code anywhere |
| `run(...) -> dict` | `dev1:README.md:29` | Stale vs normative contract |

### 4.7 F7 — CWD-relative wordlist path (real defect, found + fixed)

`dev3.py` (pre) line 217: `wl = "wordlists/raft-small.txt"` — resolved against the process CWD. Under the new tree (files inside `dev3/`), any invocation from the repo root or elsewhere made ffuf look for a nonexistent wordlist; failure was silent (empty `dirs`). Fixed in §5.2; falsifiable proof in §6.4.

---

## 5. As-built restructure (dev3 branch, uncommitted)

### 5.1 Operations

| Operation | Paths |
|---|---|
| `git mv` into `dev3/` | `dev3.py`, `parsers.py`, `scope.py`, `Dockerfile`, `wordlists/`, `DEV3_SECURITY_AUDIT_REPORT.md`, `README.md → dev3/README.md` |
| Checked out from `main@eadf234` | `README.md` (overview), `contracts.md`, `keys.example.env`, `scope.example.txt`, `schemas/` (5 files) |
| New pointer slots | `dev1/README.md`, `dev2/README.md`, `dev4/README.md`, `dev5/README.md` |
| Edited | `dev3/dev3.py` (1-line fix §5.2), `dev3/README.md` (paths + "Branch structure and integration"), root `README.md` (+4-line branch note) |
| Kept at root | `FULL_REPO_AUDIT_REPORT.md` (repo-scoped), `.gitignore` (unchanged) |
| Untouched | `.opencode/` (untracked, left alone); all other branches |

### 5.2 The fix

```diff
-    wl = "wordlists/raft-small.txt"
+    wl = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlists", "raft-small.txt")
```

Stdlib-only; no change to fallbacks, notes, exit codes, or `run()` call-shape.

### 5.3 As-built tree

```text
recon_tool/ (branch dev3, uncommitted)
  README.md                       # project overview, synced from main@eadf234 + branch note
  contracts.md                    # synced from main@eadf234
  keys.example.env                # synced
  scope.example.txt               # synced
  schemas/                        # dev2/dev3/dev4/report/run-meta — synced
  .gitignore                      # unchanged
  FULL_REPO_AUDIT_REPORT.md       # stays (repo-scoped)
  STRUCTURE_AUDIT_REPORT.md       # this file
  dev1/README.md                  # pointer slot (runner)
  dev2/README.md                  # pointer slot (passive)
  dev3/                           # ACTIVE module
    dev3.py  parsers.py  scope.py  Dockerfile  README.md
    wordlists/raft-small.txt
    DEV3_SECURITY_AUDIT_REPORT.md
  dev4/README.md                  # pointer slot (JS/API)
  dev5/README.md                  # pointer slot (merge)
```

Generated artifacts (gitignored, not part of the layout): `dev3/__pycache__/`.

---

## 6. Verification receipts

### 6.1 Compile + CLI surface

```
$ python3 -m py_compile dev3/dev3.py dev3/parsers.py dev3/scope.py   → exit 0
$ python3 dev3/dev3.py --help                                        → exit 0
```

### 6.2 Audit fallback smoke (real environment: naabu/httpx genuinely missing)

```
note: naabu binary missing, port discovery skipped (no records without tool output)
note: httpx binary missing, http probe skipped (http=null)
wrote 0 records to /tmp/recon-verify/out-audit.json (mode=audit rate=20 threads=10)
exit=0; out-audit.json = []
```

Honest fallback preserved: no abort, notes emitted, valid JSON shape.

### 6.3 Full stub chain (ctf, offline)

All four tools substituted by stubs; record shape verified end-to-end:

```json
{"host":"127.0.0.1","ip":"127.0.0.1","port":80,"service":"http","banner":"stub-httpd",
 "http":{"status":200,"title":"stub","tech":["stubtech"]},
 "dirs":["/admin","/api/v1/login"],"source_tool":"nmap+httpx+ffuf"}
```

### 6.4 Wordlist fix — falsifiable pre/post proof

Old code (`git archive origin/dev3` = `1aaacd1`) under the as-built tree, CWD = repo root:

```
ARGS: ... -w wordlists/raft-small.txt ...        CWD: /home/harsha/recon_tool
WORDLIST MISSING: wordlists/raft-small.txt        → dirs: []
```

New code, same CWD:

```
ARGS: ... -w /home/harsha/recon_tool/dev3/wordlists/raft-small.txt ...
WORDLIST OK: /home/harsha/recon_tool/dev3/wordlists/raft-small.txt → dirs: ["/admin","/api/v1/login"]
```

New code, foreign CWD (`/tmp`): same absolute `-w`, `WORDLIST OK` — CWD-independent.

### 6.5 Scope gates

| Test | Result |
|---|---|
| audit, out-of-scope target `198.51.100.7` | `error: target out of scope in audit mode` — exit 2 |
| audit, IPv6 `::1` | `error: IPv6 out for v1 in audit mode` — exit 2 |
| CIDR target `10.0.0.0/24` | `error: CIDR target not expanded in dev3, Dev1 must expand before us` — exit 2 |
| ctf, out-of-scope `198.51.100.7` (lenient) | warn note + exit 0; record host `198.51.100.7` processed end-to-end (stubs) |

### 6.6 Git state (staged, uncommitted — hand-off receipt)

```
M  README.md
A  STRUCTURE_AUDIT_REPORT.md
A  contracts.md
A  dev1/README.md
A  dev2/README.md
R  DEV3_SECURITY_AUDIT_REPORT.md -> dev3/DEV3_SECURITY_AUDIT_REPORT.md
R  Dockerfile -> dev3/Dockerfile
A  dev3/README.md
R  dev3.py -> dev3/dev3.py        (rename + 1-line wordlist fix, staged as one rename)
R  parsers.py -> dev3/parsers.py
R  scope.py -> dev3/scope.py
R  wordlists/raft-small.txt -> dev3/wordlists/raft-small.txt
A  dev4/README.md
A  dev5/README.md
A  keys.example.env
A  schemas/*.json (5 files)
A  scope.example.txt
?? .opencode/           (pre-existing, untouched)
```

21 files changed, +721/−59 staged; nothing committed; nothing pushed.

### 6.7 Cross-model re-validation (as-built state)

A second validator run (`opencode/mimo-v2.6-flash-free`, 12 pinned commands, **REJECTED COUNT: 0**) re-derived the as-built tree, staged index, wordlist fix line, branch-note lines, and this report's content from its own command output: E1–E3, E6, E7 TRUE. Two expectation/wording nits were folded in: §6.6 now reflects the staged index exactly, and §8 carries dev5's documented `--in dir --out dir` contract exception. No report claim was contradicted by any command output. (E4's PARTIAL was an artifact of the validator prompt's expectation wording, not the report or the fix — the fix line and its staged diff were both confirmed.)

---

## 7. UNTESTABLE (excluded from verdicts)

- Real `naabu` / `httpx` / `ffuf` / `masscan` / `feroxbuster` positive paths — binaries absent on this machine; policy forbids live scans. Positive paths are exercised only via stubs.
- Real `nmap` against live targets — same policy (static parsing logic covered by stubs).
- Docker build/run — needs registry/network; not executed.
- Remote push / branch-permission behavior — not attempted by design.
- Dev2/Dev4/Dev5/Dev1 adoption behavior — their branches are untouched; slots are pointers, not integrations.

---

## 8. Adoption guide (Dev1/Dev2/Dev4/Dev5)

1. Fetch this `dev3` branch; adopt the tree (hub files at root are copies synced from `main@eadf234`).
2. Drop your module files into your slot — `dev1/` (runner.py), `dev2/` (dev2.py, scope.py, parsers.py, Dockerfile, keys.example.env), `dev4/` (dev4.py, scope.py, parsers.py, wordlists/, Dockerfile), `dev5/` (merge.py, validate.py, schemas/) — and replace the pointer README.
3. Keep the attach contract: four shared flags + rate flags (`contracts.md`), `run(targets, mode, scope_file, out, **opts) -> int` for the scanner modules (dev5's merge uses the documented `--in dir --out dir` exception), module CLI runnable as `python <slot>/<module>.py ...` from the repo root.
4. Hub-file changes flow from `main`; do not fork the hub.

---

## 9. Verdict

The lead's structural criticism was **justified** — as a project/skeleton gap, not a dev3-module-quality gap: dev3's module was the only contract-conforming code in the repo, but it could not serve as the fork base without the hub files, slots, and pipeline attach structure. This branch now carries that structure, with each fix and claim backed by a re-runnable receipt above. Changes are staged/uncommitted for review; nothing was pushed and no sibling branch was touched.
