#!/usr/bin/env python3
"""Dev3: active scanning and probing (naabu -> nmap -> httpx -> [ffuf]).

Stdlib-only. Missing binaries fall back with a note (per contracts.md).
Audit: nmap -T2 top-100, ffuf off. Ctf: full chain, masscan/ferox opt-in.
"""
import argparse
import json
import shutil
import subprocess
import sys

from parsers import (
    build_record,
    parse_ffuf_paths,
    parse_httpx_jsonl,
    parse_naabu_ports,
    parse_nmap_records,
)
from scope import check_targets

DEFAULTS = {"audit": (20, 10), "ctf": (1000, 100)}
BOUNDS = {"audit": ((10, 50), (5, 20)), "ctf": ((100, 5000), (10, 200))}


def resolve_rates(mode, rate, threads, override):
    def_rate, def_threads = DEFAULTS[mode]
    rate = def_rate if rate is None else rate
    threads = def_threads if threads is None else threads
    (r_lo, r_hi), (t_lo, t_hi) = BOUNDS[mode]
    notes = []
    if mode == "audit" and (rate > r_hi or threads > t_hi):
        if not override:
            print(f"error: audit rate/threads above max ({r_hi}/{t_hi}) need --override reason-text",
                  file=sys.stderr)
            raise SystemExit(2)
        notes.append(f"override used: {override}")
    if mode == "ctf" and (not (r_lo <= rate <= r_hi) or not (t_lo <= threads <= t_hi)):
        print(f"error: ctf rate {rate} out of {r_lo}-{r_hi} or threads {threads} out of {t_lo}-{t_hi} (no override in ctf)",
              file=sys.stderr)
        raise SystemExit(2)
    if mode == "audit" and (rate < r_lo or threads < t_lo):
        print(f"error: audit rate/threads below min ({r_lo}/{t_lo})", file=sys.stderr)
        raise SystemExit(2)
    return rate, threads, notes


def _run(cmd, timeout=300):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout + p.stderr, p.returncode
    except FileNotFoundError:
        return "", 127
    except subprocess.TimeoutExpired:
        return "", 124


def discover_ports(targets, mode, rate, threads, scanner, notes):
    """Naabu (default) or masscan (ctf opt-in). Returns set of (host, port)."""
    if scanner == "masscan":
        if mode != "ctf":
            notes.append("--scanner masscan ignored in audit mode, using naabu defaults")
        elif shutil.which("masscan") is None:
            notes.append("masscan binary missing, using naabu defaults")
        else:
            out, code = _run(["masscan"] + targets + ["-p1-65535", f"--rate={rate}"])
            if code != 127:
                return parse_naabu_ports(out)
            notes.append("masscan failed, using naabu defaults")
    if shutil.which("naabu") is None:
        notes.append("naabu binary missing, port discovery skipped (no records without tool output)")
        return set()
    top = ["-top-ports", "100"] if mode == "audit" else ["-top-ports", "1000"]
    out, code = _run(["naabu", "-list", ",".join(targets)] + top + ["-rate", str(rate)])
    if code == 127:
        notes.append("naabu failed to run, port discovery skipped")
        return set()
    return parse_naabu_ports(out)


def fingerprint(host_ports, mode, notes):
    """nmap -sV -sC (audit adds -T2 --top-ports 100). Returns list of partial records."""
    if shutil.which("nmap") is None:
        notes.append("nmap binary missing, service fingerprint skipped")
        return [{"host": h, "port": p, "service": "unknown", "banner": ""} for h, p in sorted(host_ports)]
    recs = []
    for host, port in sorted(host_ports):
        cmd = ["nmap", "-sV", "-sC", "-p", str(port), host]
        if mode == "audit":
            cmd[1:1] = ["-T2"]
        out, code = _run(cmd)
        parsed = parse_nmap_records(out, default_host=host)
        hit = next((r for r in parsed if r["port"] == port), None)
        if hit:
            recs.append({"host": host, "port": port, "service": hit["service"], "banner": hit["banner"]})
        else:
            if code == 127:
                notes.append("nmap failed to run, banner empty")
            recs.append({"host": host, "port": port, "service": "unknown", "banner": ""})
    return recs


def probe_http(recs, mode, threads, notes):
    """httpx with tech detect + TLS probe. Returns {(host,port): http}."""
    if shutil.which("httpx") is None:
        notes.append("httpx binary missing, http probe skipped (http=null)")
        return {}
    targets = [f"{r['host']}:{r['port']}" for r in recs]
    if not targets:
        return {}
    out, code = _run(["httpx", "-json", "-threads", str(threads), "-tls-probe", "-tech-detect"] + targets)
    if code == 127:
        notes.append("httpx failed to run, http probe skipped")
        return {}
    return parse_httpx_jsonl(out)


def fuzz_dirs(live, mode, fuzzer, threads, notes):
    """ffuf in ctf only. Returns {(host,port): [dirs]}."""
    if mode != "ctf":
        return {}
    if not live:
        return {}
    tool = fuzzer if fuzzer == "ferox" else "ffuf"
    if shutil.which(tool) is None:
        notes.append(f"{tool} binary missing, fuzzing skipped")
        return {}
    if fuzzer == "ferox" and mode != "ctf":
        notes.append("--fuzzer ferox ignored outside ctf mode")
        return {}
    out_map = {}
    wl = "wordlists/raft-small.txt"
    for host, port in live:
        base = f"http://{host}:{port}/FUZZ" if port not in (443, 8443) else f"https://{host}:{port}/FUZZ"
        if tool == "ffuf":
            out, _ = _run(["ffuf", "-u", base, "-w", wl, "-t", str(threads), "-mc", "200,301,302,403"])
        else:
            out, _ = _run(["feroxbuster", "-u", base.rstrip("/FUZZ"), "-w", wl, "-t", str(threads)])
        out_map[(host, port)] = parse_ffuf_paths(out)
    return out_map


def run(targets, mode, scope_file, out, rate=None, threads=None, override=None,
        scanner=None, fuzzer=None):
    notes = []
    kept, scope_notes = check_targets(targets, scope_file, mode)
    notes += scope_notes
    rate, threads, rate_notes = resolve_rates(mode, rate, threads, override)
    notes += rate_notes

    ports = discover_ports(kept, mode, rate, threads, scanner, notes)
    finger = fingerprint(ports, mode, notes)
    # Map host->ip best effort: keep host as ip when target was an IP literal.
    import ipaddress

    def as_ip(h):
        try:
            ipaddress.ip_address(h)
            return h
        except ValueError:
            return ""

    http_map = probe_http(finger, mode, threads, notes)
    live = [(r["host"], r["port"]) for r in finger if (r["host"], r["port"]) in http_map]
    # Audit: ffuf stays off even if live hosts exist.
    fuzz_map = fuzz_dirs(live, mode, fuzzer, threads, notes) if mode == "ctf" else {}

    records = []
    for r in finger:
        key = (r["host"], r["port"])
        http = http_map.get(key)
        dirs = fuzz_map.get(key, [])
        if mode == "audit":
            dirs = []
        tools = ["nmap", "httpx"] + (["ffuf" if (fuzzer != "ferox") else "ferox"] if key in fuzz_map else [])
        records.append(build_record(r["host"], as_ip(r["host"]) or r["host"], r["port"],
                                    r["service"], r.get("banner", ""), http, dirs,
                                    source_tool="+".join(tools)))
    payload = records
    with open(out, "w") as f:
        json.dump(payload, f, indent=2)
    for n in notes:
        print(f"note: {n}", file=sys.stderr)
    print(f"wrote {len(records)} records to {out} (mode={mode} rate={rate} threads={threads})",
          file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Dev3 active scanner (naabu->nmap->httpx->[ffuf])")
    ap.add_argument("--in", dest="in_file", required=True, help="targets.txt, one host per line")
    ap.add_argument("--mode", required=True, choices=["ctf", "audit"])
    ap.add_argument("--scope", dest="scope", required=True)
    ap.add_argument("--out", dest="out", required=True, help="single JSON file")
    ap.add_argument("--rate", type=int, default=None)
    ap.add_argument("--threads", type=int, default=None)
    ap.add_argument("--override", default=None, help="audit-only reason text")
    ap.add_argument("--scanner", default=None, choices=["masscan"], help="ctf-only opt-in")
    ap.add_argument("--fuzzer", default=None, choices=["ferox"], help="ctf-only opt-in")
    a = ap.parse_args(argv)
    with open(a.in_file) as f:
        targets = [ln.strip() for ln in f if ln.strip() and not ln.strip().startswith("#")]
    return run(targets, a.mode, a.scope, a.out, rate=a.rate, threads=a.threads,
               override=a.override, scanner=a.scanner, fuzzer=a.fuzzer)


if __name__ == "__main__":
    raise SystemExit(main())
