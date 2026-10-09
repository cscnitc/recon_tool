"""Parsers for dev3: naabu/nmap/httpx/ffuf -> dev3.json records.

Required keys per contracts.md: host, ip, port, service.
http is an object or null (null forces dirs == []).
dirs stays empty in audit mode.
"""
import json
import re


def parse_naabu_ports(text):
    """Parse naabu output (host:port lines) -> set of (host, port)."""
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(.+):(\d+)\s*$", line)
        if m:
            out.add((m.group(1), int(m.group(2))))
    return out


def parse_masscan_oL(text):
    """Parse masscan -oL - output (e.g. 'open tcp 80 10.10.5.12') -> set of (host, port).

    Dedicated parser: never reuse parse_naabu_ports() for masscan (shape differs:
    naabu is host:port, masscan -oL is 'open <proto> <port> <ip>'). Best-effort,
    never throws; skips comments and unparseable lines."""
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^open\s+(tcp|udp)\s+(\d+)\s+(\S+)", line)
        if m:
            try:
                out.add((m.group(3), int(m.group(2))))
            except (ValueError, TypeError):
                continue
    return out


def parse_nmap_records(text, default_host=""):
    """Parse minimal nmap -oN lines like 'PORT STATE SERVICE VERSION'.
    Returns list of dicts with port/service/banner. Best-effort, never throws."""
    records = []
    for line in text.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+\w+\s+(\S+)(?:\s+(.*))?$", line.strip())
        if m:
            port = int(m.group(1))
            service = m.group(3)
            banner = (m.group(4) or "").strip()
            records.append({"host": default_host, "port": port,
                            "service": service, "banner": banner})
    return records


def parse_httpx_jsonl(text):
    """Parse httpx -json output lines -> {(host, port): http_dict}."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        host = obj.get("host") or obj.get("url") or ""
        port = obj.get("port")
        try:
            port = int(port) if port is not None else None
        except (ValueError, TypeError):
            port = None
        http = {
            "status": obj.get("status_code", obj.get("status")),
            "title": obj.get("title", ""),
            "tech": obj.get("tech") or obj.get("technologies") or [],
        }
        # TLS probe merges into tech when present.
        tls = obj.get("tls")
        if isinstance(tls, dict) and tls.get("version") and "tls" not in http["tech"]:
            http["tech"] = list(http["tech"]) + ["tls"]
        out[(host, port)] = http
    return out


def parse_ffuf_paths(text):
    """Parse ffuf stdout paths (/admin, /api/...) -> list of unique dirs.

    Slash-tolerant: accepts 'admin' and '/admin', emits normalized '/admin'.
    A leading bare word (ffuf finding line when the wordlist lacks leading
    slashes) counts only with finding evidence ('[Status' marker or '/' in
    the token); pure status codes and metadata lines fall through to the
    /path search or are skipped. Best-effort, never throws."""
    dirs = []
    seen = set()
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        first = s.split()[0].rstrip(",").rstrip(":")
        path = None
        if first.startswith("/"):
            path = first
        elif (re.match(r"^[A-Za-z0-9._~\-]+(/[A-Za-z0-9._~\-]*)*$", first)
                and not first.isdigit()
                and ("/" in first or "[Status" in s)):
            path = "/" + first.lstrip("/")
        else:
            m = re.search(r"(/\S*)", s)
            if not m:
                continue
            raw = m.group(1).rstrip(",").rstrip(":")
            if "[" in raw or "]" in raw:
                continue  # bracket fractions like [1/2], not paths
            if raw.startswith("//"):
                # URL form (ferox 'http://host/path'): drop authority, keep path
                segs = raw.split("/")
                rest = [g for g in segs[3:] if g]
                if not rest:
                    continue
                path = "/" + "/".join(rest)
            else:
                path = raw
        path = "/" + path.lstrip("/")
        if path == "/":
            continue
        if path not in seen:
            seen.add(path)
            dirs.append(path)
    return dirs


def build_record(host, ip, port, service, banner="", http=None, dirs=None, source_tool="nmap+httpx"):
    """Enforce contracts: http null forces dirs == []."""
    if http is None:
        dirs = []
    else:
        dirs = list(dirs or [])
    return {
        "host": host,
        "ip": ip,
        "port": int(port),
        "service": service,
        "banner": banner or "",
        "http": http,
        "dirs": dirs,
        "source_tool": source_tool,
    }
