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
    """Parse ffuf stdout paths (/admin, /api/...) -> list of unique dirs."""
    dirs = []
    seen = set()
    for line in text.splitlines():
        m = re.search(r"(/\S*)", line)
        if not m:
            continue
        path = m.group(1).rstrip(",")
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
