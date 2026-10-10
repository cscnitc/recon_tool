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
        m = re.match(r"^(.+):(\d+)\s*$", line) if ":" in line else None
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
        if not line or line.startswith("#") or not line.startswith("open"):
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
        if not isinstance(obj, dict):
            continue  # well-formed JSON of the wrong type (array/null/str/num)
        host = obj.get("host") or obj.get("url") or ""
        port = obj.get("port")
        try:
            port = int(port) if port is not None else None
        except (ValueError, TypeError):
            port = None
        tech = obj.get("tech") or obj.get("technologies") or []
        if isinstance(tech, str):
            tech = [tech]
        elif not isinstance(tech, list):
            tech = []  # never let a non-list reach the tls merge
        http = {
            "status": obj.get("status_code", obj.get("status")),
            "title": obj.get("title", ""),
            "tech": tech,
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
    Finding-anchored: tokens directly preceding a '[Status:' marker are
    findings (de-glued from '\\r'/progress prefixes); URL tokens use the
    authority-strip rule. Lines without findings, URLs, or a leading /path
    (banners, config echoes, wordlist comments, progress chatter) are
    skipped. Best-effort, never throws."""
    dirs = []
    seen = set()

    def emit(raw):
        raw = raw.strip().rstrip(",").rstrip(":").lstrip(":")
        if not raw or raw.startswith("#") or "\\" in raw:
            return  # comments and banner ASCII art are never findings
        raw = re.sub(r"^https?://", "//", raw)
        if raw.startswith("//"):
            # URL form (ferox 'http://host/path'): drop authority, keep path
            segs = raw.split("/")
            rest = [g for g in segs[3:] if g]
            if not rest:
                return
            path = "/" + "/".join(rest)
        elif raw.startswith("/"):
            if "[" in raw or "]" in raw:
                return  # bracket fractions like [1/2], not paths
            path = raw
        elif (not raw.isdigit() and len(raw) < 2048
                and all(c.isascii() and (c.isalnum() or c in "._~-/") for c in raw)):
            path = "/" + raw.lstrip("/")
        else:
            return
        path = "/" + path.lstrip("/")
        if path in ("/", "/FUZZ"):
            return  # root is not a finding; FUZZ is ffuf's placeholder keyword
        if path not in seen:
            seen.add(path)
            dirs.append(path)

    for line in text.replace("\r", "\n").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        # Substring precheck keeps findall linear (no ReDoS on long lines).
        cands = re.findall(r"([^\s]+)\s+\[Status:", s) if "[Status:" in s else []
        if cands:
            for c in cands:
                emit(c)
            continue
        if "://" in s:
            m = re.search(r"(https?://\S*)", s)
            if m:
                emit(m.group(1).rstrip(".,;\"'"))
            continue
        first = s.split()[0]
        if first.startswith("/"):
            emit(first)
        # Anything else (banner art, config echoes, progress chatter) is skipped.
    return dirs


def build_record(host, ip, port, service, banner="", http=None, dirs=None, source_tool="nmap+httpx"):
    """Enforce contracts: http null forces dirs == []. Returns None for invalid records; never throws."""
    try:
        if not isinstance(host, str) or not host:
            return None
        try:
            port = int(port)
        except (TypeError, ValueError):
            return None
        if not 1 <= port <= 65535:
            return None
        if not isinstance(service, str):
            service = ""
        if not isinstance(banner, str):
            banner = ""
        else:
            banner = banner or ""
        if http is not None and not isinstance(http, dict):
            http = None
        if http is None:
            dirs = []
        else:
            dirs = list(dirs or [])
        if not isinstance(source_tool, str):
            source_tool = "none"
        return {
            "host": host,
            "ip": ip,
            "port": port,
            "service": service,
            "banner": banner,
            "http": http,
            "dirs": dirs,
            "source_tool": source_tool,
        }
    except Exception:
        return None
