"""Scope check for dev3. Mirror of main contracts.md scope rule.
Canonical source: main contracts.md. This copy lets dev3 run standalone.
"""
import ipaddress
import sys


def _load_scope(scope_file):
    entries = []
    with open(scope_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(line)
    return entries


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_in_scope(target, scope_entries):
    """Return True if target is in scope. IPv6 is out for v1 (returns False)."""
    target = target.strip()
    if not target:
        return False
    # Reject IPv6 outright for v1.
    try:
        ip = ipaddress.ip_address(target)
        if isinstance(ip, ipaddress.IPv6Address):
            return False
    except ValueError:
        pass  # not an IP, treat as hostname below

    # Strip CIDR suffix if target itself is a range: only single hosts allowed as targets.
    if "/" in target:
        return False

    for entry in scope_entries:
        entry = entry.strip()
        if not entry:
            continue
        # CIDR entry
        if "/" in entry:
            try:
                net = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            if isinstance(net, ipaddress.IPv6Network):
                continue
            if _is_ip(target):
                try:
                    ip = ipaddress.ip_address(target)
                except ValueError:
                    continue
                if ip in net:
                    # Skip network and broadcast addresses.
                    if ip == net.network_address or ip == net.broadcast_address:
                        continue
                    return True
            continue
        # Exact host or domain entry
        if _is_ip(target) and _is_ip(entry):
            if target == entry:
                return True
            continue
        # Hostname: exact match or subdomain-of-domain counts.
        t = target.lower().rstrip(".")
        e = entry.lower().rstrip(".")
        if t == e or t.endswith("." + e):
            return True
    return False


def check_targets(targets, scope_file, mode):
    """Audit: raise SystemExit on first out-of-scope target (before any packet).
    Ctf: warn-and-continue (lenient for lab IPs), flag still required for shape.
    Returns (in_scope_targets, notes)."""
    entries = _load_scope(scope_file)
    notes = []
    kept = []
    for t in targets:
        if is_in_scope(t, entries):
            kept.append(t)
        else:
            if mode == "audit":
                print(f"error: target out of scope in audit mode: {t}", file=sys.stderr)
                raise SystemExit(2)
            notes.append(f"scope lenient in ctf mode, kept out-of-scope target with warning: {t}")
            kept.append(t)
    return kept, notes
