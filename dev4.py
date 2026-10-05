# skeleton only
# - parse args (in, mode, scope, out, [rate], [threads])
# - read targets and scope -> validate -> empty json out
# 0 = ok; 1 = input error; 2 = scope error

import sys
import argparse
import os
from urllib.parse import urlparse
from ipaddress import ip_address, ip_network
import json

MODES = {"ctf": {"depth": 10, "rate": 150, "threads": 10, "deep": True, "analysis": "full"},
        "audit": {"depth": 2, "rate": 20, "threads": 2, "deep": False, "analysis": "shallow"}}

MAX_RATE = 500
MAX_THREADS = 50

def log(msg):
    print(f"[dev4] {msg}", file=sys.stderr, flush=True)


def _host(s):
    s = s.strip()
    if "://" not in s:
        s = "http://" + s
    h = urlparse(s).hostname
    return h.rstrip(".").lower() if h else None


def parse(argsv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="targets", required=True, help="targets.txt (one host per line)")
    parser.add_argument("--mode", required=True, choices=["ctf", "audit"], help="ctf or audit")
    parser.add_argument("--scope", required=True, help="scope.txt (host, domain or CIDR per line)")
    parser.add_argument("--out", required=True, help="output json path")
    parser.add_argument("--rate", type=int, default=None, help="requests/sec")
    parser.add_argument("--threads", type=int, default=None, help="concurrent workers")
    args = parser.parse_args(argsv)

    cfg = dict(MODES[args.mode])

    if args.rate is not None:
        if args.rate not in range(1, MAX_RATE+1):
            raise SystemExit(f"--rate must be in range 1 to {MAX_RATE}")
        cfg["rate"] = args.rate
    if args.threads is not None:
        if args.threads not in range(1, MAX_THREADS+1):
            raise SystemExit(f"--threads must be in range 1 to {MAX_THREADS}")
        cfg["threads"] = args.threads
    return args, cfg

def main(argv=None):
    args, cfg = parse(argv)
    
    # === check existence
    if not os.path.isfile(args.targets):
        log(f"cant find targets list: {args.targets}")
        return 1
    
    if not os.path.isfile(args.scope):
        log(f"cant find scope file: {args.scope}")
        return 2

    # === read targets
    with open(args.targets, encoding="utf-8", errors="replace") as f:
        raw_targets = f.read().splitlines()
    
    targets=[]
    seen = set()

    for line in raw_targets:
        target = line.split("#", 1)[0].strip()
        if not target: continue
        host = _host(target)
        if not host: continue
        if host in seen: continue
        seen.add(host)
        targets.append(target)
    
    if not targets:
        log("targets list is empty")
        return 1
    
    # === read scope
    with open(args.scope, encoding="utf-8", errors="replace") as f:
        raw_scope = f.read().splitlines()
    
    scope_hosts = set()
    scope_domains = set()
    scope_networks = set()

    for line in raw_scope:
        raw = line.split("#", 1)[0].strip()
        if not raw: continue
        # == try CIDR
        try:
            network = ip_network(raw, strict=False)
            scope_networks.add(network)
            continue
        except ValueError:
            pass
        # == try ip address
        try:
            hosts = ip_address(raw)
            scope_hosts.add(str(hosts))
            continue
        except ValueError:
            pass
        # == try url
        hostname = _host(raw)
        if not hostname: continue
        scope_domains.add(hostname)
    
    # === validate targets against scope
    in_scope=[]
    out_of_scope=[]

    for target in targets:
        host = _host(target)
        if not host: continue
        target_in_scope = False
        # == exact host
        if host in scope_hosts:
            target_in_scope = True
        # == domain or subdomian
        if not target_in_scope:
            for domain in scope_domains:
                if host == domain or host.endswith("." + domain):
                    target_in_scope = True
                    break
        # == CIDR
        if not target_in_scope and scope_networks:
            try:
                ip = ip_address(host)
                for network in scope_networks:
                    if ip in network:
                        target_in_scope = True
                        break
            except ValueError:
                pass

        if target_in_scope:
            in_scope.append(target)
        else:
            out_of_scope.append(target)
    
    if out_of_scope:
        log(f"aborting due to scope violations: {", ".join(out_of_scope)}")
        return 2
    if not in_scope:
        log("no targets found in scope")
        return 1

    # === output json
    out_dir = os.path.dirname(args.out)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    
    rec = []
    
    for target in in_scope:
        host = _host(target)

        rec.append({
            "host": host,
            "urls": [],
            "js_endpoints": [],
            "params": [],
            "secrets": [],
            "source_tool": "gau+waybackurls+katana+LinkFinder+SecretFinder",
            "analysis": cfg["analysis"],
            "notes": ["shallow analysis"] if cfg["analysis"] == "shallow" else [],
        })

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2, ensure_ascii=False)
    
    log(f"wrote {len(rec)} record(s) to {args.out}")
    return 0

if __name__ == "__main__":
    sys.exit(main())