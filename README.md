# Dev3: active scanning and probing

This branch probes live hosts. It takes the subdomain list from Dev2 and returns open ports, service names, web titles, tech fingerprints, and found paths. It is the only branch that sends packets to ports or requests paths that may not exist.

Stack for this branch: Python, naabu to find ports, nmap to fingerprint services, httpx to probe HTTP, ffuf to fuzz paths, all packed in Docker so it runs the same on any Linux laptop.

## Input and output

Input is a text file with one host per line. It usually comes from Dev2.

```
app.college.edu
portal.college.edu
10.10.5.12
```

Output is `dev3.json`, one record per port. Dev5 reads this file directly.

```json
{
  "host": "portal.college.edu",
  "ip": "10.10.5.12",
  "port": 443,
  "service": "https",
  "banner": "nginx 1.18",
  "http": {
    "status": 200,
    "title": "Student Portal",
    "tech": ["nginx", "php"]
  },
  "dirs": ["/admin", "/api/v1/login"],
  "source_tool": "nmap+httpx+ffuf"
}
```

If httpx finds no HTTP on a port, the `http` block is null and `dirs` stays empty.

## Modes

The `--mode` flag picks defaults, while `--rate` and `--threads` let the person running it adjust within bounds. Omit them to take mode defaults.

In ctf mode the script runs the full chain: naabu for all common ports, nmap `-sV -sC` on what naabu found, httpx with tech detect and TLS probe, then ffuf with the raft wordlists. Defaults are `rate 1000, threads 100`, adjustable `100-5000` and `10-200`. Masscan (`--scanner masscan`) and feroxbuster (`--fuzzer ferox`) are ctf-only opt-ins when the binary exists, same output shape. Use this on THM, HTB, and other lab targets.

In audit mode the script stays quiet. Defaults are `rate 20, threads 10` with top 100 ports and `nmap -T2`, httpx checks status, title, and TLS only. Adjustable `rate 10-50` and `threads 5-20` freely. Above that needs `--override reason-text`, which is written to the log and report notes. ffuf does not run. This is the setting for college infra.

## Scope check

`--scope` points to a file with one allowed host, domain, or CIDR per line. Targets are arbitrary, examples are placeholders. A subdomain of a listed domain counts as in scope. For CIDR entries, network and broadcast addresses are skipped. IPv6 is out for v1. In audit mode the script reads it first and compares every target. A target outside scope stops the run before any packet is sent. ctf mode still takes the flag so the call shape stays the same, but the check is lenient for lab IPs.

## Layout

```
dev3/
  dev3.py
  scope.py
  parsers.py
  wordlists/
  Dockerfile
```

`dev3.py` handles flags and calls each step. `scope.py` holds the scope check. `parsers.py` converts nmap, naabu, httpx, and ffuf output into the JSON above.

## How to run

```bash
python dev3.py --in subdomains.txt --mode ctf --scope scope.txt --out dev3.json
python dev3.py --in subdomains.txt --mode audit --scope scope.txt --out dev3.json
```

Docker build for club laptops:

```bash
docker build -t csc-recon:dev3 .
docker run --rm -v $(pwd)/out:/out csc-recon:dev3 \
  --in /out/subdomains.txt --mode audit --scope /out/scope.txt --out /out/dev3.json
```

naabu needs privileges for SYN scan. Without root it falls back to connect scan, which is slower but fine for small scopes.

## Build order

I built httpx first because it is safe and feeds everything else. Then nmap parsing. Then the mode gate and scope check. ffuf came last since it needs live HTTP hosts from the earlier steps. If you pick this branch up, test in that same order.
