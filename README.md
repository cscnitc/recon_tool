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

The `--mode` flag changes what this script is allowed to do.

In ctf mode the script runs the full chain: naabu for all common ports, nmap `-sV -sC` on what naabu found, httpx with tech detect and TLS probe, then ffuf with the raft wordlists. Threads and rate are high. Use this on THM, HTB, and other lab targets.

In audit mode the script stays quiet. naabu is limited to the top 100 ports at `--rate 20`, nmap runs with `-T2`, httpx checks status, title, and TLS only. ffuf does not run. It exits with a note saying fuzzing was skipped. This is the setting for college infra.

## Scope check

`--scope` points to a file with one allowed host, domain, or CIDR per line. In audit mode the script reads it first and compares every target. A target outside scope stops the run before any packet is sent. ctf mode still takes the flag so the call shape stays the same, but the check is lenient for lab IPs.

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
