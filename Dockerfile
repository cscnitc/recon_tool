# Dev3 active scanner: naabu + nmap + httpx + ffuf (masscan/ferox optional).
# v1 law: THIN image + fallback is intended. Only nmap+ffuf come from apt;
# naabu/httpx via projectdiscovery manual install in club builds; masscan/ferox
# are ctf-only opt-ins. Any missing binary -> run continues on defaults with a
# stderr "note:" (same JSON shape, exit 0). Root is intentional: naabu SYN scan
# needs privs; without root it falls back to connect scan (slower, fine small scope).
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 nmap ffuf curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# naabu + httpx via projectdiscovery (manual install in club builds; fallback+note if missing, see above).
# masscan/ferox are ctf-only opt-ins: image works without them (run continues on defaults).

WORKDIR /app
COPY dev3.py scope.py parsers.py ./
COPY wordlists/ ./wordlists/

ENTRYPOINT ["python3", "dev3.py"]
