# Dev3 active scanner: naabu + nmap + httpx + ffuf (masscan/ferox optional).
FROM kalilinux/kali-rolling-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 nmap ffuf curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# naabu + httpx via projectdiscovery (manual install in club builds; fallback+note if missing).
# masscan/ferox are ctf-only opt-ins: image works without them (run continues on defaults).

WORKDIR /app
COPY dev3.py scope.py parsers.py ./
COPY wordlists/ ./wordlists/

ENTRYPOINT ["python3", "dev3.py"]
