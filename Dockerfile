# Dev3 active scanner: naabu + nmap + httpx + ffuf (masscan/ferox optional).
# v1 law: THIN image + fallback is intended. Only nmap+ffuf come from apt;
# naabu/httpx via projectdiscovery manual install in club builds; masscan/ferox
# are ctf-only opt-ins. Any missing binary -> run continues on defaults with a
# stderr "note:" (same JSON shape, exit 0). Nonroot default: image runs as dev3.
# naabu SYN scan needs runtime --cap-add=NET_RAW; use --user "$(id -u):$(id -g)"
# for bind-mounted output ownership; without capability naabu falls back to
# connect scan (slower, fine small scope).
FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 nmap ffuf curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd -r dev3 && useradd -r -g dev3 dev3

# naabu + httpx via projectdiscovery (manual install in club builds; fallback+note if missing, see above).
# masscan/ferox are ctf-only opt-ins: image works without them (run continues on defaults).

WORKDIR /app
COPY dev3.py scope.py parsers.py ./
COPY wordlists/ ./wordlists/

RUN chown -R dev3:dev3 /app

HEALTHCHECK CMD python3 -c "import sys; sys.exit(0)"

USER dev3

ENTRYPOINT ["python3", "dev3.py"]
