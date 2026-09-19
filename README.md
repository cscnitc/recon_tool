# Dev5: pipeline and reporting

This branch collects the output of Dev2, Dev3, and Dev4 and turns it into files the club can share. It checks the JSON, merges it, and writes a report for Discord or for IT.

This is a lite version. It uses flat files and a small Python script. Postgres and the HTML dashboard come later.

## What it takes in

The script expects three files in one folder, all produced with the same target list and mode:

- `dev2.json` with subdomains and IPs
- `dev3.json` with ports, services, and HTTP results
- `dev4.json` with URLs, JS endpoints, and params

If a file is missing, the merge still runs and leaves that section empty. If a record has the wrong keys, the script reports the file and line number and skips that record.

## What it puts out

- `report.json` with every host in one place
- `report.md` with tables a person can read
- `run-meta.json` with mode, time, input file hashes, and counts

`report.md` is enough for a CTF writeup or a short note to IT. `report.json` is for later work like the dashboard.

## Record shape

Each host in `report.json` looks like this:

```json
{
  "host": "portal.college.edu",
  "ips": ["10.10.5.12"],
  "ports": [{"port": 443, "service": "https"}],
  "tech": ["nginx", "php"],
  "urls": ["/api/v1/login"],
  "notes": ["ffuf skipped in audit mode"]
}
```

`notes` keeps context that would otherwise get lost, such as why fuzzing was skipped.

## Layout

```
dev5/
  merge.py
  validate.py
  schemas/
    dev2.json
    dev3.json
    dev4.json
  out/
```

`validate.py` checks keys and types. `merge.py` joins the three files on host or IP and writes the reports.

## How to run

```bash
python merge.py --in ./out --out ./report
```

This reads `./out/dev2.json`, `./out/dev3.json`, `./out/dev4.json` and writes `report.json`, `report.md`, and `run-meta.json` into `./report`.

JSON validation is strict about keys but lenient about extra fields. A module can add a new key without breaking the merge, as long as the required keys stay present.

## For later

The HTML dashboard and Postgres store belong in v2. When they land, they should read `report.json` as input so the current Dev2, Dev3, and Dev4 outputs keep working.
