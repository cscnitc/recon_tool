#!/usr/bin/env python3

import argparse
import ipaddress
import json
import logging
import sys
import subprocess
from pathlib import Path


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "dev2.log"


# ---------------------------------------------------------
# Logging
# ---------------------------------------------------------

def setup_logging() -> logging.Logger:
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("dev2")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )

        file_handler = logging.FileHandler(
            LOG_FILE,
            encoding="utf-8"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    return logger


# ---------------------------------------------------------
# File helpers
# ---------------------------------------------------------

def read_lines(filename: str) -> list[str]:
    """Read non-empty, non-comment lines from a file."""

    path = Path(filename)

    if not path.is_file():
        raise FileNotFoundError(
            f"File not found: {filename}"
        )

    values = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if line and not line.startswith("#"):
                values.append(line)

    return values


# ---------------------------------------------------------
# IP / CIDR helpers
# ---------------------------------------------------------

def parse_ipv4(value: str) -> ipaddress.IPv4Address | None:
    """Return IPv4 address or None."""

    try:
        address = ipaddress.ip_address(value)

        if address.version != 4:
            return None

        return address

    except ValueError:
        return None


def parse_ipv4_network(
    value: str,
) -> ipaddress.IPv4Network | None:
    """Return IPv4 network or None."""

    try:
        network = ipaddress.ip_network(
            value,
            strict=False
        )

        if network.version != 4:
            return None

        return network

    except ValueError:
        return None


def normalize_host(host: str) -> str:
    """Normalize a hostname/IP for comparisons."""

    return host.strip().lower().rstrip(".")


# ---------------------------------------------------------
# Scope checking
# ---------------------------------------------------------

def host_in_scope(
    target: str,
    scope_entries: list[str],
) -> bool:
    """
    Check whether a target is inside scope.

    Supported:
    - exact hostname
    - subdomain of a scoped domain
    - exact IPv4 address
    - IPv4 address inside a scoped CIDR

    IPv6 is not supported in v1.
    Network and broadcast addresses from a CIDR
    scope entry are skipped.
    """

    target = normalize_host(target)

    # IPv6 is out for v1.
    if ":" in target:
        return False

    target_ip = parse_ipv4(target)

    for raw_entry in scope_entries:

        entry = normalize_host(raw_entry)

        # Ignore IPv6 scope entries.
        if ":" in entry:
            continue

        # -------------------------------------------------
        # CIDR scope
        # -------------------------------------------------

        network = parse_ipv4_network(entry)

        if network is not None:

            if target_ip is None:
                continue

            # Network and broadcast are not considered
            # in-scope through this CIDR entry.
            if target_ip == network.network_address:
                continue

            if target_ip == network.broadcast_address:
                continue

            if target_ip in network:
                return True

            continue

        # -------------------------------------------------
        # Exact IPv4 scope
        # -------------------------------------------------

        entry_ip = parse_ipv4(entry)

        if entry_ip is not None:

            if target_ip is not None:
                if target_ip == entry_ip:
                    return True

            continue

        # -------------------------------------------------
        # Hostname / domain scope
        # -------------------------------------------------

        if target == entry:
            return True

        # Example:
        # scope = college.edu
        # target = portal.college.edu
        if target.endswith("." + entry):
            return True

    return False


def validate_targets_in_scope(
    targets: list[str],
    scope_entries: list[str],
) -> None:
    """
    Check every target before any lookup starts.

    If even one target is outside scope,
    stop the entire run.
    """

    for target in targets:

        if not host_in_scope(target, scope_entries):
            raise ValueError(
                f"Target outside scope: {target}"
            )


# ---------------------------------------------------------
# Rate / thread contract
# ---------------------------------------------------------

def validate_rate_threads(
    mode: str,
    rate: int,
    threads: int,
    override: str | None,
) -> None:
    """
    Validate the shared rate/thread limits.
    """

    if mode == "audit":

        rate_min = 10
        rate_max = 50

        thread_min = 5
        thread_max = 20

    else:

        rate_min = 100
        rate_max = 5000

        thread_min = 10
        thread_max = 200

    rate_ok = (
        rate_min <= rate <= rate_max
    )

    threads_ok = (
        thread_min <= threads <= thread_max
    )

    if rate_ok and threads_ok:
        return

    # Outside normal bounds requires --override.
    if not override:

        raise ValueError(
            f"{mode} mode limits exceeded: "
            f"rate={rate} "
            f"(allowed {rate_min}-{rate_max}), "
            f"threads={threads} "
            f"(allowed {thread_min}-{thread_max}). "
            f"Use --override with a reason."
        )


# ---------------------------------------------------------
# Target normalization
# ---------------------------------------------------------

def expand_targets(
    targets: list[str],
) -> list[str]:
    """
    Normalize input targets.

    Domain:
        portal.college.edu
        -> portal.college.edu

    IP:
        10.10.5.12
        -> 10.10.5.12

    CIDR:
        192.0.2.0/30
        -> 192.0.2.1
        -> 192.0.2.2

    IPv6 is rejected because v1 does not support IPv6.
    """

    expanded = []
    seen = set()

    for raw_target in targets:

        target = normalize_host(raw_target)

        if not target:
            continue

        # IPv6
        if ":" in target:
            raise ValueError(
                f"IPv6 is not supported in v1: {raw_target}"
            )

        # -------------------------------------------------
        # CIDR
        # -------------------------------------------------

        if "/" in target:

            network = parse_ipv4_network(target)

            if network is None:
                raise ValueError(
                    f"Invalid CIDR target: {raw_target}"
                )

            # Explicitly skip network and broadcast.
            for address in network:

                if address == network.network_address:
                    continue

                if address == network.broadcast_address:
                    continue

                host = str(address)

                if host not in seen:
                    seen.add(host)
                    expanded.append(host)

            continue

        # -------------------------------------------------
        # Plain IP
        # -------------------------------------------------

        ip = parse_ipv4(target)

        if ip is not None:
            target = str(ip)

        # -------------------------------------------------
        # Domain
        # -------------------------------------------------

        if target not in seen:
            seen.add(target)
            expanded.append(target)

    return expanded


# ---------------------------------------------------------
# Dev2 function
# ---------------------------------------------------------
def run_subfinder(domain: str) -> list[str]:
    """Run Subfinder in Docker and return discovered subdomains."""

    command = [
        "sudo",
        "docker",
        "run",
        "--rm",
        "projectdiscovery/subfinder:latest",
        "-d",
        domain,
        "-silent",
        "-timeout",
        "5",
        "-max-time",
        "1",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=75,
        )

    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f"Subfinder timed out for {domain}"
        )

    if result.returncode != 0:
        error = result.stderr.strip()

        raise RuntimeError(
            f"Subfinder failed for {domain}: {error}"
        )

    subdomains = []

    for line in result.stdout.splitlines():

        line = normalize_host(line)

        if line:
            subdomains.append(line)

    return sorted(set(subdomains))

def run(
    targets: list[str],
    mode: str,
    scope_file: str,
) -> dict:
    """
    Dev2 module entry point.
    """

    if mode not in {"ctf", "audit"}:
        raise ValueError(
            "mode must be 'ctf' or 'audit'"
        )

    scope_entries = read_lines(scope_file)

    # Audit scope check happens before any lookup.
    if mode == "audit":
        validate_targets_in_scope(
            targets,
            scope_entries
        )

    results = []
    seen_hosts = set()

    for target in targets:

        # If the input itself is an IP,
        # we already know its IP.
        target_ip = parse_ipv4(target)

        if target_ip is not None:

            host = str(target_ip)

            if host not in seen_hosts:
                seen_hosts.add(host)

                results.append(
                    {
                        "host": host,
                        "ips": [host],
                        "source_tool": "input",
                    }
                )

            continue

        # Run Subfinder for domain targets.
        subdomains = run_subfinder(target)

        for subdomain in subdomains:

            subdomain = normalize_host(subdomain)

            if subdomain in seen_hosts:
                continue

            seen_hosts.add(subdomain)

            results.append(
                {
                    "host": subdomain,
                    "ips": [],
                    "source_tool": "subfinder",
                }
            )

    return {
        "results": results
    }


# ---------------------------------------------------------
# CLI
# ---------------------------------------------------------

def parse_args() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        description=(
            "Dev2 Passive Reconnaissance Engine"
        )
    )

    # Shared flags
    parser.add_argument(
        "--in",
        dest="input_file",
        required=True,
        help="Input targets file"
    )

    parser.add_argument(
        "--mode",
        choices=["ctf", "audit"],
        required=True,
        help="Operational mode"
    )

    parser.add_argument(
        "--scope",
        required=True,
        help="Scope file"
    )

    parser.add_argument(
        "--out",
        required=True,
        help="Output JSON file"
    )

    # Shared optional flags
    parser.add_argument(
        "--rate",
        type=int,
        help="Rate limit"
    )

    parser.add_argument(
        "--threads",
        type=int,
        help="Thread count"
    )

    parser.add_argument(
        "--override",
        help="Reason for exceeding mode limits"
    )

    # Dev2-specific flag
    parser.add_argument(
        "--extended",
        action="store_true",
        help="Enable Amass in ctf mode"
    )

    return parser.parse_args()


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main() -> int:

    logger = setup_logging()

    try:

        args = parse_args()

        # -------------------------------------------------
        # Read targets
        # -------------------------------------------------

        raw_targets = read_lines(
            args.input_file
        )

        targets = expand_targets(
            raw_targets
        )

        if not targets:
            raise ValueError(
                "No valid targets found in input file"
            )

        # -------------------------------------------------
        # Shared defaults
        # -------------------------------------------------

        if args.mode == "audit":

            rate = (
                args.rate
                if args.rate is not None
                else 20
            )

            threads = (
                args.threads
                if args.threads is not None
                else 10
            )

        else:

            rate = (
                args.rate
                if args.rate is not None
                else 1000
            )

            threads = (
                args.threads
                if args.threads is not None
                else 100
            )

        # -------------------------------------------------
        # Validate rate/thread
        # -------------------------------------------------

        validate_rate_threads(
            args.mode,
            rate,
            threads,
            args.override
        )

        # -------------------------------------------------
        # Validate --extended
        # -------------------------------------------------

        if (
            args.extended
            and args.mode != "ctf"
        ):
            raise ValueError(
                "--extended is only allowed in ctf mode"
            )

        # -------------------------------------------------
        # Logging
        # -------------------------------------------------

        logger.info(
            "mode=%s",
            args.mode
        )

        logger.info(
            "targets=%d",
            len(targets)
        )

        logger.info(
            "effective rate=%d",
            rate
        )

        logger.info(
            "effective threads=%d",
            threads
        )

        logger.info(
            "override used=%s",
            bool(args.override)
        )

        if args.override:
            logger.info(
                "override reason=%s",
                args.override
            )

        if args.extended:
            logger.info(
                "extended=true"
            )

        # -------------------------------------------------
        # Run Dev2
        # -------------------------------------------------

        output = run(
            targets,
            args.mode,
            args.scope
        )

        # -------------------------------------------------
        # Write JSON
        # -------------------------------------------------

        output_path = Path(args.out)

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with output_path.open(
            "w",
            encoding="utf-8"
        ) as file:

            # dev2.json must be an array
            # of host records.
            json.dump(
                output["results"],
                file,
                indent=2
            )

            file.write("\n")

        logger.info(
            "wrote %d records to %s",
            len(output["results"]),
            output_path
        )

        return 0

    except Exception as exc:

        logger.error(
            "error: %s",
            exc
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())