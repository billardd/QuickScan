"""
Scan engine for LabScan.

Responsibilities:
  * decide whether a target is allowed (lab-only guardrail)
  * run a light, safe nmap TCP scan via subprocess
  * parse nmap XML output into structured open-port / service records

Nothing here runs unless the target passes is_target_allowed().
"""

import ipaddress
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

import config


class TargetNotAllowed(Exception):
    """Raised when a target fails the lab-only allowlist check."""


class ScanError(Exception):
    """Raised when nmap fails to run or produce parseable output."""


# ---------------------------------------------------------------------------
# Target validation (the lab-only guardrail)
# ---------------------------------------------------------------------------

def _resolve_to_ips(host):
    """Resolve a hostname/IP string to a list of ipaddress objects.

    Returns [] if it cannot be resolved.
    """
    try:
        # getaddrinfo handles both names and literal IPs.
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    ips = []
    for info in infos:
        addr = info[4][0]
        try:
            ips.append(ipaddress.ip_address(addr))
        except ValueError:
            continue
    return ips


def is_target_allowed(host):
    """Return (allowed: bool, reason: str) for a requested target.

    A host is allowed when:
      * it appears verbatim in config.ALLOWED_TARGETS, OR
      * config.ALLOW_PRIVATE_RANGES is True and every IP it resolves to is
        private, loopback, or link-local.

    Public / routable addresses are always refused.
    """
    host = (host or "").strip()
    if not host:
        return False, "No target supplied."

    # Exact-match allowlist always wins.
    if host in config.ALLOWED_TARGETS:
        return True, "Target is in the approved allowlist."

    if not config.ALLOW_PRIVATE_RANGES:
        return False, (
            "Target is not in the approved allowlist and private ranges are "
            "disabled. Add it to ALLOWED_TARGETS in config.py."
        )

    ips = _resolve_to_ips(host)
    if not ips:
        return False, f"Could not resolve '{host}' to an IP address."

    for ip in ips:
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            return False, (
                f"'{host}' resolves to {ip}, which is a public address. "
                "LabScan only scans private/lab networks."
            )

    return True, "Target is within a private/lab range."


# ---------------------------------------------------------------------------
# Running nmap
# ---------------------------------------------------------------------------

def _build_command(target):
    return [config.NMAP_BINARY, *config.NMAP_FLAGS, "-oX", "-", target]


def run_scan(target):
    """Run a light nmap scan against an already-validated target.

    Returns a dict:
        {
          "command": "<the exact command line>",
          "ports":   [ {port, protocol, state, service, product, version}, ... ],
          "host_state": "up" | "down" | "unknown",
          "raw_stderr": "...",
        }
    Raises TargetNotAllowed / ScanError.
    """
    allowed, reason = is_target_allowed(target)
    if not allowed:
        raise TargetNotAllowed(reason)

    if shutil.which(config.NMAP_BINARY) is None:
        raise ScanError(
            "nmap was not found on this machine. Install it first "
            "(e.g. 'sudo apt install nmap' or 'brew install nmap')."
        )

    cmd = _build_command(target)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.SCAN_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise ScanError(
            f"Scan timed out after {config.SCAN_TIMEOUT_SECONDS}s."
        )

    if not proc.stdout.strip():
        raise ScanError(
            "nmap produced no output. stderr: " + proc.stderr.strip()
        )

    parsed = _parse_nmap_xml(proc.stdout)
    parsed["command"] = " ".join(cmd)
    parsed["raw_stderr"] = proc.stderr.strip()
    return parsed


# ---------------------------------------------------------------------------
# Parsing nmap XML
# ---------------------------------------------------------------------------

def _parse_nmap_xml(xml_text):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise ScanError(f"Could not parse nmap XML output: {exc}")

    host_state = "unknown"
    ports = []

    host = root.find("host")
    if host is not None:
        status = host.find("status")
        if status is not None:
            host_state = status.get("state", "unknown")

        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                state = state_el.get("state") if state_el is not None else ""
                if state != "open":
                    continue

                service_el = port_el.find("service")
                service = product = version = ""
                if service_el is not None:
                    service = service_el.get("name", "") or ""
                    product = service_el.get("product", "") or ""
                    version = service_el.get("version", "") or ""

                ports.append({
                    "port": int(port_el.get("portid", "0")),
                    "protocol": port_el.get("protocol", "tcp"),
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                })

    ports.sort(key=lambda p: p["port"])
    return {"ports": ports, "host_state": host_state}
