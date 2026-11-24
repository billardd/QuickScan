"""
Optional AI summary for LabScan.

If a local Ollama server (e.g. your Qwen model) is running, this asks it to
write a short plain-English summary of the scan findings. If it isn't
reachable, we fall back to a built-in rule-based summary so the app never
depends on the LLM being up.

Nothing is sent to the internet: the request goes to localhost only.
"""

import json
import urllib.error
import urllib.request

import config


def summarize(target, label, ports, host_state):
    """Return (summary_text, source) where source is 'llm' or 'builtin'."""
    if config.ENABLE_AI_SUMMARY:
        llm = _summarize_with_ollama(target, label, ports, host_state)
        if llm:
            return llm, "llm"
    return _builtin_summary(target, ports, host_state), "builtin"


def _summarize_with_ollama(target, label, ports, host_state):
    port_lines = "\n".join(
        f"- {p['port']}/{p['protocol']} "
        f"{p['service'] or 'unknown'} "
        f"{(p['product'] + ' ' + p['version']).strip()}".strip()
        for p in ports
    ) or "- (no open ports found)"

    prompt = (
        "You are a security lab assistant. In 3-4 sentences, plainly summarize "
        "this nmap scan of a practice lab host. Note what the open services are, "
        "and flag anything commonly worth a closer look in a lab (e.g. old "
        "versions, remote-access or database services). Do not invent ports.\n\n"
        f"Target: {target}\n"
        f"Label: {label}\n"
        f"Host state: {host_state}\n"
        f"Open ports:\n{port_lines}\n"
    )

    payload = json.dumps({
        "model": config.OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }).encode("utf-8")

    req = urllib.request.Request(
        config.OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(
            req, timeout=config.OLLAMA_TIMEOUT_SECONDS
        ) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        text = (data.get("response") or "").strip()
        return text or None
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        # Ollama not running / model missing / bad response -> fall back.
        return None


def _builtin_summary(target, ports, host_state):
    if host_state != "up" and not ports:
        return (
            f"Host {target} did not appear to be up, or no open ports were "
            "found in the top 100 TCP ports. If you expect it to be live, the "
            "VM may block ping — try adding '-Pn' to NMAP_FLAGS in config.py."
        )
    if not ports:
        return (
            f"Host {target} is up, but none of the top 100 TCP ports were open. "
            "The host may be firewalled or running services on higher ports."
        )

    names = [p["service"] or f"port {p['port']}" for p in ports]
    listed = ", ".join(names)

    # Light, lab-oriented notes on commonly interesting services.
    notable = []
    interesting = {
        "ftp": "FTP (21) — often allows anonymous login in lab targets",
        "telnet": "Telnet (23) — cleartext remote access",
        "smtp": "SMTP (25) — mail service",
        "http": "HTTP — a web app to explore",
        "microsoft-ds": "SMB (445) — file sharing, a classic lab entry point",
        "netbios-ssn": "NetBIOS/SMB — file sharing",
        "mysql": "MySQL — a database service",
        "postgresql": "PostgreSQL — a database service",
        "ms-sql-s": "MS SQL — a database service",
        "vnc": "VNC — remote desktop",
        "rdp": "RDP (3389) — remote desktop",
        "ssh": "SSH — remote shell access",
    }
    for p in ports:
        key = (p["service"] or "").lower()
        if key in interesting:
            notable.append(interesting[key])

    summary = (
        f"Host {target} is up with {len(ports)} open TCP port(s): {listed}. "
    )
    if notable:
        summary += "Worth a closer look in the lab: " + "; ".join(
            dict.fromkeys(notable)
        ) + "."
    return summary
