"""
Configuration for LabScan.

This tool is for AUTHORIZED LAB TARGETS ONLY.
Only hosts that pass the allowlist check in scanner.py can be scanned.
Do not point this at networks or hosts you do not own or have explicit
written permission to test.
"""

# ---------------------------------------------------------------------------
# Target configuration
# ---------------------------------------------------------------------------

# The target shown pre-filled in the web form. Change this to your own lab
# VM's IP (e.g. your Metasploitable or Juice Shop box).
DEFAULT_TARGET = "127.0.0.1"

# Strict allowlist of exact hosts you have approved for scanning.
# Add your lab VM IPs/hostnames here, e.g. "192.168.56.101".
# A host in this list is always allowed.
ALLOWED_TARGETS = [
    "127.0.0.1",
    "localhost",
    # "192.168.56.101",   # <- example: Metasploitable VM
    # "192.168.56.102",   # <- example: Juice Shop VM
]

# If True, any host inside a private/loopback range (RFC 1918 + 127.0.0.0/8)
# is also allowed, even if not listed above. This keeps the tool usable
# across a changing lab network while still refusing public / real-world IPs.
# Set to False to allow ONLY the exact hosts in ALLOWED_TARGETS.
ALLOW_PRIVATE_RANGES = True

# ---------------------------------------------------------------------------
# Scan configuration
# ---------------------------------------------------------------------------

# Path to the nmap binary.
NMAP_BINARY = "nmap"

# Light, non-root-friendly scan flags:
#   -sT              TCP connect scan (no raw sockets / root needed)
#   -sV              service/version detection
#   --version-light  low-intensity version probes (keeps it light)
#   --top-ports 100  only the 100 most common TCP ports
#   -T3              normal timing (polite, not aggressive)
#   --open           only report open ports
# If a lab VM blocks ping and shows as "down", add "-Pn" to this list.
NMAP_FLAGS = [
    "-sT",
    "-sV",
    "--version-light",
    "--top-ports", "100",
    "-T3",
    "--open",
]

# Hard timeout (seconds) for a single scan subprocess.
SCAN_TIMEOUT_SECONDS = 180

# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

# SQLite database file (created automatically on first run).
DATABASE_PATH = "labscan.db"

# ---------------------------------------------------------------------------
# Optional AI summary (local LLM via Ollama)
# ---------------------------------------------------------------------------

# If True, after each scan LabScan asks a local LLM to write a plain-English
# summary of the findings. If the LLM isn't reachable, it falls back to a
# built-in rule-based summary, so the app always works.
ENABLE_AI_SUMMARY = True

# Ollama-compatible endpoint running on your machine. Your local Qwen setup
# fits here. Nothing leaves your machine.
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:7b"
OLLAMA_TIMEOUT_SECONDS = 60
