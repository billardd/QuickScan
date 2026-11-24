# LabScan

A small AI-assisted web interface that runs a **light, safe TCP scan** against
an **approved lab target only** and saves the results with a label.

Built for coursework and practice labs (Metasploitable, Juice Shop, Vulhub,
etc.) — **not for real networks you don't own or have written permission to test.**

> ⚠️ This app runs **locally** — it needs a Python backend and `nmap` installed.
> It is not a hosted website; GitHub stores the code, you run it on your own
> machine or lab host.

<!-- Add a screenshot of the console here once you've run it, e.g.:
![LabScan console](docs/screenshot.png) -->

---

## What it does

- **Prefilled target** — the scan form is pre-populated with your configured
  lab host (`DEFAULT_TARGET` in `config.py`).
- **Lab-only guardrail** — before any scan runs, the target must pass an
  allowlist check. A host is allowed only if it's in `ALLOWED_TARGETS` or (by
  default) falls inside a private / loopback range. **Public IPs are refused.**
- **Light scan** — `nmap -sT -sV --version-light --top-ports 100 -T3 --open`.
  A TCP connect scan (no root needed), low-intensity service detection, only
  the 100 most common ports, polite timing, open ports only.
- **Results** — lists each open port with its detected service, product, and
  version.
- **Saved with labels** — every scan is stored in SQLite with your label, the
  target, start/finish timestamps, the exact command, and one row per port.
- **AI summary (optional)** — after each scan it asks your **local LLM** (via
  Ollama) for a plain-English summary. If the LLM isn't running, it falls back
  to a built-in rule-based summary, so the app always works.

---

## Requirements

- Python 3.9+
- `nmap` installed and on your PATH
  - Debian/Kali/Ubuntu: `sudo apt install nmap`
  - macOS: `brew install nmap`
- (Optional) [Ollama](https://ollama.com) running locally with a model, e.g.
  `ollama run qwen2.5:7b`, for the AI summary.

---

## Setup

```bash
git clone https://github.com/<your-username>/labscan.git
cd labscan
python3 -m venv .venv && source .venv/bin/activate   # optional but recommended
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

The app binds to `127.0.0.1` only, so the UI is reachable just from your own
machine.

---

## Configure it for your lab

Edit `config.py`:

| Setting | What to change |
|---|---|
| `DEFAULT_TARGET` | The IP that appears prefilled in the form (e.g. your Metasploitable VM `192.168.56.101`). |
| `ALLOWED_TARGETS` | Exact hosts you've approved. Always allowed. |
| `ALLOW_PRIVATE_RANGES` | `True` lets you scan any private/lab IP without listing each one. Set `False` to allow **only** the exact hosts in `ALLOWED_TARGETS`. |
| `NMAP_FLAGS` | The scan flags. If a VM blocks ping and shows as "down", add `"-Pn"`. |
| `OLLAMA_MODEL` | Your local model name for the AI summary. |

---

## How the pieces fit

```
app.py          Flask routes + request handling
scanner.py      allowlist check, runs nmap, parses XML
storage.py      SQLite: save / list / fetch scans
ai_summary.py   local-LLM summary with a built-in fallback
config.py       all settings (target, allowlist, flags, LLM)
templates/      index (console) + scan (results) pages
static/         stylesheet
```

The scan path is: validate target → run nmap → parse open ports → summarize →
save to SQLite → show results.

---

## Safety notes

- Scanning hosts you don't own or lack written authorization to test can be a
  crime and a conduct violation. This tool deliberately refuses public
  addresses, but **you** are responsible for pointing it only at your own lab.
- Keep `ALLOW_PRIVATE_RANGES = False` and a tight `ALLOWED_TARGETS` list if you
  want the strictest possible scoping.

---

## License

Released under the [MIT License](LICENSE). Update the copyright line in
`LICENSE` with your name before publishing.
