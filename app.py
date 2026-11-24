"""
LabScan — a small Flask web interface that runs a light, safe nmap scan
against an APPROVED LAB TARGET ONLY and saves the results with a label.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://127.0.0.1:5000 in your browser.
"""

from flask import (
    Flask, render_template, request, redirect, url_for, jsonify, abort
)

import ai_summary
import config
import scanner
import storage

app = Flask(__name__)


@app.route("/")
def index():
    scans = storage.list_scans()
    return render_template(
        "index.html",
        default_target=config.DEFAULT_TARGET,
        allowed_targets=config.ALLOWED_TARGETS,
        allow_private=config.ALLOW_PRIVATE_RANGES,
        scans=scans,
    )


@app.route("/scan", methods=["POST"])
def scan():
    target = (request.form.get("target") or "").strip()
    label = (request.form.get("label") or "").strip() or "Unlabeled scan"

    allowed, reason = scanner.is_target_allowed(target)
    if not allowed:
        return jsonify({"ok": False, "error": reason}), 400

    started_at = storage.now_iso()
    try:
        result = scanner.run_scan(target)
    except scanner.TargetNotAllowed as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except scanner.ScanError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    finished_at = storage.now_iso()

    summary, summary_src = ai_summary.summarize(
        target, label, result["ports"], result["host_state"]
    )

    scan_id = storage.save_scan(
        label=label,
        target=target,
        started_at=started_at,
        finished_at=finished_at,
        command=result["command"],
        host_state=result["host_state"],
        ports=result["ports"],
        summary=summary,
        summary_src=summary_src,
    )

    return jsonify({"ok": True, "scan_id": scan_id})


@app.route("/scan/<int:scan_id>")
def view_scan(scan_id):
    scan = storage.get_scan(scan_id)
    if scan is None:
        abort(404)
    return render_template("scan.html", scan=scan)


@app.route("/scan/<int:scan_id>/delete", methods=["POST"])
def delete_scan(scan_id):
    storage.delete_scan(scan_id)
    return redirect(url_for("index"))


@app.route("/api/scans")
def api_scans():
    return jsonify(storage.list_scans())


@app.route("/api/scan/<int:scan_id>")
def api_scan(scan_id):
    scan = storage.get_scan(scan_id)
    if scan is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(scan)


if __name__ == "__main__":
    storage.init_db()
    # Bind to loopback so the UI is only reachable from this machine.
    app.run(host="127.0.0.1", port=5000, debug=False)
