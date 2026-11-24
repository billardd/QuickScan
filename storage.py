"""
SQLite storage for LabScan.

Every scan is saved with its label, target, timestamps, the exact command
run, an AI/heuristic summary, and one row per open port.
"""

import datetime
import sqlite3

import config


def _connect():
    conn = sqlite3.connect(config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create tables if they don't exist. Safe to call on every startup."""
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                label        TEXT    NOT NULL,
                target       TEXT    NOT NULL,
                started_at   TEXT    NOT NULL,
                finished_at  TEXT    NOT NULL,
                command      TEXT    NOT NULL,
                host_state   TEXT    NOT NULL,
                open_count   INTEGER NOT NULL,
                summary      TEXT    NOT NULL DEFAULT '',
                summary_src  TEXT    NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS ports (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id   INTEGER NOT NULL,
                port      INTEGER NOT NULL,
                protocol  TEXT    NOT NULL,
                state     TEXT    NOT NULL,
                service   TEXT    NOT NULL DEFAULT '',
                product   TEXT    NOT NULL DEFAULT '',
                version   TEXT    NOT NULL DEFAULT '',
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            """
        )


def save_scan(label, target, started_at, finished_at, command,
              host_state, ports, summary, summary_src):
    """Persist one scan and its ports. Returns the new scan id."""
    with _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO scans
                (label, target, started_at, finished_at, command,
                 host_state, open_count, summary, summary_src)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (label, target, started_at, finished_at, command,
             host_state, len(ports), summary, summary_src),
        )
        scan_id = cur.lastrowid
        for p in ports:
            conn.execute(
                """
                INSERT INTO ports
                    (scan_id, port, protocol, state, service, product, version)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, p["port"], p["protocol"], p["state"],
                 p["service"], p["product"], p["version"]),
            )
        return scan_id


def list_scans(limit=50):
    """Return recent scans (newest first), without their ports."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan(scan_id):
    """Return a single scan dict with a 'ports' list, or None."""
    with _connect() as conn:
        scan = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if scan is None:
            return None
        ports = conn.execute(
            "SELECT * FROM ports WHERE scan_id = ? ORDER BY port", (scan_id,)
        ).fetchall()
        scan = dict(scan)
        scan["ports"] = [dict(p) for p in ports]
        return scan


def delete_scan(scan_id):
    with _connect() as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


def now_iso():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
