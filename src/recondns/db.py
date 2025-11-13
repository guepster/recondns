import json
import os
import sqlite3
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL,
  ts TEXT NOT NULL,            -- ISO8601 UTC
  report_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_domain_ts ON snapshots(domain, ts);
"""


def init_db(db_path: str):
    os.makedirs(os.path.dirname(db_path), exist_ok=True) if os.path.dirname(db_path) else None
    con = sqlite3.connect(db_path)
    try:
        con.executescript(SCHEMA)
        con.commit()
    finally:
        con.close()


def save_snapshot(db_path: str, report: dict[str, Any]) -> int:
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO snapshots(domain, ts, report_json) VALUES (?, ?, ?)",
            (report.get("domain"), report.get("timestamp"), json.dumps(report, ensure_ascii=False)),
        )
        con.commit()
        return cur.lastrowid
    finally:
        con.close()


def list_snapshots(db_path: str, domain: str, limit: int = 20) -> list[dict[str, Any]]:
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute(
            "SELECT id, domain, ts FROM snapshots WHERE domain = ? ORDER BY ts DESC LIMIT ?",
            (domain, limit),
        )
        rows = cur.fetchall()
        return [{"id": r[0], "domain": r[1], "ts": r[2]} for r in rows]
    finally:
        con.close()


def get_snapshot_by_id(db_path: str, snap_id: int) -> dict[str, Any] | None:
    con = sqlite3.connect(db_path)
    try:
        cur = con.cursor()
        cur.execute("SELECT report_json FROM snapshots WHERE id = ?", (snap_id,))
        row = cur.fetchone()
        if not row:
            return None
        return json.loads(row[0])
    finally:
        con.close()
